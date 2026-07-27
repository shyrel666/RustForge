//! Bounded HTTP body capture.
//!
//! The proxy must never collect a complete request or response merely for
//! inspection. `tee_body` forwards every Hyper frame unchanged while retaining
//! at most `MAX_WIRE_CAPTURE_BYTES`. Decoding happens only after the stream
//! finishes and is independently capped by `MAX_DECODED_CAPTURE_BYTES`.

use http_body_util::BodyExt;
use hudsucker::hyper::body::{Body as HttpBody, Bytes, Frame, SizeHint};
use hudsucker::hyper::header::{CONTENT_ENCODING, CONTENT_TYPE};
use hudsucker::hyper::HeaderMap;
use hudsucker::{Body, Error};
use std::fmt;
use std::io::{self, Read};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

/// Maximum compressed/on-wire bytes retained per request or response.
pub const MAX_WIRE_CAPTURE_BYTES: usize = 1024 * 1024;

/// Maximum decoded bytes retained per request or response.
pub const MAX_DECODED_CAPTURE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamCompletion {
    Reading,
    Complete,
    Error,
    Dropped,
}

#[derive(Debug)]
struct CaptureState {
    wire_size: u64,
    bytes: Vec<u8>,
    truncated: bool,
    peak_buffered: usize,
    completion: StreamCompletion,
}

impl Default for CaptureState {
    fn default() -> Self {
        Self {
            wire_size: 0,
            bytes: Vec::new(),
            truncated: false,
            peak_buffered: 0,
            completion: StreamCompletion::Reading,
        }
    }
}

/// Shared observation handle for a streaming tee.
#[derive(Clone, Debug, Default)]
pub struct CaptureHandle {
    state: Arc<Mutex<CaptureState>>,
}

impl CaptureHandle {
    fn record(&self, chunk: &[u8]) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.wire_size = state.wire_size.saturating_add(chunk.len() as u64);

        let remaining = MAX_WIRE_CAPTURE_BYTES.saturating_sub(state.bytes.len());
        let retained = remaining.min(chunk.len());
        state.bytes.extend_from_slice(&chunk[..retained]);
        state.peak_buffered = state.peak_buffered.max(state.bytes.len());
        if retained < chunk.len() {
            state.truncated = true;
        }
    }

    fn mark(&self, completion: StreamCompletion) {
        if let Ok(mut state) = self.state.lock() {
            if state.completion == StreamCompletion::Reading {
                state.completion = completion;
            }
        }
    }

    fn observed_wire_size(&self) -> u64 {
        self.state
            .lock()
            .map(|state| state.wire_size)
            .unwrap_or_default()
    }

    /// Convert the bounded wire snapshot into the representation stored and
    /// inspected by the application.
    pub fn finish(&self, metadata: &BodyMetadata) -> CapturedBody {
        let state = match self.state.lock() {
            Ok(state) => CapturedWire {
                wire_size: state.wire_size,
                bytes: state.bytes.clone(),
                truncated: state.truncated,
                completion: state.completion,
            },
            Err(_) => CapturedWire {
                wire_size: 0,
                bytes: Vec::new(),
                truncated: true,
                completion: StreamCompletion::Error,
            },
        };
        decode_capture(state, metadata)
    }

    #[cfg(test)]
    fn peak_buffered(&self) -> usize {
        self.state
            .lock()
            .map(|state| state.peak_buffered)
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone)]
struct CapturedWire {
    wire_size: u64,
    bytes: Vec<u8>,
    truncated: bool,
    completion: StreamCompletion,
}

/// Header-derived information needed after the stream has finished.
#[derive(Debug, Clone, Default)]
pub struct BodyMetadata {
    encodings: Vec<String>,
    content_type: Option<String>,
}

impl BodyMetadata {
    pub fn from_headers(headers: &HeaderMap) -> Self {
        let mut encodings = Vec::new();
        for value in headers.get_all(CONTENT_ENCODING) {
            let Ok(value) = value.to_str() else {
                continue;
            };
            encodings.extend(
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_ascii_lowercase),
            );
        }

        let content_type = headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);

        Self {
            encodings,
            content_type,
        }
    }

    pub fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }
}

/// Stable values stored in `req_decode_status` / `resp_decode_status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeStatus {
    NotReceived,
    Empty,
    IdentityText,
    IdentityBinary,
    DecodedText,
    DecodedBinary,
    DecodeFailed,
    UnsupportedEncoding,
    EncodedTruncated,
    DecodeTruncated,
    StreamError,
    StreamIncomplete,
}

impl DecodeStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotReceived => "not_received",
            Self::Empty => "empty",
            Self::IdentityText => "identity_text",
            Self::IdentityBinary => "identity_binary",
            Self::DecodedText => "decoded_text",
            Self::DecodedBinary => "decoded_binary",
            Self::DecodeFailed => "decode_failed",
            Self::UnsupportedEncoding => "unsupported_encoding",
            Self::EncodedTruncated => "encoded_truncated",
            Self::DecodeTruncated => "decode_truncated",
            Self::StreamError => "stream_error",
            Self::StreamIncomplete => "stream_incomplete",
        }
    }

    pub const fn is_text(self) -> bool {
        matches!(self, Self::Empty | Self::IdentityText | Self::DecodedText)
    }
}

impl fmt::Display for DecodeStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct CapturedBody {
    pub bytes: Vec<u8>,
    pub wire_size: i64,
    pub captured_size: i64,
    pub truncated: bool,
    pub decode_status: DecodeStatus,
}

impl CapturedBody {
    pub fn not_received() -> Self {
        Self {
            bytes: Vec::new(),
            wire_size: 0,
            captured_size: 0,
            truncated: false,
            decode_status: DecodeStatus::NotReceived,
        }
    }
}

type FinishCallback = Box<dyn FnOnce(CaptureHandle) + Send + Sync + 'static>;

struct CapturingBody {
    inner: Pin<Box<Body>>,
    capture: CaptureHandle,
    on_finish: Option<FinishCallback>,
    expected_wire_size: Option<u64>,
}

impl CapturingBody {
    fn finish(&mut self, completion: StreamCompletion) {
        self.capture.mark(completion);
        if let Some(callback) = self.on_finish.take() {
            callback(self.capture.clone());
        }
    }
}

impl Drop for CapturingBody {
    fn drop(&mut self) {
        let completion = match self.expected_wire_size {
            Some(expected) if self.capture.observed_wire_size() == expected => {
                StreamCompletion::Complete
            }
            _ => StreamCompletion::Dropped,
        };
        self.finish(completion);
    }
}

impl HttpBody for CapturingBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let frame = this.inner.as_mut().poll_frame(cx);
        match &frame {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.capture.record(data);
                }
            }
            Poll::Ready(Some(Err(_))) => this.finish(StreamCompletion::Error),
            Poll::Ready(None) => this.finish(StreamCompletion::Complete),
            Poll::Pending => {}
        }
        frame
    }

    fn is_end_stream(&self) -> bool {
        self.inner.as_ref().get_ref().is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.as_ref().get_ref().size_hint()
    }
}

/// Wrap a body for bounded capture without a completion callback.
pub fn tee_body(body: Body) -> (Body, CaptureHandle) {
    tee_body_inner(body, None)
}

/// Wrap a body for bounded capture and invoke `on_finish` exactly once on EOF,
/// stream error, or downstream cancellation.
pub fn tee_body_with_callback<F>(body: Body, on_finish: F) -> (Body, CaptureHandle)
where
    F: FnOnce(CaptureHandle) + Send + Sync + 'static,
{
    tee_body_inner(body, Some(Box::new(on_finish)))
}

fn tee_body_inner(body: Body, on_finish: Option<FinishCallback>) -> (Body, CaptureHandle) {
    let capture = CaptureHandle::default();
    let expected_wire_size = body.size_hint().exact();
    let mut capturing = CapturingBody {
        inner: Box::pin(body),
        capture: capture.clone(),
        on_finish,
        expected_wire_size,
    };

    if capturing.inner.as_ref().get_ref().is_end_stream() {
        capturing.finish(StreamCompletion::Complete);
    }

    (Body::from(capturing.boxed()), capture)
}

fn decode_capture(wire: CapturedWire, metadata: &BodyMetadata) -> CapturedBody {
    let mut truncated = wire.truncated;
    let wire_size = i64::try_from(wire.wire_size).unwrap_or(i64::MAX);

    let (bytes, status) = match wire.completion {
        StreamCompletion::Error => {
            truncated = true;
            (wire.bytes, DecodeStatus::StreamError)
        }
        StreamCompletion::Dropped | StreamCompletion::Reading => {
            truncated = true;
            (wire.bytes, DecodeStatus::StreamIncomplete)
        }
        StreamCompletion::Complete if wire.bytes.is_empty() => (wire.bytes, DecodeStatus::Empty),
        StreamCompletion::Complete => {
            let (bytes, status, decoded_truncated) =
                decode_complete(wire.bytes, truncated, metadata);
            truncated |= decoded_truncated;
            (bytes, status)
        }
    };

    let captured_size = i64::try_from(bytes.len()).unwrap_or(i64::MAX);
    CapturedBody {
        bytes,
        wire_size,
        captured_size,
        truncated,
        decode_status: status,
    }
}

fn decode_complete(
    wire_bytes: Vec<u8>,
    wire_truncated: bool,
    metadata: &BodyMetadata,
) -> (Vec<u8>, DecodeStatus, bool) {
    let encodings: Vec<&str> = metadata
        .encodings
        .iter()
        .map(String::as_str)
        .filter(|encoding| *encoding != "identity")
        .collect();

    if encodings.is_empty() {
        let status = classify_status(false, &wire_bytes, metadata.content_type());
        return (wire_bytes, status, false);
    }

    if let Some(_unsupported) = encodings
        .iter()
        .find(|encoding| !matches!(**encoding, "gzip" | "x-gzip" | "deflate" | "br"))
    {
        return (wire_bytes, DecodeStatus::UnsupportedEncoding, false);
    }

    // A compressed prefix is not safe to present as decoded evidence.
    if wire_truncated {
        return (wire_bytes, DecodeStatus::EncodedTruncated, false);
    }

    let mut decoded = wire_bytes;
    for (index, encoding) in encodings.iter().rev().enumerate() {
        let decoded_layer = match decode_one(&decoded, encoding) {
            Ok(decoded) => decoded,
            Err(_) => return (decoded, DecodeStatus::DecodeFailed, false),
        };
        decoded = decoded_layer.bytes;
        if decoded_layer.truncated {
            if index + 1 < encodings.len() {
                return (decoded, DecodeStatus::DecodeTruncated, true);
            }
            let status = classify_status(true, &decoded, metadata.content_type());
            return (decoded, status, true);
        }
    }

    let status = classify_status(true, &decoded, metadata.content_type());
    (decoded, status, false)
}

struct DecodedLayer {
    bytes: Vec<u8>,
    truncated: bool,
}

fn decode_one(data: &[u8], encoding: &str) -> io::Result<DecodedLayer> {
    match encoding {
        "gzip" | "x-gzip" => read_limited(flate2::read::GzDecoder::new(data)),
        "br" => read_limited(brotli::Decompressor::new(data, 4096)),
        "deflate" => match read_limited(flate2::read::ZlibDecoder::new(data)) {
            Ok(decoded) => Ok(decoded),
            Err(_) => read_limited(flate2::read::DeflateDecoder::new(data)),
        },
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported content encoding",
        )),
    }
}

fn read_limited(reader: impl Read) -> io::Result<DecodedLayer> {
    let mut bytes = Vec::with_capacity(MAX_DECODED_CAPTURE_BYTES.min(64 * 1024));
    reader
        .take((MAX_DECODED_CAPTURE_BYTES as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    let truncated = bytes.len() > MAX_DECODED_CAPTURE_BYTES;
    bytes.truncate(MAX_DECODED_CAPTURE_BYTES);
    Ok(DecodedLayer { bytes, truncated })
}

fn classify_status(decoded: bool, bytes: &[u8], content_type: Option<&str>) -> DecodeStatus {
    let text = is_text(bytes, content_type);
    match (decoded, text) {
        (false, true) => DecodeStatus::IdentityText,
        (false, false) => DecodeStatus::IdentityBinary,
        (true, true) => DecodeStatus::DecodedText,
        (true, false) => DecodeStatus::DecodedBinary,
    }
}

fn is_text(bytes: &[u8], content_type: Option<&str>) -> bool {
    let utf8 = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => return false,
    };

    if let Some(content_type) = content_type {
        let mime = content_type
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if mime.starts_with("text/")
            || mime.ends_with("+json")
            || mime.ends_with("+xml")
            || matches!(
                mime.as_str(),
                "application/json"
                    | "application/xml"
                    | "application/javascript"
                    | "application/x-javascript"
                    | "application/x-www-form-urlencoded"
                    | "application/graphql"
                    | "image/svg+xml"
            )
        {
            return true;
        }
        if mime.starts_with("image/")
            || mime.starts_with("audio/")
            || mime.starts_with("video/")
            || mime.starts_with("font/")
            || matches!(
                mime.as_str(),
                "application/octet-stream"
                    | "application/pdf"
                    | "application/zip"
                    | "application/gzip"
                    | "application/wasm"
                    | "application/x-protobuf"
            )
        {
            return false;
        }
    }

    // Without a decisive content type, reject NUL and dense control bytes.
    let controls = utf8
        .chars()
        .filter(|character| {
            character.is_control() && !matches!(*character, '\r' | '\n' | '\t' | '\u{000C}')
        })
        .count();
    controls.saturating_mul(100) <= utf8.chars().count().max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::{DeflateEncoder, GzEncoder, ZlibEncoder};
    use flate2::Compression;
    use hudsucker::futures::stream;
    use std::io::Write;

    struct MisleadingSizeBody {
        bytes: Option<Bytes>,
        declared: u64,
    }

    impl HttpBody for MisleadingSizeBody {
        type Data = Bytes;
        type Error = Error;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Ready(self.bytes.take().map(|bytes| Ok(Frame::data(bytes))))
        }

        fn is_end_stream(&self) -> bool {
            self.bytes.is_none()
        }

        fn size_hint(&self) -> SizeHint {
            let mut hint = SizeHint::new();
            hint.set_exact(self.declared);
            hint
        }
    }

    async fn capture_stream(body: Body, metadata: BodyMetadata) -> (CapturedBody, usize) {
        let (mut forwarded, handle) = tee_body(body);
        let mut forwarded_size = 0;
        while let Some(frame) = forwarded.frame().await {
            let frame = frame.expect("body frame");
            if let Some(data) = frame.data_ref() {
                forwarded_size += data.len();
            }
        }
        (handle.finish(&metadata), forwarded_size)
    }

    fn metadata(content_type: &str, encoding: Option<&str>) -> BodyMetadata {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, content_type.parse().unwrap());
        if let Some(encoding) = encoding {
            headers.insert(CONTENT_ENCODING, encoding.parse().unwrap());
        }
        BodyMetadata::from_headers(&headers)
    }

    async fn capture_bytes(
        bytes: Vec<u8>,
        content_type: &str,
        encoding: Option<&str>,
    ) -> CapturedBody {
        capture_stream(Body::from(bytes), metadata(content_type, encoding))
            .await
            .0
    }

    #[tokio::test]
    async fn tee_forwards_every_byte_while_capture_stays_bounded() {
        const CHUNK_SIZE: usize = 64 * 1024;
        const CHUNKS: usize = 64;
        let source = stream::unfold(0, |index| async move {
            (index < CHUNKS).then(|| {
                (
                    Ok::<Bytes, io::Error>(Bytes::from(vec![b'x'; CHUNK_SIZE])),
                    index + 1,
                )
            })
        });
        let body = Body::from_stream(source);
        let (mut forwarded, handle) = tee_body(body);

        let mut forwarded_size = 0;
        while let Some(frame) = forwarded.frame().await {
            let frame = frame.unwrap();
            forwarded_size += frame.data_ref().map_or(0, Bytes::len);
        }

        let captured = handle.finish(&metadata("text/plain", None));
        assert_eq!(forwarded_size, CHUNK_SIZE * CHUNKS);
        assert_eq!(captured.wire_size as usize, forwarded_size);
        assert_eq!(captured.captured_size as usize, MAX_WIRE_CAPTURE_BYTES);
        assert!(captured.truncated);
        assert!(handle.peak_buffered() <= MAX_WIRE_CAPTURE_BYTES);
    }

    #[tokio::test]
    async fn declared_size_smaller_than_stream_cannot_bypass_actual_byte_limit() {
        let actual = vec![b'm'; MAX_WIRE_CAPTURE_BYTES + 32 * 1024];
        let source = MisleadingSizeBody {
            bytes: Some(Bytes::from(actual.clone())),
            declared: 3,
        };
        let body = Body::from(source.boxed());
        let (captured, forwarded_size) = capture_stream(body, metadata("text/plain", None)).await;

        assert_eq!(forwarded_size, actual.len());
        assert_eq!(captured.wire_size as usize, actual.len());
        assert_eq!(captured.captured_size as usize, MAX_WIRE_CAPTURE_BYTES);
        assert!(captured.truncated);
    }

    #[tokio::test]
    async fn gzip_deflate_and_brotli_decode_with_independent_limit() {
        let plain = b"bounded decoded text".repeat(256);

        let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
        gzip.write_all(&plain).unwrap();
        let gzip = gzip.finish().unwrap();

        let mut zlib = ZlibEncoder::new(Vec::new(), Compression::default());
        zlib.write_all(&plain).unwrap();
        let zlib = zlib.finish().unwrap();

        let mut raw_deflate = DeflateEncoder::new(Vec::new(), Compression::default());
        raw_deflate.write_all(&plain).unwrap();
        let raw_deflate = raw_deflate.finish().unwrap();

        let mut brotli = Vec::new();
        {
            let mut encoder = brotli::CompressorWriter::new(&mut brotli, 4096, 5, 22);
            encoder.write_all(&plain).unwrap();
        }

        for (encoded, encoding) in [
            (gzip, "gzip"),
            (zlib, "deflate"),
            (raw_deflate, "deflate"),
            (brotli, "br"),
        ] {
            let captured =
                capture_bytes(encoded, "text/plain; charset=utf-8", Some(encoding)).await;
            assert_eq!(captured.bytes, plain);
            assert_eq!(captured.decode_status, DecodeStatus::DecodedText);
            assert!(!captured.truncated);
        }
    }

    #[tokio::test]
    async fn decompression_bomb_is_cut_at_decoded_limit() {
        let plain = vec![b'A'; MAX_DECODED_CAPTURE_BYTES * 4];
        let mut gzip = GzEncoder::new(Vec::new(), Compression::best());
        gzip.write_all(&plain).unwrap();
        let gzip = gzip.finish().unwrap();
        assert!(gzip.len() < MAX_WIRE_CAPTURE_BYTES);

        let captured = capture_bytes(gzip, "text/plain", Some("gzip")).await;
        assert_eq!(captured.captured_size as usize, MAX_DECODED_CAPTURE_BYTES);
        assert_eq!(captured.decode_status, DecodeStatus::DecodedText);
        assert!(captured.truncated);
    }

    #[tokio::test]
    async fn binary_invalid_utf8_empty_and_decode_failures_are_explicit() {
        let binary = capture_bytes(
            b"ASCII but declared binary".to_vec(),
            "application/octet-stream",
            None,
        )
        .await;
        assert_eq!(binary.decode_status, DecodeStatus::IdentityBinary);

        let invalid = capture_bytes(vec![0xff, 0xfe, 0xfd], "text/plain", None).await;
        assert_eq!(invalid.decode_status, DecodeStatus::IdentityBinary);

        let empty = capture_bytes(Vec::new(), "text/plain", None).await;
        assert_eq!(empty.decode_status, DecodeStatus::Empty);

        let failed = capture_bytes(b"not gzip".to_vec(), "text/plain", Some("gzip")).await;
        assert_eq!(failed.decode_status, DecodeStatus::DecodeFailed);

        let unsupported = capture_bytes(b"opaque".to_vec(), "text/plain", Some("zstd")).await;
        assert_eq!(unsupported.decode_status, DecodeStatus::UnsupportedEncoding);
    }

    #[tokio::test]
    async fn compressed_wire_prefix_is_not_partially_decoded() {
        let source = stream::unfold(0, |index| async move {
            (index < 20).then(|| {
                (
                    Ok::<Bytes, io::Error>(Bytes::from(vec![0u8; 64 * 1024])),
                    index + 1,
                )
            })
        });
        let (captured, forwarded_size) = capture_stream(
            Body::from_stream(source),
            metadata("application/octet-stream", Some("gzip")),
        )
        .await;

        assert_eq!(forwarded_size, 20 * 64 * 1024);
        assert_eq!(captured.decode_status, DecodeStatus::EncodedTruncated);
        assert!(captured.truncated);
    }
}
