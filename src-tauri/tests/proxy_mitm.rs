//! Phase 1 验收的端到端测试（无 GUI）：
//! 本地起一个 TLS 目标站（证书由测试 CA 签发），客户端经代理 CONNECT +
//! TLS 握手（信任测试 CA）发起 HTTPS 请求，验证：
//!   1. hudsucker 完成 MITM 解密并正确转发/回包
//!   2. TrafficHandler 把完整请求/响应写入 SQLite
//!   3. FlowSink 收到与库里一致的事件载荷
//!
//! 与生产唯一差异：上游 connector 额外信任测试 CA（生产用 webpki 公共根）。

use hudsucker::certificate_authority::RcgenAuthority;
use hudsucker::rcgen::{
    date_time_ymd, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, Issuer,
    KeyPair,
};
use hudsucker::rustls::crypto::aws_lc_rs;
use hudsucker::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use hudsucker::rustls::{ClientConfig, RootCertStore, ServerConfig};
use hudsucker::Proxy;
use rustforge_lib::proxy::body_capture::MAX_WIRE_CAPTURE_BYTES;
use rustforge_lib::proxy::ca;
use rustforge_lib::proxy::interceptor::{FlowSink, TrafficHandler};
use rustforge_lib::storage::db::{open_pool, Pool};
use rustforge_lib::storage::models::TrafficSummary;
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const CA_SCOPE_HOST: &str = "localhost";
const BODY: &str = "hello rustforge mitm";

fn integration_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

#[derive(Clone, Default)]
struct VecSink(Arc<Mutex<Vec<TrafficSummary>>>);

impl FlowSink for VecSink {
    fn on_flow(&self, summary: &TrafficSummary) {
        self.0.lock().unwrap().push(summary.clone());
    }
}

fn test_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("rustforge-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn pki(name: &str) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    // 由测试 CA 签发 localhost 叶子证书
    let dir = test_dir();
    let material = ca::ensure_ca(&dir).unwrap();
    let issuer = Issuer::from_ca_cert_pem(
        &material.cert_pem,
        KeyPair::from_pem(&material.key_pem).unwrap(),
    )
    .unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![name.to_string()]).unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, name);
    params.distinguished_name = dn;
    params.not_before = date_time_ymd(2024, 1, 1);
    params.not_after = date_time_ymd(2036, 1, 1);
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = params.signed_by(&leaf_key, &issuer).unwrap();

    let ca_der = pem::parse(&material.cert_pem).unwrap().contents().to_vec();
    let chain = vec![leaf.der().clone(), CertificateDer::from(ca_der)];
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    (chain, key)
}

fn ca_der() -> CertificateDer<'static> {
    let dir = test_dir();
    let material = ca::ensure_ca(&dir).unwrap();
    CertificateDer::from(pem::parse(&material.cert_pem).unwrap().contents().to_vec())
}

fn origin_acceptor() -> TlsAcceptor {
    let (chain, key) = pki(CA_SCOPE_HOST);
    let config = ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    TlsAcceptor::from(Arc::new(config))
}

/// 本地 TLS 目标站：固定返回 200 text/plain
async fn spawn_origin() -> u16 {
    let acceptor = origin_acceptor();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut tls = acceptor.accept(tcp).await.unwrap();
                let mut buf = vec![0u8; 8192];
                let _ = tls.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\n\r\n{}",
                    BODY.len(),
                    BODY
                );
                tls.write_all(resp.as_bytes()).await.unwrap();
                let _ = tls.shutdown().await;
            });
        }
    });
    port
}

/// 单次脚本化 TLS 目标站：读完整请求后返回指定原始 HTTP 响应，并把实际上游收到的
/// 请求交给测试断言。用于验证代理没有截断转发数据。
async fn spawn_scripted_origin(response: Vec<u8>) -> (u16, oneshot::Receiver<Vec<u8>>) {
    let acceptor = origin_acceptor();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (observed_tx, observed_rx) = oneshot::channel();

    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.unwrap();
        let request = read_complete_request(&mut tls).await;
        let _ = observed_tx.send(request);
        tls.write_all(&response).await.unwrap();
        let _ = tls.shutdown().await;
    });
    (port, observed_rx)
}

/// 起代理：真实 TrafficHandler + 临时 SQLite + VecSink
async fn spawn_proxy(origin_port: u16, db: Pool, sink: VecSink) -> (u16, oneshot::Sender<()>) {
    let dir = test_dir();
    let material = ca::ensure_ca(&dir).unwrap();
    let authority: RcgenAuthority = ca::build_authority(&material).unwrap();

    // 上游 connector：信任测试 CA（生产路径是 with_rustls_connector + webpki 公共根）
    let mut roots = RootCertStore::empty();
    roots.add(ca_der()).unwrap();
    let tls_config = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    let handler = TrafficHandler::new(db, Arc::new(sink));
    let (tx, rx) = oneshot::channel::<()>();
    let proxy = Proxy::builder()
        .with_listener(listener)
        .with_ca(authority)
        .with_http_connector(https)
        .with_http_handler(handler)
        .with_graceful_shutdown(async move {
            rx.await.unwrap_or_default();
        })
        .build()
        .unwrap();
    tokio::spawn(proxy.start());
    let _ = origin_port;
    (proxy_port, tx)
}

use tokio::sync::oneshot;

fn header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

fn content_length(head: &str) -> Option<usize> {
    head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    })
}

fn is_chunked(head: &str) -> bool {
    head.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value
                    .split(',')
                    .any(|encoding| encoding.trim().eq_ignore_ascii_case("chunked"))
        })
    })
}

fn chunked_complete(body: &[u8]) -> bool {
    body == b"0\r\n\r\n" || body.windows(7).any(|window| window == b"\r\n0\r\n\r\n")
}

async fn read_complete_request(stream: &mut tokio_rustls::server::TlsStream<TcpStream>) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let read = stream.read(&mut chunk).await.unwrap();
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..read]);
        let Some(head_end) = header_end(&bytes) else {
            continue;
        };
        let head = String::from_utf8_lossy(&bytes[..head_end]);
        let body = &bytes[head_end..];
        if let Some(length) = content_length(&head) {
            if body.len() >= length {
                break;
            }
        } else if is_chunked(&head) {
            if chunked_complete(body) {
                break;
            }
        } else {
            break;
        }
    }
    bytes
}

fn encode_chunked(payload: &[u8], chunk_size: usize) -> Vec<u8> {
    let mut encoded = Vec::new();
    for chunk in payload.chunks(chunk_size) {
        encoded.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        encoded.extend_from_slice(chunk);
        encoded.extend_from_slice(b"\r\n");
    }
    encoded.extend_from_slice(b"0\r\n\r\n");
    encoded
}

fn decode_chunked(mut encoded: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::new();
    loop {
        let line_end = encoded
            .windows(2)
            .position(|window| window == b"\r\n")
            .expect("chunk size line");
        let size_text = std::str::from_utf8(&encoded[..line_end])
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let size = usize::from_str_radix(size_text.trim(), 16).unwrap();
        encoded = &encoded[line_end + 2..];
        if size == 0 {
            break;
        }
        assert!(encoded.len() >= size + 2);
        decoded.extend_from_slice(&encoded[..size]);
        assert_eq!(&encoded[size..size + 2], b"\r\n");
        encoded = &encoded[size + 2..];
    }
    decoded
}

fn http_body(message: &[u8]) -> Vec<u8> {
    let head_end = header_end(message).expect("HTTP head terminator");
    let head = String::from_utf8_lossy(&message[..head_end]);
    let body = &message[head_end..];
    if is_chunked(&head) {
        decode_chunked(body)
    } else if let Some(length) = content_length(&head) {
        body[..length.min(body.len())].to_vec()
    } else {
        body.to_vec()
    }
}

async fn request_via_proxy(proxy_port: u16, origin_port: u16, request: &[u8]) -> Vec<u8> {
    let mut tcp = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    tcp.write_all(
        format!(
            "CONNECT {CA_SCOPE_HOST}:{origin_port} HTTP/1.1\r\n\
             Host: {CA_SCOPE_HOST}:{origin_port}\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let head = read_head(&mut tcp).await;
    assert!(
        head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.0 200"),
        "CONNECT 被拒: {head}"
    );

    let mut roots = RootCertStore::empty();
    roots.add(ca_der()).unwrap();
    let config = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(CA_SCOPE_HOST).unwrap().to_owned();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();
    tls.write_all(request).await.unwrap();
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.unwrap();
    response
}

fn scoped_pool(file_name: &str) -> Pool {
    let dir = test_dir();
    let path = dir.join(file_name);
    std::fs::remove_file(&path).ok();
    let pool = open_pool(&path).unwrap();
    {
        let db = pool.get().unwrap();
        db.execute(
            "INSERT INTO projects(name, target_host, scope)
             VALUES('t', 'localhost', '[\"localhost\"]')",
            [],
        )
        .unwrap();
        let project_id = db.last_insert_rowid();
        db.execute(
            "INSERT INTO settings(key, value) VALUES('current_project_id', ?1)",
            [project_id.to_string()],
        )
        .unwrap();
    }
    pool
}

/// 读直到拿到完整 HTTP 头（\r\n\r\n）
async fn read_head(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await.unwrap();
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

#[tokio::test]
async fn mitm_https_end_to_end() {
    let _guard = integration_lock().lock().await;
    // 1) 项目 + Scope：只拦截 localhost
    let dir = test_dir();
    let pool = open_pool(&dir.join("test.db")).unwrap();
    {
        let d = pool.get().unwrap();
        d
            .execute(
                "INSERT INTO projects(name, target_host, scope) VALUES('t', 'localhost', '[\"localhost\"]')",
                [],
            )
            .unwrap();
        let pid = d.last_insert_rowid();
        d.execute(
            "INSERT INTO settings(key, value) VALUES('current_project_id', ?1)",
            [pid.to_string()],
        )
        .unwrap();
    }

    // 2) 目标站 + 代理
    let origin_port = spawn_origin().await;
    let sink = VecSink::default();
    let (proxy_port, shutdown) = spawn_proxy(origin_port, pool.clone(), sink.clone()).await;

    // 3) 客户端：CONNECT → TLS（信任测试 CA）→ GET
    let client = async {
        let mut tcp = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        tcp.write_all(
            format!("CONNECT {CA_SCOPE_HOST}:{origin_port} HTTP/1.1\r\nHost: {CA_SCOPE_HOST}:{origin_port}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
        let head = read_head(&mut tcp).await;
        assert!(
            head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.0 200"),
            "CONNECT 被拒: {head}"
        );

        let mut roots = RootCertStore::empty();
        roots.add(ca_der()).unwrap();
        let config = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));
        let server_name = ServerName::try_from(CA_SCOPE_HOST).unwrap().to_owned();
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .expect("MITM TLS 握手失败");

        tls.write_all(
            b"GET /data.json?q=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
        let mut resp = Vec::new();
        tls.read_to_end(&mut resp).await.unwrap();
        let resp = String::from_utf8_lossy(&resp).into_owned();
        assert!(resp.starts_with("HTTP/1.1 200"), "响应异常: {resp}");
        assert!(resp.contains(BODY), "响应体不对: {resp}");
    };
    tokio::time::timeout(Duration::from_secs(30), client)
        .await
        .expect("客户端流程超时");

    // 4) 断言：DB 里有完整记录（handle_response 先落库后回包，此时必然已写入）
    let d = pool.get().unwrap();
    let (method, host, path, status, resp_body, url): (
        String,
        String,
        String,
        i64,
        Vec<u8>,
        String,
    ) = d
        .query_row(
            "SELECT method, host, path, status, resp_body, url FROM traffic WHERE host = 'localhost'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        )
        .expect("流量未写入数据库");
    assert_eq!(method, "GET");
    assert_eq!(host, "localhost");
    assert_eq!(path, "/data.json?q=1");
    assert_eq!(status, 200);
    assert!(String::from_utf8_lossy(&resp_body).contains(BODY));
    assert!(url.starts_with("https://localhost"), "url 异常: {url}");
    assert!(url.contains("/data.json?q=1"), "url 异常: {url}");
    let project_count: i64 = d
        .query_row("SELECT COUNT(*) FROM traffic", [], |row| row.get(0))
        .unwrap();
    assert_eq!(project_count, 1, "Scope 外流量不应被记录");
    drop(d);

    // 5) 断言：事件载荷与落库一致
    let events = sink.0.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].status, Some(200));
    assert_eq!(events[0].path, "/data.json?q=1");

    let _ = shutdown.send(());
}

#[tokio::test]
async fn out_of_scope_not_recorded() {
    let _guard = integration_lock().lock().await;
    // Scope 只有 localhost；向 other-host 发明文 HTTP，应只转发不记录
    let dir = test_dir();
    std::fs::remove_file(dir.join("test2.db")).ok();
    let pool = open_pool(&dir.join("test2.db")).unwrap();
    {
        let d = pool.get().unwrap();
        d
            .execute(
                "INSERT INTO projects(name, target_host, scope) VALUES('t', 'localhost', '[\"localhost\"]')",
                [],
            )
            .unwrap();
        let pid = d.last_insert_rowid();
        d.execute(
            "INSERT INTO settings(key, value) VALUES('current_project_id', ?1)",
            [pid.to_string()],
        )
        .unwrap();
    }

    // 本地明文 HTTP 站
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut tcp, _) = origin.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let _ = tcp.read(&mut buf).await;
                let body = b"ok";
                let resp = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", body.len());
                tcp.write_all(resp.as_bytes()).await.unwrap();
                tcp.write_all(body).await.unwrap();
            });
        }
    });

    let sink = VecSink::default();
    let (proxy_port, shutdown) = spawn_proxy(origin_port, pool.clone(), sink.clone()).await;

    // 明文 HTTP 走代理，但 Host 头伪装成 Scope 外的域名
    let mut tcp = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    tcp.write_all(
        format!("GET http://not-in-scope.example:{origin_port}/x HTTP/1.1\r\nHost: not-in-scope.example\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    // 读一会儿就关（域名解析会失败，代理回 502；这里只关心"不记录"）
    let mut buf = vec![0u8; 4096];
    let _ = tokio::time::timeout(Duration::from_secs(10), tcp.read(&mut buf)).await;
    drop(tcp);

    tokio::time::sleep(Duration::from_millis(300)).await;
    let d = pool.get().unwrap();
    let count: i64 = d
        .query_row("SELECT COUNT(*) FROM traffic", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0, "Scope 外流量不应被记录");
    assert!(sink.0.lock().unwrap().is_empty());
    let _ = shutdown.send(());
}

#[tokio::test]
async fn bounded_capture_forwards_large_declared_and_chunked_bodies() {
    let _guard = integration_lock().lock().await;
    let pool = scoped_pool("bounded-stream.db");
    let sink = VecSink::default();
    let (proxy_port, shutdown) = spawn_proxy(0, pool.clone(), sink).await;

    // Content-Length path: both directions exceed the capture limit, but the
    // origin/client must still receive the entire body.
    let request_payload = vec![b'R'; MAX_WIRE_CAPTURE_BYTES + 192 * 1024];
    let response_payload = vec![b'S'; MAX_WIRE_CAPTURE_BYTES + 256 * 1024];
    let mut response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n\
         content-length: {}\r\nset-cookie: a=1; Path=/\r\n\
         set-cookie: b=2; Expires=Wed, 21 Oct 2030 07:28:00 GMT\r\n\
         connection: close\r\n\r\n",
        response_payload.len()
    )
    .into_bytes();
    response.extend_from_slice(&response_payload);
    let (origin_port, observed_request) = spawn_scripted_origin(response).await;

    let mut request = format!(
        "POST /large HTTP/1.1\r\nhost: localhost\r\ncontent-type: text/plain\r\n\
         content-length: {}\r\nconnection: close\r\n\r\n",
        request_payload.len()
    )
    .into_bytes();
    request.extend_from_slice(&request_payload);

    let response = tokio::time::timeout(
        Duration::from_secs(30),
        request_via_proxy(proxy_port, origin_port, &request),
    )
    .await
    .expect("large content-length flow timeout");
    let observed_request = observed_request.await.unwrap();
    assert_eq!(http_body(&observed_request), request_payload);
    assert_eq!(http_body(&response), response_payload);

    // Unknown-length/chunked path uses the exact same bounded tee.
    let chunked_request_payload = vec![b'C'; MAX_WIRE_CAPTURE_BYTES + 96 * 1024];
    let chunked_response_payload = vec![b'D'; MAX_WIRE_CAPTURE_BYTES + 128 * 1024];
    let mut chunked_response = b"HTTP/1.1 200 OK\r\n\
        content-type: text/plain\r\ntransfer-encoding: chunked\r\n\
        connection: close\r\n\r\n"
        .to_vec();
    chunked_response.extend_from_slice(&encode_chunked(&chunked_response_payload, 31 * 1024));
    let (chunked_origin_port, observed_chunked_request) =
        spawn_scripted_origin(chunked_response).await;

    let mut chunked_request = b"POST /chunked HTTP/1.1\r\nhost: localhost\r\n\
        content-type: text/plain\r\ntransfer-encoding: chunked\r\n\
        connection: close\r\n\r\n"
        .to_vec();
    chunked_request.extend_from_slice(&encode_chunked(&chunked_request_payload, 29 * 1024));
    let chunked_response = tokio::time::timeout(
        Duration::from_secs(30),
        request_via_proxy(proxy_port, chunked_origin_port, &chunked_request),
    )
    .await
    .expect("chunked flow timeout");
    let observed_chunked_request = observed_chunked_request.await.unwrap();
    assert_eq!(
        http_body(&observed_chunked_request),
        chunked_request_payload
    );
    assert_eq!(http_body(&chunked_response), chunked_response_payload);

    let db = pool.get().unwrap();
    for (path, req_len, resp_len) in [
        (
            "/large",
            request_payload.len() as i64,
            response_payload.len() as i64,
        ),
        (
            "/chunked",
            chunked_request_payload.len() as i64,
            chunked_response_payload.len() as i64,
        ),
    ] {
        let row: (i64, i64, i64, i64, bool, bool, String, String, i64, i64) = db
            .query_row(
                "SELECT req_wire_size, resp_wire_size,
                        req_captured_size, resp_captured_size,
                        req_truncated, resp_truncated,
                        req_decode_status, resp_decode_status,
                        length(req_body), length(resp_body)
                 FROM traffic WHERE path = ?1",
                [path],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(row.0, req_len);
        assert_eq!(row.1, resp_len);
        assert_eq!(row.2, MAX_WIRE_CAPTURE_BYTES as i64);
        assert_eq!(row.3, MAX_WIRE_CAPTURE_BYTES as i64);
        assert!(row.4);
        assert!(row.5);
        assert_eq!(row.6, "identity_text");
        assert_eq!(row.7, "identity_text");
        assert_eq!(row.8, MAX_WIRE_CAPTURE_BYTES as i64);
        assert_eq!(row.9, MAX_WIRE_CAPTURE_BYTES as i64);
    }

    let response_headers: String = db
        .query_row(
            "SELECT resp_headers FROM traffic WHERE path = '/large'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let response_headers: serde_json::Value = serde_json::from_str(&response_headers).unwrap();
    assert_eq!(
        response_headers["set-cookie"],
        serde_json::json!(["a=1; Path=/", "b=2; Expires=Wed, 21 Oct 2030 07:28:00 GMT"])
    );

    let _ = shutdown.send(());
}

#[tokio::test]
async fn compressed_request_and_response_are_decoded_only_for_capture() {
    let _guard = integration_lock().lock().await;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    let pool = scoped_pool("compressed-stream.db");
    let sink = VecSink::default();
    let (proxy_port, shutdown) = spawn_proxy(0, pool.clone(), sink).await;

    let request_plain = b"{\"request\":\"plain evidence\"}".repeat(64);
    let response_plain = b"{\"response\":\"plain evidence\"}".repeat(64);
    let request_gzip = gzip(&request_plain);
    let response_gzip = gzip(&response_plain);
    let mut origin_response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
         content-encoding: gzip\r\ncontent-length: {}\r\n\
         connection: close\r\n\r\n",
        response_gzip.len()
    )
    .into_bytes();
    origin_response.extend_from_slice(&response_gzip);
    let (origin_port, observed_request) = spawn_scripted_origin(origin_response).await;

    let mut request = format!(
        "POST /compressed HTTP/1.1\r\nhost: localhost\r\n\
         content-type: application/json\r\ncontent-encoding: gzip\r\n\
         content-length: {}\r\nconnection: close\r\n\r\n",
        request_gzip.len()
    )
    .into_bytes();
    request.extend_from_slice(&request_gzip);
    let client_response = request_via_proxy(proxy_port, origin_port, &request).await;
    let observed_request = observed_request.await.unwrap();

    // Forwarding stays byte-for-byte compressed in both directions.
    assert_eq!(http_body(&observed_request), request_gzip);
    assert_eq!(http_body(&client_response), response_gzip);

    let db = pool.get().unwrap();
    let row: (Vec<u8>, Vec<u8>, i64, i64, i64, i64, String, String) = db
        .query_row(
            "SELECT req_body, resp_body, req_wire_size, resp_wire_size,
                    req_captured_size, resp_captured_size,
                    req_decode_status, resp_decode_status
             FROM traffic WHERE path = '/compressed'",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(row.0, request_plain);
    assert_eq!(row.1, response_plain);
    assert_eq!(row.2, request_gzip.len() as i64);
    assert_eq!(row.3, response_gzip.len() as i64);
    assert_eq!(row.4, request_plain.len() as i64);
    assert_eq!(row.5, response_plain.len() as i64);
    assert_eq!(row.6, "decoded_text");
    assert_eq!(row.7, "decoded_text");

    let _ = shutdown.send(());
}
