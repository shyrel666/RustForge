use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayRequestInput {
    pub method: String,
    pub url: String,
    pub headers: Vec<ReplayHeader>,
    pub body_text: Option<String>,
    pub body_base64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayRequestInputSnapshot {
    /// none / text / base64 / ambiguous
    pub encoding: String,
    pub text: Option<String>,
    pub base64: Option<String>,
    pub original_size: i64,
    pub captured_size: i64,
    pub truncated: bool,
    /// SHA-256 of the complete, canonical input representation.
    pub content_hash: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum TlsPolicy {
    Strict,
    IgnoreInvalid,
}

impl TlsPolicy {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "strict" => Ok(Self::Strict),
            "ignore_invalid" => Ok(Self::IgnoreInvalid),
            _ => Err(format!("不支持的 Repeater TLS 策略: {value}")),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::IgnoreInvalid => "ignore_invalid",
        }
    }
}

impl fmt::Display for TlsPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A serializable Scope audit result. Denied decisions deliberately contain
/// only the stable error and normalized host supplied by AuthorizationError,
/// never the full URL/query.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayScopeSnapshot {
    pub allowed: bool,
    pub normalized_host: Option<String>,
    pub matched_scope: Option<String>,
    pub match_kind: Option<String>,
    pub reason_code: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplaySession {
    pub id: i64,
    pub project_id: i64,
    pub title: String,
    pub source_traffic_id: Option<i64>,
    pub tls_policy: String,
    pub is_selected: bool,
    pub run_count: i64,
    pub last_run_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReplayRun {
    pub id: i64,
    pub attempt_id: Option<i64>,
    pub session_id: i64,
    pub project_id: i64,
    pub method: String,
    pub url: String,
    pub request_headers: Vec<ReplayHeader>,
    /// Exact bounded bytes supplied to reqwest. Text is exposed only when the
    /// wire representation is known to be identity UTF-8.
    pub request_wire_body_text: Option<String>,
    pub request_wire_body_base64: Option<String>,
    pub req_wire_captured_size: i64,
    pub req_wire_truncated: bool,
    pub request_input: ReplayRequestInputSnapshot,
    pub request_body_text: Option<String>,
    pub request_body_base64: Option<String>,
    pub req_wire_size: i64,
    pub req_captured_size: i64,
    pub req_truncated: bool,
    pub req_decode_status: String,
    pub tls_policy: String,
    pub scope_decision: ReplayScopeSnapshot,
    pub outcome: String,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub status: Option<u16>,
    pub status_text: String,
    pub response_headers: Vec<ReplayHeader>,
    pub response_body_text: Option<String>,
    pub response_body_base64: Option<String>,
    pub resp_wire_size: i64,
    pub resp_captured_size: i64,
    pub resp_truncated: bool,
    pub resp_decode_status: String,
    pub duration_ms: i64,
    pub request_hash: String,
    pub req_body_hash: Option<String>,
    pub response_hash: Option<String>,
    pub resp_body_hash: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReplayRunSummary {
    pub id: i64,
    pub session_id: i64,
    pub project_id: i64,
    pub method: String,
    pub url: String,
    pub tls_policy: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub status: Option<u16>,
    pub status_text: String,
    pub req_wire_size: i64,
    pub req_wire_captured_size: i64,
    pub req_wire_truncated: bool,
    pub req_decode_status: String,
    pub resp_wire_size: i64,
    pub resp_captured_size: i64,
    pub resp_truncated: bool,
    pub resp_decode_status: String,
    pub duration_ms: i64,
    pub request_hash: String,
    pub response_hash: Option<String>,
    pub created_at: String,
}

impl From<&ReplayRun> for ReplayRunSummary {
    fn from(run: &ReplayRun) -> Self {
        Self {
            id: run.id,
            session_id: run.session_id,
            project_id: run.project_id,
            method: run.method.clone(),
            url: run.url.clone(),
            tls_policy: run.tls_policy.clone(),
            outcome: run.outcome.clone(),
            error_code: run.error_code.clone(),
            error_message: run.error_message.clone(),
            status: run.status,
            status_text: run.status_text.clone(),
            req_wire_size: run.req_wire_size,
            req_wire_captured_size: run.req_wire_captured_size,
            req_wire_truncated: run.req_wire_truncated,
            req_decode_status: run.req_decode_status.clone(),
            resp_wire_size: run.resp_wire_size,
            resp_captured_size: run.resp_captured_size,
            resp_truncated: run.resp_truncated,
            resp_decode_status: run.resp_decode_status.clone(),
            duration_ms: run.duration_ms,
            request_hash: run.request_hash.clone(),
            response_hash: run.response_hash.clone(),
            created_at: run.created_at.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReplayRunPage {
    pub runs: Vec<ReplayRunSummary>,
    pub next_before_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayBodySnapshot {
    /// text / base64 / empty
    pub encoding: String,
    pub text: Option<String>,
    pub base64: Option<String>,
    pub wire_size: i64,
    pub captured_size: i64,
    pub truncated: bool,
    pub decode_status: String,
    /// Hash of the persisted bounded representation, not an assertion that a
    /// truncated body was captured in full.
    pub captured_hash: String,
    /// Complete comparison identity. Normally this is the hash of all wire
    /// body bytes; when request construction failed before bytes existed it is
    /// the canonical original-input hash. `None` means equality is unknown.
    pub full_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReplayValueDiff<T> {
    pub changed: bool,
    pub indeterminate: bool,
    pub left: T,
    pub right: T,
}

impl<T: PartialEq> ReplayValueDiff<T> {
    pub fn new(left: T, right: T) -> Self {
        Self {
            changed: left != right,
            indeterminate: false,
            left,
            right,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReplayRunDiff {
    pub left_run_id: i64,
    pub right_run_id: i64,
    pub method: ReplayValueDiff<String>,
    pub url: ReplayValueDiff<String>,
    pub request_headers: ReplayValueDiff<Vec<ReplayHeader>>,
    pub request_body: ReplayValueDiff<ReplayBodySnapshot>,
    pub tls_policy: ReplayValueDiff<String>,
    pub scope_decision: ReplayValueDiff<ReplayScopeSnapshot>,
    pub outcome: ReplayValueDiff<String>,
    pub status: ReplayValueDiff<Option<u16>>,
    pub duration_ms: ReplayValueDiff<i64>,
    pub response_headers: ReplayValueDiff<Vec<ReplayHeader>>,
    pub response_body: ReplayValueDiff<ReplayBodySnapshot>,
}
