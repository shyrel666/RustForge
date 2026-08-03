use crate::authorization::{ScopeDecision, ScopePolicy};
use crate::replay::model::ReplayHeader;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use url::Url;

pub const DEFAULT_REQUEST_BUDGET: u32 = 120;
pub const MAX_REQUEST_BUDGET: u32 = 300;
pub const DEFAULT_REQUESTS_PER_SECOND: f64 = 1.0;
pub const MIN_REQUESTS_PER_SECOND: f64 = 0.05;
pub const MAX_REQUESTS_PER_SECOND: f64 = 2.0;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
pub const MAX_RUN_RESPONSE_BYTES: u64 = 20 * 1024 * 1024;

pub const BUILTIN_EXCLUDED_SEGMENTS: &[&str] = &[
    "logout",
    "signout",
    "delete",
    "remove",
    "destroy",
    "reset",
    "revoke",
    "terminate",
    "shutdown",
    "purge",
    "wipe",
    "drop",
    "disable",
];

const FORBIDDEN_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
    "proxy-authorization",
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
    "x-original-method",
    "x-rewrite-method",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AssessmentRequestCandidate {
    pub method: String,
    pub url: String,
    pub headers: Vec<ReplayHeader>,
    pub has_body: bool,
}

#[derive(Debug, Clone)]
pub struct AuthorizedAssessmentRequest {
    pub method: String,
    pub url: Url,
    pub headers: Vec<ReplayHeader>,
    pub scope_decision: ScopeDecision,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRejection {
    pub code: &'static str,
    pub reason: String,
}

impl std::fmt::Display for PolicyRejection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "[{}] {}", self.code, self.reason)
    }
}

impl std::error::Error for PolicyRejection {}

fn reject(code: &'static str, reason: impl Into<String>) -> PolicyRejection {
    PolicyRejection {
        code,
        reason: reason.into(),
    }
}

#[derive(Debug, Clone)]
pub struct AssessmentPolicy {
    exact_origin: String,
    excluded_paths: Vec<String>,
}

impl AssessmentPolicy {
    pub fn new(exact_origin: &str, excluded_paths: &[String]) -> Result<Self, PolicyRejection> {
        if exact_origin.trim().is_empty() {
            return Err(reject("INVALID_ORIGIN", "运行契约缺少精确 origin"));
        }
        let mut normalized = Vec::new();
        let mut seen = HashSet::new();
        for path in excluded_paths {
            let path = normalize_excluded_path(path)?;
            if seen.insert(path.clone()) {
                normalized.push(path);
            }
        }
        normalized.sort();
        Ok(Self {
            exact_origin: exact_origin.to_string(),
            excluded_paths: normalized,
        })
    }

    pub fn authorize(
        &self,
        scope: &ScopePolicy,
        candidate: AssessmentRequestCandidate,
    ) -> Result<AuthorizedAssessmentRequest, PolicyRejection> {
        let method = candidate.method.trim().to_ascii_uppercase();
        if !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS") {
            return Err(reject(
                "METHOD_NOT_READ_ONLY",
                "Assessment 只允许 GET、HEAD 和 OPTIONS",
            ));
        }
        if candidate.has_body {
            return Err(reject(
                "REQUEST_BODY_FORBIDDEN",
                "Assessment 请求禁止正文和表单提交",
            ));
        }

        for header in &candidate.headers {
            let name = header.name.trim().to_ascii_lowercase();
            if FORBIDDEN_HEADERS.contains(&name.as_str()) {
                return Err(reject(
                    "FORBIDDEN_HEADER",
                    format!("Assessment 禁止设置 Header `{}`", header.name.trim()),
                ));
            }
            if header.name.contains(['\r', '\n']) || header.value.contains(['\r', '\n']) {
                return Err(reject("INVALID_HEADER", "Header 不允许包含换行符"));
            }
        }

        let authorized = scope
            .authorize_url(&candidate.url)
            .map_err(|error| reject("SCOPE_REJECTED", error.to_string()))?;
        let origin = exact_origin(&authorized.url)?;
        if origin != self.exact_origin {
            return Err(reject(
                "CROSS_ORIGIN",
                "Assessment 只能访问起始 URL 的精确 scheme、host 和端口",
            ));
        }

        if path_has_destructive_segment(&authorized.url) {
            return Err(reject(
                "DESTRUCTIVE_PATH",
                "URL 路径包含内置禁止的破坏性动作段",
            ));
        }
        if self
            .excluded_paths
            .iter()
            .any(|excluded| path_matches_prefix(authorized.url.path(), excluded))
        {
            return Err(reject("USER_EXCLUDED_PATH", "URL 命中用户排除路径"));
        }
        if query_requests_method_override_or_destructive_action(&authorized.url) {
            return Err(reject(
                "DESTRUCTIVE_QUERY",
                "URL query 包含方法覆盖或破坏性动作",
            ));
        }

        Ok(AuthorizedAssessmentRequest {
            method,
            url: authorized.url,
            headers: candidate.headers,
            scope_decision: authorized.decision,
        })
    }

    pub fn excluded_paths(&self) -> &[String] {
        &self.excluded_paths
    }
}

pub fn normalize_start_url(
    scope: &ScopePolicy,
    raw_url: &str,
) -> Result<(String, String), PolicyRejection> {
    let mut authorized = scope
        .authorize_url(raw_url)
        .map_err(|error| reject("START_URL_REJECTED", error.to_string()))?;
    authorized.url.set_fragment(None);
    let origin = exact_origin(&authorized.url)?;
    Ok((authorized.url.to_string(), origin))
}

pub fn exact_origin(url: &Url) -> Result<String, PolicyRejection> {
    let host = url
        .host_str()
        .ok_or_else(|| reject("INVALID_ORIGIN", "URL 缺少 host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| reject("INVALID_ORIGIN", "URL 缺少有效端口"))?;
    let authority_host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_ascii_lowercase()
    };
    Ok(format!("{}://{}:{port}", url.scheme(), authority_host))
}

pub fn normalize_excluded_paths(paths: &[String]) -> Result<Vec<String>, PolicyRejection> {
    let mut normalized = Vec::new();
    let mut seen = HashSet::new();
    for path in paths {
        let value = normalize_excluded_path(path)?;
        if seen.insert(value.clone()) {
            normalized.push(value);
        }
    }
    normalized.sort();
    Ok(normalized)
}

fn normalize_excluded_path(raw: &str) -> Result<String, PolicyRejection> {
    let raw = raw.trim();
    if raw.is_empty()
        || !raw.starts_with('/')
        || raw.contains(['?', '#', '\r', '\n'])
        || raw.len() > 2048
    {
        return Err(reject(
            "INVALID_EXCLUDED_PATH",
            "排除路径必须是 2048 字符内、以 / 开始且不含 query/fragment 的路径",
        ));
    }
    let normalized = if raw.len() > 1 {
        raw.trim_end_matches('/').to_string()
    } else {
        raw.to_string()
    };
    Ok(normalized)
}

fn path_matches_prefix(path: &str, excluded: &str) -> bool {
    excluded == "/"
        || path == excluded
        || path
            .strip_prefix(excluded)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn path_has_destructive_segment(url: &Url) -> bool {
    url.path_segments().is_some_and(|segments| {
        segments
            .map(percent_decode_repeatedly)
            .flat_map(|segment| {
                segment
                    .split(['/', '\\', ';'])
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .map(|segment| segment.trim().to_ascii_lowercase())
            .any(|segment| BUILTIN_EXCLUDED_SEGMENTS.contains(&segment.as_str()))
    })
}

fn query_requests_method_override_or_destructive_action(url: &Url) -> bool {
    url.query_pairs().any(|(name, value)| {
        let name = percent_decode_repeatedly(&name).to_ascii_lowercase();
        let value = percent_decode_repeatedly(&value)
            .trim()
            .to_ascii_lowercase();
        name == "_method"
            || (matches!(name.as_str(), "action" | "do")
                && BUILTIN_EXCLUDED_SEGMENTS.contains(&value.as_str()))
    })
}

fn percent_decode_lossy(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
            {
                decoded.push((high << 4) | low);
                index += 3;
                continue;
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn percent_decode_repeatedly(value: &str) -> String {
    let mut current = value.to_string();
    // Two server-side decoding passes are common in routing stacks. Three
    // conservative passes catch double-encoded path separators/action words
    // without accepting an unbounded decoder loop.
    for _ in 0..3 {
        let next = percent_decode_lossy(&current);
        if next == current {
            break;
        }
        current = next;
    }
    current
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestPhase {
    Discovery,
    Verification,
}

#[derive(Debug, Clone)]
pub struct RequestBudget {
    total: u32,
    discovery: u32,
    used: u32,
    discovery_used: u32,
    bytes_used: u64,
}

impl RequestBudget {
    pub fn new(total: u32) -> Result<Self, PolicyRejection> {
        if total == 0 || total > MAX_REQUEST_BUDGET {
            return Err(reject(
                "INVALID_REQUEST_BUDGET",
                format!("请求预算必须在 1..={MAX_REQUEST_BUDGET} 之间"),
            ));
        }
        Ok(Self {
            total,
            discovery: 40.min(total / 3),
            used: 0,
            discovery_used: 0,
            bytes_used: 0,
        })
    }

    /// Must be called immediately before constructing the network future.
    pub fn reserve_request(&mut self, phase: RequestPhase) -> Result<u32, PolicyRejection> {
        if self.used >= self.total {
            return Err(reject("REQUEST_BUDGET_EXHAUSTED", "本轮目标请求预算已用尽"));
        }
        if phase == RequestPhase::Discovery && self.discovery_used >= self.discovery {
            return Err(reject(
                "DISCOVERY_BUDGET_EXHAUSTED",
                "发现阶段预算已用尽，剩余请求保留给安全验证",
            ));
        }
        self.used += 1;
        if phase == RequestPhase::Discovery {
            self.discovery_used += 1;
        }
        Ok(self.used)
    }

    pub fn record_response_bytes(&mut self, bytes: u64) -> Result<(), PolicyRejection> {
        self.bytes_used = self.bytes_used.saturating_add(bytes);
        if self.bytes_used > MAX_RUN_RESPONSE_BYTES {
            return Err(reject(
                "RUN_RESPONSE_BYTES_EXHAUSTED",
                "本轮响应读取总量超过 20 MiB，评估已停止",
            ));
        }
        Ok(())
    }

    pub const fn used(&self) -> u32 {
        self.used
    }

    pub const fn total(&self) -> u32 {
        self.total
    }

    pub const fn remaining(&self) -> u32 {
        self.total.saturating_sub(self.used)
    }

    pub const fn bytes_used(&self) -> u64 {
        self.bytes_used
    }

    pub const fn remaining_response_bytes(&self) -> u64 {
        MAX_RUN_RESPONSE_BYTES.saturating_sub(self.bytes_used)
    }

    pub const fn discovery_limit(&self) -> u32 {
        self.discovery
    }
}

pub fn validate_rate(rate: f64) -> Result<f64, PolicyRejection> {
    if !rate.is_finite() || !(MIN_REQUESTS_PER_SECOND..=MAX_REQUESTS_PER_SECOND).contains(&rate) {
        return Err(reject(
            "INVALID_REQUEST_RATE",
            format!(
                "请求速率必须在 {MIN_REQUESTS_PER_SECOND}..={MAX_REQUESTS_PER_SECOND} 次/秒之间"
            ),
        ));
    }
    Ok(rate)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> ScopePolicy {
        ScopePolicy::new(&["example.test".to_string()]).unwrap()
    }

    fn policy() -> AssessmentPolicy {
        AssessmentPolicy::new("https://example.test:443", &["/admin/archive".to_string()]).unwrap()
    }

    fn candidate(method: &str, url: &str) -> AssessmentRequestCandidate {
        AssessmentRequestCandidate {
            method: method.into(),
            url: url.into(),
            headers: Vec::new(),
            has_body: false,
        }
    }

    #[test]
    fn allows_only_read_only_exact_origin_requests() {
        assert!(policy()
            .authorize(&scope(), candidate("GET", "https://example.test/view?id=1"))
            .is_ok());
        assert_eq!(
            policy()
                .authorize(&scope(), candidate("POST", "https://example.test/view"))
                .unwrap_err()
                .code,
            "METHOD_NOT_READ_ONLY"
        );
        assert_eq!(
            policy()
                .authorize(&scope(), candidate("GET", "https://example.test:444/view"))
                .unwrap_err()
                .code,
            "CROSS_ORIGIN"
        );
        assert_eq!(
            policy()
                .authorize(&scope(), candidate("GET", "http://example.test/view"))
                .unwrap_err()
                .code,
            "CROSS_ORIGIN"
        );
    }

    #[test]
    fn rejects_bodies_headers_destructive_paths_and_overrides() {
        let mut with_body = candidate("GET", "https://example.test/view");
        with_body.has_body = true;
        assert_eq!(
            policy().authorize(&scope(), with_body).unwrap_err().code,
            "REQUEST_BODY_FORBIDDEN"
        );
        let mut with_header = candidate("GET", "https://example.test/view");
        with_header.headers.push(ReplayHeader {
            name: "X-HTTP-Method-Override".into(),
            value: "DELETE".into(),
        });
        assert_eq!(
            policy().authorize(&scope(), with_header).unwrap_err().code,
            "FORBIDDEN_HEADER"
        );
        for url in [
            "https://example.test/account/delete",
            "https://example.test/account/%64elete",
            "https://example.test/account/%2564elete",
            "https://example.test/account/safe%252Fdelete",
            "https://example.test/account/delete;confirm=yes",
            "https://example.test/view?_method=POST",
            "https://example.test/view?%255fmethod=POST",
            "https://example.test/view?action=destroy",
            "https://example.test/view?action=%2564elete",
            "https://example.test/admin/archive/2026",
        ] {
            assert!(policy().authorize(&scope(), candidate("GET", url)).is_err());
        }
    }

    #[test]
    fn reserves_verification_capacity_and_enforces_hard_limits() {
        let mut budget = RequestBudget::new(120).unwrap();
        assert_eq!(budget.discovery_limit(), 40);
        for _ in 0..40 {
            budget.reserve_request(RequestPhase::Discovery).unwrap();
        }
        assert_eq!(
            budget
                .reserve_request(RequestPhase::Discovery)
                .unwrap_err()
                .code,
            "DISCOVERY_BUDGET_EXHAUSTED"
        );
        assert!(budget.reserve_request(RequestPhase::Verification).is_ok());
        assert!(RequestBudget::new(301).is_err());
        assert!(validate_rate(2.01).is_err());
    }
}
