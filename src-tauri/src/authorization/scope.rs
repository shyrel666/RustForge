use super::AuthorizationError;
use serde::Serialize;
use std::collections::HashSet;
use std::net::Ipv6Addr;
use url::{Host, Url};

const WILDCARD_MARKER: &str = "scope-wildcard-marker";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeMatchKind {
    Exact,
    Wildcard,
}

/// 一次成功 Scope 判定的可审计快照。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScopeDecision {
    pub normalized_host: String,
    pub matched_scope: String,
    pub match_kind: ScopeMatchKind,
}

/// 已通过 URL 语法、scheme、userinfo、host 与 Scope 全部校验的重放目标。
#[derive(Debug, Clone)]
pub struct AuthorizedUrl {
    pub url: Url,
    pub decision: ScopeDecision,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScopePattern {
    normalized: String,
    kind: ScopeMatchKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostKind {
    Domain,
    Ip,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CanonicalHost {
    value: String,
    kind: HostKind,
}

/// 编译后的项目授权策略。构造时完成 IDN、大小写、尾随点、端口等规范化，
/// 判定路径只处理目标 host 并匹配编译结果。
#[derive(Debug, Clone)]
pub struct ScopePolicy {
    patterns: Vec<ScopePattern>,
}

impl ScopePolicy {
    pub fn new(entries: &[String]) -> Result<Self, AuthorizationError> {
        let mut patterns = Vec::new();
        let mut seen = HashSet::new();

        for raw in entries {
            let Some(pattern) = normalize_scope_pattern(raw)? else {
                continue;
            };
            if seen.insert(pattern.normalized.clone()) {
                patterns.push(pattern);
            }
        }

        Ok(Self { patterns })
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    pub fn normalized_entries(&self) -> Vec<String> {
        self.patterns
            .iter()
            .map(|pattern| pattern.normalized.clone())
            .collect()
    }

    /// 代理 CONNECT/普通请求使用的 host 授权入口。
    pub fn authorize_host(&self, host: &str) -> Result<ScopeDecision, AuthorizationError> {
        let host = canonicalize_host(host)?;
        self.authorize_canonical_host(&host.value)
    }

    /// Repeater 使用的完整 URL 授权入口。返回值中的 `Url` 必须直接用于发包，
    /// 禁止授权后再用未经解析的原始字符串构造请求。
    pub fn authorize_url(&self, raw_url: &str) -> Result<AuthorizedUrl, AuthorizationError> {
        let raw_url = raw_url.trim();
        if raw_url.is_empty()
            || raw_url
                .chars()
                .any(|character| character.is_whitespace() || character.is_control())
        {
            return Err(AuthorizationError::InvalidUrl);
        }

        // url crate 遵循 WHATWG 的浏览器式容错，会把 `https:///path` 修复成
        // host=`path`。主动发包边界不接受这种歧义写法，HTTP(S) 必须显式给出
        // `//authority`，且 authority 不能为空。
        if let Some((raw_scheme, remainder)) = raw_url.split_once(':') {
            if matches!(raw_scheme.to_ascii_lowercase().as_str(), "http" | "https") {
                let authority_and_rest = remainder
                    .strip_prefix("//")
                    .ok_or(AuthorizationError::InvalidUrl)?;
                let authority = authority_and_rest
                    .split(['/', '?', '#'])
                    .next()
                    .unwrap_or_default();
                if authority.is_empty() {
                    return Err(AuthorizationError::MissingHost);
                }
                if authority.contains('@') {
                    return Err(AuthorizationError::UrlUserInfo);
                }
                if authority.contains('\\') {
                    return Err(AuthorizationError::InvalidUrl);
                }
            }
        }

        let url = Url::parse(raw_url).map_err(|_| AuthorizationError::InvalidUrl)?;
        match url.scheme() {
            "http" | "https" => {}
            scheme => return Err(AuthorizationError::UnsupportedScheme(scheme.to_string())),
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(AuthorizationError::UrlUserInfo);
        }

        let host = canonical_url_host(&url)?;
        let decision = self.authorize_canonical_host(&host.value)?;
        Ok(AuthorizedUrl { url, decision })
    }

    fn authorize_canonical_host(
        &self,
        normalized_host: &str,
    ) -> Result<ScopeDecision, AuthorizationError> {
        if self.patterns.is_empty() {
            return Err(AuthorizationError::EmptyScope);
        }

        for pattern in &self.patterns {
            let matches = match pattern.kind {
                ScopeMatchKind::Exact => normalized_host == pattern.normalized,
                ScopeMatchKind::Wildcard => {
                    let suffix = pattern
                        .normalized
                        .strip_prefix("*.")
                        .expect("wildcard pattern has prefix");
                    normalized_host == suffix
                        || normalized_host
                            .strip_suffix(suffix)
                            .is_some_and(|prefix| prefix.ends_with('.'))
                }
            };
            if matches {
                return Ok(ScopeDecision {
                    normalized_host: normalized_host.to_string(),
                    matched_scope: pattern.normalized.clone(),
                    match_kind: pattern.kind,
                });
            }
        }

        Err(AuthorizationError::OutOfScope(normalized_host.to_string()))
    }
}

/// 保存项目时使用的规范化入口。端口只是用户输入便利，不进入 host-only Scope。
pub fn normalize_scope_entries(entries: &[String]) -> Result<Vec<String>, AuthorizationError> {
    ScopePolicy::new(entries).map(|policy| policy.normalized_entries())
}

fn normalize_scope_pattern(raw: &str) -> Result<Option<ScopePattern>, AuthorizationError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    if raw
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(invalid_scope("条目中不能包含空白字符"));
    }

    // 常见的无方括号 IPv6 Scope（如 ::1）无法直接作为 URL authority 解析。
    if let Ok(ip) = raw.parse::<Ipv6Addr>() {
        return Ok(Some(ScopePattern {
            normalized: ip.to_string(),
            kind: ScopeMatchKind::Exact,
        }));
    }

    let mut parseable = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("http://{raw}")
    };
    let authority_start = parseable
        .find("://")
        .map(|index| index + 3)
        .ok_or_else(|| invalid_scope("缺少有效 scheme"))?;
    let authority_end = parseable[authority_start..]
        .find(['/', '?', '#'])
        .map(|index| authority_start + index)
        .unwrap_or(parseable.len());
    let authority = &parseable[authority_start..authority_end];
    if authority.is_empty() {
        return Err(invalid_scope("条目缺少有效 host"));
    }
    if authority.contains('@') {
        return Err(invalid_scope("Scope 条目不允许包含 userinfo"));
    }
    if authority.contains('\\') {
        return Err(invalid_scope("Scope 条目包含歧义的 authority"));
    }
    let wildcard = authority.starts_with("*.");
    if wildcard {
        parseable.replace_range(authority_start..authority_start + 1, WILDCARD_MARKER);
    }

    let url = Url::parse(&parseable).map_err(|_| invalid_scope("条目不是有效的 host 或 URL"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(invalid_scope("Scope URL 只允许 http/https scheme"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid_scope("Scope 条目不允许包含 userinfo"));
    }

    let host = canonical_url_host(&url).map_err(|_| invalid_scope("条目缺少有效 host"))?;
    if wildcard {
        let marker_prefix = format!("{WILDCARD_MARKER}.");
        let suffix = host
            .value
            .strip_prefix(&marker_prefix)
            .ok_or_else(|| invalid_scope("通配符位置无效"))?;
        let suffix =
            canonicalize_host(suffix).map_err(|_| invalid_scope("通配符后缀不是有效域名"))?;
        if suffix.kind != HostKind::Domain {
            return Err(invalid_scope("IP 地址不能使用通配符"));
        }
        Ok(Some(ScopePattern {
            normalized: format!("*.{}", suffix.value),
            kind: ScopeMatchKind::Wildcard,
        }))
    } else {
        Ok(Some(ScopePattern {
            normalized: host.value,
            kind: ScopeMatchKind::Exact,
        }))
    }
}

fn invalid_scope(reason: impl Into<String>) -> AuthorizationError {
    AuthorizationError::InvalidScope(reason.into())
}

fn canonical_url_host(url: &Url) -> Result<CanonicalHost, AuthorizationError> {
    match url.host().ok_or(AuthorizationError::MissingHost)? {
        Host::Domain(domain) => canonical_domain(domain),
        Host::Ipv4(ip) => Ok(CanonicalHost {
            value: ip.to_string(),
            kind: HostKind::Ip,
        }),
        Host::Ipv6(ip) => Ok(CanonicalHost {
            value: ip.to_string(),
            kind: HostKind::Ip,
        }),
    }
}

fn canonicalize_host(raw: &str) -> Result<CanonicalHost, AuthorizationError> {
    let raw = raw.trim();
    if raw.is_empty()
        || raw.contains('*')
        || raw
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(AuthorizationError::InvalidHost);
    }

    let bracketless = raw
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(raw);
    if let Ok(ip) = bracketless.parse::<Ipv6Addr>() {
        return Ok(CanonicalHost {
            value: ip.to_string(),
            kind: HostKind::Ip,
        });
    }

    let without_dot = raw.trim_end_matches('.');
    if without_dot.is_empty() || without_dot.contains(':') {
        return Err(AuthorizationError::InvalidHost);
    }
    match Host::parse(without_dot).map_err(|_| AuthorizationError::InvalidHost)? {
        Host::Domain(domain) => canonical_domain(&domain),
        Host::Ipv4(ip) => Ok(CanonicalHost {
            value: ip.to_string(),
            kind: HostKind::Ip,
        }),
        Host::Ipv6(ip) => Ok(CanonicalHost {
            value: ip.to_string(),
            kind: HostKind::Ip,
        }),
    }
}

fn canonical_domain(domain: &str) -> Result<CanonicalHost, AuthorizationError> {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        return Err(AuthorizationError::InvalidHost);
    }
    Ok(CanonicalHost {
        value: domain,
        kind: HostKind::Domain,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(entries: &[&str]) -> ScopePolicy {
        ScopePolicy::new(
            &entries
                .iter()
                .map(|entry| (*entry).to_string())
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }

    #[test]
    fn exact_wildcard_apex_case_and_trailing_dot() {
        let policy = policy(&["Example.COM.", "*.Test.CN."]);
        assert_eq!(
            policy.authorize_host("EXAMPLE.com.").unwrap().match_kind,
            ScopeMatchKind::Exact
        );
        assert_eq!(
            policy.authorize_host("api.test.cn").unwrap().match_kind,
            ScopeMatchKind::Wildcard
        );
        assert!(policy.authorize_host("test.cn").is_ok());
        assert_eq!(
            policy.authorize_host("www.example.com").unwrap_err().code(),
            "OUT_OF_SCOPE"
        );
    }

    #[test]
    fn normalizes_pasted_urls_ports_and_deduplicates() {
        let entries = [
            "https://Example.com:8443/login",
            "example.com.",
            " HTTPS://EXAMPLE.COM/path ",
        ]
        .map(str::to_string);
        assert_eq!(
            normalize_scope_entries(&entries).unwrap(),
            vec!["example.com"]
        );

        let policy = policy(&["example.com:443"]);
        assert!(policy.authorize_url("https://example.com:9443/a").is_ok());
        assert_eq!(
            policy
                .authorize_url("https://example.com:99999/")
                .unwrap_err()
                .code(),
            "INVALID_URL"
        );
    }

    #[test]
    fn supports_ipv4_ipv6_and_requires_explicit_private_targets() {
        let policy = policy(&["127.0.0.1:8080", "[::1]:9000", "192.168.10.20"]);
        assert!(policy.authorize_url("http://127.0.0.1:1/").is_ok());
        assert!(policy.authorize_url("http://[::1]:65535/").is_ok());
        assert!(policy.authorize_host("192.168.10.20").is_ok());
        assert_eq!(
            policy.authorize_host("169.254.1.2").unwrap_err().code(),
            "OUT_OF_SCOPE"
        );
        assert_eq!(
            policy.authorize_host("10.0.0.9").unwrap_err().code(),
            "OUT_OF_SCOPE"
        );
        assert_eq!(
            policy.authorize_host("localhost").unwrap_err().code(),
            "OUT_OF_SCOPE"
        );
    }

    #[test]
    fn accepts_unbracketed_ipv6_scope() {
        let policy = policy(&["::1"]);
        assert_eq!(policy.normalized_entries(), vec!["::1"]);
        assert!(policy.authorize_url("http://[::1]:8080/").is_ok());
    }

    #[test]
    fn idn_and_punycode_are_equivalent() {
        let policy = policy(&["例子.测试", "*.BÜCHER.example"]);
        assert_eq!(
            policy.normalized_entries(),
            vec!["xn--fsqu00a.xn--0zwm56d", "*.xn--bcher-kva.example"]
        );
        assert!(policy.authorize_url("https://例子.测试/path").is_ok());
        assert!(policy
            .authorize_url("https://shop.xn--bcher-kva.example/")
            .is_ok());
    }

    #[test]
    fn rejects_confusing_or_unsupported_urls() {
        let policy = policy(&["example.com"]);
        assert_eq!(
            policy
                .authorize_url("http://example.com@evil.test/")
                .unwrap_err()
                .code(),
            "URL_USERINFO"
        );
        assert_eq!(
            policy
                .authorize_url("http://@example.com/")
                .unwrap_err()
                .code(),
            "URL_USERINFO"
        );
        assert_eq!(
            policy
                .authorize_url("ftp://example.com/file")
                .unwrap_err()
                .code(),
            "UNSUPPORTED_SCHEME"
        );
        assert_eq!(
            policy
                .authorize_url("mailto:user@example.com")
                .unwrap_err()
                .code(),
            "UNSUPPORTED_SCHEME"
        );
        assert_eq!(
            policy.authorize_url("https:///path").unwrap_err().code(),
            "MISSING_HOST"
        );
        assert_eq!(
            policy
                .authorize_url("https:example.com")
                .unwrap_err()
                .code(),
            "INVALID_URL"
        );
        assert_eq!(
            policy
                .authorize_url("https://example.com\\@evil.test/")
                .unwrap_err()
                .code(),
            "URL_USERINFO"
        );
    }

    #[test]
    fn proxy_host_and_repeater_url_return_identical_decisions() {
        let policy = policy(&["*.Example.com"]);
        let proxy = policy.authorize_host("API.EXAMPLE.COM.").unwrap();
        let repeater = policy
            .authorize_url("https://api.example.com:8443/path")
            .unwrap()
            .decision;
        assert_eq!(proxy, repeater);
    }

    #[test]
    fn rejects_wildcard_ip_and_scope_userinfo() {
        assert_eq!(
            ScopePolicy::new(&["*.127.0.0.1".to_string()])
                .unwrap_err()
                .code(),
            "INVALID_SCOPE"
        );
        assert_eq!(
            ScopePolicy::new(&["https://user@example.com".to_string()])
                .unwrap_err()
                .code(),
            "INVALID_SCOPE"
        );
        assert_eq!(
            ScopePolicy::new(&["https:///path".to_string()])
                .unwrap_err()
                .code(),
            "INVALID_SCOPE"
        );
    }

    #[test]
    fn empty_scope_fails_closed() {
        let policy = policy(&[]);
        assert!(policy.is_empty());
        assert_eq!(
            policy.authorize_host("example.com").unwrap_err().code(),
            "EMPTY_SCOPE"
        );
    }
}
