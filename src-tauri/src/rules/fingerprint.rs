//! 命中指纹：同一规则、同一接口、同一字段的命中必须得到同一个字符串，
//! 换了字段路径或换了接口就必须不同。Task 3.3 的去重直接依赖这里的稳定性。
//!
//! 组成成分固定为 `rule_id | rule_version | method | host | path | field_path`，
//! 每段做长度前缀，避免 `a|bc` 与 `ab|c` 撞到同一个摘要。

use sha2::{Digest, Sha256};

/// 从 URL 里取出规范化的 `(host, path)`：host 转小写去端口，path 去掉查询串与片段。
pub fn url_identity(url: &str) -> (String, String) {
    if let Ok(parsed) = url::Url::parse(url) {
        let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
        return (host, parsed.path().to_string());
    }
    // 相对路径或畸形 URL：只做最保守的切分，绝不猜测 host
    let without_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let (authority, path) = match without_scheme.find('/') {
        Some(index) if !url.starts_with('/') => without_scheme.split_at(index),
        _ => ("", without_scheme),
    };
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, rest)| rest)
        .split(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let path = path
        .split(['?', '#'])
        .next()
        .unwrap_or_default()
        .to_string();
    (host, path)
}

/// 稳定命中指纹（sha256 十六进制）。
pub fn fingerprint(
    rule_id: &str,
    rule_version: &str,
    method: &str,
    host: &str,
    path_without_query: &str,
    field_path: &str,
) -> String {
    let method = method.to_ascii_uppercase();
    let host = host.to_ascii_lowercase();
    let components = [
        rule_id,
        rule_version,
        method.as_str(),
        host.as_str(),
        path_without_query,
        field_path,
    ];
    let mut hasher = Sha256::new();
    for component in components {
        hasher.update((component.len() as u32).to_be_bytes());
        hasher.update(component.as_bytes());
        hasher.update(b"|");
    }
    format!("{:x}", hasher.finalize())
}

/// 从原始 URL 直接算指纹的便捷入口。
pub fn fingerprint_for_url(
    rule_id: &str,
    rule_version: &str,
    method: &str,
    url: &str,
    field_path: &str,
) -> String {
    let (host, path) = url_identity(url);
    fingerprint(rule_id, rule_version, method, &host, &path, field_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_inputs_always_produce_the_same_fingerprint() {
        let first = fingerprint("r", "1.0.0", "get", "Example.COM", "/a", "response.body");
        let second = fingerprint("r", "1.0.0", "GET", "example.com", "/a", "response.body");
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn query_values_and_field_paths_change_the_identity_correctly() {
        let base = fingerprint_for_url(
            "cookie-no-secure",
            "1.0.0",
            "GET",
            "https://t.cn/login?id=1",
            "response.cookie.set-cookie[0]",
        );
        let other_query = fingerprint_for_url(
            "cookie-no-secure",
            "1.0.0",
            "GET",
            "https://t.cn/login?id=2",
            "response.cookie.set-cookie[0]",
        );
        let other_field = fingerprint_for_url(
            "cookie-no-secure",
            "1.0.0",
            "GET",
            "https://t.cn/login?id=1",
            "response.cookie.set-cookie[1]",
        );
        // 查询值不参与指纹：同一接口的不同参数不应被当成两个问题
        assert_eq!(base, other_query);
        assert_ne!(base, other_field);
    }

    #[test]
    fn components_cannot_be_shifted_across_the_delimiter() {
        let left = fingerprint("ab", "c", "GET", "h", "/p", "f");
        let right = fingerprint("a", "bc", "GET", "h", "/p", "f");
        assert_ne!(left, right);
    }

    #[test]
    fn malformed_urls_still_yield_a_deterministic_identity() {
        assert_eq!(
            url_identity("https://User@T.CN:8443/a/b?x=1#z"),
            ("t.cn".to_string(), "/a/b".to_string())
        );
        assert_eq!(
            url_identity("/relative/path?x=1"),
            (String::new(), "/relative/path".to_string())
        );
        assert_eq!(
            url_identity("t.cn/only/path"),
            ("t.cn".to_string(), "/only/path".to_string())
        );
    }
}
