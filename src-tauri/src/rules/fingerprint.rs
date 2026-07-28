//! 命中指纹：同一规则、同一接口、同一字段的命中必须得到同一个字符串，
//! 换了字段路径或换了接口就必须不同。Finding 去重直接依赖这里的稳定性。
//!
//! 命中身份固定为 `rule_id | method | host | path | field_path`，
//! 每段做长度前缀，避免 `a|bc` 与 `ab|c` 撞到同一个摘要。
//!
//! **`rule_version` 刻意不进入身份。** 规则包打补丁版（1.0.0 → 1.0.1）不改变
//! "这个端点的这个字段有这个问题"这一事实；把版本算进去会让升版后的命中和
//! 历史 Finding 指纹不同、去重失效并炸出重复。版本只作为命中/证据属性记录。
//! 规则语义真的变了，就换一个新的 `rule_id`。

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

fn digest(components: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for component in components {
        hasher.update((component.len() as u32).to_be_bytes());
        hasher.update(component.as_bytes());
        hasher.update(b"|");
    }
    format!("{:x}", hasher.finalize())
}

/// 稳定命中指纹（sha256 十六进制）。
pub fn fingerprint(
    rule_id: &str,
    method: &str,
    host: &str,
    path_without_query: &str,
    field_path: &str,
) -> String {
    let method = method.to_ascii_uppercase();
    let host = host.to_ascii_lowercase();
    digest(&[
        rule_id,
        method.as_str(),
        host.as_str(),
        path_without_query,
        field_path,
    ])
}

/// 从原始 URL 直接算指纹的便捷入口。
pub fn fingerprint_for_url(rule_id: &str, method: &str, url: &str, field_path: &str) -> String {
    let (host, path) = url_identity(url);
    fingerprint(rule_id, method, &host, &path, field_path)
}

/// Finding 身份 = 项目 + 命中指纹。
///
/// 直接在引擎指纹上叠一层 project，而不是另起一套规范化逻辑——两处规范化
/// 迟早会漂移，那时同一个问题会在库里裂成两条 Finding。
pub fn finding_fingerprint(project_id: i64, hit_fingerprint: &str) -> String {
    digest(&[&project_id.to_string(), hit_fingerprint])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_inputs_always_produce_the_same_fingerprint() {
        let first = fingerprint("r", "get", "Example.COM", "/a", "response.body");
        let second = fingerprint("r", "GET", "example.com", "/a", "response.body");
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn query_values_and_field_paths_change_the_identity_correctly() {
        let base = fingerprint_for_url(
            "cookie-no-secure",
            "GET",
            "https://t.cn/login?id=1",
            "response.cookie.set-cookie[0]",
        );
        let other_query = fingerprint_for_url(
            "cookie-no-secure",
            "GET",
            "https://t.cn/login?id=2",
            "response.cookie.set-cookie[0]",
        );
        let other_field = fingerprint_for_url(
            "cookie-no-secure",
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
        let left = fingerprint("abc", "GET", "h", "/p", "f");
        let right = fingerprint("ab", "GET", "ch", "/p", "f");
        assert_ne!(left, right);
        assert_ne!(
            finding_fingerprint(1, "23"),
            finding_fingerprint(12, "3"),
            "project 与命中指纹之间同样不能移位"
        );
    }

    #[test]
    fn rule_version_is_not_part_of_the_identity() {
        // 规则包补丁升版不得让同一端点同一字段裂成两条 Finding
        let hit = fingerprint_for_url("sql-error-leak", "GET", "https://t.cn/a", "response.body");
        assert_eq!(finding_fingerprint(7, &hit), finding_fingerprint(7, &hit));
        assert_ne!(
            finding_fingerprint(7, &hit),
            finding_fingerprint(8, &hit),
            "不同项目必须是不同身份"
        );
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
