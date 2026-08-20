use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use url::Url;

/// Stable semantic identity for the deterministic response-baseline verifier.
///
/// The verifier runs once per discovered response, but the Finding represents
/// the security gap across one exact origin. Keeping observed and suspected
/// facts separate prevents an uncertain policy hint from collapsing into a
/// confirmed configuration fact.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SecurityBaselineKinds {
    pub facts: BTreeSet<String>,
    pub suspected: BTreeSet<String>,
}

impl SecurityBaselineKinds {
    pub(crate) fn from_observations(observations: &Value) -> Self {
        Self {
            facts: kinds_from_array(observations.get("facts")),
            suspected: kinds_from_array(observations.get("suspectedFacts")),
        }
    }

    pub(crate) fn from_values(facts: &[Value], suspected: &[Value]) -> Self {
        Self {
            facts: kinds_from_values(facts),
            suspected: kinds_from_values(suspected),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.facts.is_empty() && self.suspected.is_empty()
    }
}

/// Only this endpoint-wide baseline template uses origin/fact aggregation.
/// Other safe verifiers keep their endpoint-and-parameter identity.
pub(crate) fn security_baseline_fingerprint(
    project_id: i64,
    template_id: &str,
    exact_origin: &str,
    observations: &Value,
) -> Option<String> {
    let kinds = SecurityBaselineKinds::from_observations(observations);
    security_baseline_fingerprint_for_kinds(project_id, template_id, exact_origin, &kinds)
}

pub(crate) fn security_baseline_fingerprint_for_kinds(
    project_id: i64,
    template_id: &str,
    exact_origin: &str,
    kinds: &SecurityBaselineKinds,
) -> Option<String> {
    if template_id != "security_headers_cookie" || kinds.is_empty() {
        return None;
    }
    let identity = json!({
        "identityVersion": "safe-verifier-security-baseline-v1",
        "projectId": project_id,
        "templateId": template_id,
        "exactOrigin": normalize_origin(exact_origin),
        "facts": kinds.facts.iter().collect::<Vec<_>>(),
        "suspectedFacts": kinds.suspected.iter().collect::<Vec<_>>(),
    });
    let bytes = serde_json::to_vec(&identity).ok()?;
    Some(sha256(&bytes))
}

pub(crate) fn security_baseline_title(kinds: &SecurityBaselineKinds) -> String {
    if !kinds.facts.is_empty() {
        return title_for_kinds(&kinds.facts, false);
    }
    title_for_kinds(&kinds.suspected, true)
}

fn title_for_kinds(kinds: &BTreeSet<String>, suspected: bool) -> String {
    let labels = kinds
        .iter()
        .filter_map(|kind| kind_label(kind, suspected))
        .collect::<Vec<_>>();
    if labels.len() == 1 {
        return labels[0].to_string();
    }
    if labels.len() == kinds.len() && labels.len() <= 2 {
        return format!("响应安全基线：{}", labels.join("；"));
    }
    if suspected {
        format!("响应安全基线有 {} 项策略待复核", kinds.len())
    } else {
        format!("响应安全基线存在 {} 项配置缺口", kinds.len())
    }
}

fn kind_label(kind: &str, suspected: bool) -> Option<&'static str> {
    let label = match kind {
        "missing_hsts" => "缺少 HSTS",
        "session_cookie_missing_httponly" => "会话 Cookie 缺少 HttpOnly",
        "session_cookie_missing_secure" => "HTTPS 会话 Cookie 缺少 Secure",
        "missing_nosniff" => "缺少 X-Content-Type-Options: nosniff",
        "missing_frame_embedding_protection" => "缺少页面嵌入保护",
        "detailed_server_version_disclosure" => "响应头暴露详细服务版本",
        "directory_listing" => "目录列表暴露",
        "stack_trace" => "响应泄露堆栈信息",
        "database_error_detail" => "响应泄露数据库错误细节",
        "content_security_policy_not_observed" => "未观察到 Content-Security-Policy",
        "authenticated_response_cache_boundary_unproven" => "认证响应缓存边界待复核",
        "api_documentation" => "接口文档暴露待复核",
        _ => return None,
    };
    if suspected && !label.ends_with("待复核") && !label.starts_with("未观察到") {
        return None;
    }
    Some(label)
}

fn kinds_from_array(value: Option<&Value>) -> BTreeSet<String> {
    value
        .and_then(Value::as_array)
        .map(|values| kinds_from_values(values))
        .unwrap_or_default()
}

fn kinds_from_values(values: &[Value]) -> BTreeSet<String> {
    values
        .iter()
        .filter_map(|value| value.get("kind").and_then(Value::as_str))
        .map(str::trim)
        .filter(|kind| !kind.is_empty())
        .map(str::to_string)
        .collect()
}

fn normalize_origin(raw: &str) -> String {
    Url::parse(raw.trim())
        .ok()
        .map(|url| url.origin().ascii_serialization())
        .filter(|origin| origin != "null")
        .unwrap_or_else(|| raw.trim().trim_end_matches('/').to_ascii_lowercase())
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_order_independent_but_keeps_fact_sets_and_origins_separate() {
        let first = json!({
            "facts": [
                {"kind": "missing_nosniff"},
                {"kind": "missing_frame_embedding_protection"}
            ],
            "suspectedFacts": [{"kind": "content_security_policy_not_observed"}]
        });
        let reordered = json!({
            "facts": [
                {"kind": "missing_frame_embedding_protection"},
                {"kind": "missing_nosniff"}
            ],
            "suspectedFacts": [{"kind": "content_security_policy_not_observed"}]
        });
        let first_key = security_baseline_fingerprint(
            7,
            "security_headers_cookie",
            "HTTPS://Example.Test:443/path",
            &first,
        )
        .unwrap();
        assert_eq!(
            first_key,
            security_baseline_fingerprint(
                7,
                "security_headers_cookie",
                "https://example.test/other",
                &reordered,
            )
            .unwrap()
        );
        assert_ne!(
            first_key,
            security_baseline_fingerprint(
                7,
                "security_headers_cookie",
                "https://example.test:8443",
                &reordered,
            )
            .unwrap()
        );
        assert_ne!(
            first_key,
            security_baseline_fingerprint(
                7,
                "security_headers_cookie",
                "https://example.test",
                &json!({"facts": [{"kind": "missing_nosniff"}]}),
            )
            .unwrap()
        );
    }

    #[test]
    fn titles_name_the_observed_gap_instead_of_repeating_a_generic_label() {
        let nosniff = SecurityBaselineKinds::from_observations(
            &json!({"facts": [{"kind": "missing_nosniff"}]}),
        );
        assert_eq!(
            security_baseline_title(&nosniff),
            "缺少 X-Content-Type-Options: nosniff"
        );
        let html = SecurityBaselineKinds::from_observations(&json!({
            "facts": [
                {"kind": "missing_nosniff"},
                {"kind": "missing_frame_embedding_protection"}
            ],
            "suspectedFacts": [{"kind": "content_security_policy_not_observed"}]
        }));
        assert_eq!(
            security_baseline_title(&html),
            "响应安全基线：缺少页面嵌入保护；缺少 X-Content-Type-Options: nosniff"
        );
    }
}
