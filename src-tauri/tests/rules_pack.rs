//! 规则包端到端验证：样本流量 → 内置规则包 → 命中结果。
//!
//! 样本存放在 `tests/fixtures/rules/samples.json`，每条旧规则都必须同时有
//! 正例、反例和边界样本；坏规则包放在同目录，用来验证"加载失败只禁用这个
//! 包并显示原因"这条红线。

use rustforge_lib::knowledge;
use rustforge_lib::rules::engine::{self, EvaluationReport, RuleHit, TrafficView};
use rustforge_lib::rules::loader::{self, load_pack, load_pack_status, PackStatus};
use rustforge_lib::rules::schema::{
    MAX_EVIDENCE_SNIPPET_CHARS, MAX_REGEX_PATTERN_BYTES, TRUNCATED_HIT_MAX_CONFIDENCE,
};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

const SAMPLES: &str = include_str!("fixtures/rules/samples.json");
const PACK_INVALID_JSON: &str = include_str!("fixtures/rules/pack-invalid-json.txt");
const PACK_OVERLONG_REGEX: &str = include_str!("fixtures/rules/pack-overlong-regex.json");
const PACK_REGEX_BOMB: &str = include_str!("fixtures/rules/pack-regex-bomb.json");
const PACK_UNKNOWN_REFERENCE: &str = include_str!("fixtures/rules/pack-unknown-reference.json");

/// 样本里出现过的原始敏感值：任何命中证据都不允许包含它们。
const FORBIDDEN_IN_EVIDENCE: &[&str] = &[
    "hunter2",
    "abc123",
    "dozjgNryP4J3",
    "eyJhbGciOiJIUzI1NiJ9",
    "this-httponly-value",
    "very-secure-token",
    "dXNlcjpwYXNzd29yZA",
];

#[derive(Debug, Deserialize)]
struct SampleFile {
    samples: Vec<Sample>,
}

#[derive(Debug, Deserialize)]
struct Sample {
    rule_id: String,
    kind: String,
    note: String,
    expect_hit: bool,
    #[serde(default)]
    expect_field_path: Option<String>,
    traffic: Traffic,
}

impl Sample {
    fn label(&self) -> String {
        format!("{} [{}] {}", self.rule_id, self.kind, self.note)
    }
}

#[derive(Debug, Deserialize)]
struct Traffic {
    url: String,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    content_type: Option<String>,
    #[serde(default)]
    req_headers: Option<serde_json::Value>,
    #[serde(default)]
    req_body: Option<String>,
    #[serde(default)]
    resp_headers: Option<serde_json::Value>,
    #[serde(default)]
    resp_body: Option<String>,
    #[serde(default)]
    req_truncated: bool,
    #[serde(default)]
    resp_truncated: bool,
    #[serde(default)]
    req_decode_status: Option<String>,
    #[serde(default)]
    resp_decode_status: Option<String>,
}

/// `TrafficView` 借用外部字符串，所以先把样本物化成拥有所有权的缓冲。
struct MaterializedTraffic {
    method: String,
    url: String,
    status: Option<u16>,
    content_type: Option<String>,
    req_headers: String,
    req_body: Vec<u8>,
    resp_headers: Option<String>,
    resp_body: Option<Vec<u8>>,
    req_truncated: bool,
    resp_truncated: bool,
    req_decode_status: String,
    resp_decode_status: String,
}

impl Traffic {
    fn materialize(&self) -> MaterializedTraffic {
        let resp_headers = self.resp_headers.as_ref().map(ToString::to_string);
        // 样本没写 content_type 时，从响应头推导，跟代理落库的行为保持一致
        let content_type = self.content_type.clone().or_else(|| {
            self.resp_headers
                .as_ref()?
                .get("content-type")?
                .as_str()
                .map(str::to_string)
        });
        MaterializedTraffic {
            method: self.method.clone().unwrap_or_else(|| "GET".to_string()),
            url: self.url.clone(),
            status: self.status.or(Some(200)),
            content_type,
            req_headers: self
                .req_headers
                .as_ref()
                .map_or_else(|| "{}".to_string(), ToString::to_string),
            req_body: self.req_body.clone().unwrap_or_default().into_bytes(),
            resp_headers,
            resp_body: self
                .resp_body
                .clone()
                .map(String::into_bytes)
                .or_else(|| self.resp_headers.as_ref().map(|_| Vec::new())),
            req_truncated: self.req_truncated,
            resp_truncated: self.resp_truncated,
            req_decode_status: self
                .req_decode_status
                .clone()
                .unwrap_or_else(|| "identity_text".to_string()),
            resp_decode_status: self
                .resp_decode_status
                .clone()
                .unwrap_or_else(|| "identity_text".to_string()),
        }
    }
}

impl MaterializedTraffic {
    fn view(&self) -> TrafficView<'_> {
        TrafficView {
            method: &self.method,
            url: &self.url,
            req_headers: &self.req_headers,
            resp_headers: self.resp_headers.as_deref(),
            req_body: &self.req_body,
            resp_body: self.resp_body.as_deref(),
            status: self.status,
            content_type: self.content_type.as_deref(),
            req_truncated: self.req_truncated,
            resp_truncated: self.resp_truncated,
            req_decode_status: &self.req_decode_status,
            resp_decode_status: &self.resp_decode_status,
        }
    }
}

fn samples() -> Vec<Sample> {
    serde_json::from_str::<SampleFile>(SAMPLES)
        .expect("样本 fixture 必须是合法 JSON")
        .samples
}

fn builtin_rule_ids() -> BTreeSet<String> {
    loader::builtin_pack()
        .pack()
        .expect("内置规则包必须加载成功")
        .rules
        .iter()
        .map(|rule| rule.rule_id.clone())
        .collect()
}

fn hits_for<'a>(report: &'a EvaluationReport<'a>, rule_id: &str) -> Vec<&'a RuleHit<'a>> {
    report
        .hits
        .iter()
        .filter(|hit| hit.rule.rule_id == rule_id)
        .collect()
}

#[test]
fn every_legacy_rule_has_positive_negative_and_boundary_samples() {
    let mut coverage: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for sample in samples() {
        assert!(
            matches!(sample.kind.as_str(), "positive" | "negative" | "boundary"),
            "未知样本类别: {}",
            sample.label()
        );
        coverage
            .entry(sample.rule_id.clone())
            .or_default()
            .insert(sample.kind.clone());
    }

    let rule_ids = builtin_rule_ids();
    assert_eq!(rule_ids.len(), 14, "内置规则包应当仍是 14 条迁移规则");
    for rule_id in &rule_ids {
        let kinds = coverage
            .get(rule_id)
            .unwrap_or_else(|| panic!("规则 {rule_id} 没有任何样本"));
        for kind in ["positive", "negative", "boundary"] {
            assert!(kinds.contains(kind), "规则 {rule_id} 缺少 {kind} 样本");
        }
    }
    for rule_id in coverage.keys() {
        assert!(rule_ids.contains(rule_id), "样本引用了未知规则 {rule_id}");
    }
}

#[test]
fn fixture_samples_produce_the_expected_hits() {
    for sample in samples() {
        let traffic = sample.traffic.materialize();
        let report = engine::evaluate(&traffic.view());
        assert!(
            report.diagnostics.is_empty(),
            "{} 不应产生诊断: {:?}",
            sample.label(),
            report.diagnostics
        );
        let hits = hits_for(&report, &sample.rule_id);
        assert_eq!(
            !hits.is_empty(),
            sample.expect_hit,
            "{} 期望命中={}，实际命中={}",
            sample.label(),
            sample.expect_hit,
            hits.len()
        );
        if let Some(expected) = &sample.expect_field_path {
            assert_eq!(hits[0].field_path, *expected, "{}", sample.label());
        }
    }
}

#[test]
fn every_hit_carries_field_path_evidence_fingerprint_and_versioned_references() {
    for sample in samples() {
        let traffic = sample.traffic.materialize();
        let report = engine::evaluate(&traffic.view());
        for hit in &report.hits {
            let label = format!("{} → {}", sample.label(), hit.rule.rule_id);
            assert!(!hit.field_path.is_empty(), "{label} 缺字段路径");
            assert!(!hit.evidence.is_empty(), "{label} 缺证据片段");
            assert!(
                hit.evidence.chars().count() <= MAX_EVIDENCE_SNIPPET_CHARS,
                "{label} 证据超过 {MAX_EVIDENCE_SNIPPET_CHARS} 字符"
            );
            assert_eq!(
                hit.fingerprint.len(),
                64,
                "{label} 指纹必须是 sha256 十六进制"
            );
            assert!(!hit.rule.version.is_empty(), "{label} 缺规则版本");

            // 规则输出必须能引用到固定版本的标准条目
            let canonical = knowledge::validate_references(&hit.rule.references)
                .unwrap_or_else(|error| panic!("{label}: {error}"));
            assert_eq!(canonical, hit.rule.references, "{label} 引用未规范化");
            assert!(
                canonical
                    .iter()
                    .all(|reference| !reference.version.is_empty()),
                "{label} 引用缺版本"
            );
            let cards = knowledge::lookup(&hit.rule.references)
                .unwrap_or_else(|error| panic!("{label}: {error}"));
            assert_eq!(cards.len(), canonical.len(), "{label} 知识卡解析不完整");

            for secret in FORBIDDEN_IN_EVIDENCE {
                assert!(
                    !hit.evidence.contains(secret),
                    "{label} 证据泄露了原始敏感值 `{secret}`: {}",
                    hit.evidence
                );
            }
        }
    }
}

#[test]
fn multiple_cookies_missing_one_attribute_are_each_reported() {
    let traffic = Traffic {
        url: "https://shop.test/login".to_string(),
        method: None,
        status: None,
        content_type: None,
        req_headers: None,
        req_body: None,
        resp_headers: Some(serde_json::json!({
            "set-cookie": [
                "a=1; Path=/; HttpOnly",
                "b=2; Path=/; Secure; HttpOnly",
                "c=3; Path=/; HttpOnly"
            ]
        })),
        resp_body: None,
        req_truncated: false,
        resp_truncated: false,
        req_decode_status: None,
        resp_decode_status: None,
    }
    .materialize();
    let report = engine::evaluate(&traffic.view());

    let hits = hits_for(&report, "cookie-no-secure");
    assert_eq!(hits.len(), 2, "缺 Secure 的两条 Cookie 应各产出一条命中");
    assert_eq!(
        hits[0].field_path,
        "response.cookie.set-cookie[0].attribute.secure"
    );
    assert_eq!(
        hits[1].field_path,
        "response.cookie.set-cookie[2].attribute.secure"
    );
    assert_ne!(hits[0].fingerprint, hits[1].fingerprint);
    // 三条都带了 HttpOnly，不应产生 HttpOnly 缺失告警
    assert!(hits_for(&report, "cookie-no-httponly").is_empty());
    for hit in hits {
        assert!(hit.evidence.contains("[REDACTED]"), "{}", hit.evidence);
    }
}

#[test]
fn truncated_body_only_yields_marked_low_confidence_hits() {
    let mut traffic = Traffic {
        url: "https://shop.test/item?id=1".to_string(),
        method: None,
        status: Some(500),
        content_type: Some("text/plain".to_string()),
        req_headers: None,
        req_body: None,
        resp_headers: Some(serde_json::json!({ "content-type": "text/plain" })),
        resp_body: Some(
            "You have an error in your SQL syntax; check the manual for 10.0.0.7".to_string(),
        ),
        req_truncated: false,
        resp_truncated: false,
        req_decode_status: None,
        resp_decode_status: None,
    };

    let complete = traffic.materialize();
    let complete_report = engine::evaluate(&complete.view());
    let complete_hit = hits_for(&complete_report, "sql-error-leak")[0];
    assert!(!complete_hit.incomplete_evidence);
    assert_eq!(complete_hit.confidence, complete_hit.rule.confidence);

    traffic.resp_truncated = true;
    let truncated = traffic.materialize();
    let truncated_report = engine::evaluate(&truncated.view());
    let body_hits: Vec<&RuleHit<'_>> = truncated_report
        .hits
        .iter()
        .filter(|hit| hit.field_path.starts_with("response.body"))
        .collect();
    assert!(!body_hits.is_empty());
    for hit in body_hits {
        assert!(
            hit.incomplete_evidence,
            "{} 应标记证据不完整",
            hit.rule.rule_id
        );
        assert!(
            hit.confidence <= TRUNCATED_HIT_MAX_CONFIDENCE,
            "{} 截断证据的置信度必须被压到 {TRUNCATED_HIT_MAX_CONFIDENCE} 以内，实际 {}",
            hit.rule.rule_id,
            hit.confidence
        );
        assert!(hit.confidence < hit.rule.confidence);
    }
}

#[test]
fn reloading_the_same_pack_yields_identical_results_on_every_sample() {
    let first = load_pack("builtin", loader::BUILTIN_PACK_JSON).unwrap();
    let second = load_pack("builtin", loader::BUILTIN_PACK_JSON).unwrap();

    let describe = |report: &EvaluationReport<'_>| -> Vec<String> {
        report
            .hits
            .iter()
            .map(|hit| {
                format!(
                    "{}@{}|{}|{}|{}|{}",
                    hit.rule.rule_id,
                    hit.rule.version,
                    hit.field_path,
                    hit.fingerprint,
                    hit.confidence,
                    hit.evidence
                )
            })
            .collect()
    };

    for sample in samples() {
        let traffic = sample.traffic.materialize();
        let view = traffic.view();
        let from_first = describe(&engine::evaluate_pack(&first, &view));
        let from_second = describe(&engine::evaluate_pack(&second, &view));
        assert_eq!(from_first, from_second, "{}", sample.label());
        // 内置单例与新加载的实例也必须一致
        assert_eq!(
            from_first,
            describe(&engine::evaluate(&view)),
            "{}",
            sample.label()
        );
    }
}

#[test]
fn oversized_and_pathological_regexes_are_rejected_at_load_time() {
    let pattern = serde_json::from_str::<serde_json::Value>(PACK_OVERLONG_REGEX).unwrap()["rules"]
        [0]["condition"]["pattern"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        pattern.len() > MAX_REGEX_PATTERN_BYTES,
        "fixture 的正则应当超过 {MAX_REGEX_PATTERN_BYTES} 字节，实际 {}",
        pattern.len()
    );

    let overlong = load_pack_status("pack-overlong-regex.json", PACK_OVERLONG_REGEX);
    assert!(overlong.pack().is_none());
    assert_eq!(overlong.pack_id(), "overlong-regex");
    assert!(overlong.disabled_reason().unwrap().contains("超过上限"));

    let bomb = load_pack_status("pack-regex-bomb.json", PACK_REGEX_BOMB);
    assert!(bomb.pack().is_none());
    assert!(bomb.disabled_reason().unwrap().contains("正则"));
}

#[test]
fn a_broken_pack_is_disabled_with_a_reason_and_never_stops_evaluation() {
    let traffic = Traffic {
        url: "https://shop.test/admin/.git/config".to_string(),
        method: None,
        status: Some(200),
        content_type: None,
        req_headers: None,
        req_body: None,
        resp_headers: Some(serde_json::json!({ "set-cookie": "a=1; Path=/" })),
        resp_body: Some("ORA-01234: table missing".to_string()),
        req_truncated: false,
        resp_truncated: false,
        req_decode_status: None,
        resp_decode_status: None,
    }
    .materialize();
    let view = traffic.view();

    for (name, raw, expected_reason) in [
        ("pack-invalid-json.txt", PACK_INVALID_JSON, "不是有效 JSON"),
        (
            "pack-unknown-reference.json",
            PACK_UNKNOWN_REFERENCE,
            "CWE-999999",
        ),
    ] {
        let status = load_pack_status(name, raw);
        assert!(matches!(status, PackStatus::Disabled { .. }), "{name}");
        assert!(
            status.disabled_reason().unwrap().contains(expected_reason),
            "{name}: {}",
            status.disabled_reason().unwrap()
        );

        // 被禁用的包只产出诊断，不产出命中，也不会 panic
        let report = engine::evaluate_status(&status, &view);
        assert!(report.hits.is_empty(), "{name}");
        assert_eq!(report.diagnostics.len(), 1, "{name}");
        assert_eq!(report.diagnostics[0].code, "rule_pack_disabled");
    }

    // 内置包本身仍然正常工作，坏包不会影响它
    assert!(!engine::evaluate(&view).hits.is_empty());
}

#[test]
fn legacy_engine_stays_available_for_shadow_comparison() {
    // Task 3.3 会用同一批输入对比新旧结果，这里先保证旧实现仍可调用
    let traffic = Traffic {
        url: "https://shop.test/login".to_string(),
        method: None,
        status: Some(200),
        content_type: None,
        req_headers: None,
        req_body: None,
        resp_headers: Some(serde_json::json!({
            "set-cookie": ["session=abc; Path=/; Secure", "theme=dark; Path=/; Secure; HttpOnly"]
        })),
        resp_body: None,
        req_truncated: false,
        resp_truncated: false,
        req_decode_status: None,
        resp_decode_status: None,
    }
    .materialize();
    let view = traffic.view();

    let legacy_ids: BTreeSet<&str> = engine::legacy_evaluate(&view)
        .iter()
        .map(|hit| hit.rule.id)
        .collect();
    let current_ids: BTreeSet<&str> = engine::evaluate(&view)
        .hits
        .iter()
        .map(|hit| hit.rule.rule_id.as_str())
        .collect();

    // 旧实现的全局 must_absent 漏掉了 session 缺 HttpOnly，新实现能抓到
    assert!(!legacy_ids.contains("cookie-no-httponly"));
    assert!(current_ids.contains("cookie-no-httponly"));
}
