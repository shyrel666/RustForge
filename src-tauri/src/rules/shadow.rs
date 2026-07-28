//! 新旧规则引擎影子评测——**仅测试构建**。
//!
//! 生产 crate 里已经没有旧引擎了：代理只调用声明式规则包。旧版"整段文本跑
//! 正则"的实现连同它的 14 条规则一起留在这里，唯一用途是拿同一批人工标注
//! 语料把两条轨道跑一遍，量化 v2 相对 v1 的 TP/FP/FN 变化，并把逐条差异写进
//! 一张临时表供人工复核。
//!
//! 人工复核结论见 `docs/architecture/rule-shadow-evaluation.md`。

use super::engine::{body_text, TrafficView};
use rusqlite::Connection;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

#[path = "../../tests/fixtures/rules/legacy_v1.rs"]
mod legacy_fixture;
use legacy_fixture::{LegacyRule, LegacyTarget};

// ---- 旧版（v1）求值实现 ----

pub struct LegacyRuleHit {
    pub rule: &'static LegacyRule,
    /// 命中的目标段（如 "resp_body"）
    pub location: &'static str,
    pub incomplete_evidence: bool,
}

fn legacy_rules() -> &'static [LegacyRule] {
    static RULES: OnceLock<Vec<LegacyRule>> = OnceLock::new();
    RULES.get_or_init(legacy_fixture::legacy_rules)
}

/// 旧版求值：对整段原始文本跑正则。已知语义缺陷是 `must_absent` 作用于整个
/// Header JSON，任意一条合规 Cookie 都会掩盖其它 Cookie 的属性缺失。
pub fn legacy_evaluate(view: &TrafficView<'_>) -> Vec<LegacyRuleHit> {
    let req_body = body_text(view.req_body, view.req_decode_status);
    let resp_body = view
        .resp_body
        .and_then(|body| body_text(body, view.resp_decode_status));
    let empty = String::new();
    let req_body = req_body.as_deref().unwrap_or(&empty);
    let resp_body = resp_body.as_deref().unwrap_or(&empty);

    let mut hits = Vec::new();
    for rule in legacy_rules() {
        for &target in rule.targets {
            let (text, location, incomplete_evidence): (&str, &'static str, bool) = match target {
                LegacyTarget::Url => (view.url, "url", false),
                LegacyTarget::ReqHeaders => (view.req_headers, "req_headers", false),
                LegacyTarget::ReqBody => (req_body, "req_body", view.req_truncated),
                LegacyTarget::RespHeaders => {
                    (view.resp_headers.unwrap_or(""), "resp_headers", false)
                }
                LegacyTarget::RespBody => (resp_body, "resp_body", view.resp_truncated),
            };
            if text.is_empty() {
                continue;
            }
            if rule.pattern.is_match(text)
                && rule
                    .must_absent
                    .as_ref()
                    .is_none_or(|neg| !neg.is_match(text))
            {
                hits.push(LegacyRuleHit {
                    rule,
                    location,
                    incomplete_evidence,
                });
                break; // 同一规则命中一次即可
            }
        }
    }
    hits
}

// ---- 人工标注语料 ----

const CORPUS: &str = include_str!("../../tests/fixtures/rules/samples.json");

#[derive(Debug, Deserialize)]
struct CorpusFile {
    samples: Vec<LabelledSample>,
}

/// 一条人工标注样本：`expect_hit` 只针对 `rule_id`，其它规则在这条样本上
/// 是"未标注"，只能进差异表，不能计入任何一方的 TP/FP/FN。
#[derive(Debug, Deserialize)]
struct LabelledSample {
    rule_id: String,
    kind: String,
    note: String,
    expect_hit: bool,
    #[serde(default)]
    #[allow(dead_code)]
    expect_field_path: Option<String>,
    traffic: CorpusTraffic,
}

#[derive(Debug, Deserialize)]
struct CorpusTraffic {
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

/// `TrafficView` 借用外部缓冲，所以样本要先物化。
struct Materialized {
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

impl CorpusTraffic {
    fn materialize(&self) -> Materialized {
        let content_type = self.content_type.clone().or_else(|| {
            self.resp_headers
                .as_ref()?
                .get("content-type")?
                .as_str()
                .map(str::to_string)
        });
        Materialized {
            method: self.method.clone().unwrap_or_else(|| "GET".to_string()),
            url: self.url.clone(),
            status: self.status.or(Some(200)),
            content_type,
            req_headers: self
                .req_headers
                .as_ref()
                .map_or_else(|| "{}".to_string(), ToString::to_string),
            req_body: self.req_body.clone().unwrap_or_default().into_bytes(),
            resp_headers: self.resp_headers.as_ref().map(ToString::to_string),
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

impl Materialized {
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

// ---- 差异表与评测 ----

/// 一条规则在一条引擎上的混淆矩阵（只统计人工标注过的样本）。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Confusion {
    true_positive: u32,
    false_positive: u32,
    false_negative: u32,
    true_negative: u32,
}

impl Confusion {
    fn record(&mut self, expected: bool, actual: bool) {
        match (expected, actual) {
            (true, true) => self.true_positive += 1,
            (false, true) => self.false_positive += 1,
            (true, false) => self.false_negative += 1,
            (false, false) => self.true_negative += 1,
        }
    }
}

#[derive(Debug)]
struct ShadowReport {
    v2: BTreeMap<String, Confusion>,
    legacy: BTreeMap<String, Confusion>,
    /// 标注样本上 v2 优于旧引擎的差异：补上漏报，或去掉误报。
    improvements: BTreeSet<String>,
    /// 标注样本上 v2 劣于旧引擎的差异。必须为空，否则就是回退。
    regressions: BTreeSet<String>,
    /// 未标注该规则、因此不计入任何指标的差异条数
    skipped_unlabelled: u32,
    labelled_samples: u32,
}

impl ShadowReport {
    /// 出现过差异的规则集合（只看人工标注过的部分）。
    fn differing_rules(&self) -> BTreeSet<&str> {
        self.improvements
            .iter()
            .chain(&self.regressions)
            .filter_map(|entry| entry.split(" @ ").next())
            .collect()
    }
}

/// 用同一批语料同时跑两条轨道，把逐条差异写进临时表再聚合。
///
/// 临时表刻意建在内存库里：影子评测是一次性对照，不应该污染产品 schema。
fn run_shadow_evaluation() -> ShadowReport {
    let conn = Connection::open_in_memory().expect("影子评测内存库");
    conn.execute_batch(
        "         CREATE TEMP TABLE rule_shadow_diff (
             sample_label     TEXT NOT NULL,
             rule_id          TEXT NOT NULL,
             labelled         INTEGER NOT NULL,
             expected         INTEGER,
             v2_hit           INTEGER NOT NULL,
             v2_field_path    TEXT NOT NULL DEFAULT '',
             legacy_hit       INTEGER NOT NULL,
             legacy_location  TEXT NOT NULL DEFAULT '',
             legacy_incomplete INTEGER NOT NULL DEFAULT 0,
             verdict          TEXT NOT NULL,
             skip_reason      TEXT NOT NULL DEFAULT '',
             PRIMARY KEY (sample_label, rule_id)
         );",
    )
    .expect("创建差异临时表");

    let samples = serde_json::from_str::<CorpusFile>(CORPUS)
        .expect("语料必须是合法 JSON")
        .samples;
    let mut report = ShadowReport {
        v2: BTreeMap::new(),
        legacy: BTreeMap::new(),
        improvements: BTreeSet::new(),
        regressions: BTreeSet::new(),
        skipped_unlabelled: 0,
        labelled_samples: samples.len() as u32,
    };

    for sample in &samples {
        let label = format!("{} [{}] {}", sample.rule_id, sample.kind, sample.note);
        let traffic = sample.traffic.materialize();
        let view = traffic.view();

        let v2_hits: BTreeMap<String, String> = super::engine::evaluate(&view)
            .hits
            .iter()
            .map(|hit| (hit.rule.rule_id.clone(), hit.field_path.clone()))
            .collect();
        let legacy_hits: BTreeMap<String, (&'static str, bool)> = legacy_evaluate(&view)
            .iter()
            .map(|hit| {
                (
                    hit.rule.id.to_string(),
                    (hit.location, hit.incomplete_evidence),
                )
            })
            .collect();

        let mut rule_ids: BTreeSet<&str> = BTreeSet::new();
        rule_ids.insert(sample.rule_id.as_str());
        rule_ids.extend(v2_hits.keys().map(String::as_str));
        rule_ids.extend(legacy_hits.keys().map(String::as_str));

        for rule_id in rule_ids {
            let v2_field_path = v2_hits.get(rule_id);
            let legacy_evidence = legacy_hits.get(rule_id);
            let v2_hit = v2_field_path.is_some();
            let legacy_hit = legacy_evidence.is_some();
            let labelled = rule_id == sample.rule_id;
            let verdict = match (v2_hit, legacy_hit) {
                (true, true) => "both",
                (true, false) => "v2_only",
                (false, true) => "legacy_only",
                (false, false) => "none",
            };
            let skip_reason = if labelled {
                ""
            } else {
                report.skipped_unlabelled += 1;
                "样本未标注该规则"
            };
            conn.execute(
                "INSERT INTO rule_shadow_diff(
                     sample_label, rule_id, labelled, expected, v2_hit, v2_field_path,
                     legacy_hit, legacy_location, legacy_incomplete, verdict, skip_reason)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                rusqlite::params![
                    label,
                    rule_id,
                    labelled,
                    labelled.then_some(sample.expect_hit),
                    v2_hit,
                    v2_field_path.map(String::as_str).unwrap_or_default(),
                    legacy_hit,
                    legacy_evidence.map(|(location, _)| *location).unwrap_or(""),
                    legacy_evidence.is_some_and(|(_, incomplete)| *incomplete),
                    verdict,
                    skip_reason,
                ],
            )
            .expect("写入差异行");

            if !labelled {
                continue;
            }
            report
                .v2
                .entry(rule_id.to_string())
                .or_default()
                .record(sample.expect_hit, v2_hit);
            report
                .legacy
                .entry(rule_id.to_string())
                .or_default()
                .record(sample.expect_hit, legacy_hit);

            // 两条轨道判定不同时，由人工标注决定谁对：命中该命中的、放过该
            // 放过的算改进，反过来就是回退。
            if v2_hit != legacy_hit {
                let entry = format!("{rule_id} @ {label}");
                if v2_hit == sample.expect_hit {
                    report.improvements.insert(entry);
                } else {
                    report.regressions.insert(entry);
                }
            }
        }
    }

    // 临时表存在即证明逐条差异确实落过盘，也顺手校验行数与内存聚合一致
    let rows: u32 = conn
        .query_row("SELECT COUNT(*) FROM rule_shadow_diff", [], |row| {
            row.get(0)
        })
        .expect("统计差异行");
    let labelled_differences: u32 = conn
        .query_row(
            "SELECT COUNT(*) FROM rule_shadow_diff
             WHERE labelled = 1 AND verdict IN ('v2_only','legacy_only')",
            [],
            |row| row.get(0),
        )
        .expect("统计差异行");
    assert!(rows > 0);
    assert_eq!(
        labelled_differences as usize,
        report.improvements.len() + report.regressions.len()
    );
    report
}

fn render(report: &ShadowReport) -> String {
    let mut out = format!(
        "标注样本 {} 条，未标注而跳过的差异 {} 条\n\
         | rule_id | v2 TP/FP/FN | legacy TP/FP/FN |\n|---|---|---|\n",
        report.labelled_samples, report.skipped_unlabelled
    );
    for (rule_id, v2) in &report.v2 {
        let legacy = report.legacy.get(rule_id).copied().unwrap_or_default();
        out.push_str(&format!(
            "| {rule_id} | {}/{}/{} | {}/{}/{} |\n",
            v2.true_positive,
            v2.false_positive,
            v2.false_negative,
            legacy.true_positive,
            legacy.false_positive,
            legacy.false_negative,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const REVIEW_RECORD: &str =
        include_str!("../../../docs/architecture/rule-shadow-evaluation.md");

    /// 复核记录固定在这里：这些规则是两条轨道在标注语料上出现差异的全部来源。
    /// 语料扩充后如果集合变了，说明有新的行为差异需要重新人工复核。
    /// 详见 `docs/architecture/rule-shadow-evaluation.md`。
    const REVIEWED_DIFFERING_RULES: &[&str] =
        &["cookie-no-httponly", "cookie-no-secure", "cors-wildcard"];

    #[test]
    fn v2_is_never_worse_than_the_legacy_engine_on_the_labelled_corpus() {
        let report = run_shadow_evaluation();
        let table = render(&report);
        eprintln!("{table}");

        for (rule_id, v2) in &report.v2 {
            let legacy = report.legacy.get(rule_id).copied().unwrap_or_default();
            assert_eq!(v2.false_positive, 0, "{rule_id} 出现误报\n{table}");
            assert_eq!(v2.false_negative, 0, "{rule_id} 出现漏报\n{table}");
            assert!(
                v2.true_positive >= legacy.true_positive,
                "{rule_id} 的 TP 不得低于旧引擎\n{table}"
            );
            assert!(
                v2.false_positive <= legacy.false_positive,
                "{rule_id} 的 FP 不得高于旧引擎\n{table}"
            );
            assert!(
                v2.false_negative <= legacy.false_negative,
                "{rule_id} 的 FN 不得高于旧引擎\n{table}"
            );
        }
        assert!(report.skipped_unlabelled > 0, "应存在未标注而跳过的差异");
    }

    #[test]
    fn every_engine_difference_is_a_reviewed_v2_improvement() {
        let report = run_shadow_evaluation();
        let table = render(&report);

        assert!(
            report.regressions.is_empty(),
            "v2 不得在任何标注样本上劣于旧引擎：{:?}\n{table}",
            report.regressions
        );
        assert!(
            !report.improvements.is_empty(),
            "语料应覆盖到已知的新旧差异\n{table}"
        );
        assert_eq!(
            report.differing_rules(),
            REVIEWED_DIFFERING_RULES.iter().copied().collect(),
            "差异规则集合与已复核记录不一致，需要重新人工审阅\n{table}"
        );
    }

    #[test]
    fn manual_review_record_covers_every_known_difference_and_skip_policy() {
        let report = run_shadow_evaluation();
        for rule_id in report.differing_rules() {
            assert!(
                REVIEW_RECORD.contains(rule_id),
                "人工复核记录缺少差异规则 {rule_id}"
            );
        }
        for required in ["TP", "FP", "FN", "样本未标注该规则", "test-only"] {
            assert!(
                REVIEW_RECORD.contains(required),
                "人工复核记录缺少 `{required}`"
            );
        }
    }

    #[test]
    fn per_cookie_evaluation_fixes_the_legacy_global_must_absent_bug() {
        let traffic = CorpusTraffic {
            url: "https://t.cn/login".to_string(),
            method: None,
            status: None,
            content_type: None,
            req_headers: None,
            req_body: None,
            resp_headers: Some(serde_json::json!({
                "set-cookie": [
                    "session=abc; Path=/; Secure",
                    "theme=dark; Path=/; Secure; HttpOnly"
                ]
            })),
            resp_body: None,
            req_truncated: false,
            resp_truncated: false,
            req_decode_status: None,
            resp_decode_status: None,
        }
        .materialize();
        let view = traffic.view();

        // 旧实现：theme 带了 HttpOnly，全局 must_absent 就认定整条响应没问题
        assert!(!legacy_evaluate(&view)
            .iter()
            .any(|hit| hit.rule.id == "cookie-no-httponly"));

        // 新实现：逐条判定，session 缺 HttpOnly 被单独识别出来
        let report = super::super::engine::evaluate(&view);
        let hit = report
            .hits
            .iter()
            .find(|hit| hit.rule.rule_id == "cookie-no-httponly")
            .expect("新引擎应逐条识别");
        assert!(hit.field_path.contains("set-cookie[0]"));
        assert!(!hit.evidence.contains("abc"));
    }

    #[test]
    fn cookie_value_spelling_secure_is_not_mistaken_for_the_attribute() {
        let traffic = CorpusTraffic {
            url: "https://t.cn/login".to_string(),
            method: None,
            status: None,
            content_type: None,
            req_headers: None,
            req_body: None,
            resp_headers: Some(
                serde_json::json!({ "set-cookie": "sid=very-secure-token; Path=/; HttpOnly" }),
            ),
            resp_body: None,
            req_truncated: false,
            resp_truncated: false,
            req_decode_status: None,
            resp_decode_status: None,
        }
        .materialize();
        let view = traffic.view();

        // 旧实现对整段 Header JSON 跑 `(?i)secure`，Cookie 值里的 secure 会掩盖缺失
        assert!(!legacy_evaluate(&view)
            .iter()
            .any(|hit| hit.rule.id == "cookie-no-secure"));
        assert!(super::super::engine::evaluate(&view)
            .hits
            .iter()
            .any(|hit| hit.rule.rule_id == "cookie-no-secure"));
    }
}
