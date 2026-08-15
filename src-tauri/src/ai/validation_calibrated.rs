//! Provider-independent validation and evidence grounding for model output.
//!
//! Besides structural validation this module performs deterministic
//! post-calibration: evidence references are weighted, duplicate references are
//! collapsed before grounding, duplicate hypotheses are merged, and
//! high-confidence claims without body/header evidence are capped. The model is
//! never allowed to confirm a vulnerability through these fields.

use super::json::parse_llm_json;
use crate::knowledge::{self, StandardReference};
use crate::storage::models::{AnalysisResult, VulnHypothesis};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;

pub const MAX_HYPOTHESES: usize = 4;
const MAX_SUSPICIOUS_PARAMS: usize = 32;
const MAX_EVIDENCE_REFS: usize = 8;
const MAX_STANDARD_REFERENCES: usize = 8;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelHypothesis {
    vuln_type: String,
    param: String,
    standard_references: Vec<StandardReference>,
    severity: String,
    confidence: u8,
    reasoning: String,
    verify_steps: String,
    evidence_refs: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelAnalysisResult {
    purpose: String,
    suspicious_params: Vec<String>,
    hypotheses: Vec<ModelHypothesis>,
    summary: String,
}

impl From<ModelAnalysisResult> for AnalysisResult {
    fn from(value: ModelAnalysisResult) -> Self {
        Self {
            purpose: value.purpose,
            suspicious_params: value.suspicious_params,
            hypotheses: value
                .hypotheses
                .into_iter()
                .map(|hypothesis| VulnHypothesis {
                    vuln_type: hypothesis.vuln_type,
                    param: hypothesis.param,
                    standard_references: hypothesis.standard_references,
                    severity: hypothesis.severity,
                    confidence: hypothesis.confidence,
                    reasoning: hypothesis.reasoning,
                    verify_steps: hypothesis.verify_steps,
                    evidence_refs: hypothesis.evidence_refs,
                    grounding_status: String::new(),
                    validation_notes: Vec::new(),
                })
                .collect(),
            summary: value.summary,
            analysis_run_id: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidationReport {
    pub status: String,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub attempts: usize,
    pub hypotheses_total: usize,
    pub grounded_hypotheses: usize,
    pub ungrounded_hypotheses: usize,
}

impl ValidationReport {
    pub fn invalid(error: impl Into<String>) -> Self {
        Self {
            status: "invalid".to_string(),
            errors: vec![error.into()],
            warnings: Vec::new(),
            attempts: 1,
            hypotheses_total: 0,
            grounded_hypotheses: 0,
            ungrounded_hypotheses: 0,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.status == "valid" && self.errors.is_empty()
    }
}

fn char_len(value: &str) -> usize {
    value.chars().count()
}

fn require_string(errors: &mut Vec<String>, path: &str, value: &mut String, max_chars: usize) {
    *value = value.trim().to_string();
    if value.is_empty() {
        errors.push(format!("{path} 不能为空"));
    } else if char_len(value) > max_chars {
        errors.push(format!("{path} 超过 {max_chars} 字符"));
    }
}

fn optional_string(errors: &mut Vec<String>, path: &str, value: &mut String, max_chars: usize) {
    *value = value.trim().to_string();
    if char_len(value) > max_chars {
        errors.push(format!("{path} 超过 {max_chars} 字符"));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EvidenceStrength {
    /// Body is the strongest observable evidence for a traffic analysis.
    Strong,
    /// Headers, passive rule tags and status code are meaningful but indirect.
    Moderate,
    /// Method/URL/host only locate the request; they cannot prove a hypothesis.
    Weak,
}

fn evidence_strength(reference: &str) -> EvidenceStrength {
    match reference {
        "request.body" | "response.body" => EvidenceStrength::Strong,
        "request.headers" | "response.headers" | "response.status" | "passive.rule_tags" => {
            EvidenceStrength::Moderate
        }
        _ => EvidenceStrength::Weak,
    }
}

fn calibrate_confidence(
    severity: &str,
    confidence: u8,
    strengths: &[EvidenceStrength],
) -> (u8, Option<&'static str>) {
    let strong_count = strengths
        .iter()
        .filter(|strength| matches!(**strength, EvidenceStrength::Strong))
        .count();
    let moderate_count = strengths
        .iter()
        .filter(|strength| matches!(**strength, EvidenceStrength::Moderate))
        .count();
    let distinct_count = strengths.len();

    let weak_only = strong_count == 0 && moderate_count == 0;
    let (cap, reason): (u8, &'static str) = match severity {
        "critical" if weak_only => (
            45,
            "critical 假设仅引用方法/URL/Host 等辅助定位信息，置信度按后端策略封顶",
        ),
        "critical" if strong_count == 0 => {
            (60, "critical 假设没有 body 级证据，置信度按后端策略封顶")
        }
        "critical" if distinct_count < 2 => {
            (80, "critical 假设仅引用单一强证据，置信度按后端策略封顶")
        }
        "high" if weak_only => (
            45,
            "high 假设仅引用方法/URL/Host 等辅助定位信息，置信度按后端策略封顶",
        ),
        "high" if strong_count == 0 => (
            70,
            "high 假设没有 body/header 级直接证据，置信度按后端策略封顶",
        ),
        "high" if distinct_count < 2 => (85, "high 假设仅引用单一证据，置信度按后端策略封顶"),
        "medium" if weak_only => (45, "medium 假设仅引用辅助定位信息，置信度按后端策略封顶"),
        "medium" if strong_count == 0 => (70, "medium 假设没有 body 级证据，置信度按后端策略封顶"),
        "low" | "info" if weak_only => (40, "低危假设仅引用辅助定位信息，置信度按后端策略封顶"),
        _ => return (confidence, None),
    };

    if confidence > cap {
        (cap, Some(reason))
    } else {
        (confidence, None)
    }
}

pub fn parse_and_validate(
    raw: &str,
    allowed_evidence_refs: &[String],
) -> Result<(AnalysisResult, ValidationReport), ValidationReport> {
    let wire: ModelAnalysisResult = parse_llm_json(raw).map_err(|error| {
        ValidationReport::invalid(format!("模型输出不是有效的分析 JSON: {error}"))
    })?;
    let mut result = AnalysisResult::from(wire);
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    require_string(&mut errors, "purpose", &mut result.purpose, 500);
    require_string(&mut errors, "summary", &mut result.summary, 4_000);
    if result.suspicious_params.len() > MAX_SUSPICIOUS_PARAMS {
        errors.push(format!("suspicious_params 最多 {MAX_SUSPICIOUS_PARAMS} 项"));
    }
    for (index, parameter) in result.suspicious_params.iter_mut().enumerate() {
        require_string(
            &mut errors,
            &format!("suspicious_params[{index}]"),
            parameter,
            128,
        );
    }

    // Case-insensitive parameter deduplication. Duplicate names inflate the
    // UI list without adding detection value.
    let original_param_count = result.suspicious_params.len();
    let mut seen_params = HashSet::new();
    let mut unique_params = Vec::with_capacity(original_param_count);
    for parameter in result.suspicious_params.drain(..) {
        if seen_params.insert(parameter.to_lowercase()) {
            unique_params.push(parameter);
        }
    }
    if unique_params.len() < original_param_count {
        warnings.push(format!(
            "suspicious_params 去除了 {} 个大小写重复项",
            original_param_count - unique_params.len()
        ));
    }
    result.suspicious_params = unique_params;

    if result.hypotheses.len() > MAX_HYPOTHESES {
        errors.push(format!("hypotheses 最多 {MAX_HYPOTHESES} 项"));
    }

    let allowed: HashSet<&str> = allowed_evidence_refs.iter().map(String::as_str).collect();
    let mut grounded = 0;
    let mut ungrounded = 0;
    let mut unique_hypotheses = Vec::with_capacity(result.hypotheses.len());
    let mut seen_hypotheses = HashSet::new();

    for (index, mut hypothesis) in result.hypotheses.drain(..).enumerate() {
        let prefix = format!("hypotheses[{index}]");
        require_string(
            &mut errors,
            &format!("{prefix}.vuln_type"),
            &mut hypothesis.vuln_type,
            128,
        );
        optional_string(
            &mut errors,
            &format!("{prefix}.param"),
            &mut hypothesis.param,
            256,
        );
        require_string(
            &mut errors,
            &format!("{prefix}.reasoning"),
            &mut hypothesis.reasoning,
            4_000,
        );
        require_string(
            &mut errors,
            &format!("{prefix}.verify_steps"),
            &mut hypothesis.verify_steps,
            4_000,
        );
        if !matches!(
            hypothesis.severity.as_str(),
            "critical" | "high" | "medium" | "low" | "info"
        ) {
            errors.push(format!("{prefix}.severity 不是允许的枚举值"));
        }
        if hypothesis.confidence > 100 {
            errors.push(format!("{prefix}.confidence 必须在 0..=100"));
        }
        if hypothesis.standard_references.len() > MAX_STANDARD_REFERENCES {
            warnings.push(format!(
                "{prefix}.standard_references 超过 {MAX_STANDARD_REFERENCES} 项，已只保留前 {MAX_STANDARD_REFERENCES} 项"
            ));
            hypothesis
                .standard_references
                .truncate(MAX_STANDARD_REFERENCES);
        }
        match knowledge::resolve(&hypothesis.standard_references) {
            Ok(lookup) => {
                for unresolved in lookup.unresolved {
                    let note = format!(
                        "标准引用 `{}` 已忽略：{}",
                        unresolved.reference.identity(),
                        unresolved.reason
                    );
                    hypothesis.validation_notes.push(note.clone());
                    warnings.push(format!("{prefix}: {note}"));
                }
                hypothesis.standard_references = lookup
                    .cards
                    .into_iter()
                    .map(|card| card.reference)
                    .collect();
            }
            Err(error) => errors.push(format!("{prefix}.standard_references 解析失败: {error}")),
        }

        if hypothesis.evidence_refs.len() > MAX_EVIDENCE_REFS {
            errors.push(format!(
                "{prefix}.evidence_refs 最多 {MAX_EVIDENCE_REFS} 项"
            ));
        }

        // Collapse duplicates before grounding. The old logic counted a
        // duplicated valid reference as an unknown one and wrongly downgraded
        // an otherwise grounded hypothesis.
        let original_ref_count = hypothesis.evidence_refs.len();
        let mut requested_refs = Vec::new();
        for reference in &hypothesis.evidence_refs {
            if char_len(reference) > 64 {
                errors.push(format!("{prefix}.evidence_refs 含超过 64 字符的引用"));
            } else if !requested_refs.contains(reference) {
                requested_refs.push(reference.clone());
            }
        }
        let mut valid_refs = Vec::new();
        for reference in &requested_refs {
            if allowed.contains(reference.as_str()) {
                valid_refs.push(reference.clone());
            }
        }

        // Duplicate hypotheses (same vulnerability type, parameter and severity)
        // are merged after validation. They are still audited, but are not saved
        // as duplicate pending Findings.
        let hypothesis_key = (
            hypothesis.vuln_type.to_lowercase(),
            hypothesis.param.to_lowercase(),
            hypothesis.severity.clone(),
        );
        if !seen_hypotheses.insert(hypothesis_key) {
            warnings.push(format!(
                "{prefix} 与更早的假设重复（漏洞类型/参数/严重度相同），已合并为一条"
            ));
            continue;
        }

        let fully_grounded = !valid_refs.is_empty() && valid_refs.len() == requested_refs.len();
        hypothesis.evidence_refs = valid_refs;
        if fully_grounded {
            hypothesis.grounding_status = "grounded".to_string();
            if original_ref_count != requested_refs.len() {
                let note = "evidence_refs 含重复项，已按唯一引用合并";
                hypothesis.validation_notes.push(note.to_string());
                warnings.push(format!("{prefix}: {note}"));
            }
            let strengths = hypothesis
                .evidence_refs
                .iter()
                .map(|reference| evidence_strength(reference.as_str()))
                .collect::<Vec<_>>();
            let (calibrated, calibration_reason) =
                calibrate_confidence(&hypothesis.severity, hypothesis.confidence, &strengths);
            if let Some(reason) = calibration_reason {
                let note = format!(
                    "原始置信度 {} 已按证据强度校准为 {}：{}",
                    hypothesis.confidence, calibrated, reason
                );
                hypothesis.confidence = calibrated;
                hypothesis.validation_notes.push(note.clone());
                warnings.push(format!("{prefix}: {note}"));
            }
            grounded += 1;
        } else {
            hypothesis.grounding_status = "ungrounded".to_string();
            hypothesis.confidence = hypothesis.confidence.min(25);
            let note = if original_ref_count == 0 {
                "模型未提供证据引用，置信度已降至低档"
            } else {
                "一个或多个证据引用无法映射到实际发送字段，已移除并降低置信度"
            };
            hypothesis.validation_notes.push(note.to_string());
            warnings.push(format!("{prefix}: {note}"));
            ungrounded += 1;
        }

        unique_hypotheses.push(hypothesis);
    }
    result.hypotheses = unique_hypotheses;

    let report = ValidationReport {
        status: if errors.is_empty() {
            "valid".to_string()
        } else {
            "invalid".to_string()
        },
        errors,
        warnings,
        attempts: 1,
        hypotheses_total: result.hypotheses.len(),
        grounded_hypotheses: grounded,
        ungrounded_hypotheses: ungrounded,
    };
    if report.is_valid() {
        Ok((result, report))
    } else {
        Err(report)
    }
}

/// JSON Schema used only for providers explicitly configured as supporting it.
/// Every response still passes through `parse_and_validate`.
pub fn analysis_response_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "required": ["purpose", "suspicious_params", "hypotheses", "summary"],
        "properties": {
            "purpose": { "type": "string", "minLength": 1, "maxLength": 500 },
            "suspicious_params": {
                "type": "array", "maxItems": MAX_SUSPICIOUS_PARAMS,
                "items": { "type": "string", "minLength": 1, "maxLength": 128 }
            },
            "hypotheses": {
                "type": "array", "maxItems": MAX_HYPOTHESES,
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": ["vuln_type", "param", "standard_references", "severity", "confidence", "reasoning", "verify_steps", "evidence_refs"],
                    "properties": {
                        "vuln_type": { "type": "string", "minLength": 1, "maxLength": 128 },
                        "param": { "type": "string", "maxLength": 256 },
                        "standard_references": {
                            "type": "array",
                            "maxItems": MAX_STANDARD_REFERENCES,
                            "uniqueItems": true,
                            "items": {
                                "type": "object",
                                "additionalProperties": false,
                                "required": ["framework", "version", "id"],
                                "properties": {
                                    "framework": {
                                        "type": "string",
                                        "enum": ["owasp-top10", "owasp-api-top10", "asvs", "wstg", "cwe"]
                                    },
                                    "version": { "type": "string", "minLength": 1, "maxLength": 16 },
                                    "id": { "type": "string", "minLength": 1, "maxLength": 32 }
                                }
                            }
                        },
                        "severity": { "type": "string", "enum": ["critical", "high", "medium", "low", "info"] },
                        "confidence": { "type": "integer", "minimum": 0, "maximum": 100 },
                        "reasoning": { "type": "string", "minLength": 1, "maxLength": 4000 },
                        "verify_steps": { "type": "string", "minLength": 1, "maxLength": 4000 },
                        "evidence_refs": {
                            "type": "array", "maxItems": MAX_EVIDENCE_REFS, "uniqueItems": true,
                            "items": { "type": "string", "maxLength": 64 }
                        }
                    }
                }
            },
            "summary": { "type": "string", "minLength": 1, "maxLength": 4000 }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result_json() -> String {
        r#"{
                "purpose":"登录接口",
                "suspicious_params":["username"],
                "hypotheses":[{
                    "vuln_type":"SQL 注入",
                    "param":"username",
                    "standard_references":[
                        {"framework":"owasp-top10","version":"2025","id":"A05"},
                        {"framework":"cwe","version":"4.20","id":"CWE-89"}
                    ],
                    "severity":"high",
                    "confidence":80,
                    "reasoning":"响应行为异常",
                    "verify_steps":"人工重放并比较响应",
                    "evidence_refs":["response.status"]
                }],
                "summary":"需要人工复核"
            }"#
        .to_string()
    }

    fn refs() -> Vec<String> {
        vec!["response.status".to_string(), "request.body".to_string()]
    }

    #[test]
    fn valid_result_is_normalized_and_grounded() {
        let (result, report) = parse_and_validate(&result_json(), &refs()).unwrap();
        assert_eq!(
            result.hypotheses[0].standard_references[0],
            StandardReference::new("owasp-top10", "2025", "A05")
        );
        assert_eq!(result.hypotheses[0].grounding_status, "grounded");
        assert!(report.is_valid());
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("校准")));
    }

    #[test]
    fn invalid_severity_fails_validation() {
        let mut raw: Value = serde_json::from_str(&result_json()).unwrap();
        raw["hypotheses"][0]["severity"] = json!("urgent");
        let report = parse_and_validate(&raw.to_string(), &refs()).unwrap_err();
        assert!(report.errors.iter().any(|error| error.contains("severity")));
    }

    #[test]
    fn unverifiable_optional_references_are_dropped_without_losing_analysis() {
        let mut raw: Value = serde_json::from_str(&result_json()).unwrap();
        raw["hypotheses"][0]["standard_references"] = json!([
            {"framework":"owasp-api-top10","version":"2023","id":"A02"},
            {"framework":"owasp-api-top10","version":"2023","id":"API2"},
            {"framework":"cwe","version":"4.20","id":"CWE-620"}
        ]);

        let (result, report) = parse_and_validate(&raw.to_string(), &refs()).unwrap();
        let hypothesis = &result.hypotheses[0];
        assert_eq!(
            hypothesis.standard_references,
            vec![StandardReference::new("owasp-api-top10", "2023", "API2")]
        );
        assert_eq!(hypothesis.validation_notes.len(), 3);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("A02")));
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("CWE-620")));
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("校准")));
    }

    #[test]
    fn excessive_hypotheses_are_rejected() {
        let one: Value = serde_json::from_str(&result_json()).unwrap();
        let hypothesis = one["hypotheses"][0].clone();
        let raw = json!({
            "purpose": "p",
            "suspicious_params": [],
            "hypotheses": vec![hypothesis; 5],
            "summary": "s"
        });
        let report = parse_and_validate(&raw.to_string(), &refs()).unwrap_err();
        assert!(report.errors.iter().any(|error| error.contains("最多 4")));
    }

    #[test]
    fn missing_or_unknown_evidence_is_soft_downgraded() {
        let mut raw: Value = serde_json::from_str(&result_json()).unwrap();
        raw["hypotheses"][0]["evidence_refs"] = json!(["response.secret"]);
        let (result, report) = parse_and_validate(&raw.to_string(), &refs()).unwrap();
        let hypothesis = &result.hypotheses[0];
        assert_eq!(hypothesis.grounding_status, "ungrounded");
        assert!(hypothesis.confidence <= 25);
        assert_eq!(report.ungrounded_hypotheses, 1);
    }

    #[test]
    fn empty_evidence_is_explicitly_marked_ungrounded() {
        let mut raw: Value = serde_json::from_str(&result_json()).unwrap();
        raw["hypotheses"][0]["evidence_refs"] = json!([]);
        let (result, report) = parse_and_validate(&raw.to_string(), &refs()).unwrap();
        assert_eq!(result.hypotheses[0].grounding_status, "ungrounded");
        assert!(result.hypotheses[0]
            .validation_notes
            .iter()
            .any(|note| note.contains("未提供证据")));
        assert_eq!(report.ungrounded_hypotheses, 1);
    }

    #[test]
    fn duplicate_evidence_refs_are_collapsed_before_grounding() {
        let mut raw: Value = serde_json::from_str(&result_json()).unwrap();
        raw["hypotheses"][0]["evidence_refs"] = json!(["response.status", "response.status"]);
        let (result, report) = parse_and_validate(&raw.to_string(), &refs()).unwrap();
        let hypothesis = &result.hypotheses[0];
        assert_eq!(hypothesis.grounding_status, "grounded");
        assert_eq!(
            hypothesis.evidence_refs,
            vec!["response.status".to_string()]
        );
        assert_eq!(report.grounded_hypotheses, 1);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("重复项")));
    }

    #[test]
    fn high_severity_claims_are_capped_without_body_evidence() {
        let mut raw: Value = serde_json::from_str(&result_json()).unwrap();
        raw["hypotheses"][0]["severity"] = json!("critical");
        raw["hypotheses"][0]["confidence"] = json!(95);
        let (result, report) = parse_and_validate(&raw.to_string(), &refs()).unwrap();
        let hypothesis = &result.hypotheses[0];
        assert_eq!(hypothesis.grounding_status, "grounded");
        assert!(hypothesis.confidence <= 60);

        assert!(hypothesis
            .validation_notes
            .iter()
            .any(|note| note.contains("校准")));
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("校准")));
    }

    #[test]
    fn metadata_only_evidence_gets_a_harder_confidence_cap() {
        let mut raw: Value = serde_json::from_str(&result_json()).unwrap();
        raw["hypotheses"][0]["evidence_refs"] = json!(["request.url"]);
        let (result, report) =
            parse_and_validate(&raw.to_string(), &["request.url".to_string()]).unwrap();
        let hypothesis = &result.hypotheses[0];
        assert_eq!(hypothesis.grounding_status, "grounded");
        assert!(hypothesis.confidence <= 45);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("辅助定位")));
    }

    #[test]
    fn duplicate_hypotheses_are_merged_and_audited() {
        let one: Value = serde_json::from_str(&result_json()).unwrap();
        let hypothesis = one["hypotheses"][0].clone();
        let raw = json!({
            "purpose": "p",
            "suspicious_params": ["username"],
            "hypotheses": [hypothesis.clone(), hypothesis],
            "summary": "s"
        });
        let (result, report) = parse_and_validate(&raw.to_string(), &refs()).unwrap();
        assert_eq!(result.hypotheses.len(), 1);
        assert_eq!(report.hypotheses_total, 1);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("重复")));
    }

    #[test]
    fn schema_has_hard_enums_and_array_limits() {
        let schema = analysis_response_schema();
        assert_eq!(schema["properties"]["hypotheses"]["maxItems"], 4);
        assert_eq!(
            schema["properties"]["hypotheses"]["items"]["properties"]["severity"]["enum"][0],
            "critical"
        );
    }

    #[test]
    fn backend_only_or_unknown_fields_are_rejected_for_every_provider() {
        let mut raw: Value = serde_json::from_str(&result_json()).unwrap();
        raw["analysis_run_id"] = json!(999);
        assert!(parse_and_validate(&raw.to_string(), &refs()).is_err());

        let mut raw: Value = serde_json::from_str(&result_json()).unwrap();
        raw["hypotheses"][0]["grounding_status"] = json!("grounded");
        assert!(parse_and_validate(&raw.to_string(), &refs()).is_err());
    }
}
