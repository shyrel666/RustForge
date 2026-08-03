//! Provider-independent validation and evidence grounding for model output.

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
    if result.hypotheses.len() > MAX_HYPOTHESES {
        errors.push(format!("hypotheses 最多 {MAX_HYPOTHESES} 项"));
    }

    let allowed: HashSet<&str> = allowed_evidence_refs.iter().map(String::as_str).collect();
    let mut grounded = 0;
    let mut ungrounded = 0;
    for (index, hypothesis) in result.hypotheses.iter_mut().enumerate() {
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
        // 标准引用只是 Finding 的可选知识卡元数据。模型可能写出格式近似、
        // 官方存在但当前精选包未收录的编号；这些引用不能入库，但也不应让
        // 已计费且证据充分的整条分析失效。能解析的引用继续严格规范化，
        // 其余逐条丢弃并同时写入假设备注与 analysis_run 审计警告。
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
        let original_ref_count = hypothesis.evidence_refs.len();
        let mut valid_refs = Vec::new();
        for reference in &hypothesis.evidence_refs {
            if char_len(reference) > 64 {
                errors.push(format!("{prefix}.evidence_refs 含超过 64 字符的引用"));
            } else if allowed.contains(reference.as_str()) && !valid_refs.contains(reference) {
                valid_refs.push(reference.clone());
            }
        }
        let fully_grounded = !valid_refs.is_empty() && valid_refs.len() == original_ref_count;
        hypothesis.evidence_refs = valid_refs;
        if fully_grounded {
            hypothesis.grounding_status = "grounded".to_string();
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
    }

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
                            "type": "array", "maxItems": MAX_EVIDENCE_REFS,
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
        assert_eq!(hypothesis.validation_notes.len(), 2);
        assert_eq!(report.warnings.len(), 2);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("A02")));
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("CWE-620")));
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
