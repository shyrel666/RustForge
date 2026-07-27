//! Executes a previewed analysis and applies the same backend validator for
//! every provider, regardless of JSON Schema support.

use super::client::{LlmClient, Usage};
use super::context::AiContextPreview;
use super::validation::{self, ValidationReport};
use crate::secrets::redact_sensitive;
use crate::storage::models::AnalysisResult;
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub struct AnalysisAttempt {
    pub result: Option<AnalysisResult>,
    pub usage: Usage,
    pub validation: ValidationReport,
    pub raw_output_hash: String,
    pub schema_applied: bool,
}

fn sha256(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// A syntactically or semantically invalid response is retried once.  The
/// final invalid response is returned as an auditable attempt instead of being
/// converted into a Finding.
pub async fn analyze(
    client: &impl LlmClient,
    preview: &AiContextPreview,
) -> Result<AnalysisAttempt, String> {
    let schema = preview.response_schema.as_ref();
    let schema_applied = schema.is_some();
    let mut usage = Usage::default();
    let first = client
        .chat(&preview.system_prompt, &preview.user_prompt, schema)
        .await?;
    usage.add(&first.usage);
    match validation::parse_and_validate(&first.content, &preview.evidence_refs) {
        Ok((result, mut report)) => {
            report.attempts = 1;
            Ok(AnalysisAttempt {
                result: Some(result),
                usage,
                validation: report,
                raw_output_hash: sha256(&first.content),
                schema_applied,
            })
        }
        Err(first_report) => {
            eprintln!(
                "[ai] 首次结构化校验失败，重试: {}",
                redact_sensitive(&first_report.errors.join("; "), &[])
            );
            let second = match client
                .chat(&preview.system_prompt, &preview.retry_user_prompt, schema)
                .await
            {
                Ok(response) => response,
                Err(error) => {
                    let mut report = first_report;
                    report.warnings.push(format!(
                        "后端校验重试调用失败，已保留首次无效响应的审计摘要：{}",
                        redact_sensitive(&error, &[])
                    ));
                    return Ok(AnalysisAttempt {
                        result: None,
                        usage,
                        validation: report,
                        raw_output_hash: sha256(&first.content),
                        schema_applied,
                    });
                }
            };
            usage.add(&second.usage);
            match validation::parse_and_validate(&second.content, &preview.evidence_refs) {
                Ok((result, mut report)) => {
                    report.attempts = 2;
                    report
                        .warnings
                        .insert(0, "首次模型响应未通过校验，第二次响应有效".to_string());
                    Ok(AnalysisAttempt {
                        result: Some(result),
                        usage,
                        validation: report,
                        raw_output_hash: sha256(&second.content),
                        schema_applied,
                    })
                }
                Err(mut report) => {
                    report.attempts = 2;
                    report.warnings.insert(
                        0,
                        format!("首次响应也无效：{}", first_report.errors.join("；")),
                    );
                    Ok(AnalysisAttempt {
                        result: None,
                        usage,
                        validation: report,
                        raw_output_hash: sha256(&second.content),
                        schema_applied,
                    })
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::client::{ChatResponse, LlmClient};
    use super::super::context::{AiContextPreview, AiDataPolicy};
    use super::super::redaction::RedactionManifest;
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const GOOD_JSON: &str = r#"{
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
            "reasoning":"响应状态异常",
            "verify_steps":"人工重放并比较响应",
            "evidence_refs":["response.status"]
        }],
        "summary":"值得人工复核"
    }"#;

    fn preview(with_schema: bool) -> AiContextPreview {
        AiContextPreview {
            traffic_id: 1,
            provider_id: "p".to_string(),
            provider_base_url: "https://provider.test/v1".to_string(),
            model: "m".to_string(),
            prompt_id: "prompt".to_string(),
            prompt_version: 1,
            prompt_source: "builtin".to_string(),
            system_prompt: "system".to_string(),
            user_prompt: "user".to_string(),
            retry_user_prompt: "user\n\nretry".to_string(),
            response_schema: with_schema.then(super::super::validation::analysis_response_schema),
            input_hash: "a".repeat(64),
            policy: AiDataPolicy::default(),
            manifest: RedactionManifest::default(),
            evidence_refs: vec!["response.status".to_string()],
            is_relaxed: false,
        }
    }

    struct FlakyMock {
        calls: AtomicUsize,
        always_invalid: bool,
        fail_retry: bool,
    }

    impl LlmClient for FlakyMock {
        async fn chat(
            &self,
            _system: &str,
            _user: &str,
            _response_schema: Option<&serde_json::Value>,
        ) -> Result<ChatResponse, String> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_retry && call == 1 {
                return Err("retry transport failed".to_string());
            }
            let content = if self.always_invalid || call == 0 {
                r#"{"purpose":"","suspicious_params":[],"hypotheses":[],"summary":""}"#.to_string()
            } else {
                GOOD_JSON.to_string()
            };
            Ok(ChatResponse {
                content,
                usage: Usage {
                    total_tokens: 5,
                    ..Usage::default()
                },
            })
        }
    }

    #[tokio::test]
    async fn retries_once_and_returns_validated_result() {
        let mock = FlakyMock {
            calls: AtomicUsize::new(0),
            always_invalid: false,
            fail_retry: false,
        };
        let attempt = analyze(&mock, &preview(true)).await.unwrap();
        assert!(attempt.result.is_some());
        assert_eq!(attempt.validation.attempts, 2);
        assert_eq!(attempt.usage.total_tokens, 10);
        assert!(attempt.schema_applied);
    }

    #[tokio::test]
    async fn final_validation_failure_is_auditable_without_result() {
        let mock = FlakyMock {
            calls: AtomicUsize::new(0),
            always_invalid: true,
            fail_retry: false,
        };
        let attempt = analyze(&mock, &preview(false)).await.unwrap();
        assert!(attempt.result.is_none());
        assert_eq!(attempt.validation.status, "invalid");
        assert_eq!(attempt.raw_output_hash.len(), 64);
    }

    #[tokio::test]
    async fn retry_transport_failure_keeps_first_invalid_response_auditable() {
        let mock = FlakyMock {
            calls: AtomicUsize::new(0),
            always_invalid: true,
            fail_retry: true,
        };
        let attempt = analyze(&mock, &preview(false)).await.unwrap();
        assert!(attempt.result.is_none());
        assert_eq!(attempt.validation.attempts, 1);
        assert!(attempt
            .validation
            .warnings
            .iter()
            .any(|warning| warning.contains("重试调用失败")));
        assert_eq!(attempt.raw_output_hash.len(), 64);
    }
}
