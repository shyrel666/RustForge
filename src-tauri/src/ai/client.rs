//! OpenAI 兼容 LLM 客户端：POST {base_url}/chat/completions。
//! 工程控制：120s 超时；仅对传输错误/5xx 重试一次（4xx 立即失败，不浪费额度）。
//! 抽 trait 是为了分析器可用 mock 客户端做无网络测试。

use crate::secrets::{redact_sensitive, SecretString};
use std::time::Duration;
use zeroize::Zeroizing;

/// LLM 调用的 token 用量（OpenAI 兼容接口的 usage 字段；缺失时为 0）
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Usage {
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub total_tokens: i64,
}

impl Usage {
    pub fn add(&mut self, other: &Usage) {
        self.prompt_tokens += other.prompt_tokens;
        self.completion_tokens += other.completion_tokens;
        self.total_tokens += other.total_tokens;
    }
}

/// 一次成功调用的返回：正文 + 用量
pub struct ChatResponse {
    pub content: String,
    pub usage: Usage,
}

pub trait LlmClient: Send + Sync {
    fn chat(
        &self,
        system: &str,
        user: &str,
        response_schema: Option<&serde_json::Value>,
    ) -> impl std::future::Future<Output = Result<ChatResponse, String>> + Send;
}

/// 区分可重试与不可重试错误
enum CallError {
    /// 网络错误 / 5xx：值得重试一次
    Retryable(String),
    /// 4xx（鉴权、参数、余额）：重试无意义
    Fatal(String),
}

pub struct OpenAiClient {
    http: reqwest::Client,
    base_url: String,
    api_key: SecretString,
    model: String,
}

impl OpenAiClient {
    pub fn new(base_url: &str, api_key: SecretString, model: &str) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| format!("HTTP 客户端初始化失败: {e}"))?;
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key,
            model: model.to_string(),
        })
    }

    fn request_body(
        &self,
        system: &str,
        user: &str,
        response_schema: Option<&serde_json::Value>,
    ) -> serde_json::Value {
        let mut body = serde_json::json!({
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.2,
        });
        if let Some(schema) = response_schema {
            body["response_format"] = serde_json::json!({
                "type": "json_schema",
                "json_schema": {
                    "name": "rustforge_traffic_analysis",
                    "strict": true,
                    "schema": schema,
                }
            });
        }
        body
    }

    async fn chat_once(
        &self,
        system: &str,
        user: &str,
        response_schema: Option<&serde_json::Value>,
    ) -> Result<ChatResponse, CallError> {
        let body = self.request_body(system, user, response_schema);
        let resp = self
            .http
            .post(format!("{}/chat/completions", self.base_url))
            .bearer_auth(self.api_key.expose())
            .json(&body)
            .send()
            .await
            .map_err(|error| {
                CallError::Retryable(redact_sensitive(
                    &format!("请求 LLM 失败: {error}"),
                    &[self.api_key.expose()],
                ))
            })?;

        let status = resp.status();
        let text = Zeroizing::new(resp.text().await.map_err(|error| {
            CallError::Retryable(redact_sensitive(
                &error.to_string(),
                &[self.api_key.expose()],
            ))
        })?);
        if !status.is_success() {
            // 把服务端错误信息透传给用户（如余额不足/模型名错误）
            let snippet: String = text.chars().take(300).collect();
            let msg = redact_sensitive(
                &format!("LLM API 返回 {status}: {snippet}"),
                &[self.api_key.expose()],
            );
            return Err(if status.is_server_error() {
                CallError::Retryable(msg)
            } else {
                CallError::Fatal(msg)
            });
        }
        let json: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| CallError::Fatal(format!("LLM 响应非 JSON: {e}")))?;
        let content = json["choices"][0]["message"]["content"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| {
                let snippet: String = text.chars().take(300).collect();
                CallError::Fatal(redact_sensitive(
                    &format!("LLM 响应结构异常: {snippet}"),
                    &[self.api_key.expose()],
                ))
            })?;
        let usage = Usage {
            prompt_tokens: json["usage"]["prompt_tokens"].as_i64().unwrap_or(0).max(0),
            completion_tokens: json["usage"]["completion_tokens"]
                .as_i64()
                .unwrap_or(0)
                .max(0),
            total_tokens: json["usage"]["total_tokens"].as_i64().unwrap_or(0).max(0),
        };
        Ok(ChatResponse { content, usage })
    }
}

impl LlmClient for OpenAiClient {
    async fn chat(
        &self,
        system: &str,
        user: &str,
        response_schema: Option<&serde_json::Value>,
    ) -> Result<ChatResponse, String> {
        match self.chat_once(system, user, response_schema).await {
            Ok(c) => Ok(c),
            Err(CallError::Retryable(e)) => {
                eprintln!(
                    "[ai] 首次调用失败，1s 后重试: {}",
                    redact_sensitive(&e, &[self.api_key.expose()])
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
                self.chat_once(system, user, response_schema)
                    .await
                    .map_err(|e| match e {
                        CallError::Retryable(m) | CallError::Fatal(m) => m,
                    })
            }
            Err(CallError::Fatal(e)) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_schema_is_only_added_for_explicitly_capable_calls() {
        let client = OpenAiClient::new(
            "https://example.test/v1",
            SecretString::new("secret".to_string()),
            "model",
        )
        .unwrap();
        let plain = client.request_body("system", "user", None);
        assert!(plain.get("response_format").is_none());

        let schema = serde_json::json!({"type":"object"});
        let structured = client.request_body("system", "user", Some(&schema));
        assert_eq!(structured["response_format"]["type"], "json_schema");
        assert_eq!(
            structured["response_format"]["json_schema"]["schema"],
            schema
        );
        assert!(!structured.to_string().contains("secret"));
    }
}
