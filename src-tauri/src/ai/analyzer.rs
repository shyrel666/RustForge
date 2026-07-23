//! 请求分析器：流量详情 → 提示词 → LLM → 结构化 AnalysisResult。
//! 误报素养红线：解析失败重试一次；confidence 强制钳到 0-100；
//! 每条假设必须带 reasoning 和 verify_steps，空值降级为无假设。

use super::client::{ChatResponse, LlmClient, Usage};
use super::json::parse_llm_json;
use super::prompts;
use crate::storage::models::{AnalysisResult, TrafficDetail};

const SYSTEM_PROMPT: &str = "你是渗透测试教学助手，服务对象是已获授权的初学者。\
你只做分析和讲解，不生成可直接运行的攻击代码。所有结论必须诚实标注置信度。";

/// 执行一次完整分析。返回 (结构化结果, 累计 token 用量)。
pub async fn analyze(
    client: &impl LlmClient,
    template: &str,
    detail: &TrafficDetail,
) -> Result<(AnalysisResult, Usage), String> {
    let ctx = prompts::build_ctx(detail, &detail.summary.rule_tags);
    let prompt = prompts::render(template, &ctx);

    let mut usage = Usage::default();
    let first = client.chat(SYSTEM_PROMPT, &prompt).await?;
    usage.add(&first.usage);
    match parse_result(&first.content) {
        Ok(r) => Ok((r, usage)),
        Err(first_err) => {
            // 解析失败重试一次：明确要求只输出 JSON
            eprintln!("[ai] 首次解析失败，重试: {first_err}");
            let retry_prompt =
                format!("{prompt}\n\n【系统提醒】你上一次的输出不是合法 JSON。这次请只输出 JSON 对象本身，第一个字符就是 {{，最后一个字符就是 }}。");
            let second = client.chat(SYSTEM_PROMPT, &retry_prompt).await?;
            usage.add(&second.usage);
            let r = parse_result(&second.content)
                .map_err(|e| format!("AI 输出两次都不是合法 JSON，放弃: {e}"))?;
            Ok((r, usage))
        }
    }
}

/// 从模型输出里提取并校验 JSON。容错：剥 Markdown 围栏、截取首个 JSON 片段。
pub fn parse_result(raw: &str) -> Result<AnalysisResult, String> {
    let mut result: AnalysisResult = parse_llm_json(raw)?;

    // 校验与清洗：confidence 钳位；缺 reasoning/verify_steps 的假设降级剔除
    for h in &mut result.hypotheses {
        h.confidence = h.confidence.min(100);
    }
    result.hypotheses.retain(|h| {
        !h.vuln_type.trim().is_empty()
            && !h.reasoning.trim().is_empty()
            && !h.verify_steps.trim().is_empty()
    });
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const GOOD_JSON: &str = r#"{
        "purpose": "登录接口",
        "suspicious_params": ["username"],
        "hypotheses": [{
            "vuln_type": "SQL 注入",
            "param": "username",
            "owasp": "A03:2021 Injection",
            "cwe": "CWE-89",
            "severity": "high",
            "confidence": 120,
            "reasoning": "单引号触发 500",
            "verify_steps": "1. 重放\n2. 观察"
        }],
        "summary": "值得深入"
    }"#;

    #[test]
    fn parses_clean_json() {
        let r = parse_result(GOOD_JSON).unwrap();
        assert_eq!(r.purpose, "登录接口");
        // 钳位到 100
        assert_eq!(r.hypotheses[0].confidence, 100);
    }

    #[test]
    fn parses_fenced_and_noisy_json() {
        let fenced = format!("好的，分析如下：\n```json\n{GOOD_JSON}\n```\n希望对你有帮助");
        let r = parse_result(&fenced).unwrap();
        assert_eq!(r.hypotheses.len(), 1);
    }

    #[test]
    fn drops_hypothesis_without_verify_steps() {
        // GOOD_JSON 是 raw string，\n 在源文本里是字面的反斜杠+n
        let bad = GOOD_JSON.replace("1. 重放\\n2. 观察", "  ");
        let r = parse_result(&bad).unwrap();
        assert!(r.hypotheses.is_empty(), "缺验证步骤的假设必须被剔除（误报素养）");
    }

    struct FlakyMock {
        calls: AtomicUsize,
    }
    impl LlmClient for FlakyMock {
        async fn chat(&self, _s: &str, _u: &str) -> Result<ChatResponse, String> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            let content = if n == 0 {
                "我不会输出 JSON，抱歉".to_string()
            } else {
                GOOD_JSON.to_string()
            };
            Ok(ChatResponse { content, usage: Usage::default() })
        }
    }

    #[tokio::test]
    async fn retries_once_on_parse_failure() {
        let detail = TrafficDetail {
            summary: crate::storage::models::TrafficSummary {
                id: 1, project_id: 1, method: "POST".into(), scheme: "https".into(),
                host: "t.cn".into(), port: 443, path: "/login".into(),
                url: "https://t.cn/login".into(), status: Some(200),
                content_type: Some("application/json".into()),
                req_size: 10, resp_size: 10, duration_ms: 1,
                rule_tags: vec![], created_at: String::new(),
            },
            req_headers: "{}".into(),
            req_body_text: Some("{}".into()),
            req_body_base64: None,
            resp_headers: Some("{}".into()),
            resp_body_text: Some("ok".into()),
            resp_body_base64: None,
        };
        let mock = FlakyMock { calls: AtomicUsize::new(0) };
        let (result, _) = analyze(&mock, "{REQUEST}\n{RESPONSE}", &detail).await.unwrap();
        assert_eq!(result.purpose, "登录接口");
        assert_eq!(mock.calls.load(Ordering::SeqCst), 2, "应在解析失败后恰好重试一次");
    }
}
