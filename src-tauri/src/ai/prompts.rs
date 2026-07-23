//! 提示词模板系统：内置中文模板 + 占位符渲染。
//! 模板可在设置页自定义，存 settings 表；占位符：
//! {METHOD} {URL} {HOST} {STATUS} {REQUEST} {RESPONSE} {RULE_TAGS}
//! {REQUEST}/{RESPONSE} 已做去敏（凭据类头打码）与截断（防爆 token）。

use crate::storage::models::TrafficDetail;

/// settings 表里的自定义模板 key
pub const ANALYZE_TEMPLATE_KEY: &str = "prompt_analyze";

/// 单方向 body 注入 prompt 的最大字符数
pub const MAX_BODY_CHARS: usize = 6000;

/// 内置默认模板（用户可在设置页覆盖）
pub const DEFAULT_ANALYZE_TEMPLATE: &str = r#"你是一名资深渗透测试工程师，正在指导一名初学者分析一个已获授权的目标。
下面是一次 HTTP 请求的完整记录（已脱敏截断），被动扫描器命中的标签供参考。

## 请求概要
- 方法: {METHOD}
- URL: {URL}
- Host: {HOST}
- 响应状态: {STATUS}
- 被动规则标签: {RULE_TAGS}

## 原始请求
```
{REQUEST}
```

## 原始响应
```
{RESPONSE}
```

## 请完成
1. 用一句话说明这个接口的用途（根据路径、参数、响应推断）。
2. 列出值得关注的参数（名字 + 为什么可疑）。
3. 给出 0~4 个漏洞假设，每个包含：
   - vuln_type: 漏洞类型（如 "SQL 注入"、"IDOR 水平越权"）
   - param: 可疑参数/位置
   - owasp: 对应 OWASP Top 10 2021 条目（如 "A03:2021 Injection"）
   - cwe: 对应 CWE 编号（如 "CWE-89"）
   - severity: critical/high/medium/low/info
   - confidence: 0-100 的整数，诚实评估（证据不足就给低分）
   - reasoning: 你为什么怀疑它——引用请求/响应中的具体证据
   - verify_steps: 初学者可手工执行的验证步骤（Markdown，3~6 步，
     只允许"人工重放/观察"类操作，不要给出可直接运行的攻击脚本）
4. summary: 一段话总结这条流量的测试价值与建议的下一步。

## 硬性要求
- 只输出一个合法 JSON 对象，不要输出任何其他文字、不要 Markdown 代码围栏。
- JSON 结构: {"purpose": string, "suspicious_params": string[],
  "hypotheses": [{"vuln_type","param","owasp","cwe","severity","confidence",
  "reasoning","verify_steps"}], "summary": string}
- 没有可疑点时 hypotheses 返回空数组，并在 summary 说明理由。
- 这是已获授权的测试目标，你的角色是分析讲解，不是发起攻击。"#;

/// 渲染上下文：从流量详情构造（去敏 + 截断后）
pub struct PromptCtx {
    pub method: String,
    pub url: String,
    pub host: String,
    pub status: String,
    pub request: String,
    pub response: String,
    pub rule_tags: String,
}

/// 占位符替换
pub fn render(template: &str, ctx: &PromptCtx) -> String {
    template
        .replace("{METHOD}", &ctx.method)
        .replace("{URL}", &ctx.url)
        .replace("{HOST}", &ctx.host)
        .replace("{STATUS}", &ctx.status)
        .replace("{REQUEST}", &ctx.request)
        .replace("{RESPONSE}", &ctx.response)
        .replace("{RULE_TAGS}", &ctx.rule_tags)
}

/// 凭据类请求头：发给 LLM 前打码（去敏红线：流量最小化外发）
const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
];

/// headers JSON → 去敏后的 "k: v" 多行文本
pub fn redact_headers(headers_json: &str) -> String {
    let Ok(obj) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(headers_json)
    else {
        return headers_json.to_string();
    };
    obj.iter()
        .map(|(k, v)| {
            let key = k.to_lowercase();
            if SENSITIVE_HEADERS.contains(&key.as_str()) {
                format!("{k}: ***（已脱敏）")
            } else {
                format!("{k}: {}", v.as_str().unwrap_or_default())
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() > max {
        let cut: String = s.chars().take(max).collect();
        format!("{cut}\n…[已截断，原始长度 {} 字符]", s.chars().count())
    } else {
        s.to_string()
    }
}

/// 从流量详情构造渲染上下文（去敏 + 截断在此发生）
pub fn build_ctx(detail: &TrafficDetail, rule_tags: &[String]) -> PromptCtx {
    let s = &detail.summary;
    let req_head = redact_headers(&detail.req_headers);
    let req_body = detail.req_body_text.as_deref().unwrap_or("[二进制内容]");
    let request = format!(
        "{} {} HTTP/1.1\n{}\n\n{}",
        s.method,
        s.path,
        req_head,
        truncate_chars(req_body, MAX_BODY_CHARS)
    );

    let response = match &detail.resp_headers {
        Some(h) => format!(
            "HTTP/1.1 {}\n{}\n\n{}",
            s.status.map(|c| c.to_string()).unwrap_or_default(),
            redact_headers(h),
            truncate_chars(
                detail.resp_body_text.as_deref().unwrap_or("[二进制内容]"),
                MAX_BODY_CHARS
            )
        ),
        None => "[未收到响应]".to_string(),
    };

    PromptCtx {
        method: s.method.clone(),
        url: s.url.clone(),
        host: s.host.clone(),
        status: s
            .status
            .map(|c| c.to_string())
            .unwrap_or_else(|| "无响应".into()),
        request,
        response,
        rule_tags: if rule_tags.is_empty() {
            "无".into()
        } else {
            rule_tags.join("、")
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_credential_headers() {
        let h = r#"{"authorization":"Bearer sk-123456","cookie":"sid=abc","content-type":"application/json"}"#;
        let out = redact_headers(h);
        assert!(out.contains("authorization: ***"));
        assert!(out.contains("cookie: ***"));
        assert!(out.contains("content-type: application/json"));
        assert!(!out.contains("sk-123456"));
        assert!(!out.contains("sid=abc"));
    }

    #[test]
    fn truncates_long_body() {
        let long = "a".repeat(7000);
        let out = truncate_chars(&long, MAX_BODY_CHARS);
        assert!(out.contains("已截断"));
        assert!(out.chars().count() < 7000);
    }

    #[test]
    fn renders_placeholders() {
        let ctx = PromptCtx {
            method: "GET".into(),
            url: "https://t.cn/a".into(),
            host: "t.cn".into(),
            status: "200".into(),
            request: "REQ".into(),
            response: "RESP".into(),
            rule_tags: "JWT".into(),
        };
        let out = render("{METHOD} {URL} {STATUS} {REQUEST} {RESPONSE} {RULE_TAGS}", &ctx);
        assert_eq!(out, "GET https://t.cn/a 200 REQ RESP JWT");
    }
}
