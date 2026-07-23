//! 被动规则引擎：对每条落库流量做本地轻量匹配（regex/启发式），
//! 产出两类结果：① traffic.rule_tags 打标（列表直观提示）② 中危以上命中
//! 自动生成 source='rule' 的 Finding（默认"待验证"，需人工确认）。
//! 全部本地运行，不外发任何数据——这也是 AI 分析前的初筛。

use regex::Regex;
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// 规则的匹配目标（对哪一段流量做正则）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Url,
    ReqHeaders,
    ReqBody,
    RespHeaders,
    RespBody,
}

/// 单条规则。hit 判定：pattern 命中任一 target 文本 且 must_absent 未命中同一文本。
pub struct Rule {
    pub id: &'static str,
    /// 规则名（也是 Finding 标题）
    pub name: &'static str,
    /// 命中说明（写入 Finding.reasoning）
    pub description: &'static str,
    /// 人工验证提示（写入 Finding.verify_steps）
    pub verify_hint: &'static str,
    pub severity: Severity,
    /// 列表打标文本
    pub tag: &'static str,
    /// Finding 的漏洞分类信息
    pub vuln_type: &'static str,
    pub owasp: &'static str,
    pub cwe: &'static str,
    /// 规则置信度（启发式不可能 100%，诚实标注）
    pub confidence: u8,
    pub targets: &'static [Target],
    pub pattern: Regex,
    /// 反向条件：文本里不能出现它（如 Set-Cookie 缺少 HttpOnly）
    pub must_absent: Option<Regex>,
}

/// 引擎的输入视图：借用过来的流量片段（headers 是 JSON 字符串，body 原始字节）
pub struct TrafficView<'a> {
    pub url: &'a str,
    pub req_headers: &'a str,
    pub resp_headers: Option<&'a str>,
    pub req_body: &'a [u8],
    pub resp_body: Option<&'a [u8]>,
}

/// 命中结果（携带定位信息，便于 UI 展示）
pub struct RuleHit {
    pub rule: &'static Rule,
    /// 命中的目标段（如 "resp_body"）
    pub location: &'static str,
}

static RULES: LazyLock<Vec<Rule>> = LazyLock::new(super::builtin::rules);

/// 对一条流量跑全部规则，返回命中列表
pub fn evaluate(view: &TrafficView) -> Vec<RuleHit> {
    let req_body = String::from_utf8_lossy(view.req_body);
    let resp_body = view.resp_body.map(String::from_utf8_lossy);
    let empty = String::new();
    let resp_body = resp_body.as_deref().unwrap_or(&empty);

    let mut hits = Vec::new();
    for rule in RULES.iter() {
        for &target in rule.targets {
            let (text, location): (&str, &'static str) = match target {
                Target::Url => (view.url, "url"),
                Target::ReqHeaders => (view.req_headers, "req_headers"),
                Target::ReqBody => (&req_body, "req_body"),
                Target::RespHeaders => (view.resp_headers.unwrap_or(""), "resp_headers"),
                Target::RespBody => (resp_body, "resp_body"),
            };
            if text.is_empty() {
                continue;
            }
            if rule.pattern.is_match(text)
                && rule.must_absent.as_ref().is_none_or(|neg| !neg.is_match(text))
            {
                hits.push(RuleHit { rule, location });
                break; // 同一规则命中一次即可
            }
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view<'a>(url: &'a str, req_headers: &'a str, req_body: &'a [u8], resp_headers: Option<&'a str>, resp_body: Option<&'a [u8]>) -> TrafficView<'a> {
        TrafficView { url, req_headers, req_body, resp_headers, resp_body }
    }

    fn hit_ids(v: &TrafficView) -> Vec<&'static str> {
        evaluate(v).iter().map(|h| h.rule.id).collect()
    }

    #[test]
    fn hits_sql_error_and_stack() {
        let v = view(
            "https://t.cn/user?id=1",
            "{}",
            b"",
            Some(r#"{"content-type":"text/html"}"#),
            Some(b"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"),
        );
        assert!(hit_ids(&v).contains(&"sql-error-leak"));
    }

    #[test]
    fn hits_jwt_and_sensitive_param() {
        let v = view(
            "https://t.cn/api?token=abc123",
            r#"{"authorization":"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}"#,
            b"",
            None,
            None,
        );
        let ids = hit_ids(&v);
        assert!(ids.contains(&"sensitive-param-in-url"));
        assert!(ids.contains(&"jwt-exposed"));
    }

    #[test]
    fn hits_cookie_missing_flags() {
        let v = view(
            "https://t.cn/login",
            "{}",
            b"",
            Some(r#"{"set-cookie":"session=abc; Path=/"}"#),
            None,
        );
        let ids = hit_ids(&v);
        assert!(ids.contains(&"cookie-no-httponly"));
        assert!(ids.contains(&"cookie-no-secure"));
    }

    #[test]
    fn benign_passes() {
        let v = view(
            "https://t.cn/static/app.css",
            r#"{"accept":"text/css"}"#,
            b"",
            Some(r#"{"content-type":"text/css","set-cookie":"s=1; Secure; HttpOnly"}"#),
            Some(b"body { color: red }"),
        );
        let ids = hit_ids(&v);
        assert!(!ids.contains(&"cookie-no-httponly"));
        assert!(!ids.contains(&"sql-error-leak"));
    }
}
