use serde::{Deserialize, Serialize};

/// 项目：一个授权渗透目标
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: i64,
    pub name: String,
    pub target_host: String,
    /// 拦截白名单（域名/IP，支持 *.example.com 通配）
    pub scope: Vec<String>,
    pub created_at: String,
}

/// 流量列表行（也是 "traffic:new" 事件的载荷），不含 body
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficSummary {
    pub id: i64,
    pub project_id: i64,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub url: String,
    pub status: Option<u16>,
    pub content_type: Option<String>,
    pub req_size: i64,
    pub resp_size: i64,
    pub duration_ms: i64,
    /// 被动规则命中标签（如 ["SQL报错", "堆栈泄露"]）
    #[serde(default)]
    pub rule_tags: Vec<String>,
    pub created_at: String,
}

/// 流量详情（含头部与 body），body 按是否 UTF-8 文本二选一返回
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficDetail {
    #[serde(flatten)]
    pub summary: TrafficSummary,
    pub req_headers: String,
    /// UTF-8 文本时返回原文
    pub req_body_text: Option<String>,
    /// 二进制/乱码时返回 base64
    pub req_body_base64: Option<String>,
    pub resp_headers: Option<String>,
    pub resp_body_text: Option<String>,
    pub resp_body_base64: Option<String>,
}

/// 漏洞发现（来源：AI 分析 或 被动规则）。status 默认 pending（待人工验证）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: i64,
    pub project_id: i64,
    pub traffic_id: Option<i64>,
    /// 'ai' | 'rule'
    pub source: String,
    pub title: String,
    pub vuln_type: String,
    pub owasp: String,
    pub cwe: String,
    /// critical/high/medium/low/info
    pub severity: String,
    /// 0-100
    pub confidence: i64,
    pub reasoning: String,
    pub verify_steps: String,
    /// pending/confirmed/rejected
    pub status: String,
    pub created_at: String,
}

/// AI 对单条流量的结构化分析结果（prompts 里约定 JSON schema）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnHypothesis {
    /// 漏洞类型，如 "SQL 注入"
    pub vuln_type: String,
    /// 可疑参数/位置
    pub param: String,
    pub owasp: String,
    pub cwe: String,
    pub severity: String,
    /// 0-100，AI 自评（必须人工复核）
    pub confidence: u8,
    /// 为什么怀疑：观察到的证据链
    pub reasoning: String,
    /// 手动验证步骤（Markdown，人在回路：AI 不自动发包）
    pub verify_steps: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnalysisResult {
    /// 接口用途（一句话）
    pub purpose: String,
    /// 值得关注的参数清单
    pub suspicious_params: Vec<String>,
    pub hypotheses: Vec<VulnHypothesis>,
    /// 总体结论
    pub summary: String,
}
