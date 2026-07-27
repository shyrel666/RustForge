use crate::knowledge::StandardReference;
use serde::{Deserialize, Serialize};

/// 项目：一个授权渗透目标
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: i64,
    pub name: String,
    pub target_host: String,
    /// 后端规范化后的 host-only 白名单（ASCII 域名/IP，支持 *.example.com 通配）
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
    /// Bytes observed on the HTTP body stream, before content decoding.
    pub req_wire_size: i64,
    pub resp_wire_size: i64,
    /// Bytes retained in req_body / resp_body after bounded decoding.
    pub req_captured_size: i64,
    pub resp_captured_size: i64,
    /// True when the wire stream, decoded output, or stream completion was incomplete.
    pub req_truncated: bool,
    pub resp_truncated: bool,
    /// Stable body_capture status such as identity_text, decoded_text, or decode_failed.
    pub req_decode_status: String,
    pub resp_decode_status: String,
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
    /// Version-pinned references; titles are derived from validated offline packs.
    #[serde(default)]
    pub standard_references: Vec<StandardReference>,
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
#[serde(deny_unknown_fields)]
pub struct VulnHypothesis {
    /// 漏洞类型，如 "SQL 注入"
    pub vuln_type: String,
    /// 可疑参数/位置
    pub param: String,
    /// Exact, version-pinned standard references validated by the backend.
    #[serde(default)]
    pub standard_references: Vec<StandardReference>,
    pub severity: String,
    /// 0-100，AI 自评（必须人工复核）
    pub confidence: u8,
    /// 为什么怀疑：观察到的证据链
    pub reasoning: String,
    /// 手动验证步骤（Markdown，人在回路：AI 不自动发包）
    pub verify_steps: String,
    /// 必须引用本次实际发送上下文中的稳定字段标识。
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    /// 后端 grounding 校验结果；模型输入中的同名字段会被忽略。
    #[serde(default, skip_deserializing)]
    pub grounding_status: String,
    /// 后端添加的降级原因；模型不能自行声明通过校验。
    #[serde(default, skip_deserializing)]
    pub validation_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AnalysisResult {
    /// 接口用途（一句话）
    pub purpose: String,
    /// 值得关注的参数清单
    pub suspicious_params: Vec<String>,
    pub hypotheses: Vec<VulnHypothesis>,
    /// 总体结论
    pub summary: String,
    /// 成功落库后关联的审计运行；模型输入中的同名字段会被忽略。
    #[serde(default, skip_deserializing)]
    pub analysis_run_id: Option<i64>,
}
