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
    /// 首次命中的流量。删除该流量后置空，Finding 本身保留。
    pub traffic_id: Option<i64>,
    /// AI 假设的审计运行；规则 Finding 为空。删除原 traffic 不影响该运行。
    pub analysis_run_id: Option<i64>,
    /// 'ai' | 'rule'
    pub source: String,
    /// 'ai' | 'passive_rule' | 'safe_verifier'
    pub producer: String,
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
    /// 人工复核备注；与模型置信度、严重度分别维护。
    pub analyst_notes: String,
    /// 规则命中的稳定身份（项目 + 规则 + 接口 + 字段）。AI Finding 暂为空。
    pub fingerprint: Option<String>,
    /// 同一身份累计关联过的不同流量数；尚未删除的条目见 `finding_traffic`。
    pub occurrences: i64,
    pub last_seen_at: String,
    pub created_at: String,
    pub updated_at: String,
}

impl Finding {
    /// `from_row` 期望的列顺序。所有查询都用它，避免各处 SELECT 漂移。
    pub const COLUMNS: &'static str =
        "id, project_id, traffic_id, source, title, vuln_type, standard_references, \
         severity, confidence, reasoning, verify_steps, status, fingerprint, \
         occurrences, last_seen_at, created_at, analysis_run_id, analyst_notes, updated_at, producer";

    pub fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        let raw_references: String = row.get(6)?;
        let standard_references =
            crate::knowledge::references_from_json(&raw_references).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    6,
                    rusqlite::types::Type::Text,
                    Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
                )
            })?;
        Ok(Self {
            id: row.get(0)?,
            project_id: row.get(1)?,
            traffic_id: row.get(2)?,
            analysis_run_id: row.get(16)?,
            source: row.get(3)?,
            producer: row.get(19)?,
            title: row.get(4)?,
            vuln_type: row.get(5)?,
            standard_references,
            severity: row.get(7)?,
            confidence: row.get(8)?,
            reasoning: row.get(9)?,
            verify_steps: row.get(10)?,
            status: row.get(11)?,
            analyst_notes: row.get(17)?,
            fingerprint: row.get(12)?,
            occurrences: row.get(13)?,
            last_seen_at: row.get(14)?,
            created_at: row.get(15)?,
            updated_at: row.get(18)?,
        })
    }
}

/// 后台规则求值补写标签后推给前端的增量（事件 "traffic:tags"）。
/// 流量本身在规则跑完之前就已经落库并推过 "traffic:new"。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficTagsUpdate {
    pub id: i64,
    pub project_id: i64,
    pub rule_tags: Vec<String>,
}

/// Finding 关联到的一条流量，用于展示"同一问题命中过哪些请求"。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingTrafficRef {
    pub traffic_id: i64,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub first_seen_at: String,
}

/// 一次规则命中的可追溯快照；规则补丁版本不会覆盖旧 Finding 的初始说明。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingRuleHit {
    pub id: i64,
    pub finding_id: i64,
    pub evaluation_id: i64,
    pub traffic_id: i64,
    pub pack_id: String,
    pub pack_version: String,
    pub rule_id: String,
    pub rule_version: String,
    pub field_path: String,
    pub evidence: String,
    pub confidence: i64,
    pub incomplete_evidence: bool,
    pub hit_fingerprint: String,
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
