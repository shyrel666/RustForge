use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceSourceType {
    Traffic,
    AnalysisRun,
    ReplayRun,
}

impl EvidenceSourceType {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "traffic" => Ok(Self::Traffic),
            "analysis_run" => Ok(Self::AnalysisRun),
            "replay_run" => Ok(Self::ReplayRun),
            _ => Err(format!("不支持的 Evidence 来源类型: {value}")),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Traffic => "traffic",
            Self::AnalysisRun => "analysis_run",
            Self::ReplayRun => "replay_run",
        }
    }
}

impl fmt::Display for EvidenceSourceType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// 一条可独立于原始来源长期保留的脱敏证据快照。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Evidence {
    pub id: i64,
    pub project_id: i64,
    pub source_type: String,
    pub source_id: i64,
    pub source_available: bool,
    pub observation: String,
    pub redacted_snapshot: serde_json::Value,
    pub content_hash: String,
    pub qualifies_for_confirmation: bool,
    pub created_by: String,
    pub created_at: String,
    pub linked_at: String,
    pub accepted: bool,
    pub acceptance_note: String,
    pub accepted_by: Option<String>,
    pub accepted_at: Option<String>,
    pub acceptance_kind: String,
    pub verification_id: Option<i64>,
}

/// Finding 状态、人工判断和备注的不可变事件。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingEvent {
    pub id: i64,
    pub finding_id: i64,
    pub event_type: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub reason: String,
    pub actor: String,
    pub created_at: String,
}
