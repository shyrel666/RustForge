use crate::knowledge::StandardReference;
use serde::{Deserialize, Serialize};

/// 当前测试计划中的规范化节点。AI 只提出候选字段；status、人工锁定字段和
/// Evidence 关系始终由后端在合并时保护。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaskNode {
    pub id: i64,
    pub project_id: i64,
    pub parent_id: Option<i64>,
    pub stable_key: String,
    /// hypothesis / test / decision / manual_note
    pub node_type: String,
    pub title: String,
    /// 做什么
    pub description: String,
    /// 为什么做这步
    pub why: String,
    /// 怎么做
    pub how_to: String,
    /// 完成判定标准
    pub verify_criteria: String,
    /// 数字越小优先级越高，0 为最高。
    pub priority: i64,
    pub required_role: String,
    pub required_session: String,
    pub expected_observation: String,
    pub actual_observation: String,
    pub blocker_reason: String,
    #[serde(default)]
    pub standard_references: Vec<StandardReference>,
    /// ai / rule / manual
    pub source: String,
    /// 人工锁定、AI 不得覆盖的字段名。
    #[serde(default)]
    pub locked_fields: Vec<String>,
    /// todo / in_progress / done / blocked / skipped / not_applicable
    pub status: String,
    pub sort_order: i64,
    pub archived: bool,
    pub archived_at: Option<String>,
    pub created_revision: i64,
    pub updated_revision: i64,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub finding_ids: Vec<i64>,
    #[serde(default)]
    pub prerequisite_ids: Vec<i64>,
    #[serde(default)]
    pub evidence_ids: Vec<i64>,
    /// 用于“下一步”的稳定风险排序：critical=4 ... info=0。
    #[serde(default)]
    pub risk_rank: i64,
}

impl TaskNode {
    pub fn has_evidence(&self) -> bool {
        !self.evidence_ids.is_empty()
    }
}

/// AI 规划器产出的嵌套节点。stable_key 用于跨 revision 对齐；初次生成时
/// 缺失的 key 会由后端根据父路径和内容生成，而不是相信模型提供数据库 id。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedNode {
    #[serde(default)]
    pub stable_key: String,
    #[serde(default = "default_node_type")]
    pub node_type: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub why: String,
    #[serde(default)]
    pub how_to: String,
    #[serde(default)]
    pub verify_criteria: String,
    #[serde(default = "default_priority")]
    pub priority: i64,
    #[serde(default)]
    pub required_role: String,
    #[serde(default)]
    pub required_session: String,
    #[serde(default)]
    pub expected_observation: String,
    #[serde(default)]
    pub standard_references: Vec<StandardReference>,
    #[serde(default)]
    pub prerequisite_keys: Vec<String>,
    #[serde(default)]
    pub children: Vec<PlannedNode>,
    #[serde(default)]
    pub finding_ids: Vec<i64>,
}

impl Default for PlannedNode {
    fn default() -> Self {
        Self {
            stable_key: String::new(),
            node_type: default_node_type(),
            title: String::new(),
            description: String::new(),
            why: String::new(),
            how_to: String::new(),
            verify_criteria: String::new(),
            priority: default_priority(),
            required_role: String::new(),
            required_session: String::new(),
            expected_observation: String::new(),
            standard_references: Vec::new(),
            prerequisite_keys: Vec::new(),
            children: Vec::new(),
            finding_ids: Vec::new(),
        }
    }
}

fn default_node_type() -> String {
    "test".to_string()
}

fn default_priority() -> i64 {
    50
}

/// AI 生成整份测试计划时的顶层结构。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedTree {
    pub phases: Vec<PlannedNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestPlan {
    pub project_id: i64,
    pub revision: i64,
    pub needs_update: bool,
    pub update_reason: String,
    pub last_applied_proposal_id: Option<i64>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskPlanDiffItem {
    pub stable_key: String,
    pub node_id: Option<i64>,
    pub title: String,
    #[serde(default)]
    pub changed_fields: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskPlanDiff {
    #[serde(default)]
    pub additions: Vec<TaskPlanDiffItem>,
    #[serde(default)]
    pub updates: Vec<TaskPlanDiffItem>,
    #[serde(default)]
    pub preserved: Vec<TaskPlanDiffItem>,
    #[serde(default)]
    pub archives: Vec<TaskPlanDiffItem>,
}

impl TaskPlanDiff {
    pub fn changed_count(&self) -> usize {
        self.additions.len() + self.updates.len() + self.archives.len()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskPlanProposal {
    pub id: i64,
    pub project_id: i64,
    pub proposal_key: String,
    /// generate / expand / alternative
    pub operation: String,
    pub target_node_id: Option<i64>,
    pub base_revision: i64,
    pub analysis_run_id: Option<i64>,
    /// pending / applied / rejected / superseded
    pub status: String,
    pub diff: TaskPlanDiff,
    pub created_at: String,
    pub applied_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskPlanApplyResult {
    pub proposal_id: i64,
    pub revision: i64,
    pub applied: bool,
    pub diff: TaskPlanDiff,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskPlanEvent {
    pub id: i64,
    pub project_id: i64,
    pub revision: i64,
    pub event_type: String,
    pub proposal_id: Option<i64>,
    pub node_id: Option<i64>,
    pub details: serde_json::Value,
    pub actor: String,
    pub created_at: String,
}

/// 人工创建节点的完整输入。人工输入字段默认全部锁定。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTaskNodeInput {
    pub project_id: i64,
    pub parent_id: Option<i64>,
    pub node_type: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub why: String,
    #[serde(default)]
    pub how_to: String,
    #[serde(default)]
    pub verify_criteria: String,
    #[serde(default = "default_priority")]
    pub priority: i64,
    #[serde(default)]
    pub required_role: String,
    #[serde(default)]
    pub required_session: String,
    #[serde(default)]
    pub expected_observation: String,
    #[serde(default)]
    pub actual_observation: String,
    #[serde(default)]
    pub prerequisite_ids: Vec<i64>,
}

/// 人工编辑后的节点快照。后端会把 locked_fields 作为 AI 合并边界持久化，
/// status 仍只能通过专用状态命令更新。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateTaskNodeInput {
    pub node_id: i64,
    pub node_type: String,
    pub title: String,
    pub description: String,
    pub why: String,
    pub how_to: String,
    pub verify_criteria: String,
    pub priority: i64,
    pub required_role: String,
    pub required_session: String,
    pub expected_observation: String,
    pub actual_observation: String,
    #[serde(default)]
    pub prerequisite_ids: Vec<i64>,
    #[serde(default)]
    pub locked_fields: Vec<String>,
}
