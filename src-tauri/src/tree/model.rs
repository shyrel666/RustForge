use crate::knowledge::StandardReference;
use serde::{Deserialize, Serialize};

/// 任务树节点：一次渗透过程的一个步骤。
/// 四个文本字段对应教学法四问：做什么/为什么/怎么做/怎样算完成。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskNode {
    pub id: i64,
    pub project_id: i64,
    pub parent_id: Option<i64>,
    pub title: String,
    /// 做什么
    pub description: String,
    /// 为什么做这步（"为什么"交互直接展示它，不消耗 token）
    pub why: String,
    /// 怎么做（具体操作指引）
    pub how_to: String,
    /// 完成判定标准
    pub verify_criteria: String,
    /// Version-pinned references shared with Finding and report models.
    #[serde(default)]
    pub standard_references: Vec<StandardReference>,
    /// todo / in_progress / done / blocked
    pub status: String,
    pub sort_order: i64,
    pub created_at: String,
    pub updated_at: String,
    /// 关联的 Finding id 列表（双向关联，查询时填充）
    #[serde(default)]
    pub finding_ids: Vec<i64>,
}

/// AI 规划器产出的嵌套节点（插入数据库前的中间形态）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedNode {
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub why: String,
    #[serde(default)]
    pub how_to: String,
    #[serde(default)]
    pub verify_criteria: String,
    #[serde(default)]
    pub standard_references: Vec<StandardReference>,
    #[serde(default)]
    pub children: Vec<PlannedNode>,
    /// 关联的已有 Finding id（AI 给出，插入前校验存在性）
    #[serde(default)]
    pub finding_ids: Vec<i64>,
}

/// AI 生成整棵树时的顶层结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedTree {
    pub phases: Vec<PlannedNode>,
}
