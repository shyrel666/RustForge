//! 渗透任务树：模型 + 状态机。树结构存在 task_nodes 表（Phase 0 建），
//! 与 Finding 的双向关联用 task_findings 链接表。

pub mod model;
pub mod state;
