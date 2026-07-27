//! 任务状态机：白名单式流转，非法流转直接拒绝。
//!
//!   todo ──→ in_progress ──→ done
//!     ↑  ↘        ↓  ↘
//!     └── blocked ←┘   (done 可重开为 todo)

pub const STATUSES: [&str; 4] = ["todo", "in_progress", "done", "blocked"];

pub fn can_transition(from: &str, to: &str) -> bool {
    if from == to || !STATUSES.contains(&to) {
        return false;
    }
    matches!(
        (from, to),
        ("todo", "in_progress")
            | ("todo", "blocked")
            | ("in_progress", "done")
            | ("in_progress", "blocked")
            | ("in_progress", "todo")
            | ("blocked", "todo")
            | ("blocked", "in_progress")
            | ("done", "todo") // 误标完成时允许重开
    )
}

/// "下一步"选择：进行中优先；否则按插入序（即 AI 规划的 DFS 序）取第一个
/// 可执行的 todo 叶子（没有未完成子任务的节点）。
/// nodes 需按 id 升序传入（id 序 = 插入序 = 规划顺序）。
pub fn next_actionable(nodes: &[crate::tree::model::TaskNode]) -> Option<i64> {
    use std::collections::HashSet;
    if let Some(n) = nodes.iter().find(|n| n.status == "in_progress") {
        return Some(n.id);
    }
    let has_unfinished_child: HashSet<i64> = nodes
        .iter()
        .filter(|n| n.status != "done")
        .filter_map(|n| n.parent_id)
        .collect();
    nodes
        .iter()
        .find(|n| n.status == "todo" && !has_unfinished_child.contains(&n.id))
        .map(|n| n.id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::model::TaskNode;

    #[test]
    fn transitions() {
        assert!(can_transition("todo", "in_progress"));
        assert!(can_transition("in_progress", "done"));
        assert!(can_transition("in_progress", "blocked"));
        assert!(can_transition("blocked", "todo"));
        assert!(can_transition("done", "todo"));
        assert!(!can_transition("todo", "done"), "不允许跳过执行直接完成");
        assert!(!can_transition("done", "in_progress"));
        assert!(!can_transition("done", "blocked"));
        assert!(!can_transition("todo", "todo"));
        assert!(!can_transition("todo", "bogus"));
    }

    fn node(id: i64, parent: Option<i64>, status: &str) -> TaskNode {
        TaskNode {
            id,
            project_id: 1,
            parent_id: parent,
            title: format!("n{id}"),
            description: String::new(),
            why: String::new(),
            how_to: String::new(),
            verify_criteria: String::new(),
            standard_references: vec![],
            status: status.into(),
            sort_order: 0,
            created_at: String::new(),
            updated_at: String::new(),
            finding_ids: vec![],
        }
    }

    #[test]
    fn next_prefers_in_progress() {
        let nodes = vec![node(1, None, "todo"), node(2, Some(1), "in_progress")];
        assert_eq!(next_actionable(&nodes), Some(2));
    }

    #[test]
    fn next_picks_first_todo_leaf() {
        // 1 有未完成子任务 → 不可执行；2 是第一个 todo 叶子
        let nodes = vec![
            node(1, None, "todo"),
            node(2, Some(1), "todo"),
            node(3, Some(1), "done"),
            node(4, None, "todo"),
        ];
        assert_eq!(next_actionable(&nodes), Some(2));
    }

    #[test]
    fn next_none_when_all_done() {
        let nodes = vec![node(1, None, "done"), node(2, Some(1), "done")];
        assert_eq!(next_actionable(&nodes), None);
    }
}
