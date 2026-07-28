//! 版本化测试计划的状态与结构约束。

use crate::tree::model::TaskNode;
use std::collections::{HashMap, HashSet};

pub const STATUSES: [&str; 6] = [
    "todo",
    "in_progress",
    "done",
    "blocked",
    "skipped",
    "not_applicable",
];
pub const NODE_TYPES: [&str; 4] = ["hypothesis", "test", "decision", "manual_note"];
pub const EDITABLE_FIELDS: [&str; 16] = [
    "parent",
    "node_type",
    "title",
    "description",
    "why",
    "how_to",
    "verify_criteria",
    "priority",
    "required_role",
    "required_session",
    "expected_observation",
    "actual_observation",
    "prerequisites",
    "standard_references",
    "findings",
    "sort_order",
];
pub const MAX_TREE_DEPTH: usize = 3;
pub const MAX_TREE_NODES: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeShape {
    pub node_count: usize,
    pub max_depth: usize,
}

/// 对任意嵌套森林使用同一套深度/节点预算。`root_depth` 是传入首层节点
/// 在完整项目计划中的实际深度。
pub fn validate_forest<T, Children>(
    roots: &[T],
    root_depth: usize,
    children: Children,
) -> Result<TreeShape, String>
where
    Children: Copy + for<'node> Fn(&'node T) -> &'node [T],
{
    if root_depth == 0 {
        return Err("测试计划深度必须从 1 开始计算".to_string());
    }

    fn walk<T, Children>(
        nodes: &[T],
        depth: usize,
        children: Children,
        shape: &mut TreeShape,
    ) -> Result<(), String>
    where
        Children: Copy + for<'node> Fn(&'node T) -> &'node [T],
    {
        if !nodes.is_empty() && depth > MAX_TREE_DEPTH {
            return Err(format!("测试计划超过 {MAX_TREE_DEPTH} 层"));
        }
        for node in nodes {
            shape.node_count += 1;
            if shape.node_count > MAX_TREE_NODES {
                return Err(format!("测试计划超过 {MAX_TREE_NODES} 个节点"));
            }
            shape.max_depth = shape.max_depth.max(depth);
            walk(children(node), depth + 1, children, shape)?;
        }
        Ok(())
    }

    let mut shape = TreeShape {
        node_count: 0,
        max_depth: 0,
    };
    walk(roots, root_depth, children, &mut shape)?;
    Ok(shape)
}

pub fn validate_node_type(value: &str) -> Result<(), String> {
    if NODE_TYPES.contains(&value) {
        Ok(())
    } else {
        Err(format!("不支持的测试计划节点类型「{value}」"))
    }
}

pub fn validate_priority(value: i64) -> Result<(), String> {
    if (0..=100).contains(&value) {
        Ok(())
    } else {
        Err("测试计划 priority 必须在 0..=100 之间".to_string())
    }
}

pub fn validate_locked_fields(fields: &[String]) -> Result<Vec<String>, String> {
    let mut normalized = Vec::new();
    for field in fields {
        let field = field.trim();
        if !EDITABLE_FIELDS.contains(&field) {
            return Err(format!("不支持锁定字段「{field}」"));
        }
        if !normalized.iter().any(|existing| existing == field) {
            normalized.push(field.to_string());
        }
    }
    normalized.sort();
    Ok(normalized)
}

pub fn status_requires_reason(status: &str) -> bool {
    matches!(status, "blocked" | "skipped" | "not_applicable")
}

pub fn is_terminal(status: &str) -> bool {
    matches!(status, "done" | "skipped" | "not_applicable")
}

pub fn can_transition(from: &str, to: &str) -> bool {
    if from == to || !STATUSES.contains(&to) {
        return false;
    }
    matches!(
        (from, to),
        ("todo", "in_progress")
            | ("todo", "blocked")
            | ("todo", "skipped")
            | ("todo", "not_applicable")
            | ("in_progress", "done")
            | ("in_progress", "blocked")
            | ("in_progress", "skipped")
            | ("in_progress", "not_applicable")
            | ("in_progress", "todo")
            | ("blocked", "todo")
            | ("blocked", "in_progress")
            | ("blocked", "skipped")
            | ("blocked", "not_applicable")
            | ("skipped", "todo")
            | ("skipped", "not_applicable")
            | ("not_applicable", "todo")
            | ("done", "todo")
    )
}

fn prerequisites_satisfied(node: &TaskNode, nodes_by_id: &HashMap<i64, &TaskNode>) -> bool {
    node.prerequisite_ids.iter().all(|id| {
        nodes_by_id
            .get(id)
            .is_some_and(|prerequisite| !prerequisite.archived && is_terminal(&prerequisite.status))
    })
}

fn ancestors_allow_execution(node: &TaskNode, nodes_by_id: &HashMap<i64, &TaskNode>) -> bool {
    let mut current = node.parent_id;
    let mut visited = HashSet::new();
    while let Some(parent_id) = current {
        if !visited.insert(parent_id) {
            return false;
        }
        let Some(parent) = nodes_by_id.get(&parent_id) else {
            // 缺失父节点也覆盖“父节点已归档”的活动视图情形。
            return false;
        };
        if parent.archived || !matches!(parent.status.as_str(), "todo" | "in_progress") {
            return false;
        }
        current = parent.parent_id;
    }
    true
}

/// “下一步”只在所有 prerequisite 已终结后参与排序。候选节点随后严格按：
/// 风险降序、priority 升序、Evidence 缺口优先、创建时间、id 排序。
/// 结构父节点在还有未终结子节点时不是可执行叶子。
pub fn next_actionable(nodes: &[TaskNode]) -> Option<i64> {
    let active: Vec<&TaskNode> = nodes.iter().filter(|node| !node.archived).collect();
    let nodes_by_id: HashMap<i64, &TaskNode> = active.iter().map(|node| (node.id, *node)).collect();
    let has_unfinished_child: HashSet<i64> = active
        .iter()
        .filter(|node| !is_terminal(&node.status))
        .filter_map(|node| node.parent_id)
        .collect();

    let mut candidates: Vec<&TaskNode> = active
        .into_iter()
        .filter(|node| matches!(node.status.as_str(), "todo" | "in_progress"))
        .filter(|node| !has_unfinished_child.contains(&node.id))
        .filter(|node| ancestors_allow_execution(node, &nodes_by_id))
        .filter(|node| prerequisites_satisfied(node, &nodes_by_id))
        .collect();
    candidates.sort_by(|left, right| {
        right
            .risk_rank
            .cmp(&left.risk_rank)
            .then_with(|| left.priority.cmp(&right.priority))
            .then_with(|| left.has_evidence().cmp(&right.has_evidence()))
            .then_with(|| left.created_at.cmp(&right.created_at))
            .then_with(|| left.id.cmp(&right.id))
    });
    candidates.first().map(|node| node.id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: i64, parent: Option<i64>, status: &str) -> TaskNode {
        TaskNode {
            id,
            project_id: 1,
            parent_id: parent,
            stable_key: format!("node:{id}"),
            node_type: "test".into(),
            title: format!("n{id}"),
            status: status.into(),
            priority: 50,
            created_at: format!("2026-01-01 00:00:{id:02}"),
            ..TaskNode::default()
        }
    }

    #[test]
    fn transitions_require_explicit_terminal_choices() {
        assert!(can_transition("todo", "in_progress"));
        assert!(can_transition("todo", "skipped"));
        assert!(can_transition("in_progress", "done"));
        assert!(can_transition("blocked", "not_applicable"));
        assert!(can_transition("done", "todo"));
        assert!(!can_transition("todo", "done"));
        assert!(!can_transition("done", "blocked"));
        assert!(!can_transition("todo", "todo"));
        assert!(!can_transition("todo", "bogus"));
        assert!(status_requires_reason("blocked"));
        assert!(status_requires_reason("skipped"));
        assert!(status_requires_reason("not_applicable"));
        assert!(!status_requires_reason("done"));
    }

    #[test]
    fn next_uses_risk_priority_evidence_gap_and_created_time() {
        let mut low = node(1, None, "todo");
        low.priority = 10;
        let mut risky = node(2, None, "todo");
        risky.risk_rank = 4;
        risky.priority = 80;
        let mut risky_with_evidence = node(3, None, "todo");
        risky_with_evidence.risk_rank = 4;
        risky_with_evidence.priority = 80;
        risky_with_evidence.evidence_ids = vec![99];
        assert_eq!(next_actionable(&[low, risky_with_evidence, risky]), Some(2));
    }

    #[test]
    fn unmet_prerequisite_is_never_next() {
        let prerequisite = node(1, None, "in_progress");
        let mut dependent = node(2, None, "todo");
        dependent.priority = 0;
        dependent.risk_rank = 4;
        dependent.prerequisite_ids = vec![1];
        let fallback = node(3, None, "todo");
        assert_eq!(
            next_actionable(&[prerequisite.clone(), dependent.clone(), fallback]),
            Some(1)
        );

        let mut finished = prerequisite;
        finished.status = "done".into();
        assert_eq!(next_actionable(&[finished, dependent]), Some(2));
    }

    #[test]
    fn terminal_children_do_not_block_parent() {
        let mut parent = node(1, None, "todo");
        parent.priority = 0;
        let skipped = node(2, Some(1), "skipped");
        let not_applicable = node(3, Some(1), "not_applicable");
        assert_eq!(next_actionable(&[parent, skipped, not_applicable]), Some(1));
    }

    #[test]
    fn parent_with_unfinished_child_is_not_selected() {
        let mut parent = node(1, None, "in_progress");
        parent.priority = 0;
        let child = node(2, Some(1), "todo");
        assert_eq!(next_actionable(&[parent, child]), Some(2));
    }

    #[test]
    fn descendants_of_non_executable_or_missing_ancestors_are_not_selected() {
        let blocked = node(1, None, "blocked");
        let child = node(2, Some(1), "todo");
        let grandchild = node(3, Some(2), "todo");
        let fallback = node(4, None, "todo");
        assert_eq!(
            next_actionable(&[
                blocked.clone(),
                child.clone(),
                grandchild.clone(),
                fallback.clone()
            ]),
            Some(4)
        );

        let skipped = node(1, None, "skipped");
        assert_eq!(
            next_actionable(&[skipped, child.clone(), grandchild.clone(), fallback.clone()]),
            Some(4)
        );

        let missing_parent_child = node(5, Some(999), "todo");
        assert_eq!(next_actionable(&[missing_parent_child, fallback]), Some(4));
    }

    #[test]
    fn forest_validator_counts_arbitrary_nesting_from_actual_depth() {
        #[derive(Debug)]
        struct ShapeNode {
            children: Vec<ShapeNode>,
        }
        let leaf = || ShapeNode {
            children: Vec::new(),
        };
        let roots = vec![ShapeNode {
            children: vec![ShapeNode {
                children: vec![leaf()],
            }],
        }];
        assert_eq!(
            validate_forest(&roots, 1, |node| node.children.as_slice()).unwrap(),
            TreeShape {
                node_count: 3,
                max_depth: 3,
            }
        );
        assert!(validate_forest(&roots, 2, |node| node.children.as_slice()).is_err());
        let too_many: Vec<_> = (0..=MAX_TREE_NODES).map(|_| leaf()).collect();
        assert!(validate_forest(&too_many, 1, |node| node.children.as_slice()).is_err());
    }
}
