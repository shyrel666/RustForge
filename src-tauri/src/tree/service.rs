use crate::ai::planner::Alternative;
use crate::knowledge;
use crate::tree::model::{
    CreateTaskNodeInput, PlannedNode, PlannedTree, TaskNode, TaskPlanApplyResult, TaskPlanDiff,
    TaskPlanDiffItem, TaskPlanEvent, TaskPlanProposal, TestPlan, UpdateTaskNodeInput,
};
use crate::tree::state::{self, EDITABLE_FIELDS, MAX_TREE_NODES};
use rusqlite::{params, Connection, Transaction, TransactionBehavior};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

const TASK_COLUMNS: &str = "
    id, project_id, parent_id, stable_key, node_type, title, description, why,
    how_to, verify_criteria, priority, required_role, required_session,
    expected_observation, actual_observation, blocker_reason, standard_references,
    source, locked_fields, status, sort_order, archived, archived_at,
    created_revision, updated_revision, created_at, updated_at
";

#[derive(Debug, Clone)]
struct FlatPlannedNode {
    node: PlannedNode,
    parent_key: Option<String>,
    sort_order: i64,
}

pub fn get_plan(conn: &Connection, project_id: i64) -> Result<TestPlan, String> {
    ensure_plan(conn, project_id)?;
    conn.query_row(
        "SELECT project_id, revision, needs_update, update_reason,
                last_applied_proposal_id, created_at, updated_at
         FROM test_plans WHERE project_id = ?1",
        [project_id],
        |row| {
            Ok(TestPlan {
                project_id: row.get(0)?,
                revision: row.get(1)?,
                needs_update: row.get::<_, i64>(2)? != 0,
                update_reason: row.get(3)?,
                last_applied_proposal_id: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
            })
        },
    )
    .map_err(|error| error.to_string())
}

pub fn load_nodes(
    conn: &Connection,
    project_id: i64,
    include_archived: bool,
) -> Result<Vec<TaskNode>, String> {
    let archived_filter = if include_archived {
        ""
    } else {
        "AND archived = 0"
    };
    let mut statement = conn
        .prepare(&format!(
            "SELECT {TASK_COLUMNS}
             FROM task_nodes
             WHERE project_id = ?1 {archived_filter}
             ORDER BY sort_order, id"
        ))
        .map_err(|error| error.to_string())?;
    let mut rows = statement
        .query([project_id])
        .map_err(|error| error.to_string())?;
    let mut nodes = Vec::new();
    while let Some(row) = rows.next().map_err(|error| error.to_string())? {
        nodes.push(row_to_node(conn, row).map_err(|error| error.to_string())?);
    }
    Ok(nodes)
}

pub fn load_node(conn: &Connection, node_id: i64) -> Result<TaskNode, String> {
    conn.query_row(
        &format!("SELECT {TASK_COLUMNS} FROM task_nodes WHERE id = ?1"),
        [node_id],
        |row| row_to_node(conn, row),
    )
    .map_err(|error| format!("测试计划节点 #{node_id} 不存在: {error}"))
}

fn row_to_node(conn: &Connection, row: &rusqlite::Row<'_>) -> rusqlite::Result<TaskNode> {
    let id: i64 = row.get(0)?;
    let references_json: String = row.get(16)?;
    let locked_json: String = row.get(18)?;
    let finding_ids = related_ids(
        conn,
        "SELECT finding_id FROM task_findings WHERE task_id = ?1 ORDER BY finding_id",
        id,
    )?;
    let prerequisite_ids = related_ids(
        conn,
        "SELECT prerequisite_id FROM task_prerequisites
         WHERE task_id = ?1 ORDER BY prerequisite_id",
        id,
    )?;
    let evidence_ids = related_ids(
        conn,
        "SELECT evidence_id FROM task_evidence WHERE task_id = ?1 ORDER BY evidence_id",
        id,
    )?;
    let risk_rank: i64 = conn.query_row(
        "SELECT COALESCE(MAX(CASE finding.severity
             WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2
             WHEN 'low' THEN 1 ELSE 0 END), 0)
         FROM task_findings link
         JOIN findings finding ON finding.id = link.finding_id
         WHERE link.task_id = ?1 AND finding.status <> 'rejected'",
        [id],
        |risk_row| risk_row.get(0),
    )?;
    Ok(TaskNode {
        id,
        project_id: row.get(1)?,
        parent_id: row.get(2)?,
        stable_key: row.get(3)?,
        node_type: row.get(4)?,
        title: row.get(5)?,
        description: row.get(6)?,
        why: row.get(7)?,
        how_to: row.get(8)?,
        verify_criteria: row.get(9)?,
        priority: row.get(10)?,
        required_role: row.get(11)?,
        required_session: row.get(12)?,
        expected_observation: row.get(13)?,
        actual_observation: row.get(14)?,
        blocker_reason: row.get(15)?,
        standard_references: knowledge::references_from_json(&references_json).map_err(
            |error| {
                rusqlite::Error::FromSqlConversionFailure(
                    16,
                    rusqlite::types::Type::Text,
                    error.into(),
                )
            },
        )?,
        source: row.get(17)?,
        locked_fields: serde_json::from_str(&locked_json).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(18, rusqlite::types::Type::Text, error.into())
        })?,
        status: row.get(19)?,
        sort_order: row.get(20)?,
        archived: row.get::<_, i64>(21)? != 0,
        archived_at: row.get(22)?,
        created_revision: row.get(23)?,
        updated_revision: row.get(24)?,
        created_at: row.get(25)?,
        updated_at: row.get(26)?,
        finding_ids,
        prerequisite_ids,
        evidence_ids,
        risk_rank,
    })
}

fn related_ids(conn: &Connection, sql: &str, id: i64) -> rusqlite::Result<Vec<i64>> {
    let mut statement = conn.prepare(sql)?;
    let rows = statement.query_map([id], |row| row.get(0))?;
    rows.collect()
}

fn ensure_plan(conn: &Connection, project_id: i64) -> Result<(), String> {
    conn.execute(
        "INSERT OR IGNORE INTO test_plans(project_id)
         SELECT id FROM projects WHERE id = ?1",
        [project_id],
    )
    .map_err(|error| error.to_string())?;
    let exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM test_plans WHERE project_id = ?1)",
            [project_id],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if exists {
        Ok(())
    } else {
        Err(format!("项目 #{project_id} 不存在"))
    }
}

pub fn current_as_planned_tree(conn: &Connection, project_id: i64) -> Result<PlannedTree, String> {
    let nodes = load_nodes(conn, project_id, false)?;
    nodes_as_planned_tree(&nodes)
}

fn nodes_as_planned_tree(nodes: &[TaskNode]) -> Result<PlannedTree, String> {
    let by_id: HashMap<i64, &TaskNode> = nodes.iter().map(|node| (node.id, node)).collect();
    let mut children: HashMap<Option<i64>, Vec<&TaskNode>> = HashMap::new();
    for node in nodes {
        let parent = node.parent_id.filter(|parent| by_id.contains_key(parent));
        children.entry(parent).or_default().push(node);
    }
    for siblings in children.values_mut() {
        siblings.sort_by_key(|node| (node.sort_order, node.id));
    }
    fn build(
        node: &TaskNode,
        children: &HashMap<Option<i64>, Vec<&TaskNode>>,
        by_id: &HashMap<i64, &TaskNode>,
    ) -> PlannedNode {
        PlannedNode {
            stable_key: node.stable_key.clone(),
            node_type: node.node_type.clone(),
            title: node.title.clone(),
            description: node.description.clone(),
            why: node.why.clone(),
            how_to: node.how_to.clone(),
            verify_criteria: node.verify_criteria.clone(),
            priority: node.priority,
            required_role: node.required_role.clone(),
            required_session: node.required_session.clone(),
            expected_observation: node.expected_observation.clone(),
            standard_references: node.standard_references.clone(),
            prerequisite_keys: node
                .prerequisite_ids
                .iter()
                .filter_map(|id| by_id.get(id).map(|item| item.stable_key.clone()))
                .collect(),
            children: children
                .get(&Some(node.id))
                .into_iter()
                .flatten()
                .map(|child| build(child, children, by_id))
                .collect(),
            finding_ids: node.finding_ids.clone(),
        }
    }
    let phases = children
        .get(&None)
        .into_iter()
        .flatten()
        .map(|node| build(node, &children, &by_id))
        .collect();
    Ok(PlannedTree { phases })
}

pub fn plan_with_expansion(
    conn: &Connection,
    node_id: i64,
    children: Vec<PlannedNode>,
) -> Result<PlannedTree, String> {
    let node = load_node(conn, node_id)?;
    if node.archived {
        return Err("不能展开已归档节点".to_string());
    }
    let mut plan = current_as_planned_tree(conn, node.project_id)?;
    let target_key = node.stable_key;
    let mut children = Some(children);
    if !visit_planned_mut(&mut plan.phases, &target_key, &mut |target| {
        target.children.extend(children.take().unwrap_or_default());
    }) {
        return Err("当前测试计划中找不到待展开节点".to_string());
    }
    Ok(plan)
}

pub fn plan_with_alternative(
    conn: &Connection,
    node_id: i64,
    alternative: &Alternative,
) -> Result<PlannedTree, String> {
    let node = load_node(conn, node_id)?;
    if node.archived {
        return Err("不能修改已归档节点".to_string());
    }
    let mut plan = current_as_planned_tree(conn, node.project_id)?;
    let target_key = node.stable_key;
    if !visit_planned_mut(&mut plan.phases, &target_key, &mut |target| {
        target.description = alternative.description.trim().to_string();
        target.why = alternative.why.trim().to_string();
        target.how_to = alternative.how_to.trim().to_string();
        target.verify_criteria = alternative.verify_criteria.trim().to_string();
    }) {
        return Err("当前测试计划中找不到待修改节点".to_string());
    }
    Ok(plan)
}

fn visit_planned_mut(
    nodes: &mut [PlannedNode],
    stable_key: &str,
    visitor: &mut impl FnMut(&mut PlannedNode),
) -> bool {
    for node in nodes {
        if node.stable_key == stable_key {
            visitor(node);
            return true;
        }
        if visit_planned_mut(&mut node.children, stable_key, visitor) {
            return true;
        }
    }
    false
}

pub fn create_proposal(
    conn: &mut Connection,
    project_id: i64,
    operation: &str,
    target_node_id: Option<i64>,
    proposed: PlannedTree,
    analysis_run_id: Option<i64>,
) -> Result<TaskPlanProposal, String> {
    let expected_revision = get_plan(conn, project_id)?.revision;
    create_proposal_checked(
        conn,
        project_id,
        expected_revision,
        operation,
        target_node_id,
        proposed,
        analysis_run_id,
        |_| Ok(()),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn create_proposal_checked<ValidateContext>(
    conn: &mut Connection,
    project_id: i64,
    expected_revision: i64,
    operation: &str,
    target_node_id: Option<i64>,
    mut proposed: PlannedTree,
    analysis_run_id: Option<i64>,
    validate_context: ValidateContext,
) -> Result<TaskPlanProposal, String>
where
    ValidateContext: FnOnce(&Connection) -> Result<(), String>,
{
    if !matches!(operation, "generate" | "expand" | "alternative") {
        return Err("不支持的测试计划提案类型".to_string());
    }
    normalize_plan(&mut proposed)?;
    let transaction = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    ensure_plan(&transaction, project_id)?;
    let current_plan = get_plan(&transaction, project_id)?;
    if current_plan.revision != expected_revision {
        return Err(format!(
            "AI 测试计划上下文已过期：模型输入基于 revision {expected_revision}，当前已是 revision {}",
            current_plan.revision
        ));
    }
    validate_context(&transaction)?;
    validate_proposed_findings(&transaction, project_id, &proposed)?;
    validate_persisted_plan(&transaction, project_id)?;
    let current = load_nodes(&transaction, project_id, false)?;
    let diff = compute_diff(&current, &proposed)?;
    let projected_count = current.len() + diff.additions.len() - diff.archives.len();
    if projected_count > MAX_TREE_NODES {
        return Err(format!(
            "合并 proposal 后将有 {projected_count} 个活动节点，超过 {MAX_TREE_NODES} 个上限"
        ));
    }
    let proposed_json = serde_json::to_string(&proposed).map_err(|error| error.to_string())?;
    let diff_json = serde_json::to_string(&diff).map_err(|error| error.to_string())?;
    let proposal_key = proposal_key(
        project_id,
        expected_revision,
        operation,
        target_node_id,
        &proposed_json,
    );
    transaction
        .execute(
            "INSERT OR IGNORE INTO task_plan_proposals(
                 project_id, proposal_key, operation, target_node_id, base_revision,
                 analysis_run_id, proposed_plan, diff_json
             ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                project_id,
                proposal_key,
                operation,
                target_node_id,
                expected_revision,
                analysis_run_id,
                proposed_json,
                diff_json
            ],
        )
        .map_err(|error| error.to_string())?;
    let proposal_id: i64 = transaction
        .query_row(
            "SELECT id FROM task_plan_proposals
             WHERE project_id = ?1 AND proposal_key = ?2",
            params![project_id, proposal_key],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if transaction.changes() > 0 {
        append_event(
            &transaction,
            project_id,
            expected_revision,
            "proposal_created",
            Some(proposal_id),
            target_node_id,
            &json!({
                "operation": operation,
                "base_revision": expected_revision,
                "changes": diff.changed_count()
            }),
            "ai",
        )?;
    }
    transaction.commit().map_err(|error| error.to_string())?;
    load_proposal(conn, proposal_id)
}

pub fn load_proposal(conn: &Connection, proposal_id: i64) -> Result<TaskPlanProposal, String> {
    conn.query_row(
        "SELECT id, project_id, proposal_key, operation, target_node_id, base_revision,
                analysis_run_id, status, diff_json, created_at, applied_at
         FROM task_plan_proposals WHERE id = ?1",
        [proposal_id],
        |row| {
            let diff_json: String = row.get(8)?;
            let diff = serde_json::from_str(&diff_json).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    8,
                    rusqlite::types::Type::Text,
                    error.into(),
                )
            })?;
            Ok(TaskPlanProposal {
                id: row.get(0)?,
                project_id: row.get(1)?,
                proposal_key: row.get(2)?,
                operation: row.get(3)?,
                target_node_id: row.get(4)?,
                base_revision: row.get(5)?,
                analysis_run_id: row.get(6)?,
                status: row.get(7)?,
                diff,
                created_at: row.get(9)?,
                applied_at: row.get(10)?,
            })
        },
    )
    .map_err(|error| format!("测试计划 proposal #{proposal_id} 不存在: {error}"))
}

pub fn reject_proposal(conn: &Connection, proposal_id: i64) -> Result<(), String> {
    let proposal = load_proposal(conn, proposal_id)?;
    if proposal.status == "rejected" {
        return Ok(());
    }
    if proposal.status != "pending" {
        return Err(format!("proposal 当前状态为 {}，不能拒绝", proposal.status));
    }
    conn.execute(
        "UPDATE task_plan_proposals SET status = 'rejected' WHERE id = ?1",
        [proposal_id],
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

pub fn apply_proposal(
    conn: &mut Connection,
    project_id: i64,
    proposal_id: i64,
    actor: &str,
) -> Result<TaskPlanApplyResult, String> {
    let actor = validate_actor(actor)?;
    let transaction = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    let proposal = load_proposal(&transaction, proposal_id)?;
    if proposal.project_id != project_id {
        return Err(format!(
            "proposal #{proposal_id} 不属于当前项目 #{project_id}"
        ));
    }
    let plan = get_plan(&transaction, proposal.project_id)?;
    if proposal.status == "applied" {
        let applied_revision: i64 = transaction
            .query_row(
                "SELECT revision FROM task_plan_revisions
                 WHERE proposal_id=?1 ORDER BY revision LIMIT 1",
                [proposal_id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())?;
        return Ok(TaskPlanApplyResult {
            proposal_id,
            revision: applied_revision,
            applied: false,
            diff: proposal.diff,
        });
    }
    if proposal.status != "pending" {
        return Err(format!("proposal 当前状态为 {}，不能应用", proposal.status));
    }
    if plan.revision != proposal.base_revision {
        return Err(format!(
            "proposal 基于 revision {}，当前已是 revision {}，请重新生成增量提案",
            proposal.base_revision, plan.revision
        ));
    }
    let proposed_json: String = transaction
        .query_row(
            "SELECT proposed_plan FROM task_plan_proposals WHERE id = ?1",
            [proposal_id],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    let mut proposed: PlannedTree =
        serde_json::from_str(&proposed_json).map_err(|error| error.to_string())?;
    normalize_plan(&mut proposed)?;
    validate_proposed_findings(&transaction, proposal.project_id, &proposed)?;
    let current = load_nodes(&transaction, proposal.project_id, false)?;
    let diff = compute_diff(&current, &proposed)?;
    if diff != proposal.diff {
        return Err("proposal 创建后的计划保护边界已变化，请重新生成并复核最新 diff".to_string());
    }
    let new_revision = plan.revision + 1;
    merge_plan(
        &transaction,
        proposal.project_id,
        new_revision,
        proposal_id,
        &current,
        &proposed,
        &diff,
        &actor,
    )?;
    validate_persisted_plan(&transaction, proposal.project_id)?;
    let summary = format!(
        "新增 {}，更新 {}，保留 {}，归档 {}",
        diff.additions.len(),
        diff.updates.len(),
        diff.preserved.len(),
        diff.archives.len()
    );
    transaction
        .execute(
            "INSERT INTO task_plan_revisions(project_id, revision, proposal_id, actor, summary)
             VALUES(?1,?2,?3,?4,?5)",
            params![
                proposal.project_id,
                new_revision,
                proposal_id,
                actor,
                summary
            ],
        )
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "UPDATE test_plans
             SET revision = ?1, needs_update = 0, update_reason = '',
                 last_applied_proposal_id = ?2,
                 updated_at = strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
             WHERE project_id = ?3",
            params![new_revision, proposal_id, proposal.project_id],
        )
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "UPDATE task_plan_proposals
             SET status='superseded'
             WHERE project_id=?1 AND status='pending' AND id<>?2",
            params![proposal.project_id, proposal_id],
        )
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "UPDATE task_plan_proposals
             SET status = 'applied',
                 diff_json = ?1,
                 applied_at = strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
             WHERE id = ?2",
            params![
                serde_json::to_string(&diff).map_err(|error| error.to_string())?,
                proposal_id
            ],
        )
        .map_err(|error| error.to_string())?;
    append_event(
        &transaction,
        proposal.project_id,
        new_revision,
        "proposal_applied",
        Some(proposal_id),
        proposal.target_node_id,
        &json!({"summary": summary}),
        &actor,
    )?;
    transaction.commit().map_err(|error| error.to_string())?;
    Ok(TaskPlanApplyResult {
        proposal_id,
        revision: new_revision,
        applied: true,
        diff,
    })
}

fn normalize_plan(plan: &mut PlannedTree) -> Result<Vec<FlatPlannedNode>, String> {
    state::validate_forest(&plan.phases, 1, |node| node.children.as_slice())?;
    let mut used = HashSet::new();
    fn walk(
        nodes: &mut [PlannedNode],
        parent_key: Option<&str>,
        used: &mut HashSet<String>,
    ) -> Result<(), String> {
        for (index, node) in nodes.iter_mut().enumerate() {
            node.title = node.title.trim().to_string();
            if node.title.is_empty() {
                return Err("测试计划存在无标题节点".to_string());
            }
            state::validate_node_type(&node.node_type)?;
            state::validate_priority(node.priority)?;
            node.standard_references = knowledge::validate_references(&node.standard_references)
                .map_err(|error| format!("节点「{}」标准引用无效: {error}", node.title))?;
            node.finding_ids.sort_unstable();
            node.finding_ids.dedup();
            node.prerequisite_keys = node
                .prerequisite_keys
                .iter()
                .map(|key| key.trim().to_string())
                .filter(|key| !key.is_empty())
                .collect();
            node.prerequisite_keys.sort();
            node.prerequisite_keys.dedup();
            if node.stable_key.trim().is_empty() {
                node.stable_key =
                    derived_stable_key(parent_key, &node.node_type, &node.title, index);
            } else {
                node.stable_key = node.stable_key.trim().to_string();
            }
            if node.stable_key.len() > 128
                || !node.stable_key.chars().all(|character| {
                    character.is_ascii_alphanumeric()
                        || matches!(character, '-' | '_' | '.' | ':' | '/')
                })
            {
                return Err(format!("节点「{}」的 stable_key 无效", node.title));
            }
            if !used.insert(node.stable_key.clone()) {
                return Err(format!("stable_key「{}」重复", node.stable_key));
            }
            let key = node.stable_key.clone();
            walk(&mut node.children, Some(&key), used)?;
        }
        Ok(())
    }
    walk(&mut plan.phases, None, &mut used)?;
    let flat = flatten_plan(plan);
    for item in &flat {
        for prerequisite in &item.node.prerequisite_keys {
            if prerequisite == &item.node.stable_key {
                return Err(format!("节点「{}」不能依赖自身", item.node.title));
            }
            if !used.contains(prerequisite) {
                return Err(format!(
                    "节点「{}」引用了不存在的 prerequisite「{}」",
                    item.node.title, prerequisite
                ));
            }
        }
    }
    validate_prerequisite_dag(&flat)?;
    Ok(flat)
}

fn derived_stable_key(
    parent_key: Option<&str>,
    node_type: &str,
    title: &str,
    index: usize,
) -> String {
    let material = format!(
        "{}\n{node_type}\n{}\n{index}",
        parent_key.unwrap_or("root"),
        title.to_lowercase()
    );
    format!("ai:{}", &sha256(material.as_bytes())[..24])
}

fn flatten_plan(plan: &PlannedTree) -> Vec<FlatPlannedNode> {
    fn walk(nodes: &[PlannedNode], parent_key: Option<&str>, output: &mut Vec<FlatPlannedNode>) {
        for (index, node) in nodes.iter().enumerate() {
            let mut copy = node.clone();
            copy.children.clear();
            output.push(FlatPlannedNode {
                node: copy,
                parent_key: parent_key.map(str::to_string),
                sort_order: index as i64,
            });
            walk(&node.children, Some(&node.stable_key), output);
        }
    }
    let mut output = Vec::new();
    walk(&plan.phases, None, &mut output);
    output
}

fn validate_prerequisite_dag(nodes: &[FlatPlannedNode]) -> Result<(), String> {
    let edges: HashMap<&str, Vec<&str>> = nodes
        .iter()
        .map(|node| {
            (
                node.node.stable_key.as_str(),
                node.node
                    .prerequisite_keys
                    .iter()
                    .map(String::as_str)
                    .collect(),
            )
        })
        .collect();
    fn visit<'a>(
        key: &'a str,
        edges: &HashMap<&'a str, Vec<&'a str>>,
        visiting: &mut HashSet<&'a str>,
        complete: &mut HashSet<&'a str>,
    ) -> bool {
        if complete.contains(key) {
            return true;
        }
        if !visiting.insert(key) {
            return false;
        }
        if edges
            .get(key)
            .into_iter()
            .flatten()
            .any(|dependency| !visit(dependency, edges, visiting, complete))
        {
            return false;
        }
        visiting.remove(key);
        complete.insert(key);
        true
    }
    let mut visiting = HashSet::new();
    let mut complete = HashSet::new();
    for key in edges.keys() {
        if !visit(key, &edges, &mut visiting, &mut complete) {
            return Err("测试计划 prerequisite 存在循环依赖".to_string());
        }
    }
    Ok(())
}

fn compute_diff(current: &[TaskNode], proposed: &PlannedTree) -> Result<TaskPlanDiff, String> {
    let flat = flatten_plan(proposed);
    let current_by_key: HashMap<&str, &TaskNode> = current
        .iter()
        .map(|node| (node.stable_key.as_str(), node))
        .collect();
    let current_by_id: HashMap<i64, &TaskNode> =
        current.iter().map(|node| (node.id, node)).collect();
    let proposed_keys: HashSet<&str> = flat
        .iter()
        .map(|node| node.node.stable_key.as_str())
        .collect();
    let mut diff = TaskPlanDiff::default();

    for proposed_node in &flat {
        let key = proposed_node.node.stable_key.as_str();
        let Some(current_node) = current_by_key.get(key).copied() else {
            diff.additions.push(diff_item(
                proposed_node,
                None,
                Vec::new(),
                "proposal 新增节点",
            ));
            continue;
        };
        let changed = changed_fields(current_node, proposed_node, &current_by_id, &current_by_key);
        if let Some(reason) = protected_reason(current_node) {
            diff.preserved.push(diff_item(
                proposed_node,
                Some(current_node.id),
                changed,
                reason,
            ));
            continue;
        }
        let locked: HashSet<&str> = current_node
            .locked_fields
            .iter()
            .map(String::as_str)
            .collect();
        let mutable_changes: Vec<String> = changed
            .iter()
            .filter(|field| !locked.contains(field.as_str()))
            .cloned()
            .collect();
        if mutable_changes.is_empty() {
            let reason = if changed.is_empty() {
                "节点未变化"
            } else {
                "差异仅涉及人工锁定字段"
            };
            diff.preserved.push(diff_item(
                proposed_node,
                Some(current_node.id),
                changed,
                reason,
            ));
        } else {
            diff.updates.push(diff_item(
                proposed_node,
                Some(current_node.id),
                mutable_changes,
                "更新未锁定的 proposal 字段",
            ));
        }
    }

    let mut preserved_omitted: HashSet<i64> = current
        .iter()
        .filter(|node| !proposed_keys.contains(node.stable_key.as_str()))
        .filter(|node| protected_reason(node).is_some() || !node.locked_fields.is_empty())
        .map(|node| node.id)
        .collect();
    for node in current
        .iter()
        .filter(|node| proposed_keys.contains(node.stable_key.as_str()))
    {
        let locked: HashSet<&str> = node.locked_fields.iter().map(String::as_str).collect();
        let fully_protected = protected_reason(node).is_some();
        if fully_protected || locked.contains("parent") {
            preserved_omitted.extend(node.parent_id);
        }
        if fully_protected || locked.contains("prerequisites") {
            preserved_omitted.extend(node.prerequisite_ids.iter().copied());
        }
    }
    // 保留节点的结构祖先与 prerequisite，避免归档后留下悬空的活动关系。
    loop {
        let before = preserved_omitted.len();
        let snapshot: Vec<i64> = preserved_omitted.iter().copied().collect();
        for id in snapshot {
            if let Some(node) = current_by_id.get(&id) {
                if let Some(parent_id) = node.parent_id {
                    preserved_omitted.insert(parent_id);
                }
                preserved_omitted.extend(node.prerequisite_ids.iter().copied());
            }
        }
        if before == preserved_omitted.len() {
            break;
        }
    }

    for node in current {
        if proposed_keys.contains(node.stable_key.as_str()) {
            continue;
        }
        let item = TaskPlanDiffItem {
            stable_key: node.stable_key.clone(),
            node_id: Some(node.id),
            title: node.title.clone(),
            changed_fields: Vec::new(),
            reason: String::new(),
        };
        if preserved_omitted.contains(&node.id) {
            diff.preserved.push(TaskPlanDiffItem {
                reason: protected_reason(node)
                    .unwrap_or("作为受保护节点的结构或依赖关系保留")
                    .to_string(),
                ..item
            });
        } else {
            diff.archives.push(TaskPlanDiffItem {
                reason: "AI proposal 已省略且节点没有人工进度、锁定或 Evidence".to_string(),
                ..item
            });
        }
    }
    Ok(diff)
}

fn diff_item(
    node: &FlatPlannedNode,
    node_id: Option<i64>,
    changed_fields: Vec<String>,
    reason: &str,
) -> TaskPlanDiffItem {
    TaskPlanDiffItem {
        stable_key: node.node.stable_key.clone(),
        node_id,
        title: node.node.title.clone(),
        changed_fields,
        reason: reason.to_string(),
    }
}

fn protected_reason(node: &TaskNode) -> Option<&'static str> {
    if node.source == "manual" {
        Some("人工创建节点始终保留")
    } else if node.has_evidence() {
        Some("节点已关联 Evidence，AI 不得覆盖或归档")
    } else if node.status != "todo" {
        Some("节点已有人工进度状态，AI 不得覆盖或归档")
    } else {
        None
    }
}

fn changed_fields(
    current: &TaskNode,
    proposed: &FlatPlannedNode,
    current_by_id: &HashMap<i64, &TaskNode>,
    current_by_key: &HashMap<&str, &TaskNode>,
) -> Vec<String> {
    let mut changed = Vec::new();
    let parent_key = current
        .parent_id
        .and_then(|id| current_by_id.get(&id))
        .map(|node| node.stable_key.as_str());
    compare(
        &mut changed,
        "parent",
        parent_key,
        proposed.parent_key.as_deref(),
    );
    compare(
        &mut changed,
        "node_type",
        &current.node_type,
        &proposed.node.node_type,
    );
    compare(&mut changed, "title", &current.title, &proposed.node.title);
    compare(
        &mut changed,
        "description",
        &current.description,
        &proposed.node.description,
    );
    compare(&mut changed, "why", &current.why, &proposed.node.why);
    compare(
        &mut changed,
        "how_to",
        &current.how_to,
        &proposed.node.how_to,
    );
    compare(
        &mut changed,
        "verify_criteria",
        &current.verify_criteria,
        &proposed.node.verify_criteria,
    );
    compare(
        &mut changed,
        "priority",
        current.priority,
        proposed.node.priority,
    );
    compare(
        &mut changed,
        "required_role",
        &current.required_role,
        &proposed.node.required_role,
    );
    compare(
        &mut changed,
        "required_session",
        &current.required_session,
        &proposed.node.required_session,
    );
    compare(
        &mut changed,
        "expected_observation",
        &current.expected_observation,
        &proposed.node.expected_observation,
    );
    compare(
        &mut changed,
        "standard_references",
        serde_json::to_string(&current.standard_references).ok(),
        serde_json::to_string(&proposed.node.standard_references).ok(),
    );
    let mut findings = current.finding_ids.clone();
    findings.sort_unstable();
    compare(
        &mut changed,
        "findings",
        findings,
        proposed.node.finding_ids.clone(),
    );
    let mut prerequisite_keys: Vec<String> = current
        .prerequisite_ids
        .iter()
        .filter_map(|id| current_by_id.get(id).map(|node| node.stable_key.clone()))
        .collect();
    prerequisite_keys.sort();
    compare(
        &mut changed,
        "prerequisites",
        prerequisite_keys,
        proposed.node.prerequisite_keys.clone(),
    );
    compare(
        &mut changed,
        "sort_order",
        current.sort_order,
        proposed.sort_order,
    );
    // Silence a false-positive unused warning if a malformed current stable key map is empty.
    let _ = current_by_key;
    changed
}

fn compare<T: PartialEq>(changed: &mut Vec<String>, field: &str, left: T, right: T) {
    if left != right {
        changed.push(field.to_string());
    }
}

#[allow(clippy::too_many_arguments)]
fn merge_plan(
    transaction: &Transaction<'_>,
    project_id: i64,
    revision: i64,
    proposal_id: i64,
    current: &[TaskNode],
    proposed: &PlannedTree,
    diff: &TaskPlanDiff,
    actor: &str,
) -> Result<(), String> {
    let flat = flatten_plan(proposed);
    let mut ids: HashMap<String, i64> = current
        .iter()
        .map(|node| (node.stable_key.clone(), node.id))
        .collect();
    let additions: HashSet<&str> = diff
        .additions
        .iter()
        .map(|item| item.stable_key.as_str())
        .collect();
    for item in &flat {
        if !additions.contains(item.node.stable_key.as_str()) {
            continue;
        }
        let parent_id = item
            .parent_key
            .as_ref()
            .map(|key| {
                ids.get(key)
                    .copied()
                    .ok_or_else(|| format!("proposal 父节点「{key}」不存在"))
            })
            .transpose()?;
        let references = knowledge::references_to_json(&item.node.standard_references)?;
        transaction
            .execute(
                "INSERT INTO task_nodes(
                     project_id, parent_id, stable_key, node_type, title, description, why,
                     how_to, verify_criteria, priority, required_role, required_session,
                     expected_observation, standard_references, source, status, sort_order,
                     created_revision, updated_revision
                 ) VALUES(
                     ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,'ai','todo',?15,?16,?16
                 )",
                params![
                    project_id,
                    parent_id,
                    item.node.stable_key,
                    item.node.node_type,
                    item.node.title,
                    item.node.description,
                    item.node.why,
                    item.node.how_to,
                    item.node.verify_criteria,
                    item.node.priority,
                    item.node.required_role,
                    item.node.required_session,
                    item.node.expected_observation,
                    references,
                    item.sort_order,
                    revision
                ],
            )
            .map_err(|error| error.to_string())?;
        let id = transaction.last_insert_rowid();
        ids.insert(item.node.stable_key.clone(), id);
        replace_findings(transaction, id, &item.node.finding_ids)?;
        append_event(
            transaction,
            project_id,
            revision,
            "node_created",
            Some(proposal_id),
            Some(id),
            &json!({"stable_key": item.node.stable_key}),
            actor,
        )?;
    }

    let update_fields: HashMap<&str, HashSet<&str>> = diff
        .updates
        .iter()
        .map(|item| {
            (
                item.stable_key.as_str(),
                item.changed_fields.iter().map(String::as_str).collect(),
            )
        })
        .collect();
    let current_by_key: HashMap<&str, &TaskNode> = current
        .iter()
        .map(|node| (node.stable_key.as_str(), node))
        .collect();
    for item in &flat {
        let Some(fields) = update_fields.get(item.node.stable_key.as_str()) else {
            continue;
        };
        let old = current_by_key
            .get(item.node.stable_key.as_str())
            .copied()
            .ok_or("proposal 更新节点不存在")?;
        let parent_id = if fields.contains("parent") {
            item.parent_key
                .as_ref()
                .map(|key| {
                    ids.get(key)
                        .copied()
                        .ok_or_else(|| format!("proposal 父节点「{key}」不存在"))
                })
                .transpose()?
        } else {
            old.parent_id
        };
        let value = |field: &str, proposed: &str, current: &str| {
            if fields.contains(field) {
                proposed.to_string()
            } else {
                current.to_string()
            }
        };
        let node_type = value("node_type", &item.node.node_type, &old.node_type);
        let title = value("title", &item.node.title, &old.title);
        let description = value("description", &item.node.description, &old.description);
        let why = value("why", &item.node.why, &old.why);
        let how_to = value("how_to", &item.node.how_to, &old.how_to);
        let verify_criteria = value(
            "verify_criteria",
            &item.node.verify_criteria,
            &old.verify_criteria,
        );
        let required_role = value(
            "required_role",
            &item.node.required_role,
            &old.required_role,
        );
        let required_session = value(
            "required_session",
            &item.node.required_session,
            &old.required_session,
        );
        let expected_observation = value(
            "expected_observation",
            &item.node.expected_observation,
            &old.expected_observation,
        );
        let priority = if fields.contains("priority") {
            item.node.priority
        } else {
            old.priority
        };
        let sort_order = if fields.contains("sort_order") {
            item.sort_order
        } else {
            old.sort_order
        };
        let references = if fields.contains("standard_references") {
            knowledge::references_to_json(&item.node.standard_references)?
        } else {
            knowledge::references_to_json(&old.standard_references)?
        };
        transaction
            .execute(
                "UPDATE task_nodes
                 SET parent_id=?1, node_type=?2, title=?3, description=?4, why=?5,
                     how_to=?6, verify_criteria=?7, priority=?8, required_role=?9,
                     required_session=?10, expected_observation=?11,
                     standard_references=?12, sort_order=?13, updated_revision=?14,
                     updated_at=strftime('%Y-%m-%d %H:%M:%f','now','localtime')
                 WHERE id=?15",
                params![
                    parent_id,
                    node_type,
                    title,
                    description,
                    why,
                    how_to,
                    verify_criteria,
                    priority,
                    required_role,
                    required_session,
                    expected_observation,
                    references,
                    sort_order,
                    revision,
                    old.id
                ],
            )
            .map_err(|error| error.to_string())?;
        if fields.contains("findings") {
            replace_findings(transaction, old.id, &item.node.finding_ids)?;
        }
        append_event(
            transaction,
            project_id,
            revision,
            "node_updated",
            Some(proposal_id),
            Some(old.id),
            &json!({"changed_fields": fields}),
            actor,
        )?;
    }

    // 所有新节点已获得 id 后统一替换 prerequisite，允许引用后出现的节点。
    for item in &flat {
        let id = *ids
            .get(&item.node.stable_key)
            .ok_or("proposal 节点未映射到数据库 id")?;
        let is_addition = additions.contains(item.node.stable_key.as_str());
        let changes_prerequisites = update_fields
            .get(item.node.stable_key.as_str())
            .is_some_and(|fields| fields.contains("prerequisites"));
        if is_addition || changes_prerequisites {
            transaction
                .execute("DELETE FROM task_prerequisites WHERE task_id = ?1", [id])
                .map_err(|error| error.to_string())?;
            for key in &item.node.prerequisite_keys {
                let prerequisite_id = ids
                    .get(key)
                    .copied()
                    .ok_or_else(|| format!("prerequisite「{key}」未映射"))?;
                transaction
                    .execute(
                        "INSERT INTO task_prerequisites(task_id, prerequisite_id)
                         VALUES(?1,?2)",
                        params![id, prerequisite_id],
                    )
                    .map_err(|error| error.to_string())?;
            }
        }
    }

    for item in &diff.archives {
        let node_id = item.node_id.ok_or("归档 diff 缺少 node id")?;
        transaction
            .execute(
                "UPDATE task_nodes
                 SET archived=1,
                     archived_at=strftime('%Y-%m-%d %H:%M:%f','now','localtime'),
                     updated_revision=?1,
                     updated_at=strftime('%Y-%m-%d %H:%M:%f','now','localtime')
                 WHERE id=?2 AND archived=0",
                params![revision, node_id],
            )
            .map_err(|error| error.to_string())?;
        append_event(
            transaction,
            project_id,
            revision,
            "node_archived",
            Some(proposal_id),
            Some(node_id),
            &json!({"reason": item.reason}),
            actor,
        )?;
    }
    Ok(())
}

fn replace_findings(
    transaction: &Transaction<'_>,
    node_id: i64,
    finding_ids: &[i64],
) -> Result<(), String> {
    transaction
        .execute("DELETE FROM task_findings WHERE task_id = ?1", [node_id])
        .map_err(|error| error.to_string())?;
    for finding_id in finding_ids {
        transaction
            .execute(
                "INSERT INTO task_findings(task_id, finding_id) VALUES(?1,?2)",
                params![node_id, finding_id],
            )
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn validate_proposed_findings(
    conn: &Connection,
    project_id: i64,
    proposed: &PlannedTree,
) -> Result<(), String> {
    let mut checked = HashSet::new();
    for finding_id in flatten_plan(proposed)
        .into_iter()
        .flat_map(|item| item.node.finding_ids.into_iter())
    {
        if !checked.insert(finding_id) {
            continue;
        }
        let valid: bool = conn
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM findings
                     WHERE id=?1 AND project_id=?2 AND status <> 'rejected'
                 )",
                params![finding_id, project_id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if !valid {
            return Err(format!(
                "proposal 引用的 Finding #{finding_id} 已被拒绝、缺失或不属于当前项目，请重新生成"
            ));
        }
    }
    Ok(())
}

pub fn create_manual_node(
    conn: &mut Connection,
    input: &CreateTaskNodeInput,
    actor: &str,
) -> Result<i64, String> {
    validate_actor(actor)?;
    validate_node_values(&input.node_type, &input.title, input.priority)?;
    let transaction = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    ensure_plan(&transaction, input.project_id)?;
    if let Some(parent_id) = input.parent_id {
        let parent = load_node(&transaction, parent_id)?;
        if parent.project_id != input.project_id || parent.archived {
            return Err("父节点不属于当前活动测试计划".to_string());
        }
    }
    validate_prerequisite_ids(
        &transaction,
        input.project_id,
        None,
        &input.prerequisite_ids,
    )?;
    let plan = get_plan(&transaction, input.project_id)?;
    let revision = plan.revision + 1;
    let locked_fields = serde_json::to_string(&EDITABLE_FIELDS).map_err(|e| e.to_string())?;
    transaction
        .execute(
            "INSERT INTO task_nodes(
                 project_id, parent_id, node_type, title, description, why, how_to,
                 verify_criteria, priority, required_role, required_session,
                 expected_observation, actual_observation, source, locked_fields,
                 created_revision, updated_revision
             ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,'manual',?14,?15,?15)",
            params![
                input.project_id,
                input.parent_id,
                input.node_type,
                input.title.trim(),
                input.description.trim(),
                input.why.trim(),
                input.how_to.trim(),
                input.verify_criteria.trim(),
                input.priority,
                input.required_role.trim(),
                input.required_session.trim(),
                input.expected_observation.trim(),
                input.actual_observation.trim(),
                locked_fields,
                revision
            ],
        )
        .map_err(|error| error.to_string())?;
    let node_id = transaction.last_insert_rowid();
    replace_prerequisite_ids(&transaction, node_id, &input.prerequisite_ids)?;
    append_manual_revision(
        &transaction,
        input.project_id,
        revision,
        actor,
        "人工创建测试计划节点",
    )?;
    append_event(
        &transaction,
        input.project_id,
        revision,
        "node_created",
        None,
        Some(node_id),
        &json!({"source": "manual"}),
        actor,
    )?;
    validate_persisted_plan(&transaction, input.project_id)?;
    transaction.commit().map_err(|error| error.to_string())?;
    Ok(node_id)
}

pub fn update_manual_fields(
    conn: &mut Connection,
    input: &UpdateTaskNodeInput,
    actor: &str,
) -> Result<TaskNode, String> {
    validate_actor(actor)?;
    validate_node_values(&input.node_type, &input.title, input.priority)?;
    let locked_fields = state::validate_locked_fields(&input.locked_fields)?;
    let transaction = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    let current = load_node(&transaction, input.node_id)?;
    if current.archived {
        return Err("不能编辑已归档节点".to_string());
    }
    validate_prerequisite_ids(
        &transaction,
        current.project_id,
        Some(current.id),
        &input.prerequisite_ids,
    )?;
    let plan = get_plan(&transaction, current.project_id)?;
    let revision = plan.revision + 1;
    transaction
        .execute(
            "UPDATE task_nodes
             SET node_type=?1, title=?2, description=?3, why=?4, how_to=?5,
                 verify_criteria=?6, priority=?7, required_role=?8,
                 required_session=?9, expected_observation=?10,
                 actual_observation=?11, locked_fields=?12, updated_revision=?13,
                 updated_at=strftime('%Y-%m-%d %H:%M:%f','now','localtime')
             WHERE id=?14",
            params![
                input.node_type,
                input.title.trim(),
                input.description.trim(),
                input.why.trim(),
                input.how_to.trim(),
                input.verify_criteria.trim(),
                input.priority,
                input.required_role.trim(),
                input.required_session.trim(),
                input.expected_observation.trim(),
                input.actual_observation.trim(),
                serde_json::to_string(&locked_fields).map_err(|error| error.to_string())?,
                revision,
                input.node_id
            ],
        )
        .map_err(|error| error.to_string())?;
    replace_prerequisite_ids(&transaction, input.node_id, &input.prerequisite_ids)?;
    append_manual_revision(
        &transaction,
        current.project_id,
        revision,
        actor,
        "人工编辑测试计划节点并更新字段锁",
    )?;
    append_event(
        &transaction,
        current.project_id,
        revision,
        "node_updated",
        None,
        Some(input.node_id),
        &json!({"locked_fields": locked_fields}),
        actor,
    )?;
    validate_persisted_plan(&transaction, current.project_id)?;
    transaction.commit().map_err(|error| error.to_string())?;
    load_node(conn, input.node_id)
}

pub fn update_status(
    conn: &mut Connection,
    node_id: i64,
    status: &str,
    reason: Option<&str>,
    actor: &str,
) -> Result<TaskNode, String> {
    validate_actor(actor)?;
    let transaction = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    let current = load_node(&transaction, node_id)?;
    if current.archived {
        return Err("不能更新已归档节点状态".to_string());
    }
    if !state::can_transition(&current.status, status) {
        return Err(format!("不允许从「{}」变为「{}」", current.status, status));
    }
    let reason = reason.unwrap_or("").trim();
    if state::status_requires_reason(status) && reason.is_empty() {
        return Err(format!("状态「{status}」必须填写原因"));
    }
    let plan = get_plan(&transaction, current.project_id)?;
    let revision = plan.revision + 1;
    append_manual_revision(
        &transaction,
        current.project_id,
        revision,
        actor,
        "人工推进测试计划状态",
    )?;
    append_event(
        &transaction,
        current.project_id,
        revision,
        "status_changed",
        None,
        Some(node_id),
        &json!({"from": current.status, "to": status, "reason": reason}),
        actor,
    )?;
    transaction
        .execute(
            "UPDATE task_nodes
             SET status=?1, blocker_reason=?2, updated_revision=?3,
                 updated_at=strftime('%Y-%m-%d %H:%M:%f','now','localtime')
             WHERE id=?4",
            params![
                status,
                if state::status_requires_reason(status) {
                    reason
                } else {
                    ""
                },
                revision,
                node_id
            ],
        )
        .map_err(|error| error.to_string())?;
    transaction.commit().map_err(|error| error.to_string())?;
    load_node(conn, node_id)
}

pub fn archive_node(conn: &mut Connection, node_id: i64, actor: &str) -> Result<(), String> {
    validate_actor(actor)?;
    let transaction = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    let current = load_node(&transaction, node_id)?;
    if current.archived {
        transaction.commit().map_err(|error| error.to_string())?;
        return Ok(());
    }
    let plan = get_plan(&transaction, current.project_id)?;
    let revision = plan.revision + 1;
    let ids: Vec<i64> = {
        let mut statement = transaction
            .prepare(
                "WITH RECURSIVE subtree(id) AS (
                     SELECT ?1
                     UNION ALL
                     SELECT node.id FROM task_nodes node
                     JOIN subtree ON node.parent_id = subtree.id
                     WHERE node.archived = 0
                 )
                 SELECT id FROM subtree ORDER BY id DESC",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([node_id], |row| row.get(0))
            .map_err(|error| error.to_string())?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|error| error.to_string())?
    };
    for id in &ids {
        transaction
            .execute(
                "UPDATE task_nodes
                 SET archived=1,
                     archived_at=strftime('%Y-%m-%d %H:%M:%f','now','localtime'),
                     updated_revision=?1,
                     updated_at=strftime('%Y-%m-%d %H:%M:%f','now','localtime')
                 WHERE id=?2",
                params![revision, id],
            )
            .map_err(|error| error.to_string())?;
        append_event(
            &transaction,
            current.project_id,
            revision,
            "node_archived",
            None,
            Some(*id),
            &json!({"reason": "人工归档"}),
            actor,
        )?;
    }
    append_manual_revision(
        &transaction,
        current.project_id,
        revision,
        actor,
        "人工归档测试计划节点及其后代",
    )?;
    validate_persisted_plan(&transaction, current.project_id)?;
    transaction.commit().map_err(|error| error.to_string())?;
    Ok(())
}

fn validate_node_values(node_type: &str, title: &str, priority: i64) -> Result<(), String> {
    state::validate_node_type(node_type)?;
    state::validate_priority(priority)?;
    if title.trim().is_empty() {
        return Err("测试计划节点标题不能为空".to_string());
    }
    if title.chars().count() > 256 {
        return Err("测试计划节点标题不能超过 256 个字符".to_string());
    }
    Ok(())
}

fn validate_prerequisite_ids(
    conn: &Connection,
    project_id: i64,
    node_id: Option<i64>,
    ids: &[i64],
) -> Result<(), String> {
    let unique: HashSet<i64> = ids.iter().copied().collect();
    if unique.len() != ids.len() {
        return Err("prerequisite 不能重复".to_string());
    }
    if node_id.is_some_and(|id| unique.contains(&id)) {
        return Err("节点不能依赖自身".to_string());
    }
    for id in ids {
        let valid: bool = conn
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM task_nodes
                     WHERE id=?1 AND project_id=?2 AND archived=0
                 )",
                params![id, project_id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if !valid {
            return Err(format!("prerequisite 节点 #{id} 不属于当前活动测试计划"));
        }
    }
    Ok(())
}

fn replace_prerequisite_ids(
    transaction: &Transaction<'_>,
    node_id: i64,
    ids: &[i64],
) -> Result<(), String> {
    transaction
        .execute("DELETE FROM task_prerequisites WHERE task_id=?1", [node_id])
        .map_err(|error| error.to_string())?;
    for id in ids {
        transaction
            .execute(
                "INSERT INTO task_prerequisites(task_id, prerequisite_id) VALUES(?1,?2)",
                params![node_id, id],
            )
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn append_manual_revision(
    transaction: &Transaction<'_>,
    project_id: i64,
    revision: i64,
    actor: &str,
    summary: &str,
) -> Result<(), String> {
    transaction
        .execute(
            "INSERT INTO task_plan_revisions(project_id, revision, actor, summary)
             VALUES(?1,?2,?3,?4)",
            params![project_id, revision, actor, summary],
        )
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "UPDATE test_plans
             SET revision=?1,
                 updated_at=strftime('%Y-%m-%d %H:%M:%f','now','localtime')
             WHERE project_id=?2",
            params![revision, project_id],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

pub fn list_events(conn: &Connection, project_id: i64) -> Result<Vec<TaskPlanEvent>, String> {
    let mut statement = conn
        .prepare(
            "SELECT id, project_id, revision, event_type, proposal_id, node_id,
                    details_json, actor, created_at
             FROM task_plan_events
             WHERE project_id=?1 ORDER BY revision, id",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([project_id], |row| {
            let details_json: String = row.get(6)?;
            let details = serde_json::from_str(&details_json).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    6,
                    rusqlite::types::Type::Text,
                    error.into(),
                )
            })?;
            Ok(TaskPlanEvent {
                id: row.get(0)?,
                project_id: row.get(1)?,
                revision: row.get(2)?,
                event_type: row.get(3)?,
                proposal_id: row.get(4)?,
                node_id: row.get(5)?,
                details,
                actor: row.get(7)?,
                created_at: row.get(8)?,
            })
        })
        .map_err(|error| error.to_string())?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|error| error.to_string())
}

pub fn mark_update_available(
    transaction: &Transaction<'_>,
    project_id: i64,
    reason: &str,
    actor: &str,
    node_id: Option<i64>,
) -> Result<(), String> {
    ensure_plan(transaction, project_id)?;
    let revision: i64 = transaction
        .query_row(
            "SELECT revision FROM test_plans WHERE project_id=?1",
            [project_id],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "UPDATE test_plans
             SET needs_update=1, update_reason=?1,
                 updated_at=strftime('%Y-%m-%d %H:%M:%f','now','localtime')
             WHERE project_id=?2",
            params![reason, project_id],
        )
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "UPDATE task_plan_proposals
             SET status='superseded'
             WHERE project_id=?1 AND status='pending'",
            [project_id],
        )
        .map_err(|error| error.to_string())?;
    append_event(
        transaction,
        project_id,
        revision,
        "plan_update_available",
        None,
        node_id,
        &json!({"reason": reason}),
        actor,
    )
}

#[allow(clippy::too_many_arguments)]
fn append_event(
    transaction: &Transaction<'_>,
    project_id: i64,
    revision: i64,
    event_type: &str,
    proposal_id: Option<i64>,
    node_id: Option<i64>,
    details: &serde_json::Value,
    actor: &str,
) -> Result<(), String> {
    transaction
        .execute(
            "INSERT INTO task_plan_events(
                 project_id, revision, event_type, proposal_id, node_id, details_json, actor
             ) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                project_id,
                revision,
                event_type,
                proposal_id,
                node_id,
                serde_json::to_string(details).map_err(|error| error.to_string())?,
                actor
            ],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn validate_persisted_plan(conn: &Connection, project_id: i64) -> Result<(), String> {
    let nodes = load_nodes(conn, project_id, false)?;
    if nodes.len() > MAX_TREE_NODES {
        return Err(format!("测试计划超过 {MAX_TREE_NODES} 个活动节点"));
    }
    let by_id: HashMap<i64, &TaskNode> = nodes.iter().map(|node| (node.id, node)).collect();
    let mut children: HashMap<Option<i64>, Vec<i64>> = HashMap::new();
    for node in &nodes {
        if node.parent_id.is_some_and(|id| !by_id.contains_key(&id)) {
            return Err(format!("活动节点 #{} 的父节点缺失或已归档", node.id));
        }
        if node
            .prerequisite_ids
            .iter()
            .any(|id| !by_id.contains_key(id))
        {
            return Err(format!(
                "活动节点 #{} 的 prerequisite 缺失或已归档",
                node.id
            ));
        }
        children.entry(node.parent_id).or_default().push(node.id);
    }
    fn walk(
        id: i64,
        depth: usize,
        children: &HashMap<Option<i64>, Vec<i64>>,
        visiting: &mut HashSet<i64>,
        visited: &mut HashSet<i64>,
    ) -> Result<(), String> {
        if depth > state::MAX_TREE_DEPTH {
            return Err(format!("测试计划超过 {} 层", state::MAX_TREE_DEPTH));
        }
        if !visiting.insert(id) {
            return Err("测试计划 parent 关系存在循环".to_string());
        }
        for child in children.get(&Some(id)).into_iter().flatten() {
            walk(*child, depth + 1, children, visiting, visited)?;
        }
        visiting.remove(&id);
        visited.insert(id);
        Ok(())
    }
    let mut visiting = HashSet::new();
    let mut visited = HashSet::new();
    for root in children.get(&None).into_iter().flatten() {
        walk(*root, 1, &children, &mut visiting, &mut visited)?;
    }
    if visited.len() != nodes.len() {
        return Err("测试计划存在无法从根节点到达的 parent 环".to_string());
    }
    Ok(())
}

fn proposal_key(
    project_id: i64,
    revision: i64,
    operation: &str,
    target_node_id: Option<i64>,
    proposed_json: &str,
) -> String {
    sha256(
        format!(
            "{project_id}\n{revision}\n{operation}\n{}\n{proposed_json}",
            target_node_id.unwrap_or_default()
        )
        .as_bytes(),
    )
}

fn sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn validate_actor(actor: &str) -> Result<String, String> {
    let actor = actor.trim();
    if actor.is_empty() || actor.chars().count() > 128 {
        Err("测试计划事件操作者标识无效".to_string())
    } else {
        Ok(actor.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::migrations;

    fn database() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        migrations::migrate(&mut conn).unwrap();
        conn.execute("INSERT INTO projects(name) VALUES('p')", [])
            .unwrap();
        conn
    }

    fn planned(key: &str, title: &str) -> PlannedNode {
        PlannedNode {
            stable_key: key.into(),
            node_type: "test".into(),
            title: title.into(),
            description: format!("{title} description"),
            why: String::new(),
            how_to: "manual".into(),
            verify_criteria: "observed".into(),
            priority: 50,
            required_role: String::new(),
            required_session: String::new(),
            expected_observation: String::new(),
            standard_references: Vec::new(),
            prerequisite_keys: Vec::new(),
            children: Vec::new(),
            finding_ids: Vec::new(),
        }
    }

    #[test]
    fn applying_the_same_proposal_twice_is_idempotent() {
        let mut conn = database();
        let proposal = create_proposal(
            &mut conn,
            1,
            "generate",
            None,
            PlannedTree {
                phases: vec![planned("ai:one", "One")],
            },
            None,
        )
        .unwrap();
        let first = apply_proposal(&mut conn, 1, proposal.id, "analyst").unwrap();
        let second = apply_proposal(&mut conn, 1, proposal.id, "analyst").unwrap();
        assert!(first.applied);
        assert!(!second.applied);
        assert_eq!(first.revision, second.revision);
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM task_nodes", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn replan_preserves_manual_progress_locks_and_evidence() {
        let mut conn = database();
        let initial = create_proposal(
            &mut conn,
            1,
            "generate",
            None,
            PlannedTree {
                phases: vec![
                    planned("ai:progress", "Progress"),
                    planned("ai:evidence", "Evidence"),
                ],
            },
            None,
        )
        .unwrap();
        apply_proposal(&mut conn, 1, initial.id, "analyst").unwrap();
        let nodes = load_nodes(&conn, 1, false).unwrap();
        let progress = nodes
            .iter()
            .find(|node| node.stable_key == "ai:progress")
            .unwrap();
        update_status(&mut conn, progress.id, "in_progress", None, "analyst").unwrap();
        let evidence = nodes
            .iter()
            .find(|node| node.stable_key == "ai:evidence")
            .unwrap();
        conn.execute(
            "INSERT INTO evidence(
                 project_id, source_type, source_id, observation, redacted_snapshot,
                 content_hash, created_by
             ) VALUES(1,'analysis_run',1,'observed','{}',?1,'analyst')",
            ["a".repeat(64)],
        )
        .unwrap();
        let evidence_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO task_evidence(task_id,evidence_id) VALUES(?1,?2)",
            params![evidence.id, evidence_id],
        )
        .unwrap();
        let manual = create_manual_node(
            &mut conn,
            &CreateTaskNodeInput {
                project_id: 1,
                parent_id: None,
                node_type: "manual_note".into(),
                title: "Manual note".into(),
                description: "keep me".into(),
                why: String::new(),
                how_to: String::new(),
                verify_criteria: String::new(),
                priority: 50,
                required_role: String::new(),
                required_session: String::new(),
                expected_observation: String::new(),
                actual_observation: "analyst note".into(),
                prerequisite_ids: Vec::new(),
            },
            "analyst",
        )
        .unwrap();

        let proposal = create_proposal(
            &mut conn,
            1,
            "generate",
            None,
            PlannedTree { phases: vec![] },
            None,
        )
        .unwrap();
        assert!(proposal
            .diff
            .preserved
            .iter()
            .any(|item| item.node_id == Some(progress.id)));
        assert!(proposal
            .diff
            .preserved
            .iter()
            .any(|item| item.node_id == Some(evidence.id)));
        assert!(proposal
            .diff
            .preserved
            .iter()
            .any(|item| item.node_id == Some(manual)));
        apply_proposal(&mut conn, 1, proposal.id, "analyst").unwrap();
        assert_eq!(load_nodes(&conn, 1, false).unwrap().len(), 3);
    }

    #[test]
    fn terminal_statuses_require_reason_and_are_audited() {
        let mut conn = database();
        let id = create_manual_node(
            &mut conn,
            &CreateTaskNodeInput {
                project_id: 1,
                parent_id: None,
                node_type: "test".into(),
                title: "test".into(),
                description: String::new(),
                why: String::new(),
                how_to: String::new(),
                verify_criteria: String::new(),
                priority: 50,
                required_role: String::new(),
                required_session: String::new(),
                expected_observation: String::new(),
                actual_observation: String::new(),
                prerequisite_ids: Vec::new(),
            },
            "analyst",
        )
        .unwrap();
        assert!(conn
            .execute(
                "UPDATE task_nodes
                 SET status='skipped', blocker_reason='silent change'
                 WHERE id=?1",
                [id],
            )
            .is_err());
        assert!(update_status(&mut conn, id, "skipped", None, "analyst").is_err());
        let node = update_status(&mut conn, id, "skipped", Some("授权范围外"), "analyst").unwrap();
        assert_eq!(node.blocker_reason, "授权范围外");
        let events = list_events(&conn, 1).unwrap();
        let event = events
            .iter()
            .find(|event| event.event_type == "status_changed")
            .unwrap();
        assert_eq!(event.details["reason"], "授权范围外");
    }

    #[test]
    fn ai_merge_updates_only_unlocked_fields() {
        let mut conn = database();
        let initial = create_proposal(
            &mut conn,
            1,
            "generate",
            None,
            PlannedTree {
                phases: vec![planned("ai:locked", "AI title")],
            },
            None,
        )
        .unwrap();
        apply_proposal(&mut conn, 1, initial.id, "analyst").unwrap();
        let current = load_nodes(&conn, 1, false).unwrap().remove(0);
        update_manual_fields(
            &mut conn,
            &UpdateTaskNodeInput {
                node_id: current.id,
                node_type: current.node_type,
                title: "Analyst title".into(),
                description: current.description,
                why: current.why,
                how_to: current.how_to,
                verify_criteria: current.verify_criteria,
                priority: current.priority,
                required_role: current.required_role,
                required_session: current.required_session,
                expected_observation: current.expected_observation,
                actual_observation: "manual observation".into(),
                prerequisite_ids: current.prerequisite_ids,
                locked_fields: vec!["title".into(), "actual_observation".into()],
            },
            "analyst",
        )
        .unwrap();

        let mut changed = planned("ai:locked", "AI replacement title");
        changed.description = "new unlocked description".into();
        let proposal = create_proposal(
            &mut conn,
            1,
            "generate",
            None,
            PlannedTree {
                phases: vec![changed],
            },
            None,
        )
        .unwrap();
        let update = proposal.diff.updates.first().unwrap();
        assert!(update.changed_fields.contains(&"description".to_string()));
        assert!(!update.changed_fields.contains(&"title".to_string()));
        apply_proposal(&mut conn, 1, proposal.id, "analyst").unwrap();

        let merged = load_node(&conn, current.id).unwrap();
        assert_eq!(merged.title, "Analyst title");
        assert_eq!(merged.description, "new unlocked description");
        assert_eq!(merged.actual_observation, "manual observation");
    }

    #[test]
    fn checked_proposal_rejects_a_stale_revision() {
        let mut conn = database();
        let base_revision = get_plan(&conn, 1).unwrap().revision;
        create_manual_node(
            &mut conn,
            &CreateTaskNodeInput {
                project_id: 1,
                parent_id: None,
                node_type: "test".into(),
                title: "concurrent edit".into(),
                description: String::new(),
                why: String::new(),
                how_to: String::new(),
                verify_criteria: String::new(),
                priority: 50,
                required_role: String::new(),
                required_session: String::new(),
                expected_observation: String::new(),
                actual_observation: String::new(),
                prerequisite_ids: Vec::new(),
            },
            "analyst",
        )
        .unwrap();

        let error = create_proposal_checked(
            &mut conn,
            1,
            base_revision,
            "generate",
            None,
            PlannedTree { phases: vec![] },
            None,
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(error.contains("上下文已过期"));
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM task_plan_proposals", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn applying_a_proposal_revalidates_finding_status_and_project() {
        let mut conn = database();
        conn.execute(
            "INSERT INTO findings(project_id, source, title)
             VALUES(1, 'rule', 'pending finding')",
            [],
        )
        .unwrap();
        let finding_id = conn.last_insert_rowid();
        let mut linked = planned("ai:linked", "linked task");
        linked.finding_ids = vec![finding_id];
        let proposal = create_proposal(
            &mut conn,
            1,
            "generate",
            None,
            PlannedTree {
                phases: vec![linked],
            },
            None,
        )
        .unwrap();

        conn.execute("INSERT INTO projects(name) VALUES('other')", [])
            .unwrap();
        let other_project_id = conn.last_insert_rowid();
        let project_error =
            apply_proposal(&mut conn, other_project_id, proposal.id, "analyst").unwrap_err();
        assert!(project_error.contains("不属于当前项目"));

        conn.execute(
            "INSERT INTO finding_events(
                 finding_id, event_type, old_value, new_value, reason, actor
             ) VALUES(?1, 'status_changed', 'pending', 'rejected', 'false positive', 'analyst')",
            [finding_id],
        )
        .unwrap();
        conn.execute(
            "UPDATE findings SET status='rejected' WHERE id=?1",
            [finding_id],
        )
        .unwrap();
        let rejected_error = apply_proposal(&mut conn, 1, proposal.id, "analyst").unwrap_err();
        assert!(rejected_error.contains("已被拒绝"));
        let link_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM task_findings", [], |row| row.get(0))
            .unwrap();
        assert_eq!(link_count, 0);
    }
}
