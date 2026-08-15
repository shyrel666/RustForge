use super::model::{Evidence, EvidenceSourceType, FindingEvent};
use crate::ai::redaction::{
    redact_fallback_text, redact_headers, redact_text_body, redact_url, RedactionManifest,
};
use crate::replay;
use crate::storage::models::Finding;
use crate::tree::service as tree_service;
use base64::Engine;
use rusqlite::{Connection, Transaction, TransactionBehavior};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const SNAPSHOT_BODY_MAX_BYTES: usize = 8 * 1024;
const SNAPSHOT_HEADER_MAX_BYTES: usize = 4 * 1024;
const SNAPSHOT_URL_MAX_BYTES: usize = 4 * 1024;
const OBSERVATION_MAX_CHARS: usize = 4000;
const ACTOR_MAX_CHARS: usize = 120;

pub fn load_finding(conn: &Connection, id: i64) -> Result<Finding, String> {
    conn.query_row(
        &format!("SELECT {} FROM findings WHERE id = ?1", Finding::COLUMNS),
        [id],
        Finding::from_row,
    )
    .map_err(|error| format!("Finding #{id} 不存在: {error}"))
}

pub fn list_finding_evidence(conn: &Connection, finding_id: i64) -> Result<Vec<Evidence>, String> {
    ensure_finding_exists(conn, finding_id)?;
    let mut statement = conn
        .prepare(
            "SELECT e.id, e.project_id, e.source_type, e.source_id, e.observation,
                    e.redacted_snapshot, e.content_hash, e.qualifies_for_confirmation,
                    e.created_by, e.created_at,
                    fe.linked_at, fe.accepted, fe.acceptance_note,
                    fe.accepted_by, fe.accepted_at, fe.acceptance_kind, fe.verification_id
             FROM finding_evidence fe
             JOIN evidence e ON e.id = fe.evidence_id
             WHERE fe.finding_id = ?1
             ORDER BY fe.linked_at, e.id",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([finding_id], evidence_from_row)
        .map_err(|error| error.to_string())?;
    let mut evidence = Vec::new();
    for row in rows {
        let mut item = row.map_err(|error| error.to_string())?;
        item.source_available = source_available(conn, &item.source_type, item.source_id)?;
        evidence.push(item);
    }
    Ok(evidence)
}

pub fn list_finding_events(
    conn: &Connection,
    finding_id: i64,
) -> Result<Vec<FindingEvent>, String> {
    ensure_finding_exists(conn, finding_id)?;
    let mut statement = conn
        .prepare(
            "SELECT id, finding_id, event_type, old_value, new_value, reason, actor, created_at
             FROM finding_events
             WHERE finding_id = ?1
             ORDER BY created_at, id",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([finding_id], |row| {
            Ok(FindingEvent {
                id: row.get(0)?,
                finding_id: row.get(1)?,
                event_type: row.get(2)?,
                old_value: row.get(3)?,
                new_value: row.get(4)?,
                reason: row.get(5)?,
                actor: row.get(6)?,
                created_at: row.get(7)?,
            })
        })
        .map_err(|error| error.to_string())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())
}

pub fn create_finding_evidence(
    conn: &mut Connection,
    finding_id: i64,
    source_type: EvidenceSourceType,
    source_id: i64,
    observation: &str,
    actor: &str,
) -> Result<Evidence, String> {
    if source_id <= 0 {
        return Err("Evidence 来源 ID 必须为正整数".to_string());
    }
    let actor = validate_actor(actor)?;
    let observation = redact_user_text(observation, "evidence.observation", true)?;
    let transaction = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    let project_id: i64 = transaction
        .query_row(
            "SELECT project_id FROM findings WHERE id = ?1",
            [finding_id],
            |row| row.get(0),
        )
        .map_err(|error| format!("Finding #{finding_id} 不存在: {error}"))?;
    let evidence_id = insert_evidence(
        &transaction,
        project_id,
        source_type,
        source_id,
        &observation,
        &actor,
    )?;
    transaction
        .execute(
            "INSERT INTO finding_evidence(finding_id, evidence_id) VALUES(?1,?2)",
            rusqlite::params![finding_id, evidence_id],
        )
        .map_err(|error| error.to_string())?;
    touch_finding(&transaction, finding_id)?;
    tree_service::mark_update_available(
        &transaction,
        project_id,
        "new_finding_evidence",
        &actor,
        None,
    )?;
    transaction.commit().map_err(|error| error.to_string())?;

    load_linked_evidence(conn, finding_id, evidence_id)
}

/// 将来源快照关联到当前测试计划节点。Evidence 到达只标记计划可更新，
/// 不会自动调用 AI 或修改节点。
pub fn create_task_evidence(
    conn: &mut Connection,
    task_id: i64,
    source_type: EvidenceSourceType,
    source_id: i64,
    observation: &str,
    actor: &str,
) -> Result<i64, String> {
    if source_id <= 0 {
        return Err("Evidence 来源 ID 必须为正整数".to_string());
    }
    let actor = validate_actor(actor)?;
    let observation = redact_user_text(observation, "evidence.observation", true)?;
    let transaction = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    let project_id: i64 = transaction
        .query_row(
            "SELECT project_id FROM task_nodes WHERE id = ?1",
            [task_id],
            |row| row.get(0),
        )
        .map_err(|error| format!("任务节点 #{task_id} 不存在: {error}"))?;
    let evidence_id = insert_evidence(
        &transaction,
        project_id,
        source_type,
        source_id,
        &observation,
        &actor,
    )?;
    transaction
        .execute(
            "INSERT INTO task_evidence(task_id, evidence_id) VALUES(?1,?2)",
            rusqlite::params![task_id, evidence_id],
        )
        .map_err(|error| error.to_string())?;
    tree_service::mark_update_available(
        &transaction,
        project_id,
        "new_task_evidence",
        &actor,
        Some(task_id),
    )?;
    transaction.commit().map_err(|error| error.to_string())?;
    Ok(evidence_id)
}

pub(crate) fn insert_evidence(
    transaction: &Transaction<'_>,
    project_id: i64,
    source_type: EvidenceSourceType,
    source_id: i64,
    observation: &str,
    actor: &str,
) -> Result<i64, String> {
    let snapshot = build_source_snapshot(transaction, project_id, source_type, source_id)?;
    let qualifies_for_confirmation =
        source_qualifies_for_confirmation(transaction, project_id, source_type, source_id)?;
    let snapshot_json = serde_json::to_string(&snapshot)
        .map_err(|error| format!("序列化 Evidence 失败: {error}"))?;
    if snapshot_json.len() > 65_536 {
        return Err("Evidence 脱敏快照超过 64 KiB 上限".to_string());
    }
    let content_hash = sha256(snapshot_json.as_bytes());
    transaction
        .execute(
            "INSERT INTO evidence(
                 project_id, source_type, source_id, observation,
                 redacted_snapshot, content_hash, qualifies_for_confirmation, created_by
             ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            rusqlite::params![
                project_id,
                source_type.as_str(),
                source_id,
                observation,
                snapshot_json,
                content_hash,
                qualifies_for_confirmation,
                actor,
            ],
        )
        .map_err(|error| error.to_string())?;
    Ok(transaction.last_insert_rowid())
}

pub fn set_finding_evidence_accepted(
    conn: &mut Connection,
    finding_id: i64,
    evidence_id: i64,
    accepted: bool,
    reason: &str,
    actor: &str,
) -> Result<Evidence, String> {
    let actor = validate_actor(actor)?;
    let reason = redact_user_text(reason, "finding_evidence.acceptance_note", true)?;
    let transaction = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    let (current, finding_status, qualifies_for_confirmation): (bool, String, bool) = transaction
        .query_row(
            "SELECT fe.accepted, f.status, e.qualifies_for_confirmation
             FROM finding_evidence fe
             JOIN findings f ON f.id = fe.finding_id
             JOIN evidence e ON e.id = fe.evidence_id
             WHERE fe.finding_id = ?1 AND fe.evidence_id = ?2",
            rusqlite::params![finding_id, evidence_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|error| {
            format!("Evidence #{evidence_id} 未关联到 Finding #{finding_id}: {error}")
        })?;
    if current == accepted {
        transaction.commit().map_err(|error| error.to_string())?;
        return load_linked_evidence(conn, finding_id, evidence_id);
    }
    if !accepted && finding_status == "confirmed" && qualifies_for_confirmation {
        let accepted_count: i64 = transaction
            .query_row(
                "SELECT COUNT(*)
                 FROM finding_evidence fe
                 JOIN evidence e ON e.id = fe.evidence_id
                 WHERE fe.finding_id = ?1
                   AND fe.accepted = 1
                   AND e.qualifies_for_confirmation = 1",
                [finding_id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if accepted_count <= 1 {
            return Err(
                "已确认 Finding 必须至少保留一条已接受的 Evidence；请先重置为待验证".to_string(),
            );
        }
    }

    let old_event_value = format!(
        "evidence:{evidence_id}:{}",
        if current { "accepted" } else { "unaccepted" }
    );
    let new_event_value = format!(
        "evidence:{evidence_id}:{}",
        if accepted { "accepted" } else { "unaccepted" }
    );
    append_event(
        &transaction,
        finding_id,
        if accepted {
            "evidence_accepted"
        } else {
            "evidence_revoked"
        },
        Some(&old_event_value),
        Some(&new_event_value),
        &reason,
        &actor,
    )?;
    if accepted {
        transaction
            .execute(
                "UPDATE finding_evidence
                 SET accepted = 1, acceptance_note = ?1, accepted_by = ?2,
                     accepted_at = strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                 WHERE finding_id = ?3 AND evidence_id = ?4",
                rusqlite::params![reason, actor, finding_id, evidence_id],
            )
            .map_err(|error| error.to_string())?;
    } else {
        transaction
            .execute(
                "UPDATE finding_evidence
                 SET accepted = 0, acceptance_note = ?1, accepted_by = NULL, accepted_at = NULL
                 WHERE finding_id = ?2 AND evidence_id = ?3",
                rusqlite::params![reason, finding_id, evidence_id],
            )
            .map_err(|error| error.to_string())?;
    }
    touch_finding(&transaction, finding_id)?;
    transaction.commit().map_err(|error| error.to_string())?;
    load_linked_evidence(conn, finding_id, evidence_id)
}

pub fn update_finding_status(
    conn: &mut Connection,
    finding_id: i64,
    status: &str,
    reason: Option<&str>,
    actor: &str,
) -> Result<Finding, String> {
    if !matches!(status, "pending" | "confirmed" | "rejected") {
        return Err(format!("非法 Finding 状态: {status}"));
    }
    let actor = validate_actor(actor)?;
    let reason = redact_optional_user_text(reason, "finding.status_reason")?;
    if status == "rejected" && reason.is_empty() {
        return Err("标记误报必须填写简短原因".to_string());
    }

    let transaction = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    let current: String = transaction
        .query_row(
            "SELECT status FROM findings WHERE id = ?1",
            [finding_id],
            |row| row.get(0),
        )
        .map_err(|error| format!("Finding #{finding_id} 不存在: {error}"))?;
    if current == status {
        transaction.commit().map_err(|error| error.to_string())?;
        return load_finding(conn, finding_id);
    }
    if status == "confirmed" {
        let accepted_count: i64 = transaction
            .query_row(
                "SELECT COUNT(*)
                 FROM finding_evidence fe
                 JOIN evidence e ON e.id = fe.evidence_id
                 WHERE fe.finding_id = ?1
                   AND fe.accepted = 1
                   AND e.qualifies_for_confirmation = 1",
                [finding_id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if accepted_count == 0 {
            return Err(
                "至少需要一条已接受且具备响应验证结果的 Evidence 后才能确认 Finding".to_string(),
            );
        }
    }

    append_event(
        &transaction,
        finding_id,
        "status_changed",
        Some(&current),
        Some(status),
        &reason,
        &actor,
    )?;
    transaction
        .execute(
            "UPDATE findings
             SET status = ?1, updated_at = datetime('now', 'localtime')
             WHERE id = ?2",
            rusqlite::params![status, finding_id],
        )
        .map_err(|error| error.to_string())?;
    transaction.commit().map_err(|error| error.to_string())?;
    load_finding(conn, finding_id)
}

pub fn update_finding_review(
    conn: &mut Connection,
    finding_id: i64,
    severity: &str,
    analyst_notes: &str,
    reason: Option<&str>,
    actor: &str,
) -> Result<Finding, String> {
    if !matches!(severity, "critical" | "high" | "medium" | "low" | "info") {
        return Err(format!("非法严重度: {severity}"));
    }
    let actor = validate_actor(actor)?;
    let notes = redact_user_text(analyst_notes, "finding.analyst_notes", false)?;
    let reason = redact_optional_user_text(reason, "finding.review_reason")?;
    let transaction = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    let (old_severity, old_notes): (String, String) = transaction
        .query_row(
            "SELECT severity, analyst_notes FROM findings WHERE id = ?1",
            [finding_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| format!("Finding #{finding_id} 不存在: {error}"))?;
    if old_severity == severity && old_notes == notes {
        transaction.commit().map_err(|error| error.to_string())?;
        return load_finding(conn, finding_id);
    }

    if old_severity != severity {
        append_event(
            &transaction,
            finding_id,
            "severity_changed",
            Some(&old_severity),
            Some(severity),
            &reason,
            &actor,
        )?;
        transaction
            .execute(
                "UPDATE findings SET severity = ?1 WHERE id = ?2",
                rusqlite::params![severity, finding_id],
            )
            .map_err(|error| error.to_string())?;
    }
    if old_notes != notes {
        append_event(
            &transaction,
            finding_id,
            "notes_changed",
            Some(&old_notes),
            Some(&notes),
            &reason,
            &actor,
        )?;
        transaction
            .execute(
                "UPDATE findings SET analyst_notes = ?1 WHERE id = ?2",
                rusqlite::params![notes, finding_id],
            )
            .map_err(|error| error.to_string())?;
    }
    touch_finding(&transaction, finding_id)?;
    transaction.commit().map_err(|error| error.to_string())?;
    load_finding(conn, finding_id)
}

/// 删除未确认的 Finding。confirmed 结论是已验证的不可变审计事实，禁止无痕删除；
/// pending/rejected 等假设项可在事务内清理。返回被删除的 Finding 供命令层发事件。
pub fn delete_finding(conn: &mut Connection, finding_id: i64) -> Result<Finding, String> {
    let finding = load_finding(conn, finding_id)?;
    if finding.status == "confirmed" {
        return Err("已确认的发现不可删除，请先撤销证据或调整状态".into());
    }
    let tx = conn.transaction().map_err(|error| error.to_string())?;
    tx.execute("DELETE FROM findings WHERE id = ?1", [finding_id])
        .map_err(|error| error.to_string())?;
    tx.commit().map_err(|error| error.to_string())?;
    Ok(finding)
}

fn ensure_finding_exists(conn: &Connection, finding_id: i64) -> Result<(), String> {
    let exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM findings WHERE id = ?1)",
            [finding_id],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if exists {
        Ok(())
    } else {
        Err(format!("Finding #{finding_id} 不存在"))
    }
}

fn evidence_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Evidence> {
    let raw_snapshot: String = row.get(5)?;
    let redacted_snapshot = serde_json::from_str(&raw_snapshot).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(Evidence {
        id: row.get(0)?,
        project_id: row.get(1)?,
        source_type: row.get(2)?,
        source_id: row.get(3)?,
        source_available: false,
        observation: row.get(4)?,
        redacted_snapshot,
        content_hash: row.get(6)?,
        qualifies_for_confirmation: row.get(7)?,
        created_by: row.get(8)?,
        created_at: row.get(9)?,
        linked_at: row.get(10)?,
        accepted: row.get(11)?,
        acceptance_note: row.get(12)?,
        accepted_by: row.get(13)?,
        accepted_at: row.get(14)?,
        acceptance_kind: row.get(15)?,
        verification_id: row.get(16)?,
    })
}

fn load_linked_evidence(
    conn: &Connection,
    finding_id: i64,
    evidence_id: i64,
) -> Result<Evidence, String> {
    let mut evidence = conn
        .query_row(
            "SELECT e.id, e.project_id, e.source_type, e.source_id, e.observation,
                    e.redacted_snapshot, e.content_hash, e.qualifies_for_confirmation,
                    e.created_by, e.created_at,
                    fe.linked_at, fe.accepted, fe.acceptance_note,
                    fe.accepted_by, fe.accepted_at, fe.acceptance_kind, fe.verification_id
             FROM finding_evidence fe
             JOIN evidence e ON e.id = fe.evidence_id
             WHERE fe.finding_id = ?1 AND fe.evidence_id = ?2",
            rusqlite::params![finding_id, evidence_id],
            evidence_from_row,
        )
        .map_err(|error| error.to_string())?;
    evidence.source_available = source_available(conn, &evidence.source_type, evidence.source_id)?;
    Ok(evidence)
}

fn source_available(conn: &Connection, source_type: &str, source_id: i64) -> Result<bool, String> {
    let table = match source_type {
        "traffic" => "traffic",
        "analysis_run" => "analysis_runs",
        "replay_run" => "replay_runs",
        _ => return Ok(false),
    };
    conn.query_row(
        &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE id = ?1)"),
        [source_id],
        |row| row.get(0),
    )
    .map_err(|error| error.to_string())
}

fn build_source_snapshot(
    conn: &Connection,
    project_id: i64,
    source_type: EvidenceSourceType,
    source_id: i64,
) -> Result<Value, String> {
    match source_type {
        EvidenceSourceType::Traffic => traffic_snapshot(conn, project_id, source_id),
        EvidenceSourceType::AnalysisRun => analysis_run_snapshot(conn, project_id, source_id),
        EvidenceSourceType::ReplayRun => replay_run_snapshot(conn, project_id, source_id),
    }
}

fn source_qualifies_for_confirmation(
    conn: &Connection,
    project_id: i64,
    source_type: EvidenceSourceType,
    source_id: i64,
) -> Result<bool, String> {
    match source_type {
        // AnalysisRun 只证明模型调用、脱敏和结构化校验发生过，不证明漏洞
        // 已被真实响应验证，因此只能作为 provenance/audit Evidence。
        EvidenceSourceType::AnalysisRun => Ok(false),
        // 代理失败时仍会保留 Traffic 审计行；只有确实收到 HTTP 响应的流量
        // 才能成为 confirmed Finding 的支撑证据。
        EvidenceSourceType::Traffic => conn
            .query_row(
                "SELECT status IS NOT NULL AND resp_decode_status <> 'not_received'
                 FROM traffic
                 WHERE id = ?1 AND project_id = ?2",
                rusqlite::params![source_id, project_id],
                |row| row.get(0),
            )
            .map_err(|error| format!("项目内不存在 Traffic #{source_id}: {error}")),
        EvidenceSourceType::ReplayRun => {
            let run = replay::service::load_run(conn, source_id)?;
            if run.project_id != project_id {
                return Err(format!(
                    "项目 #{project_id} 内不存在 Repeater run #{source_id}"
                ));
            }
            let owner_kind: String = conn
                .query_row(
                    "SELECT owner_kind FROM replay_sessions WHERE id = ?1",
                    [run.session_id],
                    |row| row.get(0),
                )
                .map_err(|error| error.to_string())?;
            Ok(if owner_kind == "assessment" {
                run.outcome == "completed" && run.status.is_some() && !run.resp_truncated
            } else {
                matches!(run.outcome.as_str(), "completed" | "response_incomplete")
                    && run.status.is_some()
            })
        }
    }
}

#[derive(Debug)]
struct TrafficSnapshotInput {
    method: String,
    url: String,
    status: Option<i64>,
    content_type: Option<String>,
    req_headers: String,
    req_body: Option<Vec<u8>>,
    resp_headers: Option<String>,
    resp_body: Option<Vec<u8>>,
    req_truncated: bool,
    resp_truncated: bool,
    req_decode_status: String,
    resp_decode_status: String,
    req_wire_size: i64,
    resp_wire_size: i64,
    req_captured_size: i64,
    resp_captured_size: i64,
    created_at: String,
}

fn traffic_snapshot(conn: &Connection, project_id: i64, traffic_id: i64) -> Result<Value, String> {
    let input = conn
        .query_row(
            "SELECT method, url, status, content_type, req_headers, req_body,
                    resp_headers, resp_body, req_truncated, resp_truncated,
                    req_decode_status, resp_decode_status,
                    req_wire_size, resp_wire_size, req_captured_size, resp_captured_size,
                    created_at
             FROM traffic WHERE id = ?1 AND project_id = ?2",
            rusqlite::params![traffic_id, project_id],
            |row| {
                Ok(TrafficSnapshotInput {
                    method: row.get(0)?,
                    url: row.get(1)?,
                    status: row.get(2)?,
                    content_type: row.get(3)?,
                    req_headers: row.get(4)?,
                    req_body: row.get(5)?,
                    resp_headers: row.get(6)?,
                    resp_body: row.get(7)?,
                    req_truncated: row.get(8)?,
                    resp_truncated: row.get(9)?,
                    req_decode_status: row.get(10)?,
                    resp_decode_status: row.get(11)?,
                    req_wire_size: row.get(12)?,
                    resp_wire_size: row.get(13)?,
                    req_captured_size: row.get(14)?,
                    resp_captured_size: row.get(15)?,
                    created_at: row.get(16)?,
                })
            },
        )
        .map_err(|error| format!("项目内不存在 traffic #{traffic_id}: {error}"))?;

    let mut manifest = RedactionManifest::default();
    let redacted_url = redact_url(&input.url, true, &mut manifest);
    let url = cap_utf8(
        &redacted_url,
        SNAPSHOT_URL_MAX_BYTES,
        "request.url",
        &mut manifest,
    );
    let (request_headers, request_content_type) =
        redact_headers(&input.req_headers, "request.headers", true, &mut manifest);
    let (response_headers, response_content_type) = input.resp_headers.as_deref().map_or_else(
        || ("{}".to_string(), None),
        |headers| redact_headers(headers, "response.headers", true, &mut manifest),
    );
    let request_headers = cap_utf8(
        &request_headers,
        SNAPSHOT_HEADER_MAX_BYTES,
        "request.headers",
        &mut manifest,
    );
    let response_headers = cap_utf8(
        &response_headers,
        SNAPSHOT_HEADER_MAX_BYTES,
        "response.headers",
        &mut manifest,
    );
    let request_body = snapshot_body(
        input.req_body.as_deref(),
        &input.req_decode_status,
        request_content_type.as_deref(),
        "request.body",
        &mut manifest,
    );
    let response_body = snapshot_body(
        input.resp_body.as_deref(),
        &input.resp_decode_status,
        response_content_type
            .as_deref()
            .or(input.content_type.as_deref()),
        "response.body",
        &mut manifest,
    );

    Ok(json!({
        "schema_version": 1,
        "source": {"type": "traffic", "id": traffic_id},
        "request": {
            "method": input.method,
            "url": url,
            "headers": request_headers,
            "body": request_body,
            "wire_size": input.req_wire_size,
            "captured_size": input.req_captured_size,
            "capture_status": input.req_decode_status,
            "truncated": input.req_truncated
        },
        "response": {
            "status": input.status,
            "headers": response_headers,
            "body": response_body,
            "wire_size": input.resp_wire_size,
            "captured_size": input.resp_captured_size,
            "capture_status": input.resp_decode_status,
            "truncated": input.resp_truncated
        },
        "source_created_at": input.created_at,
        "redaction_manifest": manifest
    }))
}

fn analysis_run_snapshot(conn: &Connection, project_id: i64, run_id: i64) -> Result<Value, String> {
    let row = conn
        .query_row(
            "SELECT traffic_id, provider_id, model, prompt_id, prompt_version,
                    input_hash, policy_json, manifest_json, validation_status,
                    validation_json, raw_output_hash, schema_applied,
                    prompt_tokens, cached_tokens, completion_tokens, total_tokens, created_at
             FROM analysis_runs WHERE id = ?1 AND project_id = ?2",
            rusqlite::params![run_id, project_id],
            |row| {
                Ok((
                    row.get::<_, Option<i64>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, bool>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, i64>(13)?,
                    row.get::<_, i64>(14)?,
                    row.get::<_, i64>(15)?,
                    row.get::<_, String>(16)?,
                ))
            },
        )
        .map_err(|error| format!("项目内不存在 analysis run #{run_id}: {error}"))?;
    let policy: Value =
        serde_json::from_str(&row.6).map_err(|error| format!("AI 策略审计损坏: {error}"))?;
    let manifest: Value =
        serde_json::from_str(&row.7).map_err(|error| format!("AI 脱敏清单损坏: {error}"))?;
    let validation: Value =
        serde_json::from_str(&row.9).map_err(|error| format!("AI 校验审计损坏: {error}"))?;
    Ok(json!({
        "schema_version": 1,
        "source": {"type": "analysis_run", "id": run_id},
        "traffic_id": row.0,
        "provider_id": row.1,
        "model": row.2,
        "prompt": {"id": row.3, "version": row.4},
        "input_hash": row.5,
        "policy": policy,
        "redaction_manifest": manifest,
        "validation": {"status": row.8, "report": validation},
        "raw_output_hash": row.10,
        "schema_applied": row.11,
        "usage": {
            "prompt_tokens": row.12,
            "cached_tokens": row.13,
            "completion_tokens": row.14,
            "total_tokens": row.15
        },
        "source_created_at": row.16
    }))
}

fn replay_run_snapshot(conn: &Connection, project_id: i64, run_id: i64) -> Result<Value, String> {
    let run = replay::service::load_run(conn, run_id)?;
    if run.project_id != project_id {
        return Err(format!(
            "项目 #{project_id} 内不存在 Repeater run #{run_id}"
        ));
    }

    let mut manifest = RedactionManifest::default();
    let redacted_url = redact_url(&run.url, true, &mut manifest);
    let url = cap_utf8(
        &redacted_url,
        SNAPSHOT_URL_MAX_BYTES,
        "request.url",
        &mut manifest,
    );
    let request_headers_json = replay::service::headers_to_multimap_json(&run.request_headers)?;
    let response_headers_json = replay::service::headers_to_multimap_json(&run.response_headers)?;
    let (request_headers, request_content_type) = redact_headers(
        &request_headers_json,
        "request.headers",
        true,
        &mut manifest,
    );
    let (response_headers, response_content_type) = redact_headers(
        &response_headers_json,
        "response.headers",
        true,
        &mut manifest,
    );
    let request_headers = cap_utf8(
        &request_headers,
        SNAPSHOT_HEADER_MAX_BYTES,
        "request.headers",
        &mut manifest,
    );
    let response_headers = cap_utf8(
        &response_headers,
        SNAPSHOT_HEADER_MAX_BYTES,
        "response.headers",
        &mut manifest,
    );
    let request_bytes = replay_body_bytes(
        run.request_body_text.as_deref(),
        run.request_body_base64.as_deref(),
    )?;
    let response_bytes = replay_body_bytes(
        run.response_body_text.as_deref(),
        run.response_body_base64.as_deref(),
    )?;
    let request_body = snapshot_body(
        request_bytes.as_deref(),
        &run.req_decode_status,
        request_content_type.as_deref(),
        "request.body",
        &mut manifest,
    );
    let response_body = snapshot_body(
        response_bytes.as_deref(),
        &run.resp_decode_status,
        response_content_type.as_deref(),
        "response.body",
        &mut manifest,
    );

    Ok(json!({
        "schema_version": 1,
        "source": {"type": "replay_run", "id": run_id},
        "session_id": run.session_id,
        "request": {
            "method": run.method,
            "url": url,
            "headers": request_headers,
            "body": request_body,
            "wire_size": run.req_wire_size,
            "wire_captured_size": run.req_wire_captured_size,
            "wire_truncated": run.req_wire_truncated,
            "captured_size": run.req_captured_size,
            "capture_status": run.req_decode_status,
            "truncated": run.req_truncated,
            "hash": run.request_hash,
            "body_hash": run.req_body_hash,
            "input": {
                "encoding": run.request_input.encoding,
                "original_size": run.request_input.original_size,
                "captured_size": run.request_input.captured_size,
                "truncated": run.request_input.truncated,
                "hash": run.request_input.content_hash
            }
        },
        "authorization": {
            "scope": run.scope_decision,
            "tls_policy": run.tls_policy
        },
        "response": {
            "outcome": run.outcome,
            "error_code": run.error_code,
            "status": run.status,
            "headers": response_headers,
            "body": response_body,
            "wire_size": run.resp_wire_size,
            "captured_size": run.resp_captured_size,
            "capture_status": run.resp_decode_status,
            "truncated": run.resp_truncated,
            "duration_ms": run.duration_ms,
            "hash": run.response_hash,
            "body_hash": run.resp_body_hash
        },
        "source_created_at": run.created_at,
        "redaction_manifest": manifest
    }))
}

fn replay_body_bytes(text: Option<&str>, encoded: Option<&str>) -> Result<Option<Vec<u8>>, String> {
    match (text, encoded) {
        (Some(text), None) => Ok(Some(text.as_bytes().to_vec())),
        (None, Some(encoded)) => base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map(Some)
            .map_err(|error| format!("Repeater 正文 Base64 损坏: {error}")),
        (None, None) => Ok(None),
        (Some(_), Some(_)) => Err("Repeater 正文同时包含文本和 Base64".to_string()),
    }
}

fn snapshot_body(
    body: Option<&[u8]>,
    decode_status: &str,
    content_type: Option<&str>,
    location: &str,
    manifest: &mut RedactionManifest,
) -> Option<String> {
    let Some(body) = body else {
        manifest.omit(location, "body_not_captured");
        return None;
    };
    if !matches!(decode_status, "empty" | "identity_text" | "decoded_text") {
        manifest.omit(location, format!("non_text_capture:{decode_status}"));
        return None;
    }
    let Ok(text) = std::str::from_utf8(body) else {
        manifest.omit(location, "captured_body_is_not_utf8");
        return None;
    };
    let redacted = redact_text_body(text, content_type, location, true, manifest);
    Some(cap_utf8(
        &redacted,
        SNAPSHOT_BODY_MAX_BYTES,
        location,
        manifest,
    ))
}

fn cap_utf8(
    value: &str,
    max_bytes: usize,
    location: &str,
    manifest: &mut RedactionManifest,
) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    manifest.omit(
        location,
        format!("snapshot_truncated_after_{max_bytes}_bytes"),
    );
    format!("{}\n[OMITTED:snapshot_limit]", &value[..end])
}

fn redact_optional_user_text(value: Option<&str>, location: &str) -> Result<String, String> {
    match value {
        Some(value) if !value.trim().is_empty() => redact_user_text(value, location, true),
        _ => Ok(String::new()),
    }
}

fn redact_user_text(
    value: &str,
    location: &str,
    require_non_empty: bool,
) -> Result<String, String> {
    let trimmed = value.trim();
    if require_non_empty && trimmed.is_empty() {
        return Err("内容不能为空".to_string());
    }
    if trimmed.chars().count() > OBSERVATION_MAX_CHARS {
        return Err(format!("内容不能超过 {OBSERVATION_MAX_CHARS} 个字符"));
    }
    let mut manifest = RedactionManifest::default();
    Ok(redact_fallback_text(trimmed, location, true, &mut manifest))
}

fn validate_actor(actor: &str) -> Result<String, String> {
    let actor = actor.trim();
    if actor.is_empty() || actor.chars().count() > ACTOR_MAX_CHARS {
        return Err("事件操作者标识无效".to_string());
    }
    Ok(actor.to_string())
}

fn append_event(
    transaction: &Transaction<'_>,
    finding_id: i64,
    event_type: &str,
    old_value: Option<&str>,
    new_value: Option<&str>,
    reason: &str,
    actor: &str,
) -> Result<(), String> {
    transaction
        .execute(
            "INSERT INTO finding_events(
                 finding_id, event_type, old_value, new_value, reason, actor
             ) VALUES(?1,?2,?3,?4,?5,?6)",
            rusqlite::params![finding_id, event_type, old_value, new_value, reason, actor],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn touch_finding(transaction: &Transaction<'_>, finding_id: i64) -> Result<(), String> {
    transaction
        .execute(
            "UPDATE findings SET updated_at = datetime('now', 'localtime') WHERE id = ?1",
            [finding_id],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::migrations;

    fn database() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        migrations::migrate(&mut conn).unwrap();
        conn
    }

    fn fixture(conn: &Connection) -> (i64, i64, i64) {
        conn.execute("INSERT INTO projects(name) VALUES('p')", [])
            .unwrap();
        let project_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO traffic(
                 project_id, method, host, path, url, req_headers, req_body,
                 status, resp_headers, resp_body, content_type,
                 req_wire_size, resp_wire_size, req_captured_size, resp_captured_size,
                 req_decode_status, resp_decode_status
             ) VALUES(
                 ?1,'POST','example.test','/login',
                 'https://example.test/login?token=visible',
                 '{\"Authorization\":\"Bearer secret-token\",\"Content-Type\":\"application/json\"}',
                 ?2,500,'{\"Set-Cookie\":\"session=secret\"}',?3,'application/json',
                 31,37,31,37,'identity_text','identity_text'
             )",
            rusqlite::params![
                project_id,
                br#"{"password":"hunter2","name":"alice"}"#,
                br#"{"error":"token=top-secret"}"#
            ],
        )
        .unwrap();
        let traffic_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO findings(
                 project_id, traffic_id, source, title, severity, confidence
             ) VALUES(?1,?2,'rule','SQL error','high',80)",
            rusqlite::params![project_id, traffic_id],
        )
        .unwrap();
        (project_id, traffic_id, conn.last_insert_rowid())
    }

    #[test]
    fn confirmation_requires_manually_accepted_evidence() {
        let mut conn = database();
        let (_, traffic_id, finding_id) = fixture(&conn);

        let error =
            update_finding_status(&mut conn, finding_id, "confirmed", None, "analyst").unwrap_err();
        assert!(error.contains("Evidence"));

        let evidence = create_finding_evidence(
            &mut conn,
            finding_id,
            EvidenceSourceType::Traffic,
            traffic_id,
            "服务端错误可复现",
            "analyst",
        )
        .unwrap();
        assert!(!evidence.accepted);
        assert!(
            update_finding_status(&mut conn, finding_id, "confirmed", None, "analyst").is_err()
        );

        set_finding_evidence_accepted(
            &mut conn,
            finding_id,
            evidence.id,
            true,
            "已人工核对响应",
            "analyst",
        )
        .unwrap();
        let finding =
            update_finding_status(&mut conn, finding_id, "confirmed", None, "analyst").unwrap();
        assert_eq!(finding.status, "confirmed");
    }

    #[test]
    fn delete_finding_removes_unconfirmed_and_guards_confirmed() {
        let mut conn = database();
        let (project_id, traffic_id, finding_id) = fixture(&conn);

        let deleted = delete_finding(&mut conn, finding_id).unwrap();
        assert_eq!(deleted.id, finding_id);
        assert!(load_finding(&conn, finding_id).is_err());

        conn.execute(
            "INSERT INTO findings(project_id, traffic_id, source, title, severity, confidence)
             VALUES(?1,?2,'rule','Second','high',80)",
            rusqlite::params![project_id, traffic_id],
        )
        .unwrap();
        let confirmed_id = conn.last_insert_rowid();
        let evidence = create_finding_evidence(
            &mut conn,
            confirmed_id,
            EvidenceSourceType::Traffic,
            traffic_id,
            "确认用证据",
            "analyst",
        )
        .unwrap();
        set_finding_evidence_accepted(
            &mut conn,
            confirmed_id,
            evidence.id,
            true,
            "已核对",
            "analyst",
        )
        .unwrap();
        update_finding_status(&mut conn, confirmed_id, "confirmed", None, "analyst").unwrap();

        let error = delete_finding(&mut conn, confirmed_id).unwrap_err();
        assert!(error.contains("已确认"), "got: {error}");
        assert!(load_finding(&conn, confirmed_id).is_ok());

        assert!(delete_finding(&mut conn, 999_999).is_err());
    }

    #[test]
    fn rejection_requires_reason_and_events_replay_in_order() {
        let mut conn = database();
        let (_, _, finding_id) = fixture(&conn);
        assert!(conn
            .execute(
                "UPDATE findings SET status = 'rejected' WHERE id = ?1",
                [finding_id],
            )
            .is_err());
        assert!(update_finding_status(&mut conn, finding_id, "rejected", None, "analyst").is_err());
        update_finding_review(
            &mut conn,
            finding_id,
            "medium",
            "需要与开发确认",
            Some("人工校正"),
            "analyst",
        )
        .unwrap();
        update_finding_status(
            &mut conn,
            finding_id,
            "rejected",
            Some("仅测试环境错误页"),
            "analyst",
        )
        .unwrap();

        let events = list_finding_events(&conn, finding_id).unwrap();
        assert_eq!(events.first().unwrap().event_type, "created");
        assert_eq!(events.last().unwrap().event_type, "status_changed");
        assert_eq!(
            events.last().unwrap().new_value.as_deref(),
            Some("rejected")
        );
        assert!(events
            .windows(2)
            .all(|pair| (pair[0].created_at.as_str(), pair[0].id)
                <= (pair[1].created_at.as_str(), pair[1].id)));

        let immutable = conn.execute(
            "UPDATE finding_events SET reason = 'rewritten' WHERE finding_id = ?1",
            [finding_id],
        );
        assert!(immutable.is_err());
        assert!(conn
            .execute(
                "DELETE FROM finding_events WHERE finding_id = ?1",
                [finding_id],
            )
            .is_err());
        conn.execute("DELETE FROM findings WHERE id = ?1", [finding_id])
            .unwrap();
        let event_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM finding_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(event_count, 0, "删除 Finding 时允许生命周期级联");
    }

    #[test]
    fn traffic_snapshot_is_redacted_hashed_and_survives_source_deletion() {
        let mut conn = database();
        let (project_id, traffic_id, finding_id) = fixture(&conn);
        let evidence = create_finding_evidence(
            &mut conn,
            finding_id,
            EvidenceSourceType::Traffic,
            traffic_id,
            "Authorization: Bearer should-not-remain",
            "analyst",
        )
        .unwrap();
        let rendered = serde_json::to_string(&evidence.redacted_snapshot).unwrap();
        assert!(!rendered.contains("visible"));
        assert!(!rendered.contains("hunter2"));
        assert!(!rendered.contains("secret-token"));
        assert!(!evidence.observation.contains("should-not-remain"));
        assert_eq!(evidence.content_hash.len(), 64);
        assert!(evidence.source_available);
        assert!(conn
            .execute("DELETE FROM evidence WHERE id = ?1", [evidence.id])
            .is_err());

        conn.execute("DELETE FROM traffic WHERE id = ?1", [traffic_id])
            .unwrap();
        let preserved = list_finding_evidence(&conn, finding_id).unwrap();
        assert_eq!(preserved.len(), 1);
        assert!(!preserved[0].source_available);
        assert_eq!(preserved[0].redacted_snapshot, evidence.redacted_snapshot);
        assert_eq!(preserved[0].content_hash, evidence.content_hash);

        conn.execute("DELETE FROM projects WHERE id = ?1", [project_id])
            .unwrap();
        let evidence_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM evidence", [], |row| row.get(0))
            .unwrap();
        assert_eq!(evidence_count, 0, "删除项目时允许 Evidence 生命周期级联");
    }

    #[test]
    fn confirmed_finding_cannot_revoke_its_last_accepted_evidence() {
        let mut conn = database();
        let (_, traffic_id, finding_id) = fixture(&conn);
        let evidence = create_finding_evidence(
            &mut conn,
            finding_id,
            EvidenceSourceType::Traffic,
            traffic_id,
            "复现",
            "analyst",
        )
        .unwrap();
        set_finding_evidence_accepted(&mut conn, finding_id, evidence.id, true, "接受", "analyst")
            .unwrap();
        update_finding_status(&mut conn, finding_id, "confirmed", None, "analyst").unwrap();

        let error = set_finding_evidence_accepted(
            &mut conn,
            finding_id,
            evidence.id,
            false,
            "撤销",
            "analyst",
        )
        .unwrap_err();
        assert!(error.contains("至少保留"));
        assert!(conn
            .execute(
                "DELETE FROM finding_evidence WHERE finding_id = ?1 AND evidence_id = ?2",
                rusqlite::params![finding_id, evidence.id],
            )
            .is_err());
        assert!(list_finding_evidence(&conn, finding_id).unwrap()[0].accepted);
    }

    #[test]
    fn evidence_link_judgment_is_audited_and_immutable_between_transitions() {
        let mut conn = database();
        let (_, traffic_id, finding_id) = fixture(&conn);
        let evidence = create_finding_evidence(
            &mut conn,
            finding_id,
            EvidenceSourceType::Traffic,
            traffic_id,
            "reproduced",
            "analyst",
        )
        .unwrap();

        assert!(conn
            .execute(
                "UPDATE finding_evidence
                 SET acceptance_note = 'rewritten without an event'
                 WHERE finding_id = ?1 AND evidence_id = ?2",
                rusqlite::params![finding_id, evidence.id],
            )
            .is_err());
        set_finding_evidence_accepted(
            &mut conn,
            finding_id,
            evidence.id,
            true,
            "accepted after review",
            "analyst",
        )
        .unwrap();
        assert!(conn
            .execute(
                "UPDATE finding_evidence
                 SET acceptance_note = 'silently rewritten',
                     accepted_by = 'other',
                     accepted_at = '2000-01-01'
                 WHERE finding_id = ?1 AND evidence_id = ?2",
                rusqlite::params![finding_id, evidence.id],
            )
            .is_err());
        assert!(conn
            .execute(
                "UPDATE finding_evidence SET linked_at = '2000-01-01'
                 WHERE finding_id = ?1 AND evidence_id = ?2",
                rusqlite::params![finding_id, evidence.id],
            )
            .is_err());

        let revoked = set_finding_evidence_accepted(
            &mut conn,
            finding_id,
            evidence.id,
            false,
            "revoked after review",
            "reviewer",
        )
        .unwrap();
        assert!(!revoked.accepted);
        assert!(conn
            .execute(
                "DELETE FROM finding_evidence
                 WHERE finding_id = ?1 AND evidence_id = ?2",
                rusqlite::params![finding_id, evidence.id],
            )
            .is_err());

        conn.execute("DELETE FROM findings WHERE id = ?1", [finding_id])
            .unwrap();
        let link_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM finding_evidence", [], |row| {
                row.get(0)
            })
            .unwrap();
        let evidence_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM evidence", [], |row| row.get(0))
            .unwrap();
        assert_eq!(link_count, 0, "Finding 生命周期删除允许关联级联");
        assert_eq!(evidence_count, 1, "独立 Evidence 快照仍保留在项目中");
    }

    #[test]
    fn source_must_belong_to_the_findings_project() {
        let mut conn = database();
        let (_, _, finding_id) = fixture(&conn);
        conn.execute("INSERT INTO projects(name) VALUES('other')", [])
            .unwrap();
        let other_project = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO traffic(project_id, method, host, url)
             VALUES(?1,'GET','other.test','https://other.test/')",
            [other_project],
        )
        .unwrap();
        let other_traffic = conn.last_insert_rowid();
        let error = create_finding_evidence(
            &mut conn,
            finding_id,
            EvidenceSourceType::Traffic,
            other_traffic,
            "跨项目",
            "analyst",
        )
        .unwrap_err();
        assert!(error.contains("项目内不存在"));
    }

    #[test]
    fn analysis_run_is_referenceable_without_copying_model_output() {
        let mut conn = database();
        let (project_id, traffic_id, finding_id) = fixture(&conn);
        conn.execute(
            "INSERT INTO analysis_runs(
                 project_id, traffic_id, provider_id, provider_base_url, model, prompt_id,
                 prompt_version, input_hash, policy_json, manifest_json,
                 prompt_tokens, cached_tokens, validation_status, validation_json, raw_output_hash
              ) VALUES(
                 ?1,?2,'provider','https://provider.test/v1','model','analyze',1,
                 ?3,'{}','{}',10,7,'valid','{}',?4
              )",
            rusqlite::params![project_id, traffic_id, "a".repeat(64), "b".repeat(64)],
        )
        .unwrap();
        let run_id = conn.last_insert_rowid();
        let item = create_finding_evidence(
            &mut conn,
            finding_id,
            EvidenceSourceType::AnalysisRun,
            run_id,
            "结构化校验通过",
            "analyst",
        )
        .unwrap();

        let snapshot = serde_json::to_string(&item.redacted_snapshot).unwrap();
        assert!(snapshot.contains("\"analysis_run\""));
        assert!(snapshot.contains("\"cached_tokens\":7"));
        assert!(snapshot.contains(&"b".repeat(64)));
        assert!(!snapshot.contains("raw model output"));
        assert!(item.source_available);
        assert!(!item.qualifies_for_confirmation);
        set_finding_evidence_accepted(
            &mut conn,
            finding_id,
            item.id,
            true,
            "仅接受为 AI 审计来源",
            "analyst",
        )
        .unwrap();
        assert!(
            update_finding_status(&mut conn, finding_id, "confirmed", None, "analyst").is_err(),
            "AnalysisRun 审计元数据不能单独确认 Finding"
        );
    }

    #[test]
    fn traffic_without_a_received_response_does_not_confirm_a_finding() {
        let mut conn = database();
        let (project_id, _, finding_id) = fixture(&conn);
        conn.execute(
            "INSERT INTO traffic(
                 project_id, method, host, url, resp_decode_status
             ) VALUES(?1, 'GET', 'failed.test', 'https://failed.test/', 'not_received')",
            [project_id],
        )
        .unwrap();
        let traffic_id = conn.last_insert_rowid();
        let item = create_finding_evidence(
            &mut conn,
            finding_id,
            EvidenceSourceType::Traffic,
            traffic_id,
            "请求失败审计",
            "analyst",
        )
        .unwrap();
        assert!(!item.qualifies_for_confirmation);
        set_finding_evidence_accepted(
            &mut conn,
            finding_id,
            item.id,
            true,
            "接受为失败审计",
            "analyst",
        )
        .unwrap();
        assert!(
            update_finding_status(&mut conn, finding_id, "confirmed", None, "analyst").is_err()
        );
    }

    #[test]
    fn content_hash_is_stable_for_the_same_redacted_source_snapshot() {
        let mut conn = database();
        let (_, traffic_id, finding_id) = fixture(&conn);
        let first = create_finding_evidence(
            &mut conn,
            finding_id,
            EvidenceSourceType::Traffic,
            traffic_id,
            "第一次观察",
            "analyst",
        )
        .unwrap();
        let second = create_finding_evidence(
            &mut conn,
            finding_id,
            EvidenceSourceType::Traffic,
            traffic_id,
            "第二次观察",
            "analyst",
        )
        .unwrap();
        assert_eq!(first.content_hash, second.content_hash);
        assert_ne!(first.observation, second.observation);
    }

    #[test]
    fn new_evidence_only_marks_the_test_plan_update_available() {
        let mut conn = database();
        let (project_id, traffic_id, finding_id) = fixture(&conn);
        conn.execute(
            "INSERT INTO task_nodes(project_id, title) VALUES(?1, 'manual test')",
            [project_id],
        )
        .unwrap();
        let task_id = conn.last_insert_rowid();
        let current_plan = tree_service::current_as_planned_tree(&conn, project_id).unwrap();
        let pending = tree_service::create_proposal(
            &mut conn,
            project_id,
            "generate",
            None,
            current_plan,
            None,
        )
        .unwrap();

        create_finding_evidence(
            &mut conn,
            finding_id,
            EvidenceSourceType::Traffic,
            traffic_id,
            "Finding 新证据",
            "analyst",
        )
        .unwrap();
        let after_finding = tree_service::get_plan(&conn, project_id).unwrap();
        assert!(after_finding.needs_update);
        assert_eq!(after_finding.update_reason, "new_finding_evidence");
        assert_eq!(
            tree_service::load_proposal(&conn, pending.id)
                .unwrap()
                .status,
            "superseded",
            "新 Evidence 必须让旧 diff 失效，避免确认过时保护边界"
        );

        create_task_evidence(
            &mut conn,
            task_id,
            EvidenceSourceType::Traffic,
            traffic_id,
            "测试节点新证据",
            "analyst",
        )
        .unwrap();
        let after_task = tree_service::get_plan(&conn, project_id).unwrap();
        assert!(after_task.needs_update);
        assert_eq!(after_task.update_reason, "new_task_evidence");
        let node = tree_service::load_node(&conn, task_id).unwrap();
        assert_eq!(node.status, "todo", "Evidence 到达不能自动推进状态");
        assert_eq!(node.title, "manual test", "Evidence 到达不能自动改写节点");
        assert_eq!(node.evidence_ids.len(), 1);
        let events = tree_service::list_events(&conn, project_id).unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.event_type == "plan_update_available")
                .count(),
            2
        );
    }
}
