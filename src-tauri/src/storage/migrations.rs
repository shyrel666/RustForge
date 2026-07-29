//! SQLite schema versioning.
//!
//! The unversioned development schema is normalized as v1 first. Released
//! changes are then applied as ordered, transactional steps instead of
//! extending the bootstrap schema silently.

use rusqlite::{Connection, TransactionBehavior};
use std::collections::HashSet;
use thiserror::Error;

pub const LATEST_SCHEMA_VERSION: u32 = 2;
pub(crate) const SCHEMA_V1: &str = include_str!("migrations/v1.sql");
pub(crate) const SCHEMA_V2: &str = include_str!("migrations/v2.sql");

const V1_TABLES: &[(&str, &[&str])] = &[
    ("settings", &["key", "value"]),
    (
        "projects",
        &["id", "name", "target_host", "scope", "created_at"],
    ),
    (
        "traffic",
        &[
            "id",
            "project_id",
            "method",
            "scheme",
            "host",
            "port",
            "path",
            "url",
            "req_headers",
            "req_body",
            "status",
            "resp_headers",
            "resp_body",
            "content_type",
            "req_wire_size",
            "resp_wire_size",
            "req_captured_size",
            "resp_captured_size",
            "req_truncated",
            "resp_truncated",
            "req_decode_status",
            "resp_decode_status",
            "duration_ms",
            "rule_tags",
            "created_at",
        ],
    ),
    (
        "prompt_versions",
        &[
            "id",
            "prompt_id",
            "version",
            "content",
            "based_on_id",
            "operation",
            "created_at",
        ],
    ),
    (
        "analysis_runs",
        &[
            "id",
            "project_id",
            "traffic_id",
            "provider_id",
            "provider_base_url",
            "model",
            "prompt_id",
            "prompt_version",
            "input_hash",
            "policy_json",
            "manifest_json",
            "prompt_tokens",
            "completion_tokens",
            "total_tokens",
            "schema_applied",
            "validation_status",
            "validation_json",
            "raw_output_hash",
            "created_at",
        ],
    ),
    (
        "findings",
        &[
            "id",
            "project_id",
            "traffic_id",
            "analysis_run_id",
            "source",
            "title",
            "vuln_type",
            "standard_references",
            "severity",
            "confidence",
            "reasoning",
            "verify_steps",
            "status",
            "analyst_notes",
            "fingerprint",
            "occurrences",
            "last_seen_at",
            "created_at",
            "updated_at",
        ],
    ),
    (
        "finding_events",
        &[
            "id",
            "finding_id",
            "event_type",
            "old_value",
            "new_value",
            "reason",
            "actor",
            "created_at",
        ],
    ),
    (
        "replay_sessions",
        &[
            "id",
            "project_id",
            "title",
            "source_traffic_id",
            "tls_policy",
            "is_selected",
            "created_at",
            "updated_at",
        ],
    ),
    ("replay_run_delete_guards", &["session_id", "project_id"]),
    (
        "replay_attempts",
        &[
            "id",
            "execution_token",
            "session_id",
            "project_id",
            "method",
            "url",
            "request_headers",
            "request_wire_body",
            "req_wire_size",
            "req_wire_captured_size",
            "req_wire_truncated",
            "request_input",
            "request_body",
            "req_captured_size",
            "req_truncated",
            "req_decode_status",
            "tls_policy",
            "scope_decision",
            "request_hash",
            "req_body_hash",
            "created_at",
        ],
    ),
    (
        "replay_runs",
        &[
            "id",
            "attempt_id",
            "session_id",
            "project_id",
            "method",
            "url",
            "request_headers",
            "request_wire_body",
            "req_wire_captured_size",
            "req_wire_truncated",
            "request_input",
            "request_body",
            "req_wire_size",
            "req_captured_size",
            "req_truncated",
            "req_decode_status",
            "tls_policy",
            "scope_allowed",
            "scope_decision",
            "outcome",
            "error_code",
            "error_message",
            "status",
            "status_text",
            "response_headers",
            "response_body",
            "resp_wire_size",
            "resp_captured_size",
            "resp_truncated",
            "resp_decode_status",
            "duration_ms",
            "request_hash",
            "req_body_hash",
            "response_hash",
            "resp_body_hash",
            "created_at",
        ],
    ),
    (
        "finding_traffic",
        &["finding_id", "traffic_id", "first_seen_at"],
    ),
    (
        "evidence",
        &[
            "id",
            "project_id",
            "source_type",
            "source_id",
            "observation",
            "redacted_snapshot",
            "content_hash",
            "qualifies_for_confirmation",
            "created_by",
            "created_at",
        ],
    ),
    (
        "finding_evidence",
        &[
            "finding_id",
            "evidence_id",
            "accepted",
            "acceptance_note",
            "accepted_by",
            "accepted_at",
            "linked_at",
        ],
    ),
    (
        "rule_evaluations",
        &[
            "id",
            "project_id",
            "traffic_id",
            "pack_id",
            "pack_version",
            "status",
            "hit_count",
            "finding_count",
            "duration_ms",
            "diagnostics",
            "created_at",
        ],
    ),
    (
        "finding_rule_hits",
        &[
            "id",
            "finding_id",
            "evaluation_id",
            "traffic_id",
            "pack_id",
            "pack_version",
            "rule_id",
            "rule_version",
            "field_path",
            "evidence",
            "confidence",
            "incomplete_evidence",
            "hit_fingerprint",
            "created_at",
        ],
    ),
    (
        "task_plan_proposals",
        &[
            "id",
            "project_id",
            "proposal_key",
            "operation",
            "target_node_id",
            "base_revision",
            "analysis_run_id",
            "status",
            "proposed_plan",
            "diff_json",
            "created_at",
            "applied_at",
        ],
    ),
    ("task_plan_delete_guards", &["project_id"]),
    (
        "test_plans",
        &[
            "project_id",
            "revision",
            "needs_update",
            "update_reason",
            "last_applied_proposal_id",
            "created_at",
            "updated_at",
        ],
    ),
    (
        "task_plan_revisions",
        &[
            "project_id",
            "revision",
            "proposal_id",
            "actor",
            "summary",
            "created_at",
        ],
    ),
    (
        "task_nodes",
        &[
            "id",
            "project_id",
            "parent_id",
            "stable_key",
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
            "blocker_reason",
            "standard_references",
            "source",
            "locked_fields",
            "status",
            "sort_order",
            "archived",
            "archived_at",
            "created_revision",
            "updated_revision",
            "created_at",
            "updated_at",
        ],
    ),
    (
        "task_prerequisites",
        &["task_id", "prerequisite_id", "created_at"],
    ),
    ("task_evidence", &["task_id", "evidence_id", "linked_at"]),
    (
        "analyses",
        &[
            "id",
            "project_id",
            "traffic_id",
            "analysis_run_id",
            "purpose",
            "suspicious_params",
            "summary",
            "raw_json",
            "model",
            "created_at",
        ],
    ),
    ("task_findings", &["task_id", "finding_id"]),
    (
        "task_plan_events",
        &[
            "id",
            "project_id",
            "revision",
            "event_type",
            "proposal_id",
            "node_id",
            "details_json",
            "actor",
            "created_at",
        ],
    ),
];

const V1_INDEXES: &[&str] = &[
    "idx_traffic_project",
    "idx_replay_sessions_project",
    "idx_replay_sessions_selected",
    "idx_replay_attempts_session",
    "idx_replay_runs_session",
    "idx_replay_runs_project",
    "idx_prompt_versions_prompt",
    "idx_analysis_runs_traffic",
    "idx_findings_project",
    "idx_findings_fingerprint",
    "idx_finding_events_finding",
    "idx_finding_traffic_finding",
    "idx_evidence_source",
    "idx_finding_evidence_evidence",
    "idx_rule_evaluations_traffic",
    "idx_finding_rule_hits_finding",
    "idx_finding_rule_hits_evaluation",
    "idx_task_plan_proposals_project",
    "idx_task_nodes_project",
    "idx_task_nodes_stable_key",
    "idx_task_nodes_actionable",
    "idx_task_prerequisites_reverse",
    "idx_task_evidence_evidence",
    "idx_analyses_traffic",
    "idx_task_plan_events_project",
    "idx_task_plan_events_node",
];

const V1_TRIGGERS: &[&str] = &[
    "trg_prompt_versions_immutable_update",
    "trg_prompt_versions_immutable_delete",
    "trg_replay_session_source_project_insert",
    "trg_replay_session_source_project_update",
    "trg_replay_session_prepare_run_delete",
    "trg_replay_session_finish_run_delete",
    "trg_project_prepare_replay_run_delete",
    "trg_project_finish_replay_run_delete",
    "trg_replay_attempt_same_project_insert",
    "trg_replay_attempts_immutable_update",
    "trg_replay_attempts_immutable_delete",
    "trg_replay_run_same_project_insert",
    "trg_replay_runs_immutable_update",
    "trg_replay_runs_immutable_delete",
    "trg_replay_session_blocks_pending_attempt_delete",
    "trg_project_blocks_pending_replay_attempt_delete",
    "trg_analysis_run_traffic_project_insert",
    "trg_analysis_run_traffic_project_update",
    "trg_finding_sources_same_project_insert",
    "trg_finding_sources_same_project_update",
    "trg_finding_initial_status_pending",
    "trg_finding_initial_event",
    "trg_finding_events_immutable_update",
    "trg_finding_events_immutable_delete",
    "trg_finding_rejected_event_requires_reason",
    "trg_finding_status_requires_event",
    "trg_finding_severity_requires_event",
    "trg_finding_notes_requires_event",
    "trg_finding_traffic_same_project_insert",
    "trg_finding_traffic_same_project_update",
    "trg_evidence_immutable_update",
    "trg_evidence_immutable_delete",
    "trg_finding_evidence_same_project_insert",
    "trg_finding_evidence_initial_unaccepted",
    "trg_finding_evidence_acceptance_requires_event",
    "trg_finding_evidence_metadata_requires_transition",
    "trg_finding_evidence_immutable_delete",
    "trg_confirmed_finding_keeps_accepted_evidence_update",
    "trg_confirmed_finding_keeps_accepted_evidence_delete",
    "trg_finding_confirmed_requires_evidence",
    "trg_ai_finding_requires_valid_run_insert",
    "trg_ai_finding_requires_valid_run_update",
    "trg_project_prepare_task_plan_delete",
    "trg_project_finish_task_plan_delete",
    "trg_task_nodes_assign_stable_key",
    "trg_task_nodes_parent_same_project_insert",
    "trg_task_nodes_parent_same_project_update",
    "trg_task_prerequisites_valid_insert",
    "trg_task_prerequisites_immutable_update",
    "trg_task_evidence_same_project_insert",
    "trg_task_findings_same_project_insert",
    "trg_task_plan_event_context_insert",
    "trg_task_plan_events_immutable_update",
    "trg_task_plan_events_immutable_delete",
    "trg_task_status_requires_event",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationReport {
    pub from_version: u32,
    pub to_version: u32,
}

#[derive(Debug, Error)]
pub enum MigrationError {
    #[error("数据库操作失败: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("数据库 schema 版本 v{found} 高于当前应用支持的 v{latest}")]
    NewerSchema { found: u32, latest: u32 },
    #[error("数据库 schema v{version} 结构无效: {reason}")]
    InvalidSchema { version: u32, reason: String },
    #[error("缺少从 schema v{from} 开始的迁移步骤")]
    MissingStep { from: u32 },
}

/// Bring a connection to the latest schema.
///
/// `user_version = 0` is normalized with the idempotent v1 DDL first, then
/// follows the same ordered migration path as every versioned database.
pub fn migrate(conn: &mut Connection) -> Result<MigrationReport, MigrationError> {
    let from_version = schema_version(conn)?;
    if from_version > LATEST_SCHEMA_VERSION {
        return Err(MigrationError::NewerSchema {
            found: from_version,
            latest: LATEST_SCHEMA_VERSION,
        });
    }

    let mut current = from_version;
    while current < LATEST_SCHEMA_VERSION {
        match current {
            0 => apply_step(conn, 1, SCHEMA_V1)?,
            1 => apply_step(conn, 2, SCHEMA_V2)?,
            from => return Err(MigrationError::MissingStep { from }),
        }
        current = schema_version(conn)?;
    }

    validate_version(conn, current)?;
    Ok(MigrationReport {
        from_version,
        to_version: current,
    })
}

pub fn schema_version(conn: &Connection) -> Result<u32, rusqlite::Error> {
    conn.pragma_query_value(None, "user_version", |row| row.get(0))
}

fn apply_step(conn: &mut Connection, target_version: u32, sql: &str) -> Result<(), MigrationError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute_batch(sql)?;
    validate_version(&tx, target_version)?;
    tx.pragma_update(None, "user_version", target_version)?;
    tx.commit()?;
    Ok(())
}

fn validate_version(conn: &Connection, version: u32) -> Result<(), MigrationError> {
    match version {
        1 => validate_v1(conn),
        2 => validate_v2(conn),
        from => Err(MigrationError::MissingStep { from }),
    }
}

fn validate_v1(conn: &Connection) -> Result<(), MigrationError> {
    for (table, required_columns) in V1_TABLES {
        let columns = table_columns(conn, table)?;
        if columns.is_empty() {
            return Err(invalid_v1(format!("缺少表 `{table}`")));
        }
        for column in *required_columns {
            if !columns.contains(*column) {
                return Err(invalid_v1(format!("表 `{table}` 缺少字段 `{column}`")));
            }
        }
    }

    for index in V1_INDEXES {
        let exists: bool = conn.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = ?1
             )",
            [index],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(invalid_v1(format!("缺少索引 `{index}`")));
        }
    }

    for trigger in V1_TRIGGERS {
        let exists: bool = conn.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM sqlite_master WHERE type = 'trigger' AND name = ?1
             )",
            [trigger],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(invalid_v1(format!("缺少触发器 `{trigger}`")));
        }
    }

    let integrity: String = conn.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(invalid_v1(format!("SQLite quick_check: {integrity}")));
    }

    let mut foreign_keys = conn.prepare("PRAGMA foreign_key_check")?;
    let mut violations = foreign_keys.query([])?;
    if let Some(row) = violations.next()? {
        let table: String = row.get(0)?;
        let row_id: Option<i64> = row.get(1)?;
        return Err(invalid_v1(format!(
            "外键完整性失败: table={table}, rowid={row_id:?}"
        )));
    }
    Ok(())
}

fn validate_v2(conn: &Connection) -> Result<(), MigrationError> {
    validate_v1(conn)?;
    let columns = table_columns(conn, "analysis_runs")?;
    if !columns.contains("cached_tokens") {
        return Err(MigrationError::InvalidSchema {
            version: 2,
            reason: "表 `analysis_runs` 缺少字段 `cached_tokens`".to_string(),
        });
    }
    Ok(())
}

fn table_columns(conn: &Connection, table: &str) -> Result<HashSet<String>, rusqlite::Error> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info(\"{table}\")"))?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    rows.collect()
}

fn invalid_v1(reason: String) -> MigrationError {
    MigrationError::InvalidSchema { version: 1, reason }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table_exists(conn: &Connection, table: &str) -> bool {
        conn.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1
             )",
            [table],
            |row| row.get(0),
        )
        .unwrap()
    }

    #[test]
    fn fresh_database_initializes_at_latest_version() {
        let mut conn = Connection::open_in_memory().unwrap();
        let report = migrate(&mut conn).unwrap();

        assert_eq!(
            report,
            MigrationReport {
                from_version: 0,
                to_version: 2,
            }
        );
        assert_eq!(schema_version(&conn).unwrap(), 2);
        validate_v2(&conn).unwrap();
    }

    #[test]
    fn current_unversioned_schema_is_stamped_without_data_loss() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
        conn.execute("INSERT INTO projects(name) VALUES('existing')", [])
            .unwrap();
        let project_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO traffic(project_id, method, host, url)
             VALUES(?1, 'GET', 'example.test', 'https://example.test/')",
            [project_id],
        )
        .unwrap();

        let report = migrate(&mut conn).unwrap();

        assert_eq!(report.from_version, 0);
        assert_eq!(report.to_version, 2);
        let project_name: String = conn
            .query_row(
                "SELECT name FROM projects WHERE id = ?1",
                [project_id],
                |row| row.get(0),
            )
            .unwrap();
        let traffic_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM traffic", [], |row| row.get(0))
            .unwrap();
        assert_eq!(project_name, "existing");
        assert_eq!(traffic_count, 1);
    }

    #[test]
    fn reopening_latest_schema_is_idempotent() {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate(&mut conn).unwrap();
        conn.execute(
            "INSERT INTO settings(key, value) VALUES('marker', 'kept')",
            [],
        )
        .unwrap();

        let report = migrate(&mut conn).unwrap();

        assert_eq!(
            report,
            MigrationReport {
                from_version: 2,
                to_version: 2,
            }
        );
        let marker: String = conn
            .query_row(
                "SELECT value FROM settings WHERE key = 'marker'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(marker, "kept");
    }

    #[test]
    fn v1_migrates_cached_tokens_without_losing_existing_usage() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
        conn.pragma_update(None, "user_version", 1).unwrap();
        conn.execute("INSERT INTO projects(name) VALUES('existing')", [])
            .unwrap();
        let project_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO analysis_runs(
                project_id, provider_id, provider_base_url, model, prompt_id,
                prompt_version, input_hash, policy_json, manifest_json,
                prompt_tokens, completion_tokens, total_tokens,
                validation_status, validation_json, raw_output_hash
             ) VALUES(?1,'p','https://provider.test/v1','m','prompt',1,?2,'{}','{}',
                      12,3,15,'valid','{}',?2)",
            rusqlite::params![project_id, "a".repeat(64)],
        )
        .unwrap();

        let report = migrate(&mut conn).unwrap();

        assert_eq!(
            report,
            MigrationReport {
                from_version: 1,
                to_version: 2,
            }
        );
        let usage: (i64, i64, i64) = conn
            .query_row(
                "SELECT prompt_tokens, cached_tokens, total_tokens FROM analysis_runs",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(usage, (12, 0, 15));
        assert!(
            conn.execute(
                "UPDATE analysis_runs SET cached_tokens = prompt_tokens + 1",
                []
            )
            .is_err(),
            "缓存命中必须保持为输入 Token 的子集"
        );
        validate_v2(&conn).unwrap();
    }

    #[test]
    fn failing_step_rolls_back_schema_and_version() {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate(&mut conn).unwrap();

        let result = apply_step(
            &mut conn,
            3,
            "CREATE TABLE should_rollback(id INTEGER);
             INSERT INTO table_that_does_not_exist(id) VALUES(1);",
        );

        assert!(result.is_err());
        assert_eq!(schema_version(&conn).unwrap(), 2);
        assert!(!table_exists(&conn, "should_rollback"));
    }

    #[test]
    fn malformed_unversioned_schema_is_not_stamped() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE projects(id INTEGER PRIMARY KEY);")
            .unwrap();

        let result = migrate(&mut conn);

        assert!(matches!(
            result,
            Err(MigrationError::InvalidSchema { version: 1, .. })
        ));
        assert_eq!(schema_version(&conn).unwrap(), 0);
        assert!(!table_exists(&conn, "settings"));
    }

    #[test]
    fn unversioned_schema_with_broken_foreign_key_is_not_stamped() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
        conn.pragma_update(None, "foreign_keys", "OFF").unwrap();
        conn.execute(
            "INSERT INTO traffic(project_id, method, host, url)
             VALUES(999, 'GET', 'example.test', 'https://example.test/')",
            [],
        )
        .unwrap();

        let result = migrate(&mut conn);

        assert!(matches!(
            result,
            Err(MigrationError::InvalidSchema { version: 1, .. })
        ));
        assert_eq!(schema_version(&conn).unwrap(), 0);
    }

    #[test]
    fn newer_schema_is_rejected() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "user_version", 99).unwrap();

        let result = migrate(&mut conn);

        assert!(matches!(
            result,
            Err(MigrationError::NewerSchema {
                found: 99,
                latest: 2
            })
        ));
        assert_eq!(schema_version(&conn).unwrap(), 99);
    }

    #[test]
    fn invalid_analysis_run_cannot_create_ai_finding() {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate(&mut conn).unwrap();
        conn.execute("INSERT INTO projects(name) VALUES('p')", [])
            .unwrap();
        let project_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO traffic(project_id, method, host, url)
             VALUES(?1, 'GET', 'example.test', 'https://example.test/')",
            [project_id],
        )
        .unwrap();
        let traffic_id = conn.last_insert_rowid();
        let insert_run = |status: &str| {
            conn.execute(
                "INSERT INTO analysis_runs(
                    project_id, traffic_id, provider_id, provider_base_url, model, prompt_id,
                    prompt_version, input_hash, policy_json, manifest_json,
                    validation_status, validation_json, raw_output_hash
                 ) VALUES(?1,?2,'p','https://provider.test/v1','m','prompt',1,?3,'{}','{}',?4,'{}',?3)",
                rusqlite::params![project_id, traffic_id, "a".repeat(64), status],
            )
            .unwrap();
            conn.last_insert_rowid()
        };
        let invalid_run = insert_run("invalid");
        let rejected = conn.execute(
            "INSERT INTO findings(project_id, traffic_id, analysis_run_id, source, title)
             VALUES(?1,?2,?3,'ai','must fail')",
            rusqlite::params![project_id, traffic_id, invalid_run],
        );
        assert!(rejected.is_err());
        let finding_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM findings", [], |row| row.get(0))
            .unwrap();
        assert_eq!(finding_count, 0);

        let valid_run = insert_run("valid");
        conn.execute(
            "INSERT INTO findings(project_id, traffic_id, analysis_run_id, source, title)
             VALUES(?1,?2,?3,'ai','allowed')",
            rusqlite::params![project_id, traffic_id, valid_run],
        )
        .unwrap();

        conn.execute("DELETE FROM traffic WHERE id = ?1", [traffic_id])
            .unwrap();
        let detached: (Option<i64>, Option<i64>) = conn
            .query_row(
                "SELECT traffic_id, analysis_run_id FROM findings WHERE title = 'allowed'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(detached, (None, Some(valid_run)));
        let run_traffic: Option<i64> = conn
            .query_row(
                "SELECT traffic_id FROM analysis_runs WHERE id = ?1",
                [valid_run],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(run_traffic, None);
    }

    #[test]
    fn project_scoped_relationships_reject_cross_project_rows() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        migrate(&mut conn).unwrap();
        conn.execute_batch(
            "INSERT INTO projects(id, name) VALUES(1, 'a'), (2, 'b');
             INSERT INTO traffic(id, project_id, method, host, url) VALUES
                 (11, 1, 'GET', 'a.test', 'https://a.test/'),
                 (22, 2, 'GET', 'b.test', 'https://b.test/');
             INSERT INTO findings(id, project_id, traffic_id, source, title)
                 VALUES(31, 1, 11, 'rule', 'a finding');
             INSERT INTO test_plans(project_id, revision) VALUES(1, 0), (2, 0);
             INSERT INTO task_nodes(id, project_id, title)
                 VALUES(41, 1, 'a task');",
        )
        .unwrap();

        assert!(conn
            .execute(
                "INSERT INTO finding_traffic(finding_id, traffic_id) VALUES(31, 22)",
                [],
            )
            .is_err());
        assert!(conn
            .execute(
                "INSERT INTO findings(project_id, traffic_id, source, title)
                 VALUES(1, 22, 'rule', 'cross-project source')",
                [],
            )
            .is_err());
        assert!(conn
            .execute(
                "INSERT INTO task_plan_events(
                     project_id, revision, event_type, node_id, details_json, actor
                 ) VALUES(
                     2, 0, 'status_changed', 41,
                     '{\"from\":\"todo\",\"to\":\"in_progress\"}', 'attacker'
                 )",
                [],
            )
            .is_err());
        assert!(conn
            .execute(
                "INSERT INTO task_plan_events(
                     project_id, revision, event_type, node_id, details_json, actor
                 ) VALUES(
                     1, 999, 'status_changed', 41,
                     '{\"from\":\"todo\",\"to\":\"in_progress\"}', 'attacker'
                 )",
                [],
            )
            .is_err());

        conn.execute_batch(
            "INSERT INTO finding_traffic(finding_id, traffic_id) VALUES(31, 11);
             INSERT INTO task_plan_events(
                 project_id, revision, event_type, node_id, details_json, actor
             ) VALUES(
                 1, 0, 'status_changed', 41,
                 '{\"from\":\"todo\",\"to\":\"in_progress\"}', 'analyst'
             );
             UPDATE task_nodes
             SET status='in_progress', updated_revision=0
             WHERE id=41;",
        )
        .unwrap();
        let status: String = conn
            .query_row("SELECT status FROM task_nodes WHERE id=41", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(status, "in_progress");
    }
}
