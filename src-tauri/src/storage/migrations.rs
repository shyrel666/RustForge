//! SQLite schema versioning.
//!
//! The unversioned development schema is normalized as v1 first. Released
//! changes are then applied as ordered, transactional steps instead of
//! extending the bootstrap schema silently.

#[cfg(test)]
use crate::assessment::finding_identity::security_baseline_fingerprint;
use crate::assessment::finding_identity::{
    security_baseline_fingerprint_for_kinds, security_baseline_title, SecurityBaselineKinds,
};
use rusqlite::{Connection, Transaction, TransactionBehavior};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use thiserror::Error;

pub const LATEST_SCHEMA_VERSION: u32 = 5;
pub(crate) const SCHEMA_V1: &str = include_str!("migrations/v1.sql");
pub(crate) const SCHEMA_V2: &str = include_str!("migrations/v2.sql");
pub(crate) const SCHEMA_V3: &str = include_str!("migrations/v3.sql");
pub(crate) const SCHEMA_V4: &str = include_str!("migrations/v4.sql");
pub(crate) const SCHEMA_V5: &str = include_str!("migrations/v5.sql");

const V3_TABLES: &[(&str, &[&str])] = &[
    (
        "assessment_auth_profiles",
        &[
            "id",
            "project_id",
            "label",
            "source_traffic_id",
            "header_name",
            "secret_revision",
        ],
    ),
    (
        "assessment_runs",
        &[
            "id",
            "project_id",
            "status",
            "start_url",
            "exact_origin",
            "contract_json",
            "contract_hash",
            "template_registry_hash",
            "request_budget",
            "request_count",
            "response_bytes_read",
            "stop_reason",
        ],
    ),
    (
        "assessment_rounds",
        &["id", "run_id", "round_number", "analysis_run_id", "status"],
    ),
    (
        "assessment_endpoints",
        &[
            "id",
            "run_id",
            "endpoint_key",
            "method",
            "url",
            "path",
            "query_parameter_names",
            "resource_owner_profile_id",
        ],
    ),
    (
        "assessment_checks",
        &[
            "id",
            "run_id",
            "round_id",
            "endpoint_id",
            "requested_endpoint_id",
            "template_id",
            "template_version",
            "identity_mode",
            "policy_result",
            "status",
        ],
    ),
    (
        "assessment_check_replays",
        &["check_id", "replay_run_id", "role"],
    ),
    (
        "assessment_verifications",
        &[
            "id",
            "check_id",
            "verifier_id",
            "verifier_version",
            "verdict",
            "observations_json",
            "content_hash",
        ],
    ),
    (
        "assessment_finding_links",
        &["verification_id", "finding_id", "relation"],
    ),
    (
        "assessment_coverage_gaps",
        &[
            "id",
            "run_id",
            "check_id",
            "category",
            "reason_code",
            "detail",
        ],
    ),
    (
        "assessment_events",
        &["id", "run_id", "check_id", "event_type", "details_json"],
    ),
];

const V3_EXTENDED_COLUMNS: &[(&str, &[&str])] = &[
    ("replay_sessions", &["owner_kind", "assessment_run_id"]),
    ("findings", &["producer"]),
    ("finding_evidence", &["acceptance_kind", "verification_id"]),
];

const V3_INDEXES: &[&str] = &[
    "idx_assessment_auth_profiles_project",
    "idx_assessment_runs_project",
    "idx_assessment_runs_one_active",
    "idx_assessment_rounds_run",
    "idx_assessment_endpoints_run",
    "idx_assessment_checks_run",
    "idx_replay_sessions_assessment",
    "idx_assessment_check_replays_run",
    "idx_assessment_verifications_verdict",
    "idx_assessment_finding_links_finding",
    "idx_assessment_coverage_gaps_run",
    "idx_assessment_events_run",
    "idx_finding_evidence_verification",
];

const V3_TRIGGERS: &[&str] = &[
    "trg_assessment_auth_source_project_insert",
    "trg_assessment_auth_source_project_update",
    "trg_assessment_run_profiles_same_project_insert",
    "trg_assessment_run_profiles_same_project_update",
    "trg_assessment_round_same_project_insert",
    "trg_assessment_endpoint_same_project_insert",
    "trg_assessment_check_context_insert",
    "trg_assessment_replay_session_context_insert",
    "trg_assessment_replay_session_context_update",
    "trg_assessment_check_replay_context_insert",
    "trg_assessment_finding_link_context_insert",
    "trg_assessment_gap_context_insert",
    "trg_assessment_event_context_insert",
    "trg_assessment_run_status_requires_event",
    "trg_assessment_events_immutable_update",
    "trg_assessment_events_immutable_delete",
    "trg_assessment_verifications_immutable_update",
    "trg_assessment_verifications_immutable_delete",
    "trg_assessment_finding_links_immutable_update",
    "trg_assessment_finding_links_immutable_delete",
    "trg_finding_evidence_verifier_authority_insert",
    "trg_finding_evidence_verifier_authority_update",
];

/// (table, from column, referenced table, referenced column, ON DELETE)
const V3_FOREIGN_KEYS: &[(&str, &str, &str, &str, &str)] = &[
    (
        "assessment_auth_profiles",
        "project_id",
        "projects",
        "id",
        "CASCADE",
    ),
    (
        "assessment_auth_profiles",
        "source_traffic_id",
        "traffic",
        "id",
        "SET NULL",
    ),
    ("assessment_runs", "project_id", "projects", "id", "CASCADE"),
    (
        "assessment_runs",
        "identity_a_profile_id",
        "assessment_auth_profiles",
        "id",
        "SET NULL",
    ),
    (
        "assessment_runs",
        "identity_b_profile_id",
        "assessment_auth_profiles",
        "id",
        "SET NULL",
    ),
    (
        "assessment_rounds",
        "run_id",
        "assessment_runs",
        "id",
        "CASCADE",
    ),
    (
        "assessment_rounds",
        "analysis_run_id",
        "analysis_runs",
        "id",
        "SET NULL",
    ),
    (
        "assessment_endpoints",
        "run_id",
        "assessment_runs",
        "id",
        "CASCADE",
    ),
    (
        "assessment_endpoints",
        "source_traffic_id",
        "traffic",
        "id",
        "SET NULL",
    ),
    (
        "assessment_endpoints",
        "resource_owner_profile_id",
        "assessment_auth_profiles",
        "id",
        "SET NULL",
    ),
    (
        "assessment_checks",
        "run_id",
        "assessment_runs",
        "id",
        "CASCADE",
    ),
    (
        "assessment_checks",
        "round_id",
        "assessment_rounds",
        "id",
        "SET NULL",
    ),
    (
        "assessment_checks",
        "endpoint_id",
        "assessment_endpoints",
        "id",
        "CASCADE",
    ),
    (
        "replay_sessions",
        "assessment_run_id",
        "assessment_runs",
        "id",
        "CASCADE",
    ),
    (
        "assessment_check_replays",
        "check_id",
        "assessment_checks",
        "id",
        "CASCADE",
    ),
    (
        "assessment_check_replays",
        "replay_run_id",
        "replay_runs",
        "id",
        "RESTRICT",
    ),
    (
        "assessment_verifications",
        "check_id",
        "assessment_checks",
        "id",
        "CASCADE",
    ),
    (
        "assessment_finding_links",
        "verification_id",
        "assessment_verifications",
        "id",
        "CASCADE",
    ),
    (
        "assessment_finding_links",
        "finding_id",
        "findings",
        "id",
        "CASCADE",
    ),
    (
        "assessment_coverage_gaps",
        "run_id",
        "assessment_runs",
        "id",
        "CASCADE",
    ),
    (
        "assessment_coverage_gaps",
        "check_id",
        "assessment_checks",
        "id",
        "SET NULL",
    ),
    (
        "assessment_events",
        "run_id",
        "assessment_runs",
        "id",
        "CASCADE",
    ),
    (
        "assessment_events",
        "check_id",
        "assessment_checks",
        "id",
        "SET NULL",
    ),
    (
        "finding_evidence",
        "verification_id",
        "assessment_verifications",
        "id",
        "RESTRICT",
    ),
];

const V4_TABLES: &[(&str, &[&str])] = &[
    (
        "assessment_missions",
        &[
            "id",
            "project_id",
            "title",
            "goal",
            "start_url",
            "exact_origin",
            "status",
            "autonomy_mode",
            "budget_profile",
            "request_budget",
            "max_planning_cycles",
            "contract_hash",
            "tool_registry_hash",
            "permission_hash",
            "context_hash",
            "context_approved_hash",
            "active_run_id",
            "legacy_run_id",
            "legacy",
            "revision",
        ],
    ),
    (
        "assessment_messages",
        &[
            "id",
            "mission_id",
            "role",
            "message_kind",
            "content",
            "content_hash",
            "old_value",
            "new_value",
            "details_json",
            "revision",
        ],
    ),
    (
        "assessment_workstreams",
        &[
            "id",
            "mission_id",
            "parent_id",
            "stable_key",
            "title",
            "objective",
            "status",
            "sort_order",
        ],
    ),
    (
        "assessment_actions",
        &[
            "id",
            "mission_id",
            "workstream_id",
            "tool_id",
            "tool_version",
            "execution_kind",
            "risk_level",
            "surface_id",
            "identity_mode",
            "parameter_json",
            "rationale",
            "expected_signal",
            "request_cost",
            "permission_snapshot",
            "permission_hash",
            "approval_status",
            "approval_source",
            "status",
            "redacted_request_json",
            "redacted_response_json",
            "result_json",
            "revision",
        ],
    ),
    (
        "assessment_mission_resources",
        &[
            "id",
            "mission_id",
            "resource_type",
            "source_id",
            "display_name",
            "media_type",
            "summary_json",
            "content_hash",
        ],
    ),
    (
        "assessment_tool_permissions",
        &[
            "project_id",
            "tool_id",
            "decision",
            "revision",
            "updated_at",
        ],
    ),
    (
        "assessment_surfaces",
        &[
            "id",
            "run_id",
            "surface_id",
            "surface_kind",
            "method",
            "path_shape",
            "query_parameter_names",
            "form_fields_json",
            "content_types_json",
            "identity_visibility_json",
            "response_structure_hash",
            "source_kinds_json",
            "safe_to_request",
            "concrete_count",
        ],
    ),
    (
        "assessment_action_checks",
        &["action_id", "check_id", "linked_at"],
    ),
    (
        "assessment_mission_runs",
        &["mission_id", "run_id", "cycle", "linked_at"],
    ),
    (
        "assessment_manual_handoffs",
        &[
            "id",
            "action_id",
            "recipe_id",
            "recipe_version",
            "draft_json",
            "draft_hash",
            "replay_session_id",
            "replay_run_id",
            "evidence_id",
            "status",
        ],
    ),
];

const V4_INDEXES: &[&str] = &[
    "idx_assessment_missions_project",
    "idx_assessment_missions_status",
    "idx_assessment_missions_one_network_active",
    "idx_assessment_messages_mission",
    "idx_assessment_workstreams_mission",
    "idx_assessment_actions_mission",
    "idx_assessment_actions_waiting",
    "idx_assessment_mission_resources_mission",
    "idx_assessment_surfaces_run",
    "idx_assessment_tool_permissions_project",
    "idx_assessment_action_checks_check",
    "idx_assessment_mission_runs_mission",
    "idx_assessment_manual_handoffs_status",
];

const V4_TRIGGERS: &[&str] = &[
    "trg_assessment_mission_profiles_same_project_insert",
    "trg_assessment_mission_profiles_same_project_update",
    "trg_assessment_workstream_parent_context_insert",
    "trg_assessment_workstream_parent_context_update",
    "trg_assessment_action_context_insert",
    "trg_assessment_action_identity_immutable_update",
    "trg_assessment_resource_context_insert",
    "trg_assessment_action_check_context_insert",
    "trg_assessment_mission_run_context_insert",
    "trg_assessment_handoff_context_insert",
    "trg_assessment_handoff_context_update",
    "trg_assessment_mission_status_requires_message",
    "trg_assessment_messages_immutable_update",
    "trg_assessment_messages_immutable_delete",
    "trg_assessment_resources_immutable_update",
    "trg_assessment_resources_immutable_delete",
];

const V4_FOREIGN_KEYS: &[(&str, &str, &str, &str, &str)] = &[
    (
        "assessment_missions",
        "project_id",
        "projects",
        "id",
        "CASCADE",
    ),
    (
        "assessment_missions",
        "identity_a_profile_id",
        "assessment_auth_profiles",
        "id",
        "SET NULL",
    ),
    (
        "assessment_missions",
        "identity_b_profile_id",
        "assessment_auth_profiles",
        "id",
        "SET NULL",
    ),
    (
        "assessment_missions",
        "active_run_id",
        "assessment_runs",
        "id",
        "SET NULL",
    ),
    (
        "assessment_missions",
        "legacy_run_id",
        "assessment_runs",
        "id",
        "CASCADE",
    ),
    (
        "assessment_messages",
        "mission_id",
        "assessment_missions",
        "id",
        "CASCADE",
    ),
    (
        "assessment_workstreams",
        "mission_id",
        "assessment_missions",
        "id",
        "CASCADE",
    ),
    (
        "assessment_workstreams",
        "parent_id",
        "assessment_workstreams",
        "id",
        "CASCADE",
    ),
    (
        "assessment_actions",
        "mission_id",
        "assessment_missions",
        "id",
        "CASCADE",
    ),
    (
        "assessment_actions",
        "workstream_id",
        "assessment_workstreams",
        "id",
        "SET NULL",
    ),
    (
        "assessment_mission_resources",
        "mission_id",
        "assessment_missions",
        "id",
        "CASCADE",
    ),
    (
        "assessment_tool_permissions",
        "project_id",
        "projects",
        "id",
        "CASCADE",
    ),
    (
        "assessment_surfaces",
        "run_id",
        "assessment_runs",
        "id",
        "CASCADE",
    ),
    (
        "assessment_action_checks",
        "action_id",
        "assessment_actions",
        "id",
        "CASCADE",
    ),
    (
        "assessment_action_checks",
        "check_id",
        "assessment_checks",
        "id",
        "CASCADE",
    ),
    (
        "assessment_mission_runs",
        "mission_id",
        "assessment_missions",
        "id",
        "CASCADE",
    ),
    (
        "assessment_mission_runs",
        "run_id",
        "assessment_runs",
        "id",
        "CASCADE",
    ),
    (
        "assessment_manual_handoffs",
        "action_id",
        "assessment_actions",
        "id",
        "CASCADE",
    ),
    (
        "assessment_manual_handoffs",
        "replay_session_id",
        "replay_sessions",
        "id",
        "SET NULL",
    ),
    (
        "assessment_manual_handoffs",
        "replay_run_id",
        "replay_runs",
        "id",
        "RESTRICT",
    ),
    (
        "assessment_manual_handoffs",
        "evidence_id",
        "evidence",
        "id",
        "RESTRICT",
    ),
];

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
            2 => apply_step(conn, 3, SCHEMA_V3)?,
            3 => apply_step(conn, 4, SCHEMA_V4)?,
            4 => apply_step(conn, 5, SCHEMA_V5)?,
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
    // v4 widens two v3 CHECK constraints by transactionally rebuilding the
    // parent tables. SQLite cannot toggle FK enforcement inside a transaction,
    // so preserve the connection setting, disable it only for this step, then
    // run the normal structural + foreign_key_check validation before commit.
    let foreign_keys_enabled: bool =
        conn.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    let rebuilds_v3_parents = target_version == 4;
    if rebuilds_v3_parents && foreign_keys_enabled {
        conn.pragma_update(None, "foreign_keys", false)?;
    }
    let result = (|| {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(sql)?;
        if target_version == 5 {
            migrate_security_baseline_findings(&tx)?;
        }
        validate_version(&tx, target_version)?;
        tx.pragma_update(None, "user_version", target_version)?;
        tx.commit()?;
        Ok(())
    })();
    let restore = if rebuilds_v3_parents && foreign_keys_enabled {
        conn.pragma_update(None, "foreign_keys", true)
            .map_err(MigrationError::from)
    } else {
        Ok(())
    };
    match (result, restore) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn validate_version(conn: &Connection, version: u32) -> Result<(), MigrationError> {
    match version {
        1 => validate_v1(conn),
        2 => validate_v2(conn),
        3 => validate_v3(conn),
        4 => validate_v4(conn),
        5 => validate_v5(conn),
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

fn validate_v3(conn: &Connection) -> Result<(), MigrationError> {
    validate_v2(conn)?;

    for (table, required_columns) in V3_TABLES.iter().chain(V3_EXTENDED_COLUMNS.iter()) {
        let columns = table_columns(conn, table)?;
        if columns.is_empty() {
            return Err(invalid_v3(format!("缺少表 `{table}`")));
        }
        for column in *required_columns {
            if !columns.contains(*column) {
                return Err(invalid_v3(format!("表 `{table}` 缺少字段 `{column}`")));
            }
        }
    }

    for index in V3_INDEXES {
        if !schema_object_exists(conn, "index", index)? {
            return Err(invalid_v3(format!("缺少索引 `{index}`")));
        }
    }

    for trigger in V3_TRIGGERS {
        if !schema_object_exists(conn, "trigger", trigger)? {
            return Err(invalid_v3(format!("缺少触发器 `{trigger}`")));
        }
    }

    for (table, from_column, referenced_table, referenced_column, on_delete) in V3_FOREIGN_KEYS {
        if !foreign_key_exists(
            conn,
            table,
            from_column,
            referenced_table,
            referenced_column,
            on_delete,
        )? {
            return Err(invalid_v3(format!(
                "表 `{table}` 缺少外键 `{from_column}` -> `{referenced_table}.{referenced_column}` ON DELETE {on_delete}"
            )));
        }
    }

    let integrity: String = conn.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(invalid_v3(format!("SQLite quick_check: {integrity}")));
    }

    let mut foreign_keys = conn.prepare("PRAGMA foreign_key_check")?;
    let mut violations = foreign_keys.query([])?;
    if let Some(row) = violations.next()? {
        let table: String = row.get(0)?;
        let row_id: Option<i64> = row.get(1)?;
        return Err(invalid_v3(format!(
            "外键完整性失败: table={table}, rowid={row_id:?}"
        )));
    }
    Ok(())
}

fn validate_v4(conn: &Connection) -> Result<(), MigrationError> {
    validate_v3(conn)?;

    for (table, required_check) in [
        ("assessment_runs", "max_rounds BETWEEN 1 AND 6"),
        ("assessment_rounds", "round_number BETWEEN 1 AND 6"),
    ] {
        let sql: String = conn.query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
            [table],
            |row| row.get(0),
        )?;
        if !sql.contains(required_check) {
            return Err(invalid_v4(format!(
                "表 `{table}` 未启用 6 轮 mission 规划约束"
            )));
        }
    }

    for (table, required_columns) in V4_TABLES {
        let columns = table_columns(conn, table)?;
        if columns.is_empty() {
            return Err(invalid_v4(format!("缺少表 `{table}`")));
        }
        for column in *required_columns {
            if !columns.contains(*column) {
                return Err(invalid_v4(format!("表 `{table}` 缺少字段 `{column}`")));
            }
        }
    }

    for index in V4_INDEXES {
        if !schema_object_exists(conn, "index", index)? {
            return Err(invalid_v4(format!("缺少索引 `{index}`")));
        }
    }

    for trigger in V4_TRIGGERS {
        if !schema_object_exists(conn, "trigger", trigger)? {
            return Err(invalid_v4(format!("缺少触发器 `{trigger}`")));
        }
    }

    for (table, from_column, referenced_table, referenced_column, on_delete) in V4_FOREIGN_KEYS {
        if !foreign_key_exists(
            conn,
            table,
            from_column,
            referenced_table,
            referenced_column,
            on_delete,
        )? {
            return Err(invalid_v4(format!(
                "表 `{table}` 缺少外键 `{from_column}` -> `{referenced_table}.{referenced_column}` ON DELETE {on_delete}"
            )));
        }
    }

    let integrity: String = conn.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(invalid_v4(format!("SQLite quick_check: {integrity}")));
    }
    let mut foreign_keys = conn.prepare("PRAGMA foreign_key_check")?;
    let mut violations = foreign_keys.query([])?;
    if let Some(row) = violations.next()? {
        let table: String = row.get(0)?;
        let row_id: Option<i64> = row.get(1)?;
        return Err(invalid_v4(format!(
            "外键完整性失败: table={table}, rowid={row_id:?}"
        )));
    }
    Ok(())
}

fn validate_v5(conn: &Connection) -> Result<(), MigrationError> {
    // v5 intentionally changes Finding identity data without widening the
    // schema. All structural and referential guarantees therefore remain v4.
    validate_v4(conn)
}

#[derive(Debug)]
struct LegacySecurityBaselineFinding {
    id: i64,
    status: String,
    severity: String,
    analyst_notes: String,
    occurrences: i64,
    created_at: String,
    last_seen_at: String,
    updated_at: String,
    semantic_variants: BTreeMap<String, SecurityBaselineKinds>,
    has_unmigratable_link: bool,
}

/// Promote old per-URL baseline identities when every linked verification has
/// the same exact-origin/semantic-gap identity. Ambiguous histories and shared
/// audit relationships remain legacy records; migration must never invent a
/// gap union or discard a per-Finding Evidence judgment.
fn migrate_security_baseline_findings(tx: &Transaction<'_>) -> Result<(), MigrationError> {
    let mut findings = HashMap::<i64, LegacySecurityBaselineFinding>::new();
    {
        let mut statement = tx.prepare(
            "SELECT f.id, f.project_id, f.status, f.severity, f.analyst_notes,
                    f.occurrences, f.created_at, f.last_seen_at, f.updated_at,
                    ar.exact_origin, av.observations_json
             FROM findings f
             JOIN assessment_finding_links afl ON afl.finding_id = f.id
             JOIN assessment_verifications av ON av.id = afl.verification_id
             JOIN assessment_checks ac ON ac.id = av.check_id
             JOIN assessment_runs ar ON ar.id = ac.run_id
             WHERE f.producer = 'safe_verifier'
               AND ac.template_id = 'security_headers_cookie'
             ORDER BY f.id, av.id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, String>(10)?,
            ))
        })?;
        for row in rows {
            let (
                id,
                project_id,
                status,
                severity,
                analyst_notes,
                occurrences,
                created_at,
                last_seen_at,
                updated_at,
                exact_origin,
                observations_json,
            ) = row?;
            let observations: Value =
                serde_json::from_str(&observations_json).map_err(|error| {
                    invalid_v5(format!(
                        "Finding #{id} 的安全基线 observations 无法解析: {error}"
                    ))
                })?;
            let finding = findings
                .entry(id)
                .or_insert_with(|| LegacySecurityBaselineFinding {
                    id,
                    status,
                    severity,
                    analyst_notes,
                    occurrences,
                    created_at,
                    last_seen_at,
                    updated_at,
                    semantic_variants: BTreeMap::new(),
                    has_unmigratable_link: false,
                });
            let observed_kinds = SecurityBaselineKinds::from_observations(&observations);
            let Some(fingerprint) = security_baseline_fingerprint_for_kinds(
                project_id,
                "security_headers_cookie",
                &exact_origin,
                &observed_kinds,
            ) else {
                finding.has_unmigratable_link = true;
                continue;
            };
            if let Some(existing) = finding.semantic_variants.get(&fingerprint) {
                if existing != &observed_kinds {
                    finding.has_unmigratable_link = true;
                }
            } else {
                finding
                    .semantic_variants
                    .insert(fingerprint, observed_kinds);
            }
        }
    }

    let mut groups = BTreeMap::<String, Vec<LegacySecurityBaselineFinding>>::new();
    for finding in findings.into_values() {
        // A v4 endpoint Finding may legitimately contain observations from
        // different points in time. There is no lossless way to project one
        // human review state and one occurrence count onto several semantic
        // identities, so preserve that row as legacy instead of fabricating a
        // union of gaps that no verification observed.
        if finding.has_unmigratable_link || finding.semantic_variants.len() != 1 {
            continue;
        }
        let fingerprint = finding
            .semantic_variants
            .first_key_value()
            .expect("one semantic variant checked above")
            .0
            .clone();
        groups.entry(fingerprint).or_default().push(finding);
    }
    if groups.is_empty() {
        return Ok(());
    }

    // These two audit tables are append-only during normal operation. Their
    // foreign keys are repointed only inside this atomic migration and the
    // guards are restored before validation/commit.
    tx.execute_batch(
        "DROP TRIGGER IF EXISTS trg_finding_events_immutable_update;
         DROP TRIGGER IF EXISTS trg_assessment_finding_links_immutable_update;",
    )?;

    for (fingerprint, mut group) in groups {
        group.sort_by_key(|finding| finding.id);
        let first = &group[0];
        let same_review_state = group.iter().all(|finding| {
            finding.status == first.status
                && finding.severity == first.severity
                && (group.len() == 1 || finding.analyst_notes.trim().is_empty())
        });
        if !same_review_state {
            // Preserve divergent human decisions as separate legacy records.
            continue;
        }
        if group.len() > 1 && finding_group_has_shared_audit_links(tx, &group)? {
            // Both relationship tables use composite primary keys. More
            // importantly, a shared Evidence may carry different per-Finding
            // human decisions. Preserve such rows rather than failing the
            // migration or silently discarding one audit record.
            continue;
        }

        let canonical_id = first.id;
        let kinds = first
            .semantic_variants
            .values()
            .next()
            .expect("one semantic variant checked above");
        let title = security_baseline_title(kinds);
        let occurrences = group.iter().try_fold(0_i64, |total, finding| {
            total.checked_add(finding.occurrences).ok_or_else(|| {
                invalid_v5(format!("合并 Finding #{canonical_id} 时 occurrences 溢出"))
            })
        })?;
        let created_at = group
            .iter()
            .map(|finding| finding.created_at.as_str())
            .min()
            .unwrap_or(first.created_at.as_str());
        let last_seen_at = group
            .iter()
            .map(|finding| finding.last_seen_at.as_str())
            .max()
            .unwrap_or(first.last_seen_at.as_str());
        let updated_at = group
            .iter()
            .map(|finding| finding.updated_at.as_str())
            .max()
            .unwrap_or(first.updated_at.as_str());

        // Free every legacy unique key first so this also handles a database
        // that already contains one row with the new semantic fingerprint.
        for finding in &group {
            tx.execute(
                "UPDATE findings SET fingerprint = NULL WHERE id = ?1",
                [finding.id],
            )?;
        }

        for duplicate in group.iter().skip(1) {
            tx.execute(
                "UPDATE assessment_finding_links SET finding_id = ?1 WHERE finding_id = ?2",
                rusqlite::params![canonical_id, duplicate.id],
            )?;
            tx.execute(
                "UPDATE finding_evidence SET finding_id = ?1 WHERE finding_id = ?2",
                rusqlite::params![canonical_id, duplicate.id],
            )?;
            tx.execute(
                "UPDATE finding_events SET finding_id = ?1 WHERE finding_id = ?2",
                rusqlite::params![canonical_id, duplicate.id],
            )?;
            tx.execute(
                "UPDATE OR IGNORE finding_traffic SET finding_id = ?1 WHERE finding_id = ?2",
                rusqlite::params![canonical_id, duplicate.id],
            )?;
            tx.execute(
                "UPDATE OR IGNORE finding_rule_hits SET finding_id = ?1 WHERE finding_id = ?2",
                rusqlite::params![canonical_id, duplicate.id],
            )?;
            tx.execute(
                "UPDATE OR IGNORE task_findings SET finding_id = ?1 WHERE finding_id = ?2",
                rusqlite::params![canonical_id, duplicate.id],
            )?;
            tx.execute("DELETE FROM findings WHERE id = ?1", [duplicate.id])?;
        }

        tx.execute(
            "UPDATE findings
             SET title = ?2, fingerprint = ?3, occurrences = ?4,
                 created_at = ?5, last_seen_at = ?6, updated_at = ?7
             WHERE id = ?1",
            rusqlite::params![
                canonical_id,
                title,
                fingerprint,
                occurrences,
                created_at,
                last_seen_at,
                updated_at,
            ],
        )?;
    }

    tx.execute_batch(
        "CREATE TRIGGER trg_finding_events_immutable_update
         BEFORE UPDATE ON finding_events
         BEGIN
             SELECT RAISE(ABORT, 'finding events are immutable');
         END;
         CREATE TRIGGER trg_assessment_finding_links_immutable_update
         BEFORE UPDATE ON assessment_finding_links
         BEGIN
             SELECT RAISE(ABORT, 'assessment finding links are immutable');
         END;",
    )?;
    Ok(())
}

fn finding_group_has_shared_audit_links(
    tx: &Transaction<'_>,
    group: &[LegacySecurityBaselineFinding],
) -> Result<bool, MigrationError> {
    let mut evidence_ids = HashSet::<i64>::new();
    let mut verification_ids = HashSet::<i64>::new();
    for finding in group {
        let mut evidence_statement =
            tx.prepare("SELECT evidence_id FROM finding_evidence WHERE finding_id = ?1")?;
        let evidence_rows =
            evidence_statement.query_map([finding.id], |row| row.get::<_, i64>(0))?;
        for evidence_id in evidence_rows {
            if !evidence_ids.insert(evidence_id?) {
                return Ok(true);
            }
        }

        let mut verification_statement = tx.prepare(
            "SELECT verification_id FROM assessment_finding_links WHERE finding_id = ?1",
        )?;
        let verification_rows =
            verification_statement.query_map([finding.id], |row| row.get::<_, i64>(0))?;
        for verification_id in verification_rows {
            if !verification_ids.insert(verification_id?) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn schema_object_exists(
    conn: &Connection,
    object_type: &str,
    name: &str,
) -> Result<bool, rusqlite::Error> {
    conn.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM sqlite_master WHERE type = ?1 AND name = ?2
         )",
        (object_type, name),
        |row| row.get(0),
    )
}

fn table_columns(conn: &Connection, table: &str) -> Result<HashSet<String>, rusqlite::Error> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info(\"{table}\")"))?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    rows.collect()
}

fn foreign_key_exists(
    conn: &Connection,
    table: &str,
    from_column: &str,
    referenced_table: &str,
    referenced_column: &str,
    on_delete: &str,
) -> Result<bool, rusqlite::Error> {
    let mut statement = conn.prepare(&format!("PRAGMA foreign_key_list(\"{table}\")"))?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(6)?,
        ))
    })?;
    for row in rows {
        let (target_table, source_column, target_column, delete_action) = row?;
        if source_column == from_column
            && target_table == referenced_table
            && target_column == referenced_column
            && delete_action.eq_ignore_ascii_case(on_delete)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn invalid_v1(reason: String) -> MigrationError {
    MigrationError::InvalidSchema { version: 1, reason }
}

fn invalid_v3(reason: String) -> MigrationError {
    MigrationError::InvalidSchema { version: 3, reason }
}

fn invalid_v4(reason: String) -> MigrationError {
    MigrationError::InvalidSchema { version: 4, reason }
}

fn invalid_v5(reason: String) -> MigrationError {
    MigrationError::InvalidSchema { version: 5, reason }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
                to_version: 5,
            }
        );
        assert_eq!(schema_version(&conn).unwrap(), 5);
        validate_v5(&conn).unwrap();
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
        assert_eq!(report.to_version, 5);
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
                from_version: 5,
                to_version: 5,
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
                to_version: 5,
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
        validate_v5(&conn).unwrap();
    }

    #[test]
    fn v2_migrates_assessment_schema_without_losing_legacy_task_tree() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
        conn.execute_batch(SCHEMA_V2).unwrap();
        conn.pragma_update(None, "user_version", 2).unwrap();
        conn.execute("INSERT INTO projects(id, name) VALUES(1, 'existing')", [])
            .unwrap();
        conn.execute(
            "INSERT INTO test_plans(project_id, revision) VALUES(1, 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO task_nodes(id, project_id, title) VALUES(7, 1, 'legacy node')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO analysis_runs(
                 id, project_id, provider_id, provider_base_url, model, prompt_id,
                 prompt_version, input_hash, policy_json, manifest_json,
                 validation_status, validation_json, raw_output_hash
             ) VALUES(
                 8, 1, 'legacy', 'https://provider.test/v1', 'model', 'prompt',
                 1, ?1, '{}', '{}', 'valid', '{}', ?1
             )",
            ["a".repeat(64)],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO findings(id, project_id, analysis_run_id, source, title)
             VALUES(9, 1, 8, 'ai', 'legacy ai')",
            [],
        )
        .unwrap();

        let report = migrate(&mut conn).unwrap();

        assert_eq!(report.from_version, 2);
        assert_eq!(report.to_version, 5);
        let legacy_title: String = conn
            .query_row("SELECT title FROM task_nodes WHERE id = 7", [], |row| {
                row.get(0)
            })
            .unwrap();
        let producer: String = conn
            .query_row("SELECT producer FROM findings WHERE id = 9", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(legacy_title, "legacy node");
        assert_eq!(producer, "ai");
        validate_v5(&conn).unwrap();
    }

    #[test]
    fn v3_enforces_global_admission_audit_immutability_and_lifecycle_cascade() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        migrate(&mut conn).unwrap();
        conn.execute_batch(
            "INSERT INTO projects(id, name, scope) VALUES
                 (1, 'assessment-a', '[\"a.test\"]'),
                 (2, 'assessment-b', '[\"b.test\"]');
             INSERT INTO assessment_auth_profiles(
                 id, project_id, label, header_name
             ) VALUES(9, 2, 'foreign identity', 'Authorization');",
        )
        .unwrap();
        let run_sql = "INSERT INTO assessment_runs(
                 id, project_id, status, start_url, exact_origin, contract_json,
                 contract_hash, template_registry_hash, provider_id, model,
                 request_budget, discovery_budget, requests_per_second
             ) VALUES(?1, ?2, ?3, ?4, ?5, '{}', ?6, ?6, 'provider', 'model',
                      120, 40, 1.0)";
        conn.execute(
            run_sql,
            rusqlite::params![
                10,
                1,
                "queued",
                "https://a.test/",
                "https://a.test:443",
                "a".repeat(64),
            ],
        )
        .unwrap();
        assert!(
            conn.execute(
                run_sql,
                rusqlite::params![
                    11,
                    2,
                    "queued",
                    "https://b.test/",
                    "https://b.test:443",
                    "b".repeat(64),
                ],
            )
            .is_err(),
            "only one active assessment is allowed globally"
        );
        assert!(
            conn.execute(
                "INSERT INTO assessment_runs(
                     id, project_id, status, start_url, exact_origin, contract_json,
                     contract_hash, template_registry_hash, identity_a_profile_id,
                     provider_id, model, request_budget, discovery_budget,
                     requests_per_second
                 ) VALUES(
                     12, 1, 'completed', 'https://a.test/', 'https://a.test:443',
                     '{}', ?1, ?1, 9, 'provider', 'model', 120, 40, 1.0
                 )",
                ["c".repeat(64)],
            )
            .is_err(),
            "identity profiles cannot cross projects"
        );

        assert!(
            conn.execute(
                "UPDATE assessment_runs SET status='discovering' WHERE id=10",
                [],
            )
            .is_err(),
            "status changes require a preceding event"
        );
        conn.execute(
            "INSERT INTO assessment_events(
                 run_id, event_type, old_value, new_value, details_json
             ) VALUES(10, 'status_changed', 'queued', 'discovering', '{}')",
            [],
        )
        .unwrap();
        conn.execute(
            "UPDATE assessment_runs SET status='discovering' WHERE id=10",
            [],
        )
        .unwrap();
        assert!(conn
            .execute(
                "UPDATE assessment_events SET details_json='{\"tampered\":true}'
                 WHERE run_id=10",
                [],
            )
            .is_err());

        conn.execute(
            "INSERT INTO assessment_endpoints(
                 id, run_id, endpoint_key, method, url, path, source_kind
             ) VALUES(20,10,?1,'GET','https://a.test/','/','start_url')",
            ["d".repeat(64)],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO assessment_checks(
                 id, run_id, endpoint_id, requested_endpoint_id, template_id,
                 template_version, identity_mode, policy_result, status
             ) VALUES(
                 30,10,20,'ep_fixture','security_headers_cookie','1',
                 'anonymous','allowed','completed'
             )",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO assessment_verifications(
                 id, check_id, verifier_id, verifier_version, verdict,
                 observations_json, content_hash
             ) VALUES(40,30,'security_headers_cookie','1','not_observed','{}',?1)",
            ["e".repeat(64)],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO findings(
                 id, project_id, source, producer, title
             ) VALUES(50,1,'rule','safe_verifier','fixture')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO assessment_finding_links(
                 verification_id, finding_id, relation
             ) VALUES(40,50,'supports')",
            [],
        )
        .unwrap();
        assert!(conn
            .execute(
                "UPDATE assessment_verifications SET observations_json='{\"x\":1}'
                 WHERE id=40",
                [],
            )
            .is_err());
        assert!(conn
            .execute(
                "UPDATE assessment_finding_links SET relation='human_conflict'
                 WHERE verification_id=40 AND finding_id=50",
                [],
            )
            .is_err());
        conn.execute(
            "INSERT INTO assessment_coverage_gaps(
                 run_id, check_id, category, reason_code, detail
             ) VALUES(10,30,'fixture','not_covered','fixture gap')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO assessment_events(
                 run_id, event_type, old_value, new_value, details_json
             ) VALUES(10, 'status_changed', 'discovering', 'completed', '{}')",
            [],
        )
        .unwrap();
        conn.execute(
            "UPDATE assessment_runs SET status='completed' WHERE id=10",
            [],
        )
        .unwrap();

        conn.execute("DELETE FROM projects WHERE id=1", []).unwrap();
        for table in [
            "assessment_runs",
            "assessment_endpoints",
            "assessment_checks",
            "assessment_verifications",
            "assessment_finding_links",
            "assessment_coverage_gaps",
            "assessment_events",
        ] {
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "{table} must be removed by project lifecycle");
        }
        validate_v5(&conn).unwrap();
    }

    #[test]
    fn v3_to_v4_backfills_legacy_runs_without_reactivating_task_nodes() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
        conn.execute_batch(SCHEMA_V2).unwrap();
        conn.execute_batch(SCHEMA_V3).unwrap();
        conn.pragma_update(None, "user_version", 3).unwrap();
        conn.execute("INSERT INTO projects(id, name) VALUES(1, 'legacy')", [])
            .unwrap();
        conn.execute(
            "INSERT INTO task_nodes(id, project_id, title) VALUES(7, 1, 'legacy tree')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO assessment_runs(
                 id, project_id, status, start_url, exact_origin, contract_json,
                 contract_hash, template_registry_hash, provider_id, model,
                 request_budget, discovery_budget, requests_per_second
             ) VALUES(
                 9, 1, 'completed', 'https://legacy.test/',
                 'https://legacy.test:443', '{}', ?1, ?2, 'fixture', 'model',
                 120, 20, 1.0
             )",
            rusqlite::params!["a".repeat(64), "b".repeat(64)],
        )
        .unwrap();

        let report = migrate(&mut conn).unwrap();

        assert_eq!(report.from_version, 3);
        assert_eq!(report.to_version, 5);
        let mission: (i64, i64, String, i64) = conn
            .query_row(
                "SELECT project_id, legacy_run_id, status, legacy
                 FROM assessment_missions",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(mission, (1, 9, "completed".to_string(), 1));
        let legacy_tree: String = conn
            .query_row("SELECT title FROM task_nodes WHERE id=7", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(legacy_tree, "legacy tree");
        let action_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM assessment_actions", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(action_count, 0);
        conn.execute("UPDATE assessment_runs SET max_rounds=6 WHERE id=9", [])
            .unwrap();
        conn.execute(
            "INSERT INTO assessment_rounds(
                 run_id, round_number, status, input_hash, selected_checks
             ) VALUES(9,6,'valid',?1,0)",
            ["c".repeat(64)],
        )
        .unwrap();
        let sixth_round: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM assessment_rounds
                 WHERE run_id=9 AND round_number=6",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(sixth_round, 1);
        validate_v5(&conn).unwrap();
    }

    fn v4_security_baseline_database() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
        conn.execute_batch(SCHEMA_V2).unwrap();
        conn.execute_batch(SCHEMA_V3).unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        conn.pragma_update(None, "user_version", 3).unwrap();
        apply_step(&mut conn, 4, SCHEMA_V4).unwrap();
        conn.execute(
            "INSERT INTO projects(id, name) VALUES(1, 'legacy baseline')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO assessment_runs(
                 id, project_id, status, start_url, exact_origin, contract_json,
                 contract_hash, template_registry_hash, provider_id, model,
                 request_budget, discovery_budget, requests_per_second
             ) VALUES(
                 10, 1, 'completed', 'http://target.test:9011/',
                 'http://target.test:9011', '{}', ?1, ?1, 'fixture', 'model',
                 120, 20, 1.0
             )",
            ["a".repeat(64)],
        )
        .unwrap();
        conn
    }

    #[test]
    fn v5_merges_compatible_security_baseline_findings_and_preserves_audit_links() {
        let mut conn = v4_security_baseline_database();
        let observations = json!({
            "facts": [{"kind": "missing_nosniff", "applicable": true}],
            "suspectedFacts": [],
            "responseComplete": true
        })
        .to_string();
        for (offset, fingerprint, occurrences) in
            [(0_i64, "b".repeat(64), 1_i64), (1, "c".repeat(64), 2)]
        {
            let check_id = 20 + offset;
            let verification_id = 30 + offset;
            let finding_id = 40 + offset;
            conn.execute(
                "INSERT INTO assessment_checks(
                     id, run_id, requested_endpoint_id, template_id,
                     template_version, identity_mode, policy_result, status
                 ) VALUES(?1, 10, ?2, 'security_headers_cookie', '1',
                          'anonymous', 'allowed', 'completed')",
                rusqlite::params![check_id, format!("ep_{offset}")],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO assessment_verifications(
                     id, check_id, verifier_id, verifier_version, verdict,
                     observations_json, content_hash
                 ) VALUES(?1, ?2, 'security_headers_cookie', '1', 'suspected', ?3, ?4)",
                rusqlite::params![
                    verification_id,
                    check_id,
                    observations,
                    format!("{offset:x}").repeat(64),
                ],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO findings(
                     id, project_id, source, producer, title, severity,
                     fingerprint, occurrences
                 ) VALUES(?1, 1, 'rule', 'safe_verifier',
                          '响应安全基线配置缺口', 'low', ?2, ?3)",
                rusqlite::params![finding_id, fingerprint, occurrences],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO assessment_finding_links(verification_id, finding_id)
                 VALUES(?1, ?2)",
                rusqlite::params![verification_id, finding_id],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO evidence(
                     id, project_id, source_type, source_id, observation,
                     redacted_snapshot, content_hash, created_by
                 ) VALUES(?1, 1, 'replay_run', ?2, 'legacy evidence', '{}', ?3, 'fixture')",
                rusqlite::params![50 + offset, 60 + offset, "d".repeat(64)],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO finding_evidence(finding_id, evidence_id)
                 VALUES(?1, ?2)",
                rusqlite::params![finding_id, 50 + offset],
            )
            .unwrap();
        }

        let report = migrate(&mut conn).unwrap();

        assert_eq!(
            report,
            MigrationReport {
                from_version: 4,
                to_version: 5,
            }
        );
        let finding: (i64, String, i64, String) = conn
            .query_row(
                "SELECT id, title, occurrences, fingerprint FROM findings",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(finding.0, 40);
        assert_eq!(finding.1, "缺少 X-Content-Type-Options: nosniff");
        assert_eq!(finding.2, 3);
        assert_eq!(
            finding.3,
            security_baseline_fingerprint(
                1,
                "security_headers_cookie",
                "http://target.test:9011",
                &serde_json::from_str(&observations).unwrap(),
            )
            .unwrap()
        );
        for table in [
            "assessment_finding_links",
            "finding_evidence",
            "finding_events",
        ] {
            let count: i64 = conn
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE finding_id = 40"),
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 2, "{table} must retain both legacy audit links");
        }
        assert!(conn
            .execute(
                "UPDATE finding_events SET reason='tampered' WHERE finding_id=40",
                [],
            )
            .is_err());
        assert!(conn
            .execute(
                "UPDATE assessment_finding_links SET relation='human_conflict'
                 WHERE verification_id=30",
                [],
            )
            .is_err());
        validate_v5(&conn).unwrap();
    }

    #[test]
    fn v5_preserves_findings_that_share_the_same_evidence_link() {
        let mut conn = v4_security_baseline_database();
        let observations = json!({
            "facts": [{"kind": "missing_nosniff", "applicable": true}],
            "suspectedFacts": [],
            "responseComplete": true
        })
        .to_string();
        for (offset, fingerprint) in [(0_i64, "b".repeat(64)), (1, "c".repeat(64))] {
            let check_id = 20 + offset;
            let verification_id = 30 + offset;
            let finding_id = 40 + offset;
            conn.execute(
                "INSERT INTO assessment_checks(
                     id, run_id, requested_endpoint_id, template_id,
                     template_version, identity_mode, policy_result, status
                 ) VALUES(?1, 10, ?2, 'security_headers_cookie', '1',
                          'anonymous', 'allowed', 'completed')",
                rusqlite::params![check_id, format!("ep_{offset}")],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO assessment_verifications(
                     id, check_id, verifier_id, verifier_version, verdict,
                     observations_json, content_hash
                 ) VALUES(?1, ?2, 'security_headers_cookie', '1', 'suspected', ?3, ?4)",
                rusqlite::params![
                    verification_id,
                    check_id,
                    observations,
                    format!("{offset:x}").repeat(64),
                ],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO findings(
                     id, project_id, source, producer, title, severity, fingerprint
                 ) VALUES(?1, 1, 'rule', 'safe_verifier',
                          '响应安全基线配置缺口', 'low', ?2)",
                rusqlite::params![finding_id, fingerprint],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO assessment_finding_links(verification_id, finding_id)
                 VALUES(?1, ?2)",
                rusqlite::params![verification_id, finding_id],
            )
            .unwrap();
        }
        conn.execute(
            "INSERT INTO evidence(
                 id, project_id, source_type, source_id, observation,
                 redacted_snapshot, content_hash, created_by
             ) VALUES(50, 1, 'replay_run', 60, 'shared evidence', '{}', ?1, 'fixture')",
            ["d".repeat(64)],
        )
        .unwrap();
        conn.execute_batch(
            "INSERT INTO finding_evidence(finding_id, evidence_id) VALUES(40, 50);
             INSERT INTO finding_evidence(finding_id, evidence_id) VALUES(41, 50);",
        )
        .unwrap();

        let report = migrate(&mut conn).unwrap();

        assert_eq!(report.to_version, 5);
        let finding_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM findings", [], |row| row.get(0))
            .unwrap();
        let evidence_link_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM finding_evidence", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(finding_count, 2);
        assert_eq!(evidence_link_count, 2);
        validate_v5(&conn).unwrap();
    }

    #[test]
    fn v5_does_not_union_distinct_historical_gap_sets() {
        let mut conn = v4_security_baseline_database();
        conn.execute(
            "INSERT INTO findings(
                 id, project_id, source, producer, title, severity, fingerprint
             ) VALUES(40, 1, 'rule', 'safe_verifier',
                      'legacy endpoint baseline', 'low', ?1)",
            ["b".repeat(64)],
        )
        .unwrap();
        for (offset, kind) in [(0_i64, "missing_nosniff"), (1, "missing_hsts")] {
            let check_id = 20 + offset;
            let verification_id = 30 + offset;
            let observations = json!({
                "facts": [{"kind": kind, "applicable": true}],
                "suspectedFacts": [],
                "responseComplete": true
            })
            .to_string();
            conn.execute(
                "INSERT INTO assessment_checks(
                     id, run_id, requested_endpoint_id, template_id,
                     template_version, identity_mode, policy_result, status
                 ) VALUES(?1, 10, ?2, 'security_headers_cookie', '1',
                          'anonymous', 'allowed', 'completed')",
                rusqlite::params![check_id, format!("ep_{offset}")],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO assessment_verifications(
                     id, check_id, verifier_id, verifier_version, verdict,
                     observations_json, content_hash
                 ) VALUES(?1, ?2, 'security_headers_cookie', '1', 'suspected', ?3, ?4)",
                rusqlite::params![
                    verification_id,
                    check_id,
                    observations,
                    format!("{offset:x}").repeat(64),
                ],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO assessment_finding_links(verification_id, finding_id)
                 VALUES(?1, 40)",
                [verification_id],
            )
            .unwrap();
        }

        migrate(&mut conn).unwrap();

        let finding: (String, String) = conn
            .query_row(
                "SELECT title, fingerprint FROM findings WHERE id = 40",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(finding.0, "legacy endpoint baseline");
        assert_eq!(finding.1, "b".repeat(64));
        let link_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM assessment_finding_links WHERE finding_id = 40",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(link_count, 2);
        validate_v5(&conn).unwrap();
    }

    #[test]
    fn v4_persists_waiting_missions_and_enforces_audited_transitions() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        migrate(&mut conn).unwrap();
        conn.execute("INSERT INTO projects(id, name) VALUES(1, 'mission')", [])
            .unwrap();
        let mission_sql = "INSERT INTO assessment_missions(
                id, project_id, title, goal, start_url, exact_origin, status,
                provider_id, model, contract_hash, tool_registry_hash,
                permission_hash, context_hash
            ) VALUES(?1, 1, ?2, ?3, 'https://mission.test/',
                     'https://mission.test:443', ?4, 'fixture', 'model',
                     ?5, ?5, ?5, ?5)";
        conn.execute(
            mission_sql,
            rusqlite::params![
                10,
                "等待上下文",
                "验证匿名攻击面",
                "awaiting_context_approval",
                "a".repeat(64)
            ],
        )
        .unwrap();
        conn.execute(
            mission_sql,
            rusqlite::params![
                11,
                "等待动作",
                "验证登录攻击面",
                "awaiting_action_approval",
                "b".repeat(64)
            ],
        )
        .unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM assessment_missions
                 WHERE status LIKE 'awaiting_%'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            2
        );
        assert!(conn
            .execute(
                "UPDATE assessment_missions
                 SET status='queued', revision=2 WHERE id=10",
                [],
            )
            .is_err());
        conn.execute(
            "INSERT INTO assessment_messages(
                 mission_id, role, message_kind, content, content_hash,
                 old_value, new_value, revision
             ) VALUES(10, 'system', 'status', '上下文已确认', ?1,
                      'awaiting_context_approval', 'queued', 2)",
            ["c".repeat(64)],
        )
        .unwrap();
        conn.execute(
            "UPDATE assessment_missions
             SET status='queued', revision=2 WHERE id=10",
            [],
        )
        .unwrap();
        assert_eq!(schema_version(&conn).unwrap(), 5);
        migrate(&mut conn).unwrap();
        let status: String = conn
            .query_row(
                "SELECT status FROM assessment_missions WHERE id=11",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, "awaiting_action_approval");
    }

    #[test]
    fn v4_rejects_cross_project_resources_and_manual_auto_execution() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        migrate(&mut conn).unwrap();
        conn.execute_batch(
            "INSERT INTO projects(id, name) VALUES(1, 'one'), (2, 'two');
             INSERT INTO traffic(id, project_id, method, host, url)
             VALUES(20, 2, 'GET', 'two.test', 'https://two.test/');",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO assessment_missions(
                 id, project_id, title, goal, start_url, status, provider_id,
                 model, contract_hash, tool_registry_hash, permission_hash
             ) VALUES(
                 10, 1, 'mission', 'goal', 'https://one.test/', 'draft',
                 'fixture', 'model', ?1, ?1, ?1
             )",
            ["a".repeat(64)],
        )
        .unwrap();
        assert!(conn
            .execute(
                "INSERT INTO assessment_mission_resources(
                     mission_id, resource_type, source_id, display_name,
                     summary_json, content_hash
                 ) VALUES(10, 'traffic', 20, 'foreign', '{}', ?1)",
                ["b".repeat(64)],
            )
            .is_err());
        assert!(conn
            .execute(
                "INSERT INTO assessment_actions(
                     mission_id, tool_id, tool_version, execution_kind,
                     risk_level, rationale, expected_signal, permission_snapshot,
                     permission_hash, approval_status, status
                 ) VALUES(
                     10, 'manual_sqli', '1.0.0', 'manual_recipe', 'manual',
                     '生成差异草稿', '由用户观察响应差异', 'execute', ?1,
                     'not_required', 'queued'
                 )",
                ["c".repeat(64)],
            )
            .is_err());
    }

    #[test]
    fn failing_step_rolls_back_schema_and_version() {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate(&mut conn).unwrap();

        let result = apply_step(
            &mut conn,
            6,
            "CREATE TABLE should_rollback(id INTEGER);
             INSERT INTO table_that_does_not_exist(id) VALUES(1);",
        );

        assert!(result.is_err());
        assert_eq!(schema_version(&conn).unwrap(), 5);
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
                latest: 5
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
