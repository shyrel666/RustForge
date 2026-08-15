use super::catalog::{self, ToolSpec};
use super::model::{
    AssessmentAction, AssessmentManualHandoff, AssessmentMessage, AssessmentMission,
    AssessmentMissionDetail, AssessmentMissionResource, AssessmentSurface,
    AssessmentToolPermission, AssessmentWorkstream, AttachMissionResourceInput, AutonomyMode,
    BudgetProfile, ConfirmMissionContextInput, CreateAssessmentMissionInput,
    CreateMissionHandoffInput, DecideAssessmentActionInput, ImportMissionOpenApiInput,
    LinkMissionHandoffReplayInput, MissionContextPreview, MissionControlInput,
    MissionCoverageSummary, MissionStatus, MissionToolDescriptor, SendMissionMessageInput,
    SetAssessmentToolPermissionInput,
};
use super::planner::PlannedCheck;
use super::service;
use crate::ai::redaction::{redact_fallback_text, RedactionManifest};
use crate::evidence::model::EvidenceSourceType;
use crate::replay::model::TlsPolicy;
use crate::secrets::SecretStore;
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction, TransactionBehavior};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use url::Url;

const MAX_OPENAPI_BYTES: u64 = 2 * 1024 * 1024;
const MAX_OPENAPI_PATHS: usize = 500;

pub fn create_mission(
    conn: &mut Connection,
    secrets: &dyn SecretStore,
    input: &CreateAssessmentMissionInput,
    provider_id: &str,
    model: &str,
) -> Result<AssessmentMissionDetail, String> {
    let autonomy = AutonomyMode::parse(input.autonomy_mode.trim())?;
    let budget = BudgetProfile::parse(input.budget_profile.trim())?;
    let (request_budget, max_cycles) = budget.limits();
    if !input.written_authorization_confirmed {
        return Err("[AUTHORIZATION_REQUIRED] 必须确认已获得目标的书面授权".into());
    }
    let (goal, goal_redactions) = redact_mission_text(
        conn,
        secrets,
        &input.goal,
        MissionTextContext {
            project_id: input.project_id,
            identity_a: input.identity_a_profile_id,
            identity_b: input.identity_b_profile_id,
            location: "assessment_mission.goal",
            max_len: 12_000,
        },
    )?;
    let title_source = input.title.as_deref().unwrap_or_else(|| {
        goal.lines()
            .find(|line| !line.trim().is_empty())
            .unwrap_or("新安全评估任务")
    });
    let title = validate_title(title_source)?;
    let contract_input = super::model::AssessmentContractInput {
        project_id: input.project_id,
        start_url: input.start_url.clone(),
        excluded_paths: input.excluded_paths.clone(),
        tls_policy: input.tls_policy.clone(),
        request_budget,
        requests_per_second: 2.0,
        identity_a_profile_id: input.identity_a_profile_id,
        identity_b_profile_id: input.identity_b_profile_id,
        resource_ownership: Vec::new(),
        include_recent_traffic: input.include_recent_traffic,
        provider_id: provider_id.to_string(),
        model: model.to_string(),
        max_rounds: max_cycles,
        written_authorization_confirmed: input.written_authorization_confirmed,
    };
    let contract = service::preview_contract(conn, secrets, &contract_input)?;
    let permission_state = permission_state(conn, input.project_id, autonomy)?;
    let context = context_material(
        &goal,
        &contract,
        &[],
        &permission_state.tools,
        &goal_redactions,
    )?;
    let context_hash = hash_json(&context.summary)?;
    let contract_json = serde_json::to_string(&contract).map_err(|error| error.to_string())?;
    let disclosure_json =
        serde_json::to_string(&context.disclosure_manifest).map_err(|error| error.to_string())?;
    let goal_hash = sha256(goal.as_bytes());
    let redaction_json =
        serde_json::to_string(&goal_redactions).map_err(|error| error.to_string())?;

    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    tx.execute(
        "INSERT INTO assessment_missions(
             project_id, title, goal, start_url, exact_origin, status,
             autonomy_mode, budget_profile, request_budget, max_planning_cycles,
             requests_per_second, identity_a_profile_id, identity_b_profile_id,
             provider_id, model, tls_policy, include_recent_traffic,
             contract_json, contract_hash, tool_registry_hash, permission_hash,
             context_hash, disclosure_manifest_json
         ) VALUES(
             ?1, ?2, ?3, ?4, ?5, 'awaiting_context_approval', ?6, ?7, ?8, ?9,
             2.0, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21
         )",
        params![
            input.project_id,
            title,
            goal,
            contract.normalized_start_url,
            contract.exact_origin,
            autonomy.as_str(),
            budget.as_str(),
            request_budget,
            max_cycles,
            input.identity_a_profile_id,
            input.identity_b_profile_id,
            provider_id,
            model,
            contract.tls_policy,
            input.include_recent_traffic,
            contract_json,
            contract.contract_hash,
            catalog::registry_hash(),
            permission_state.hash,
            context_hash,
            disclosure_json,
        ],
    )
    .map_err(|error| format!("创建评估任务失败: {error}"))?;
    let mission_id = tx.last_insert_rowid();
    tx.execute(
        "INSERT INTO assessment_messages(
             mission_id, role, message_kind, content, content_hash,
             details_json, redaction_manifest_json, revision
         ) VALUES(?1, 'user', 'goal', ?2, ?3, ?4, ?5, 1)",
        params![
            mission_id,
            goal,
            goal_hash,
            serde_json::to_string(&json!({"source": "mission_create"}))
                .map_err(|error| error.to_string())?,
            redaction_json,
        ],
    )
    .map_err(|error| error.to_string())?;
    tx.commit().map_err(|error| error.to_string())?;
    get_detail(conn, input.project_id, mission_id)
}

pub fn list_missions(conn: &Connection, project_id: i64) -> Result<Vec<AssessmentMission>, String> {
    ensure_project(conn, project_id)?;
    let mut statement = conn
        .prepare(&format!(
            "{} WHERE project_id = ?1 ORDER BY legacy ASC, id DESC",
            mission_select_sql()
        ))
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([project_id], map_mission)
        .map_err(|error| error.to_string())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())
}

pub fn get_mission(
    conn: &Connection,
    project_id: i64,
    mission_id: i64,
) -> Result<AssessmentMission, String> {
    conn.query_row(
        &format!("{} WHERE id = ?1 AND project_id = ?2", mission_select_sql()),
        params![mission_id, project_id],
        map_mission,
    )
    .optional()
    .map_err(|error| error.to_string())?
    .ok_or_else(|| "评估任务不存在或不属于当前项目".to_string())
}

pub fn get_detail(
    conn: &Connection,
    project_id: i64,
    mission_id: i64,
) -> Result<AssessmentMissionDetail, String> {
    let mission = get_mission(conn, project_id, mission_id)?;
    Ok(AssessmentMissionDetail {
        messages: list_messages(conn, mission_id)?,
        workstreams: list_workstreams(conn, mission_id)?,
        actions: list_actions(conn, mission_id)?,
        resources: list_resources(conn, mission_id)?,
        surfaces: list_surfaces(conn, mission_id)?,
        tool_permissions: list_tool_permissions(conn, project_id)?,
        handoffs: list_handoffs(conn, mission_id)?,
        coverage: coverage_summary(conn, mission_id)?,
        mission,
    })
}

pub fn get_action_detail(
    conn: &Connection,
    project_id: i64,
    mission_id: i64,
    action_id: i64,
) -> Result<AssessmentAction, String> {
    get_action(conn, project_id, mission_id, action_id)
}

pub fn preview_context(
    conn: &Connection,
    project_id: i64,
    mission_id: i64,
) -> Result<MissionContextPreview, String> {
    let mission = get_mission(conn, project_id, mission_id)?;
    if mission.legacy {
        return Err("旧版评估没有 v2 AI 上下文；请使用只读 legacy 详情".into());
    }
    let contract: super::model::AssessmentContractPreview = conn
        .query_row(
            "SELECT contract_json FROM assessment_missions WHERE id=?1",
            [mission_id],
            |row| row.get::<_, String>(0),
        )
        .map_err(|error| error.to_string())
        .and_then(|raw| serde_json::from_str(&raw).map_err(|error| error.to_string()))?;
    let resources = list_resources(conn, mission_id)?;
    let permission_state = permission_state(conn, project_id, mission.autonomy_mode)?;
    let mut stored_manifest = conn
        .query_row(
            "SELECT disclosure_manifest_json FROM assessment_missions WHERE id=?1",
            [mission_id],
            |row| row.get::<_, String>(0),
        )
        .map_err(|error| error.to_string())
        .and_then(|raw| {
            serde_json::from_str::<Vec<String>>(&raw).map_err(|error| error.to_string())
        })?;
    stored_manifest.sort();
    stored_manifest.dedup();
    let context = context_material(
        &mission.goal,
        &contract,
        &resources,
        &permission_state.tools,
        &stored_manifest,
    )?;
    let context_hash = hash_json(&context.summary)?;
    let registry_hash = catalog::registry_hash();
    let approved = mission.context_approved_hash.as_deref() == Some(context_hash.as_str())
        && mission.permission_hash == permission_state.hash
        && mission.tool_registry_hash == registry_hash;
    Ok(MissionContextPreview {
        project_id,
        mission_id,
        revision: mission.revision,
        context_hash,
        contract_hash: mission.contract_hash,
        tool_registry_hash: registry_hash,
        permission_hash: permission_state.hash,
        disclosure_manifest: context.disclosure_manifest,
        context_summary: context.summary,
        tools: permission_state.tools,
        requires_approval: !approved,
        approved,
    })
}

pub fn confirm_context(
    conn: &mut Connection,
    secrets: &dyn SecretStore,
    input: &ConfirmMissionContextInput,
) -> Result<AssessmentMissionDetail, String> {
    let mission = get_mission(conn, input.project_id, input.mission_id)?;
    ensure_revision(mission.revision, input.expected_revision)?;
    if mission.legacy || mission.status.is_terminal() || mission.status.is_network_active() {
        return Err("当前任务状态不能确认上下文".into());
    }
    let current = preview_context(conn, input.project_id, input.mission_id)?;
    if input.context_hash.len() != 64 || input.context_hash != current.context_hash {
        return Err("[CONTEXT_DRIFT] AI 上下文已变化，请重新预览".into());
    }

    // Rebuild the v3 execution contract so provider/scope/identity/tool drift is
    // checked again at the approval boundary.
    let contract_input = contract_input_from_mission(conn, &mission)?;
    let contract = service::preview_contract(conn, secrets, &contract_input)?;
    let contract_json = serde_json::to_string(&contract).map_err(|error| error.to_string())?;

    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    let live_revision: i64 = tx
        .query_row(
            "SELECT revision FROM assessment_missions WHERE id=?1 AND project_id=?2",
            params![input.mission_id, input.project_id],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    ensure_revision(live_revision, input.expected_revision)?;
    prepare_workstreams_and_actions(&tx, &mission, &current.tools, &current.permission_hash)?;
    let pending: bool = tx
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM assessment_actions
                 WHERE mission_id=?1 AND approval_status='pending'
                   AND status='awaiting_approval'
             )",
            [input.mission_id],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    let next = if pending {
        MissionStatus::AwaitingActionApproval
    } else {
        MissionStatus::Queued
    };
    let next_revision = live_revision + 1;
    append_message_on(
        &tx,
        input.mission_id,
        MessageEntry {
            role: "system",
            kind: "status",
            content: if pending {
                "AI 上下文已确认；部分工具动作等待逐项审批。"
            } else {
                "AI 上下文已确认；所有计划动作已按权限策略进入队列。"
            },
            old_value: Some(mission.status.as_str()),
            new_value: Some(next.as_str()),
            details: &json!({
                "contextHash": current.context_hash,
                "permissionHash": current.permission_hash,
                "toolRegistryHash": current.tool_registry_hash,
            }),
            manifest: &[],
        },
        next_revision,
    )?;
    let updated = tx
        .execute(
            "UPDATE assessment_missions
             SET status=?3, revision=?4,
                 context_hash=?5, context_approved_hash=?5,
                 permission_hash=?6, tool_registry_hash=?7,
                 contract_json=?8, contract_hash=?9,
                 updated_at=strftime('%Y-%m-%d %H:%M:%f','now','localtime')
             WHERE id=?1 AND project_id=?2 AND revision=?10",
            params![
                input.mission_id,
                input.project_id,
                next.as_str(),
                next_revision,
                current.context_hash,
                current.permission_hash,
                current.tool_registry_hash,
                contract_json,
                contract.contract_hash,
                live_revision,
            ],
        )
        .map_err(|error| error.to_string())?;
    if updated != 1 {
        return Err("[REVISION_CONFLICT] 任务已被其他操作更新".into());
    }
    tx.commit().map_err(|error| error.to_string())?;
    get_detail(conn, input.project_id, input.mission_id)
}

pub fn attach_resource(
    conn: &mut Connection,
    input: &AttachMissionResourceInput,
) -> Result<AssessmentMissionDetail, String> {
    let mission = get_mission(conn, input.project_id, input.mission_id)?;
    ensure_revision(mission.revision, input.expected_revision)?;
    ensure_resource_mutable(&mission)?;
    let (display_name, media_type, summary) = summarize_project_resource(
        conn,
        input.project_id,
        &input.resource_type,
        input.source_id,
    )?;
    let content_hash = hash_json(&summary)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    tx.execute(
        "INSERT INTO assessment_mission_resources(
             mission_id, resource_type, source_id, display_name, media_type,
             summary_json, content_hash
         ) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![
            input.mission_id,
            input.resource_type,
            input.source_id,
            display_name,
            media_type,
            serde_json::to_string(&summary).map_err(|error| error.to_string())?,
            content_hash,
        ],
    )
    .map_err(|error| format!("附加任务资源失败: {error}"))?;
    bump_context_revision(
        &tx,
        input.mission_id,
        input.project_id,
        input.expected_revision,
        &format!("已附加 {} 资源。", input.resource_type),
        &json!({"resourceType": input.resource_type, "sourceId": input.source_id}),
    )?;
    tx.commit().map_err(|error| error.to_string())?;
    get_detail(conn, input.project_id, input.mission_id)
}

pub fn import_openapi(
    conn: &mut Connection,
    input: &ImportMissionOpenApiInput,
) -> Result<AssessmentMissionDetail, String> {
    let mission = get_mission(conn, input.project_id, input.mission_id)?;
    ensure_revision(mission.revision, input.expected_revision)?;
    ensure_resource_mutable(&mission)?;
    let path = Path::new(&input.path);
    let metadata =
        std::fs::metadata(path).map_err(|error| format!("读取 OpenAPI 文件失败: {error}"))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_OPENAPI_BYTES {
        return Err("OpenAPI 文件必须是 1 B..=2 MiB 的普通文件".into());
    }
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !matches!(extension.as_str(), "json" | "yaml" | "yml") {
        return Err("仅支持 OpenAPI JSON、YAML 或 YML 文件".into());
    }
    let bytes = std::fs::read(path).map_err(|error| format!("读取 OpenAPI 文件失败: {error}"))?;
    let text = String::from_utf8(bytes).map_err(|_| "OpenAPI 文件必须是 UTF-8".to_string())?;
    let summary = if extension == "json" {
        summarize_openapi_json(&text)?
    } else {
        summarize_openapi_yaml(&text)?
    };
    let raw_display_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("openapi")
        .chars()
        .take(240)
        .collect::<String>();
    let mut file_manifest = RedactionManifest::default();
    let display_name = redact_fallback_text(
        &raw_display_name,
        "assessment_mission.openapi_filename",
        true,
        &mut file_manifest,
    );
    let content_hash = hash_json(&summary)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    tx.execute(
        "INSERT INTO assessment_mission_resources(
             mission_id, resource_type, source_id, display_name, media_type,
             summary_json, content_hash
         ) VALUES(?1,'openapi',NULL,?2,?3,?4,?5)",
        params![
            input.mission_id,
            display_name,
            if extension == "json" {
                "application/json"
            } else {
                "application/yaml"
            },
            serde_json::to_string(&summary).map_err(|error| error.to_string())?,
            content_hash,
        ],
    )
    .map_err(|error| format!("导入 OpenAPI 摘要失败: {error}"))?;
    bump_context_revision(
        &tx,
        input.mission_id,
        input.project_id,
        input.expected_revision,
        "已导入有界 OpenAPI 结构摘要。",
        &json!({"displayName": display_name}),
    )?;
    tx.commit().map_err(|error| error.to_string())?;
    get_detail(conn, input.project_id, input.mission_id)
}

pub fn send_message(
    conn: &mut Connection,
    secrets: &dyn SecretStore,
    input: &SendMissionMessageInput,
) -> Result<AssessmentMissionDetail, String> {
    let mission = get_mission(conn, input.project_id, input.mission_id)?;
    ensure_revision(mission.revision, input.expected_revision)?;
    if mission.legacy || mission.status.is_terminal() {
        return Err("只读或已结束任务不能接收新的目标调整".into());
    }
    let (content, manifest) = redact_mission_text(
        conn,
        secrets,
        &input.content,
        MissionTextContext {
            project_id: input.project_id,
            identity_a: mission.identity_a_profile_id,
            identity_b: mission.identity_b_profile_id,
            location: "assessment_mission.follow_up",
            max_len: 8_000,
        },
    )?;
    let next_revision = mission.revision + 1;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    append_message_on(
        &tx,
        input.mission_id,
        MessageEntry {
            role: "user",
            kind: "follow_up",
            content: &content,
            old_value: None,
            new_value: None,
            details: &json!({"replanAt": "next_planning_point"}),
            manifest: &manifest,
        },
        next_revision,
    )?;
    let updated = tx
        .execute(
            "UPDATE assessment_missions
             SET revision=?3, pending_steering=1,
                 updated_at=strftime('%Y-%m-%d %H:%M:%f','now','localtime')
             WHERE id=?1 AND project_id=?2 AND revision=?4",
            params![
                input.mission_id,
                input.project_id,
                next_revision,
                mission.revision
            ],
        )
        .map_err(|error| error.to_string())?;
    if updated != 1 {
        return Err("[REVISION_CONFLICT] 任务已被其他操作更新".into());
    }
    tx.commit().map_err(|error| error.to_string())?;
    get_detail(conn, input.project_id, input.mission_id)
}

pub fn decide_action(
    conn: &mut Connection,
    input: &DecideAssessmentActionInput,
) -> Result<AssessmentMissionDetail, String> {
    let mission = get_mission(conn, input.project_id, input.mission_id)?;
    ensure_revision(mission.revision, input.expected_mission_revision)?;
    if mission.status != MissionStatus::AwaitingActionApproval {
        return Err("当前任务不在动作审批状态".into());
    }
    assert_mission_integrity(conn, &mission)?;
    let action = get_action(conn, input.project_id, input.mission_id, input.action_id)?;
    if action.revision != input.expected_action_revision || action.approval_status != "pending" {
        return Err("[REVISION_CONFLICT] 动作已被其他审批更新".into());
    }
    let action_ids = if input.apply_to_same_tool {
        let mut statement = conn
            .prepare(
                "SELECT id FROM assessment_actions
                 WHERE mission_id=?1 AND tool_id=?2 AND approval_status='pending'
                   AND status='awaiting_approval' ORDER BY id",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(params![input.mission_id, action.tool_id], |row| row.get(0))
            .map_err(|error| error.to_string())?;
        rows.collect::<Result<Vec<i64>, _>>()
            .map_err(|error| error.to_string())?
    } else {
        vec![input.action_id]
    };
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    for action_id in &action_ids {
        let live_revision: i64 = tx
            .query_row(
                "SELECT revision FROM assessment_actions
                 WHERE id=?1 AND mission_id=?2 AND approval_status='pending'",
                params![action_id, input.mission_id],
                |row| row.get(0),
            )
            .map_err(|_| "动作已不再等待审批".to_string())?;
        let (approval_status, status) = if input.approve {
            // Approval grants the planner permission to select the recipe; it
            // does not create a draft by itself. Only a later, validated model
            // selection may advance a manual action to `manual_ready`.
            ("approved", "queued")
        } else {
            ("rejected", "rejected")
        };
        let changed = tx
            .execute(
                "UPDATE assessment_actions
                 SET approval_status=?2, approval_source=?3, status=?4,
                     revision=revision+1,
                     approved_at=strftime('%Y-%m-%d %H:%M:%f','now','localtime'),
                     completed_at=CASE WHEN ?4='rejected'
                         THEN strftime('%Y-%m-%d %H:%M:%f','now','localtime')
                         ELSE completed_at END
                 WHERE id=?1 AND revision=?5 AND approval_status='pending'",
                params![
                    action_id,
                    approval_status,
                    if input.apply_to_same_tool {
                        "bulk_user"
                    } else {
                        "user"
                    },
                    status,
                    live_revision,
                ],
            )
            .map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err("[REVISION_CONFLICT] 并发动作审批冲突".into());
        }
    }
    let approval_revision = mission.revision + 1;
    append_message_on(
        &tx,
        input.mission_id,
        MessageEntry {
            role: "action",
            kind: "approval",
            content: if input.approve {
                "已批准工具动作；后端仍会在执行前重新检查 Scope、工具版本和权限。"
            } else {
                "已拒绝工具动作；拒绝路径未创建请求或网络客户端。"
            },
            old_value: None,
            new_value: None,
            details: &json!({
                "actionIds": action_ids,
                "toolId": action.tool_id,
                "decision": if input.approve {"approved"} else {"rejected"},
            }),
            manifest: &[],
        },
        approval_revision,
    )?;
    tx.execute(
        "UPDATE assessment_missions SET revision=?2,
             updated_at=strftime('%Y-%m-%d %H:%M:%f','now','localtime')
         WHERE id=?1 AND revision=?3",
        params![input.mission_id, approval_revision, mission.revision],
    )
    .map_err(|error| error.to_string())?;

    let pending: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM assessment_actions
             WHERE mission_id=?1 AND approval_status='pending'
               AND status='awaiting_approval')",
            [input.mission_id],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if !pending {
        transition_mission_on(
            &tx,
            input.mission_id,
            input.project_id,
            MissionTransitionInput {
                current: MissionStatus::AwaitingActionApproval,
                next: MissionStatus::Queued,
                current_revision: approval_revision,
                content: "动作审批已完成，任务进入串行执行队列。",
                details: &json!({"approvedOrRejected": true}),
                stop_reason: None,
            },
        )?;
    }
    tx.commit().map_err(|error| error.to_string())?;
    get_detail(conn, input.project_id, input.mission_id)
}

pub fn set_tool_permission(
    conn: &mut Connection,
    input: &SetAssessmentToolPermissionInput,
) -> Result<Vec<AssessmentToolPermission>, String> {
    ensure_project(conn, input.project_id)?;
    let tool =
        catalog::tool(input.tool_id.trim()).ok_or_else(|| "未知或未注册的工具 ID".to_string())?;
    if !matches!(input.decision.as_str(), "disabled" | "ask" | "execute") {
        return Err("工具权限只能是 disabled、ask 或 execute".into());
    }
    if tool.execution_kind == "manual_recipe" && input.decision == "execute" {
        return Err("人工配方不可设置为自动执行；只能禁用或逐次询问".into());
    }
    let existing: Option<i64> = conn
        .query_row(
            "SELECT revision FROM assessment_tool_permissions
             WHERE project_id=?1 AND tool_id=?2",
            params![input.project_id, tool.id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    match (existing, input.expected_revision) {
        (Some(current), Some(expected)) if current != expected => {
            return Err("[REVISION_CONFLICT] 工具权限已被其他操作更新".into())
        }
        (Some(_), None) => return Err("修改已有权限时必须提供 expectedRevision".into()),
        (None, Some(_)) => return Err("工具权限尚不存在，不能使用旧 revision".into()),
        _ => {}
    }
    conn.execute(
        "INSERT INTO assessment_tool_permissions(project_id, tool_id, decision)
         VALUES(?1,?2,?3)
         ON CONFLICT(project_id, tool_id) DO UPDATE SET
             decision=excluded.decision,
             revision=assessment_tool_permissions.revision+1,
             updated_at=strftime('%Y-%m-%d %H:%M:%f','now','localtime')",
        params![input.project_id, tool.id, input.decision],
    )
    .map_err(|error| error.to_string())?;
    list_tool_permissions(conn, input.project_id)
}

pub fn prepare_start(
    conn: &Connection,
    secrets: &dyn SecretStore,
    input: &MissionControlInput,
) -> Result<super::model::AssessmentContractPreview, String> {
    let mission = get_mission(conn, input.project_id, input.mission_id)?;
    ensure_revision(mission.revision, input.expected_revision)?;
    if mission.legacy {
        return Err("旧版评估不能重新启动".into());
    }
    if mission.status != MissionStatus::Queued {
        return Err("任务尚未完成上下文与动作审批".into());
    }
    assert_mission_integrity(conn, &mission)?;
    let pending: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM assessment_actions
             WHERE mission_id=?1 AND approval_status='pending')",
            [mission.id],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if pending {
        return Err("仍有工具动作等待审批".into());
    }
    let contract_input = contract_input_from_mission(conn, &mission)?;
    let preview = service::preview_contract(conn, secrets, &contract_input)?;
    if preview.contract_hash != mission.contract_hash {
        return Err("[CONTRACT_DRIFT] Scope、身份或运行契约已变化，请重新确认上下文".into());
    }
    Ok(preview)
}

pub fn link_run(
    conn: &mut Connection,
    project_id: i64,
    mission_id: i64,
    run_id: i64,
) -> Result<AssessmentMission, String> {
    let mission = get_mission(conn, project_id, mission_id)?;
    if mission.status != MissionStatus::Queued || mission.active_run_id.is_some() {
        return Err("任务不在可绑定运行的队列状态".into());
    }
    let next_revision = mission.revision + 1;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    tx.execute(
        "INSERT INTO assessment_mission_runs(mission_id, run_id, cycle)
         VALUES(?1,?2,?3)",
        params![mission_id, run_id, mission.completed_cycles + 1],
    )
    .map_err(|error| error.to_string())?;
    append_message_on(
        &tx,
        mission_id,
        MessageEntry {
            role: "system",
            kind: "summary",
            content: "确定性执行层已创建；所有目标请求仍保持单并发和 2 RPS 硬上限。",
            old_value: None,
            new_value: None,
            details: &json!({"runId": run_id}),
            manifest: &[],
        },
        next_revision,
    )?;
    tx.execute(
        "UPDATE assessment_missions
         SET active_run_id=?3, revision=?4,
             updated_at=strftime('%Y-%m-%d %H:%M:%f','now','localtime')
         WHERE id=?1 AND project_id=?2 AND revision=?5",
        params![
            mission_id,
            project_id,
            run_id,
            next_revision,
            mission.revision
        ],
    )
    .map_err(|error| error.to_string())?;
    tx.commit().map_err(|error| error.to_string())?;
    get_mission(conn, project_id, mission_id)
}

pub fn request_stop(
    conn: &mut Connection,
    input: &MissionControlInput,
) -> Result<(AssessmentMissionDetail, Option<i64>), String> {
    let mission = get_mission(conn, input.project_id, input.mission_id)?;
    ensure_revision(mission.revision, input.expected_revision)?;
    if mission.legacy || mission.status.is_terminal() {
        return Err("任务已结束或为只读 legacy 运行".into());
    }
    if mission.status.is_network_active() {
        let run_id = mission
            .active_run_id
            .ok_or_else(|| "运行中的 mission 缺少 active run".to_string())?;
        let next_revision = mission.revision + 1;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        append_message_on(
            &tx,
            mission.id,
            MessageEntry {
                role: "user",
                kind: "status",
                content: "用户请求停止；当前单个请求将先安全结束，随后取消等待并保存部分结果。",
                old_value: Some(mission.status.as_str()),
                new_value: Some(mission.status.as_str()),
                details: &json!({"stopRequested": true}),
                manifest: &[],
            },
            next_revision,
        )?;
        tx.execute(
            "UPDATE assessment_missions SET revision=?2,
                 stop_reason='user_stop_requested',
                 updated_at=strftime('%Y-%m-%d %H:%M:%f','now','localtime')
             WHERE id=?1 AND revision=?3",
            params![mission.id, next_revision, mission.revision],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        return Ok((
            get_detail(conn, input.project_id, input.mission_id)?,
            Some(run_id),
        ));
    }
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    tx.execute(
        "UPDATE assessment_actions SET status='cancelled',
             completed_at=strftime('%Y-%m-%d %H:%M:%f','now','localtime')
         WHERE mission_id=?1 AND status IN ('proposed','awaiting_approval','queued','manual_ready')",
        [mission.id],
    )
    .map_err(|error| error.to_string())?;
    transition_mission_on(
        &tx,
        mission.id,
        mission.project_id,
        MissionTransitionInput {
            current: mission.status,
            next: MissionStatus::Stopped,
            current_revision: mission.revision,
            content: "任务已停止；未获批或尚未执行的动作没有创建 socket。",
            details: &json!({"reason": "user_stopped_while_waiting"}),
            stop_reason: Some("user_stopped_while_waiting"),
        },
    )?;
    tx.commit().map_err(|error| error.to_string())?;
    Ok((get_detail(conn, input.project_id, input.mission_id)?, None))
}

pub fn create_handoff(
    conn: &mut Connection,
    input: &CreateMissionHandoffInput,
) -> Result<AssessmentManualHandoff, String> {
    let mission = get_mission(conn, input.project_id, input.mission_id)?;
    if mission.legacy || mission.status.is_terminal() {
        return Err("当前任务不能创建人工接力".into());
    }
    let action = get_action(conn, input.project_id, input.mission_id, input.action_id)?;
    if action.revision != input.expected_action_revision
        || action.execution_kind != "manual_recipe"
        || action.approval_status != "approved"
        || !matches!(
            action.status.as_str(),
            "manual_ready" | "manual_result_pending"
        )
    {
        return Err("人工配方动作尚未获批或 revision 已变化".into());
    }
    if let Some(existing) = get_handoff_by_action(conn, action.id)? {
        return Ok(existing);
    }
    let tls = TlsPolicy::parse(&mission.tls_policy)?;
    // Creating/selecting a manual session persists only draft metadata and never
    // constructs an HTTP client or calls replay_request.
    let session = crate::replay::service::create_session(
        conn,
        input.project_id,
        &format!("AI 接力 · {}", action.tool_id),
        None,
        tls,
    )?;
    let draft = build_manual_recipe_draft(conn, &mission, &action, session.id)?;
    let draft_hash = hash_json(&draft)?;
    conn.execute(
        "INSERT INTO assessment_manual_handoffs(
             action_id, recipe_id, recipe_version, draft_json, draft_hash,
             replay_session_id, status
         ) VALUES(?1,?2,?3,?4,?5,?6,'draft_created')",
        params![
            action.id,
            action.tool_id,
            action.tool_version,
            serde_json::to_string(&draft).map_err(|error| error.to_string())?,
            draft_hash,
            session.id,
        ],
    )
    .map_err(|error| error.to_string())?;
    let handoff_id = conn.last_insert_rowid();
    get_handoff(conn, input.project_id, input.mission_id, handoff_id)
}

pub fn link_handoff_replay(
    conn: &mut Connection,
    input: &LinkMissionHandoffReplayInput,
) -> Result<AssessmentManualHandoff, String> {
    let _mission = get_mission(conn, input.project_id, input.mission_id)?;
    let handoff = get_handoff(conn, input.project_id, input.mission_id, input.handoff_id)?;
    let action = get_action(conn, input.project_id, input.mission_id, handoff.action_id)?;
    if handoff.status == "result_linked" {
        return Err("该人工接力已经回传结果".into());
    }
    let replay: Option<(i64, String)> = conn
        .query_row(
            "SELECT rr.session_id, rr.outcome
             FROM replay_runs rr
             JOIN replay_sessions rs ON rs.id=rr.session_id
             JOIN assessment_manual_handoffs h ON h.replay_session_id=rs.id
             JOIN assessment_actions a ON a.id=h.action_id
             JOIN assessment_missions m ON m.id=a.mission_id
             WHERE rr.id=?1 AND rr.project_id=?2 AND m.id=?3 AND h.id=?4
               AND rs.owner_kind='manual'",
            params![
                input.replay_run_id,
                input.project_id,
                input.mission_id,
                input.handoff_id
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let (session_id, outcome) =
        replay.ok_or_else(|| "只能回传同项目、同 handoff 手动会话中的 ReplayRun".to_string())?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    let evidence_id = crate::evidence::service::insert_evidence(
        &tx,
        input.project_id,
        EvidenceSourceType::ReplayRun,
        input.replay_run_id,
        "AI 评估人工接力结果，默认待复核且不会自动确认 Finding。",
        "assessment_mission_handoff",
    )?;
    let result = json!({
        "selection": action
            .result
            .as_ref()
            .and_then(|value| value.get("selection")),
        "manualEvidence": {
            "replayRunId": input.replay_run_id,
            "evidenceId": evidence_id,
            "outcome": outcome,
            "accepted": false,
        },
    });
    let result_hash = hash_json(&result)?;
    tx.execute(
        "UPDATE assessment_manual_handoffs
         SET replay_session_id=?2, replay_run_id=?3, evidence_id=?4,
             status='result_linked',
             updated_at=strftime('%Y-%m-%d %H:%M:%f','now','localtime')
         WHERE id=?1",
        params![
            input.handoff_id,
            session_id,
            input.replay_run_id,
            evidence_id
        ],
    )
    .map_err(|error| error.to_string())?;
    tx.execute(
        "UPDATE assessment_actions
         SET status='manual_result_pending', revision=revision+1,
             result_json=?2, result_hash=?3,
             completed_at=strftime('%Y-%m-%d %H:%M:%f','now','localtime')
         WHERE id=(SELECT action_id FROM assessment_manual_handoffs WHERE id=?1)",
        params![
            input.handoff_id,
            serde_json::to_string(&result).map_err(|error| error.to_string())?,
            result_hash,
        ],
    )
    .map_err(|error| error.to_string())?;
    tx.commit().map_err(|error| error.to_string())?;
    get_handoff(conn, input.project_id, input.mission_id, input.handoff_id)
}

/// Mirror only real network run phases. Durable approval/manual waiting states
/// remain mission-owned and are therefore not touched by run recovery.
pub fn sync_from_run(
    conn: &mut Connection,
    run_id: i64,
    run_status: super::model::AssessmentStatus,
    reason: Option<&str>,
) -> Result<(), String> {
    let mapping: Option<(i64, i64, String, i64)> = conn
        .query_row(
            "SELECT m.id, m.project_id, m.status, m.revision
             FROM assessment_missions m
             JOIN assessment_mission_runs mr ON mr.mission_id=m.id
             WHERE mr.run_id=?1 AND m.legacy=0",
            [run_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some((mission_id, project_id, current_raw, revision)) = mapping else {
        return Ok(());
    };
    let current = MissionStatus::parse(&current_raw)?;
    let mut next = match run_status {
        super::model::AssessmentStatus::Queued => MissionStatus::Queued,
        super::model::AssessmentStatus::Discovering => MissionStatus::Discovering,
        super::model::AssessmentStatus::Planning => MissionStatus::Planning,
        super::model::AssessmentStatus::Executing => MissionStatus::Executing,
        super::model::AssessmentStatus::Verifying => MissionStatus::Verifying,
        super::model::AssessmentStatus::Completed => MissionStatus::Completed,
        super::model::AssessmentStatus::Stopped => MissionStatus::Stopped,
        super::model::AssessmentStatus::Cancelled => MissionStatus::Cancelled,
        super::model::AssessmentStatus::Failed => MissionStatus::Failed,
        super::model::AssessmentStatus::Interrupted => MissionStatus::Interrupted,
    };
    if run_status == super::model::AssessmentStatus::Completed {
        let manual_pending: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM assessment_actions
                 WHERE mission_id=?1 AND execution_kind='manual_recipe'
                   AND approval_status='approved'
                   AND status IN ('manual_ready','manual_result_pending'))",
                [mission_id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if manual_pending {
            next = MissionStatus::AwaitingManualHandoff;
        }
    }
    if current == next {
        return Ok(());
    }
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    transition_mission_on(
        &tx,
        mission_id,
        project_id,
        MissionTransitionInput {
            current,
            next,
            current_revision: revision,
            content: &format!("确定性执行层进入 {}。", next.as_str()),
            details: &json!({"runId": run_id, "reason": reason.unwrap_or("")}),
            stop_reason: reason,
        },
    )?;
    if next.is_terminal() || next == MissionStatus::AwaitingManualHandoff {
        tx.execute(
            "UPDATE assessment_missions
             SET active_run_id=NULL, completed_cycles=MIN(max_planning_cycles, completed_cycles+1)
             WHERE id=?1",
            [mission_id],
        )
        .map_err(|error| error.to_string())?;
        sync_actions_from_run_on(
            &tx,
            mission_id,
            run_id,
            run_status == super::model::AssessmentStatus::Completed,
        )?;
    }
    tx.commit().map_err(|error| error.to_string())?;
    Ok(())
}

pub fn allowed_planner_tools_for_run(
    conn: &Connection,
    run_id: i64,
) -> Result<Option<BTreeSet<String>>, String> {
    let mission_id: Option<i64> = conn
        .query_row(
            "SELECT mission_id FROM assessment_mission_runs WHERE run_id=?1",
            [run_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some(mission_id) = mission_id else {
        return Ok(None);
    };
    let mut statement = conn
        .prepare(
            "SELECT DISTINCT tool_id FROM assessment_actions
             WHERE mission_id=?1
               AND execution_kind IN ('observe','safe_probe','manual_recipe')
               AND approval_status IN ('not_required','approved')
               AND status='queued'",
        )
        .map_err(|error| error.to_string())?;
    let tools = statement
        .query_map([mission_id], |row| row.get::<_, String>(0))
        .map_err(|error| error.to_string())?
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|error| error.to_string())?;
    Ok(Some(tools))
}

/// Persist model-selected manual recipes without materializing a check or
/// constructing a transport. The planner may choose only a previously approved
/// tool, an opaque endpoint from this exact run, and an inventoried parameter.
/// Invalid selections become coverage gaps and never advance the action.
pub fn select_manual_plans_for_run(
    conn: &mut Connection,
    run_id: i64,
    round_id: i64,
    plans: &[PlannedCheck],
    allowed_tool_ids: Option<&BTreeSet<String>>,
) -> Result<usize, String> {
    if plans.is_empty() {
        return Ok(0);
    }
    let allowed = allowed_tool_ids.ok_or_else(|| "旧版运行不能选择 v2 人工配方".to_string())?;
    let mapping: Option<(i64, i64)> = conn
        .query_row(
            "SELECT m.id, m.project_id
             FROM assessment_missions m
             JOIN assessment_mission_runs mr ON mr.mission_id=m.id
             WHERE mr.run_id=?1 AND m.legacy=0 AND m.active_run_id=?1",
            [run_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let (mission_id, project_id) =
        mapping.ok_or_else(|| "人工配方选择不属于活动 mission".to_string())?;
    let mission = get_mission(conn, project_id, mission_id)?;
    if mission.status != MissionStatus::Planning {
        return Err("人工配方只能在持久化规划点选择".into());
    }
    assert_mission_integrity(conn, &mission)?;
    let round_is_current: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM assessment_rounds
             WHERE id=?1 AND run_id=?2)",
            params![round_id, run_id],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if !round_is_current {
        return Err("人工配方引用了无效规划轮次".into());
    }

    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    let mut accepted = Vec::<Value>::new();
    for plan in plans {
        let Some(tool) = catalog::tool(&plan.template_id) else {
            continue;
        };
        if tool.execution_kind != "manual_recipe" {
            continue;
        }

        let endpoint: Option<(String, Vec<String>)> = tx
            .query_row(
                "SELECT method, query_parameter_names
                 FROM assessment_endpoints
                 WHERE run_id=?1
                   AND ('ep_' || substr(endpoint_key,1,24))=?2
                 ORDER BY id DESC LIMIT 1",
                params![run_id, plan.endpoint_id],
                |row| {
                    let names: String = row.get(1)?;
                    Ok((
                        row.get(0)?,
                        serde_json::from_str(&names).unwrap_or_default(),
                    ))
                },
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let action: Option<(i64, i64, String)> = tx
            .query_row(
                "SELECT a.id, a.revision, w.stable_key
                 FROM assessment_actions a
                 JOIN assessment_workstreams w ON w.id=a.workstream_id
                 WHERE a.mission_id=?1 AND a.tool_id=?2
                   AND a.execution_kind='manual_recipe'
                   AND a.approval_status='approved' AND a.status='queued'
                 ORDER BY a.id DESC LIMIT 1",
                params![mission_id, tool.id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;

        let rejection = if !allowed.contains(tool.id) {
            Some("manual_tool_not_approved")
        } else if action.is_none() {
            Some("manual_action_not_queued")
        } else if endpoint.is_none() {
            Some("manual_surface_not_in_run")
        } else if endpoint.as_ref().is_some_and(|row| row.0 != "GET") {
            Some("manual_surface_requires_get")
        } else if !tool
            .allowed_identity_modes
            .contains(&plan.identity_mode.as_str())
        {
            Some("manual_identity_mode_not_allowed")
        } else if plan.identity_mode == "a" && mission.identity_a_profile_id.is_none() {
            Some("manual_identity_a_missing")
        } else if plan.identity_mode == "b" && mission.identity_b_profile_id.is_none() {
            Some("manual_identity_b_missing")
        } else if plan.identity_mode == "a_vs_b"
            && (mission.identity_a_profile_id.is_none() || mission.identity_b_profile_id.is_none())
        {
            Some("manual_dual_identity_missing")
        } else if tool.requires_parameter && plan.parameter_name.is_none() {
            Some("manual_parameter_required")
        } else if plan.parameter_name.as_ref().is_some_and(|parameter| {
            endpoint
                .as_ref()
                .is_none_or(|row| !row.1.iter().any(|name| name == parameter))
        }) {
            Some("manual_parameter_not_in_inventory")
        } else if plan
            .workstream_key
            .as_ref()
            .is_some_and(|key| action.as_ref().is_none_or(|row| row.2 != *key))
        {
            Some("manual_workstream_not_allowed")
        } else {
            None
        };
        if let Some(reason) = rejection {
            tx.execute(
                "INSERT INTO assessment_coverage_gaps(
                     run_id, check_id, category, reason_code, detail
                 ) VALUES(?1,NULL,'manual',?2,?3)",
                params![
                    run_id,
                    reason,
                    format!("{} @ {} 被后端拒绝", plan.template_id, plan.endpoint_id)
                ],
            )
            .map_err(|error| error.to_string())?;
            continue;
        }

        let (action_id, action_revision, _) = action.expect("validated manual action exists");
        let selection = json!({
            "selection": {
                "roundId": round_id,
                "surfaceId": plan.endpoint_id,
                "parameterName": plan.parameter_name,
                "identityMode": plan.identity_mode,
                "workstreamKey": plan.workstream_key,
                "rationale": plan.rationale,
                "expectedSignal": plan.expected_signal,
            },
            "sendAutomatically": false,
            "requiresUserClick": true,
        });
        let selection_hash = hash_json(&selection)?;
        let changed = tx
            .execute(
                "UPDATE assessment_actions
                 SET status='manual_ready', result_json=?2, result_hash=?3,
                     revision=revision+1,
                     started_at=strftime('%Y-%m-%d %H:%M:%f','now','localtime')
                 WHERE id=?1 AND revision=?4 AND status='queued'
                   AND approval_status='approved'",
                params![
                    action_id,
                    serde_json::to_string(&selection).map_err(|error| error.to_string())?,
                    selection_hash,
                    action_revision,
                ],
            )
            .map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err("[REVISION_CONFLICT] 人工配方选择发生并发冲突".into());
        }
        accepted.push(json!({
            "actionId": action_id,
            "toolId": plan.template_id,
            "surfaceId": plan.endpoint_id,
            "parameterName": plan.parameter_name,
            "identityMode": plan.identity_mode,
        }));
    }

    let accepted_count = accepted.len();
    if accepted_count > 0 {
        let next_revision = mission.revision + 1;
        let details = json!({"roundId": round_id, "selections": accepted});
        append_message_on(
            &tx,
            mission_id,
            MessageEntry {
                role: "assistant",
                kind: "result",
                content:
                    "AI 在已审批工具范围内选择了人工配方；后端只创建待人工接力动作，不发送请求。",
                old_value: None,
                new_value: None,
                details: &details,
                manifest: &[],
            },
            next_revision,
        )?;
        let changed = tx
            .execute(
                "UPDATE assessment_missions
                 SET revision=?2,
                     updated_at=strftime('%Y-%m-%d %H:%M:%f','now','localtime')
                 WHERE id=?1 AND revision=?3 AND status='planning'",
                params![mission_id, next_revision, mission.revision],
            )
            .map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err("[REVISION_CONFLICT] mission 在人工配方选择时已变化".into());
        }
        tx.execute(
            "UPDATE assessment_workstreams SET status='awaiting_human',
                 updated_at=strftime('%Y-%m-%d %H:%M:%f','now','localtime')
             WHERE mission_id=?1 AND stable_key='manual'",
            [mission_id],
        )
        .map_err(|error| error.to_string())?;
    }
    tx.commit().map_err(|error| error.to_string())?;
    Ok(accepted_count)
}

pub fn planner_steering_for_run(conn: &Connection, run_id: i64) -> Result<Option<Value>, String> {
    let mission_id: Option<i64> = conn
        .query_row(
            "SELECT mission_id FROM assessment_mission_runs WHERE run_id=?1",
            [run_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some(mission_id) = mission_id else {
        return Ok(None);
    };
    let mission: (String, i64) = conn
        .query_row(
            "SELECT goal, pending_steering FROM assessment_missions WHERE id=?1",
            [mission_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| error.to_string())?;
    let mut statement = conn
        .prepare(
            "SELECT content FROM assessment_messages
             WHERE mission_id=?1 AND message_kind='follow_up'
             ORDER BY id DESC LIMIT 8",
        )
        .map_err(|error| error.to_string())?;
    let mut follow_ups = statement
        .query_map([mission_id], |row| row.get::<_, String>(0))
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    follow_ups.reverse();
    let mut surface_statement = conn
        .prepare(
            "SELECT surface_id, surface_kind, method, path_shape,
                    query_parameter_names, form_fields_json, content_types_json,
                    identity_visibility_json, response_structure_hash,
                    source_kinds_json, safe_to_request
             FROM assessment_surfaces WHERE run_id=?1 ORDER BY id LIMIT 500",
        )
        .map_err(|error| error.to_string())?;
    let surfaces = surface_statement
        .query_map([run_id], |row| {
            let query: String = row.get(4)?;
            let fields: String = row.get(5)?;
            let content: String = row.get(6)?;
            let visibility: String = row.get(7)?;
            let sources: String = row.get(9)?;
            Ok(json!({
                "surfaceId": row.get::<_, String>(0)?,
                "surfaceKind": row.get::<_, String>(1)?,
                "method": row.get::<_, String>(2)?,
                "pathShape": row.get::<_, String>(3)?,
                "parameterNames": serde_json::from_str::<Value>(&query).unwrap_or_else(|_| json!([])),
                "formFields": serde_json::from_str::<Value>(&fields).unwrap_or_else(|_| json!([])),
                "contentTypes": serde_json::from_str::<Value>(&content).unwrap_or_else(|_| json!([])),
                "identityVisibility": serde_json::from_str::<Value>(&visibility).unwrap_or_else(|_| json!({})),
                "responseStructureHash": row.get::<_, Option<String>>(8)?,
                "sourceKinds": serde_json::from_str::<Value>(&sources).unwrap_or_else(|_| json!([])),
                "safeToRequest": row.get::<_, i64>(10)? != 0,
            }))
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    drop(surface_statement);
    let resources = list_resources(conn, mission_id)?
        .into_iter()
        .map(|resource| {
            json!({
                "resourceType": resource.resource_type,
                "displayName": resource.display_name,
                "contentHash": resource.content_hash,
                "summary": resource.summary,
            })
        })
        .collect::<Vec<_>>();
    let workstreams = list_workstreams(conn, mission_id)?
        .into_iter()
        .map(|workstream| {
            json!({
                "workstreamKey": workstream.stable_key,
                "title": workstream.title,
                "objective": workstream.objective,
            })
        })
        .collect::<Vec<_>>();
    Ok(Some(json!({
        "goal": mission.0,
        "followUps": follow_ups,
        "steeringPending": mission.1 != 0,
        "workstreams": workstreams,
        "surfaces": surfaces,
        "resources": resources,
    })))
}

pub fn clear_steering_for_run(conn: &Connection, run_id: i64) -> Result<(), String> {
    conn.execute(
        "UPDATE assessment_missions SET pending_steering=0
         WHERE id=(SELECT mission_id FROM assessment_mission_runs WHERE run_id=?1)",
        [run_id],
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

// ---------- Internal helpers ----------

struct PermissionState {
    hash: String,
    tools: Vec<MissionToolDescriptor>,
}

struct ContextMaterial {
    summary: Value,
    disclosure_manifest: Vec<String>,
}

fn permission_state(
    conn: &Connection,
    project_id: i64,
    autonomy: AutonomyMode,
) -> Result<PermissionState, String> {
    let overrides = permission_override_map(conn, project_id)?;
    let mut tools = Vec::new();
    let mut hash_rows = Vec::new();
    for tool in catalog::TOOL_SPECS {
        let decision =
            effective_permission(autonomy, tool, overrides.get(tool.id).map(String::as_str));
        hash_rows.push(json!({
            "id": tool.id,
            "version": tool.version,
            "decision": decision,
        }));
        if decision == "disabled" {
            continue;
        }
        tools.push(MissionToolDescriptor {
            id: tool.id.into(),
            version: tool.version.into(),
            display_name: tool.display_name.into(),
            description: tool.description.into(),
            execution_kind: tool.execution_kind.into(),
            risk_level: tool.risk_level.into(),
            parameter_schema: serde_json::from_str(tool.parameter_schema)
                .map_err(|error| error.to_string())?,
            allowed_identity_modes: tool
                .allowed_identity_modes
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            request_cost: tool.request_cost,
            default_permission: tool.default_permission.into(),
            effective_permission: decision.into(),
            can_auto_confirm: tool.can_auto_confirm,
        });
    }
    let hash = hash_json(&json!({
        "registryHash": catalog::registry_hash(),
        "autonomyMode": autonomy.as_str(),
        "tools": hash_rows,
    }))?;
    Ok(PermissionState { hash, tools })
}

fn effective_permission(
    autonomy: AutonomyMode,
    tool: &ToolSpec,
    override_decision: Option<&str>,
) -> &'static str {
    if let Some(decision) = override_decision {
        return match decision {
            "disabled" => "disabled",
            "ask" => "ask",
            "execute" if tool.execution_kind != "manual_recipe" => "execute",
            _ => "ask",
        };
    }
    match autonomy {
        AutonomyMode::Manual => {
            if tool.execution_kind == "observe" {
                "execute"
            } else {
                "ask"
            }
        }
        AutonomyMode::Smart => {
            if tool.execution_kind == "observe"
                || (tool.execution_kind == "safe_probe" && tool.risk_level == "low")
            {
                "execute"
            } else {
                "ask"
            }
        }
        AutonomyMode::Automatic => {
            if tool.execution_kind == "manual_recipe" {
                "ask"
            } else {
                "execute"
            }
        }
    }
}

fn context_material(
    goal: &str,
    contract: &super::model::AssessmentContractPreview,
    resources: &[AssessmentMissionResource],
    tools: &[MissionToolDescriptor],
    inherited_manifest: &[String],
) -> Result<ContextMaterial, String> {
    let start = Url::parse(&contract.normalized_start_url).map_err(|error| error.to_string())?;
    let start_surface = surface_summary(&start);
    let resource_summaries = resources
        .iter()
        .map(|resource| {
            json!({
                "resourceType": resource.resource_type,
                "displayName": resource.display_name,
                "contentHash": resource.content_hash,
                "summary": resource.summary,
            })
        })
        .collect::<Vec<_>>();
    let tool_manifest = tools
        .iter()
        .map(|tool| {
            json!({
                "toolId": tool.id,
                "version": tool.version,
                "executionKind": tool.execution_kind,
                "riskLevel": tool.risk_level,
                "effectivePermission": tool.effective_permission,
                "allowedIdentityModes": tool.allowed_identity_modes,
                "requestCost": tool.request_cost,
            })
        })
        .collect::<Vec<_>>();
    let mut disclosure_manifest = vec![
        "用户目标（已执行秘密扫描与脱敏）".to_string(),
        "规范化路径形状与参数名（不含完整 URL 和参数值）".to_string(),
        "身份标签与 secret revision（不含身份值）".to_string(),
        "附件的不可变脱敏结构摘要与 hash".to_string(),
        "启用工具的 ID、版本、风险与权限判定".to_string(),
    ];
    disclosure_manifest.extend(inherited_manifest.iter().cloned());
    disclosure_manifest.sort();
    disclosure_manifest.dedup();
    Ok(ContextMaterial {
        summary: json!({
            "contextVersion": "assessment_mission_context_v2",
            "goal": goal,
            "startSurface": start_surface,
            "scopeEntryCount": contract.normalized_scope.len(),
            "excludedPaths": contract.excluded_paths,
            "identities": {
                "a": contract.identity_a_profile_id.map(|id| json!({
                    "profileId": id,
                    "label": contract.identity_a_label,
                    "secretRevision": contract.identity_a_secret_revision,
                })),
                "b": contract.identity_b_profile_id.map(|id| json!({
                    "profileId": id,
                    "label": contract.identity_b_label,
                    "secretRevision": contract.identity_b_secret_revision,
                })),
            },
            "resources": resource_summaries,
            "tools": tool_manifest,
            "budget": {
                "targetRequests": contract.request_budget,
                "rpsHardLimit": 2,
                "concurrencyHardLimit": 1,
            },
            "provider": {
                "providerId": contract.provider_id,
                "model": contract.model,
            },
        }),
        disclosure_manifest,
    })
}

fn prepare_workstreams_and_actions(
    tx: &Transaction<'_>,
    mission: &AssessmentMission,
    tools: &[MissionToolDescriptor],
    permission_hash: &str,
) -> Result<(), String> {
    tx.execute(
        "UPDATE assessment_actions SET status='cancelled',
             completed_at=strftime('%Y-%m-%d %H:%M:%f','now','localtime')
         WHERE mission_id=?1 AND status IN ('proposed','awaiting_approval','queued')",
        [mission.id],
    )
    .map_err(|error| error.to_string())?;
    let streams = [
        (
            "inventory",
            "攻击面与本地基线",
            "发现并聚合稳定 surface，先执行确定性观察。",
            10,
        ),
        (
            "access",
            "身份与浏览器边界",
            "比较匿名/登录可见性、CORS、JWT 与只读资源边界。",
            20,
        ),
        (
            "input",
            "输入与导航边界",
            "检查已有参数的重定向和惰性反射信号。",
            30,
        ),
        (
            "manual",
            "人工深度验证",
            "为高风险类别创建不发送的 Repeater 人工配方。",
            40,
        ),
    ];
    let mut stream_ids = HashMap::new();
    for (key, title, objective, order) in streams {
        tx.execute(
            "INSERT INTO assessment_workstreams(
                 mission_id, stable_key, title, objective, sort_order
             ) VALUES(?1,?2,?3,?4,?5)
             ON CONFLICT(mission_id, stable_key) DO UPDATE SET
                 title=excluded.title, objective=excluded.objective,
                 sort_order=excluded.sort_order,
                 updated_at=strftime('%Y-%m-%d %H:%M:%f','now','localtime')",
            params![mission.id, key, title, objective, order],
        )
        .map_err(|error| error.to_string())?;
        let id: i64 = tx
            .query_row(
                "SELECT id FROM assessment_workstreams WHERE mission_id=?1 AND stable_key=?2",
                params![mission.id, key],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        stream_ids.insert(key, id);
    }
    for tool in tools.iter().filter(|tool| tool_relevant(mission, tool)) {
        let stream = match tool.id.as_str() {
            "security_headers_cookie"
            | "html_surface_inventory"
            | "static_route_inventory"
            | "openapi_inventory"
            | "options_capabilities" => "inventory",
            "credentialed_cors"
            | "jwt_integrity"
            | "readonly_idor"
            | "anonymous_authenticated_diff" => "access",
            "open_redirect" | "lazy_reflection" => "input",
            _ if tool.execution_kind == "manual_recipe" => "manual",
            _ => "inventory",
        };
        let requires_approval =
            tool.effective_permission == "ask" || tool.execution_kind == "manual_recipe";
        let (approval_status, status) = if requires_approval {
            ("pending", "awaiting_approval")
        } else {
            ("not_required", "queued")
        };
        tx.execute(
            "INSERT INTO assessment_actions(
                 mission_id, workstream_id, tool_id, tool_version,
                 execution_kind, risk_level, identity_mode, parameter_json,
                 rationale, expected_signal, request_cost,
                 permission_snapshot, permission_hash, approval_status,
                 approval_source, status, policy_reason
             ) VALUES(?1,?2,?3,?4,?5,?6,?7,'{}',?8,?9,?10,?11,?12,?13,'policy',?14,?15)",
            params![
                mission.id,
                stream_ids[stream],
                tool.id,
                tool.version,
                tool.execution_kind,
                tool.risk_level,
                default_identity_mode(mission, tool),
                format!(
                    "为目标“{}”选择 {}；具体 URL、方法和探针由后端版本实现绑定。",
                    mission.title, tool.display_name
                ),
                expected_signal(tool),
                tool.request_cost,
                tool.effective_permission,
                permission_hash,
                approval_status,
                status,
                if requires_approval {
                    "awaiting_user_approval"
                } else {
                    "allowed_by_permission_profile"
                },
            ],
        )
        .map_err(|error| format!("创建可信工具动作失败: {error}"))?;
    }
    Ok(())
}

fn tool_relevant(mission: &AssessmentMission, tool: &MissionToolDescriptor) -> bool {
    if tool.id == "openapi_inventory" {
        return true;
    }
    if matches!(
        tool.id.as_str(),
        "jwt_integrity" | "readonly_idor" | "anonymous_authenticated_diff" | "credentialed_cors"
    ) && mission.identity_a_profile_id.is_none()
        && mission.identity_b_profile_id.is_none()
    {
        return false;
    }
    if tool.execution_kind != "manual_recipe" {
        return true;
    }
    let goal = mission.goal.to_ascii_lowercase();
    match tool.id.as_str() {
        "manual_sqli_recipe" => {
            goal.contains("sql") || goal.contains("注入") || goal.contains("全面")
        }
        "manual_ssrf_recipe" => {
            goal.contains("ssrf") || goal.contains("服务端请求") || goal.contains("全面")
        }
        "manual_xss_recipe" => {
            goal.contains("xss") || goal.contains("跨站") || goal.contains("全面")
        }
        "manual_business_logic_recipe" => {
            goal.contains("业务") || goal.contains("logic") || goal.contains("全面")
        }
        _ => false,
    }
}

fn default_identity_mode(
    mission: &AssessmentMission,
    tool: &MissionToolDescriptor,
) -> &'static str {
    if tool
        .allowed_identity_modes
        .iter()
        .any(|mode| mode == "a_vs_b")
        && mission.identity_a_profile_id.is_some()
        && mission.identity_b_profile_id.is_some()
    {
        "a_vs_b"
    } else if tool.allowed_identity_modes.iter().any(|mode| mode == "a")
        && mission.identity_a_profile_id.is_some()
    {
        "a"
    } else if tool.allowed_identity_modes.iter().any(|mode| mode == "b")
        && mission.identity_b_profile_id.is_some()
    {
        "b"
    } else {
        "anonymous"
    }
}

fn expected_signal(tool: &MissionToolDescriptor) -> &'static str {
    match tool.id.as_str() {
        "security_headers_cookie" => "版本固定验证器输出事实型 Header/Cookie/缓存观察。",
        "credentialed_cors" => "匿名、身份与受控 Origin 响应的 CORS Header 组合差异。",
        "jwt_integrity" => "固定 JWT 变体相对匿名与合法身份的授权结果差异。",
        "readonly_idor" => "身份 A/B 对明确归属资源的完整响应结构差异。",
        "open_redirect" => "不跟随响应中的 Location 是否指向固定无效外部 origin。",
        "lazy_reflection" => "惰性标记是否在完整响应中出现；不会直接确认 XSS。",
        "options_capabilities" => "Allow 与 CORS 能力边界，不据此单独确认漏洞。",
        _ if tool.execution_kind == "manual_recipe" => {
            "用户在独立 Repeater 会话观察差异并回传未接受 Evidence。"
        }
        _ => "形成稳定 surface、来源和覆盖状态，不产生模型漏洞结论。",
    }
}

fn assert_mission_integrity(conn: &Connection, mission: &AssessmentMission) -> Result<(), String> {
    if mission.tool_registry_hash != catalog::registry_hash() {
        return Err("[REGISTRY_DRIFT] 工具注册表已变化，请重新确认上下文".into());
    }
    let permissions = permission_state(conn, mission.project_id, mission.autonomy_mode)?;
    if mission.permission_hash != permissions.hash {
        return Err("[PERMISSION_DRIFT] 工具权限已变化，请重新确认上下文".into());
    }
    if mission.context_hash.is_none()
        || mission.context_hash.as_deref() != mission.context_approved_hash.as_deref()
    {
        return Err("[CONTEXT_DRIFT] AI 上下文尚未确认或已变化".into());
    }
    Ok(())
}

struct MissionTransitionInput<'a> {
    current: MissionStatus,
    next: MissionStatus,
    current_revision: i64,
    content: &'a str,
    details: &'a Value,
    stop_reason: Option<&'a str>,
}

struct MessageEntry<'a> {
    role: &'a str,
    kind: &'a str,
    content: &'a str,
    old_value: Option<&'a str>,
    new_value: Option<&'a str>,
    details: &'a Value,
    manifest: &'a [String],
}

fn transition_mission_on(
    tx: &Transaction<'_>,
    mission_id: i64,
    project_id: i64,
    input: MissionTransitionInput<'_>,
) -> Result<(), String> {
    validate_mission_transition(input.current, input.next)?;
    let next_revision = input.current_revision + 1;
    append_message_on(
        tx,
        mission_id,
        MessageEntry {
            role: "system",
            kind: "status",
            content: input.content,
            old_value: Some(input.current.as_str()),
            new_value: Some(input.next.as_str()),
            details: input.details,
            manifest: &[],
        },
        next_revision,
    )?;
    let changed = tx
        .execute(
            "UPDATE assessment_missions
             SET status=?3, revision=?4,
                 stop_reason=CASE WHEN ?5 IS NULL THEN stop_reason ELSE ?5 END,
                 started_at=CASE WHEN started_at IS NULL AND ?3 IN
                    ('discovering','planning','executing','verifying')
                    THEN strftime('%Y-%m-%d %H:%M:%f','now','localtime') ELSE started_at END,
                 ended_at=CASE WHEN ?3 IN
                    ('completed','stopped','cancelled','failed','interrupted')
                    THEN strftime('%Y-%m-%d %H:%M:%f','now','localtime') ELSE ended_at END,
                 updated_at=strftime('%Y-%m-%d %H:%M:%f','now','localtime')
             WHERE id=?1 AND project_id=?2 AND revision=?6 AND status=?7",
            params![
                mission_id,
                project_id,
                input.next.as_str(),
                next_revision,
                input.stop_reason,
                input.current_revision,
                input.current.as_str(),
            ],
        )
        .map_err(|error| error.to_string())?;
    if changed != 1 {
        return Err("[REVISION_CONFLICT] mission 状态已被其他操作更新".into());
    }
    Ok(())
}

fn validate_mission_transition(current: MissionStatus, next: MissionStatus) -> Result<(), String> {
    if current == next {
        return Ok(());
    }
    let allowed = match current {
        MissionStatus::Draft => matches!(
            next,
            MissionStatus::AwaitingContextApproval | MissionStatus::Stopped
        ),
        MissionStatus::AwaitingContextApproval => matches!(
            next,
            MissionStatus::AwaitingActionApproval
                | MissionStatus::Queued
                | MissionStatus::Stopped
                | MissionStatus::Cancelled
        ),
        MissionStatus::AwaitingActionApproval => matches!(
            next,
            MissionStatus::Queued
                | MissionStatus::AwaitingContextApproval
                | MissionStatus::Stopped
                | MissionStatus::Cancelled
        ),
        MissionStatus::Queued => matches!(
            next,
            MissionStatus::Discovering
                | MissionStatus::Stopped
                | MissionStatus::Cancelled
                | MissionStatus::Failed
                | MissionStatus::Interrupted
        ),
        MissionStatus::Discovering => matches!(
            next,
            MissionStatus::Planning
                | MissionStatus::Stopped
                | MissionStatus::Cancelled
                | MissionStatus::Failed
                | MissionStatus::Interrupted
        ),
        MissionStatus::Planning => matches!(
            next,
            MissionStatus::Executing
                | MissionStatus::Completed
                | MissionStatus::AwaitingManualHandoff
                | MissionStatus::Stopped
                | MissionStatus::Cancelled
                | MissionStatus::Failed
                | MissionStatus::Interrupted
        ),
        MissionStatus::Executing => matches!(
            next,
            MissionStatus::Planning
                | MissionStatus::Verifying
                | MissionStatus::Completed
                | MissionStatus::AwaitingManualHandoff
                | MissionStatus::Stopped
                | MissionStatus::Cancelled
                | MissionStatus::Failed
                | MissionStatus::Interrupted
        ),
        MissionStatus::Verifying => matches!(
            next,
            MissionStatus::Planning
                | MissionStatus::Completed
                | MissionStatus::AwaitingManualHandoff
                | MissionStatus::Stopped
                | MissionStatus::Cancelled
                | MissionStatus::Failed
                | MissionStatus::Interrupted
        ),
        MissionStatus::AwaitingManualHandoff => matches!(
            next,
            MissionStatus::Completed | MissionStatus::Stopped | MissionStatus::Cancelled
        ),
        _ => false,
    };
    if allowed {
        Ok(())
    } else {
        Err(format!(
            "不允许 mission 状态从 {} 变为 {}",
            current.as_str(),
            next.as_str()
        ))
    }
}

fn append_message_on(
    tx: &Transaction<'_>,
    mission_id: i64,
    message: MessageEntry<'_>,
    revision: i64,
) -> Result<i64, String> {
    tx.execute(
        "INSERT INTO assessment_messages(
             mission_id, role, message_kind, content, content_hash,
             old_value, new_value, details_json, redaction_manifest_json, revision
         ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        params![
            mission_id,
            message.role,
            message.kind,
            message.content,
            sha256(message.content.as_bytes()),
            message.old_value,
            message.new_value,
            serde_json::to_string(message.details).map_err(|error| error.to_string())?,
            serde_json::to_string(message.manifest).map_err(|error| error.to_string())?,
            revision,
        ],
    )
    .map_err(|error| error.to_string())?;
    Ok(tx.last_insert_rowid())
}

fn bump_context_revision(
    tx: &Transaction<'_>,
    mission_id: i64,
    project_id: i64,
    current_revision: i64,
    content: &str,
    details: &Value,
) -> Result<(), String> {
    let next_revision = current_revision + 1;
    append_message_on(
        tx,
        mission_id,
        MessageEntry {
            role: "system",
            kind: "summary",
            content,
            old_value: None,
            new_value: None,
            details,
            manifest: &[],
        },
        next_revision,
    )?;
    let changed = tx
        .execute(
            "UPDATE assessment_missions
             SET revision=?3, context_hash=NULL, context_approved_hash=NULL,
                 updated_at=strftime('%Y-%m-%d %H:%M:%f','now','localtime')
             WHERE id=?1 AND project_id=?2 AND revision=?4",
            params![mission_id, project_id, next_revision, current_revision],
        )
        .map_err(|error| error.to_string())?;
    if changed != 1 {
        return Err("[REVISION_CONFLICT] 任务资源已被其他操作更新".into());
    }
    Ok(())
}

fn sync_actions_from_run_on(
    tx: &Transaction<'_>,
    mission_id: i64,
    run_id: i64,
    run_completed: bool,
) -> Result<(), String> {
    let mut statement = tx
        .prepare(
            "SELECT c.id, c.template_id, c.status, c.policy_result,
                    v.verdict, v.observations_json, v.content_hash
             FROM assessment_checks c
             LEFT JOIN assessment_verifications v ON v.check_id=c.id
             WHERE c.run_id=?1 ORDER BY c.id",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([run_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
            ))
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    drop(statement);
    for (check_id, tool_id, status, policy, verdict, observations, result_hash) in rows {
        let action_id: Option<i64> = tx
            .query_row(
                "SELECT id FROM assessment_actions
                 WHERE mission_id=?1 AND tool_id=?2
                   AND approval_status IN ('not_required','approved')
                 ORDER BY id DESC LIMIT 1",
                params![mission_id, tool_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some(action_id) = action_id else { continue };
        tx.execute(
            "INSERT OR IGNORE INTO assessment_action_checks(action_id, check_id)
             VALUES(?1,?2)",
            params![action_id, check_id],
        )
        .map_err(|error| error.to_string())?;
        let result = json!({
            "checkId": check_id,
            "checkStatus": status,
            "policyResult": policy,
            "verdict": verdict,
            "observations": observations
                .as_deref()
                .and_then(|raw| serde_json::from_str::<Value>(raw).ok()),
        });
        tx.execute(
            "UPDATE assessment_actions
             SET status='completed', result_json=?2,
                 result_hash=COALESCE(?3, result_hash), revision=revision+1,
                 completed_at=strftime('%Y-%m-%d %H:%M:%f','now','localtime')
             WHERE id=?1",
            params![
                action_id,
                serde_json::to_string(&result).map_err(|error| error.to_string())?,
                result_hash,
            ],
        )
        .map_err(|error| error.to_string())?;
    }
    if run_completed {
        let (surface_count, form_count, script_count): (i64, i64, i64) = tx
            .query_row(
                "SELECT COUNT(*),
                        COALESCE(SUM(CASE WHEN surface_kind='form' THEN 1 ELSE 0 END),0),
                        COALESCE(SUM(CASE WHEN surface_kind='script' THEN 1 ELSE 0 END),0)
                 FROM assessment_surfaces WHERE run_id=?1",
                [run_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|error| error.to_string())?;
        let openapi_resources: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM assessment_mission_resources
                 WHERE mission_id=?1 AND resource_type='openapi'",
                [mission_id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let inventory_result = json!({
            "coverage": "inventory_completed",
            "surfaceCount": surface_count,
            "formCount": form_count,
            "scriptCount": script_count,
            "openApiResourceCount": openapi_resources,
        });
        let inventory_json =
            serde_json::to_string(&inventory_result).map_err(|error| error.to_string())?;
        let inventory_hash = hash_json(&inventory_result)?;
        tx.execute(
            "UPDATE assessment_actions
             SET status='completed', result_json=?2,
                 result_hash=?3, revision=revision+1,
                 completed_at=strftime('%Y-%m-%d %H:%M:%f','now','localtime')
             WHERE mission_id=?1 AND execution_kind='observe' AND status='queued'",
            params![mission_id, inventory_json, inventory_hash],
        )
        .map_err(|error| error.to_string())?;

        let skipped = json!({
            "coverage": "coverage_gap",
            "reason": "planner_not_selected",
            "socketCreated": false,
        });
        let skipped_json = serde_json::to_string(&skipped).map_err(|error| error.to_string())?;
        let skipped_hash = hash_json(&skipped)?;
        tx.execute(
            "UPDATE assessment_actions
             SET status='skipped', result_json=?2, result_hash=?3,
                 revision=revision+1,
                 completed_at=strftime('%Y-%m-%d %H:%M:%f','now','localtime')
             WHERE mission_id=?1 AND status='queued'
               AND execution_kind IN ('safe_probe','manual_recipe')",
            params![mission_id, skipped_json, skipped_hash],
        )
        .map_err(|error| error.to_string())?;
    } else {
        let cancelled = json!({
            "coverage": "run_not_completed",
            "socketCreated": false,
        });
        tx.execute(
            "UPDATE assessment_actions
             SET status='cancelled', revision=revision+1,
                 result_json=?2, result_hash=?3,
                 completed_at=strftime('%Y-%m-%d %H:%M:%f','now','localtime')
             WHERE mission_id=?1 AND status='queued'",
            params![
                mission_id,
                serde_json::to_string(&cancelled).map_err(|error| error.to_string())?,
                hash_json(&cancelled)?,
            ],
        )
        .map_err(|error| error.to_string())?;
    }
    tx.execute(
        "UPDATE assessment_workstreams
         SET status=CASE
             WHEN EXISTS(SELECT 1 FROM assessment_actions a
                 WHERE a.workstream_id=assessment_workstreams.id
                   AND a.status IN ('manual_ready','manual_result_pending'))
                 THEN 'awaiting_human'
             WHEN EXISTS(SELECT 1 FROM assessment_actions a
                 WHERE a.workstream_id=assessment_workstreams.id
                   AND a.status IN ('proposed','awaiting_approval','queued','executing'))
                 THEN 'in_progress'
             ELSE 'completed' END,
             updated_at=strftime('%Y-%m-%d %H:%M:%f','now','localtime')
         WHERE mission_id=?1",
        [mission_id],
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn build_manual_recipe_draft(
    conn: &Connection,
    mission: &AssessmentMission,
    action: &AssessmentAction,
    session_id: i64,
) -> Result<Value, String> {
    let marker = match action.tool_id.as_str() {
        "manual_sqli_recipe" => "RF_SQLI_REVIEW_20260803",
        "manual_ssrf_recipe" => "https://invalid.rustforge.example/ssrf-review",
        "manual_xss_recipe" => "RF_XSS_INERT_REVIEW_20260803",
        "manual_business_logic_recipe" => "RF_LOGIC_REVIEW_20260803",
        _ => return Err("未知人工配方".into()),
    };
    let selection = action
        .result
        .as_ref()
        .and_then(|result| result.get("selection"))
        .ok_or_else(|| "人工配方尚未由规划器选择具体 surface".to_string())?;
    let round_id = selection
        .get("roundId")
        .and_then(Value::as_i64)
        .ok_or_else(|| "人工配方缺少规划轮次".to_string())?;
    let surface_id = selection
        .get("surfaceId")
        .and_then(Value::as_str)
        .ok_or_else(|| "人工配方缺少不透明 surface ID".to_string())?;
    let parameter_name = selection.get("parameterName").and_then(Value::as_str);
    let identity_mode = selection
        .get("identityMode")
        .and_then(Value::as_str)
        .unwrap_or("anonymous");
    let selected: Option<(String, String)> = conn
        .query_row(
            "SELECT e.method, e.url
             FROM assessment_rounds r
             JOIN assessment_mission_runs mr ON mr.run_id=r.run_id
             JOIN assessment_endpoints e ON e.run_id=r.run_id
             WHERE r.id=?1 AND mr.mission_id=?2
               AND ('ep_' || substr(e.endpoint_key,1,24))=?3
             ORDER BY e.id DESC LIMIT 1",
            params![round_id, mission.id, surface_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let (method, baseline_url) =
        selected.ok_or_else(|| "人工配方 surface 不属于其规划轮次".to_string())?;
    if method != "GET" {
        return Err("人工配方草稿只接受已登记的 GET surface".into());
    }
    let mut baseline = Url::parse(&baseline_url).map_err(|_| "人工配方 URL 已损坏".to_string())?;
    let live_origin = super::policy::exact_origin(&baseline).map_err(|error| error.to_string())?;
    if live_origin != mission.exact_origin {
        return Err("[SCOPE_DRIFT] 人工配方 surface 已偏离精确 origin".into());
    }
    baseline.set_fragment(None);
    let baseline_url = baseline.to_string();
    let mut proposed_url = baseline_url.clone();
    if let Some(parameter_name) = parameter_name {
        let mut url = baseline;
        let mut pairs = url
            .query_pairs()
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();
        let mut replaced = false;
        for (name, value) in &mut pairs {
            if name == parameter_name {
                *value = marker.into();
                replaced = true;
            }
        }
        if !replaced {
            pairs.push((parameter_name.into(), marker.into()));
        }
        url.query_pairs_mut().clear().extend_pairs(pairs);
        proposed_url = url.to_string();
    }
    Ok(json!({
        "schemaVersion": 1,
        "sessionId": session_id,
        "recipeId": action.tool_id,
        "recipeVersion": action.tool_version,
        "sendAutomatically": false,
        "requiresUserClick": true,
        "baseline": {
            "method": method,
            "url": baseline_url,
            "headers": [],
            "body": null,
        },
        "request": {
            "method": method,
            "url": proposed_url,
            "headers": [],
            "bodyText": null,
            "bodyBase64": null,
        },
        "proposedDifference": {
            "field": parameter_name,
            "reviewMarker": marker,
            "surfaceId": surface_id,
            "identityMode": identity_mode,
            "instructions": "请在 Repeater 中核对 Scope、身份与差异后亲自点击发送。",
        },
        "evidencePolicy": {
            "defaultAccepted": false,
            "autoConfirmFinding": false,
        }
    }))
}

fn summarize_project_resource(
    conn: &Connection,
    project_id: i64,
    resource_type: &str,
    source_id: i64,
) -> Result<(String, String, Value), String> {
    match resource_type {
        "traffic" => {
            let row: (String, String, Option<i64>, String, i64, i64) = conn
                .query_row(
                    "SELECT method, url, status, content_type, req_truncated, resp_truncated
                     FROM traffic WHERE id=?1 AND project_id=?2",
                    params![source_id, project_id],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                        ))
                    },
                )
                .optional()
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "Traffic 不存在或不属于当前项目".to_string())?;
            let url = Url::parse(&row.1).map_err(|_| "Traffic URL 无法规范化".to_string())?;
            Ok((
                format!(
                    "Traffic #{source_id} · {} {}",
                    row.0,
                    normalize_path_shape(url.path())
                ),
                row.3.clone(),
                json!({
                    "method": row.0,
                    "surface": surface_summary(&url),
                    "status": row.2,
                    "contentType": row.3,
                    "requestComplete": row.4 == 0,
                    "responseComplete": row.5 == 0,
                }),
            ))
        }
        "finding" => {
            let row: (String, String, String, String, String) = conn
                .query_row(
                    "SELECT title, vuln_type, severity, status, reasoning
                     FROM findings WHERE id=?1 AND project_id=?2",
                    params![source_id, project_id],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .optional()
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "Finding 不存在或不属于当前项目".to_string())?;
            let mut manifest = RedactionManifest::default();
            let safe_title = redact_fallback_text(
                &row.0,
                "mission.resource.finding.title",
                true,
                &mut manifest,
            );
            Ok((
                format!(
                    "Finding #{source_id} · {}",
                    safe_title.chars().take(120).collect::<String>()
                ),
                "application/vnd.rustforge.finding+json".into(),
                json!({
                    "title": safe_title,
                    "vulnerabilityType": row.1,
                    "severity": row.2,
                    "status": row.3,
                    "reasoningExcerpt": redact_fallback_text(
                        &row.4.chars().take(1200).collect::<String>(),
                        "mission.resource.finding.reasoning", true, &mut manifest
                    ),
                }),
            ))
        }
        "assessment_run" => {
            let row: (String, String, i64, i64) = conn
                .query_row(
                    "SELECT status, contract_hash, request_count, completed_rounds
                     FROM assessment_runs WHERE id=?1 AND project_id=?2",
                    params![source_id, project_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "历史评估不存在或不属于当前项目".to_string())?;
            let counts: (i64, i64, i64) = conn
                .query_row(
                    "SELECT
                         COUNT(DISTINCT e.id), COUNT(DISTINCT c.id), COUNT(DISTINCT g.id)
                     FROM assessment_runs r
                     LEFT JOIN assessment_endpoints e ON e.run_id=r.id
                     LEFT JOIN assessment_checks c ON c.run_id=r.id
                     LEFT JOIN assessment_coverage_gaps g ON g.run_id=r.id
                     WHERE r.id=?1",
                    [source_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|error| error.to_string())?;
            Ok((
                format!("历史评估 #{source_id}"),
                "application/vnd.rustforge.assessment+json".into(),
                json!({
                    "status": row.0,
                    "contractHash": row.1,
                    "requestCount": row.2,
                    "completedRounds": row.3,
                    "endpointCount": counts.0,
                    "checkCount": counts.1,
                    "coverageGapCount": counts.2,
                }),
            ))
        }
        _ => Err("资源类型只能是 traffic、finding 或 assessment_run".into()),
    }
}

fn summarize_openapi_json(raw: &str) -> Result<Value, String> {
    let value: Value =
        serde_json::from_str(raw).map_err(|error| format!("OpenAPI JSON 无效: {error}"))?;
    let paths = value
        .get("paths")
        .and_then(Value::as_object)
        .ok_or_else(|| "OpenAPI JSON 缺少 paths 对象".to_string())?;
    if paths.len() > MAX_OPENAPI_PATHS {
        return Err(format!("OpenAPI paths 超过 {MAX_OPENAPI_PATHS} 条上限"));
    }
    let mut surfaces = Vec::new();
    for (path, item) in paths {
        let Some(operations) = item.as_object() else {
            continue;
        };
        let methods = operations
            .keys()
            .filter(|method| is_openapi_method(method))
            .map(|method| method.to_ascii_uppercase())
            .collect::<Vec<_>>();
        if methods.is_empty() {
            continue;
        }
        let mut parameters = BTreeSet::new();
        collect_openapi_parameter_names(item, &mut parameters);
        for operation in operations.values() {
            collect_openapi_parameter_names(operation, &mut parameters);
        }
        let shape = normalize_path_shape(path);
        surfaces.push(json!({
            "surfaceId": opaque_surface_id(&shape, &methods.join(",")),
            "pathShape": shape,
            "methods": methods,
            "parameterNames": parameters,
        }));
    }
    let raw_title = value
        .pointer("/info/title")
        .and_then(Value::as_str)
        .unwrap_or("");
    let mut manifest = RedactionManifest::default();
    let title = redact_fallback_text(
        raw_title,
        "assessment_mission.openapi_title",
        true,
        &mut manifest,
    );
    Ok(json!({
        "format": "openapi_json",
        "title": title,
        "surfaceCount": surfaces.len(),
        "surfaces": surfaces,
        "serversOmitted": true,
        "examplesOmitted": true,
        "securityValuesOmitted": true,
    }))
}

fn summarize_openapi_yaml(raw: &str) -> Result<Value, String> {
    if !raw
        .lines()
        .any(|line| line.trim_start().starts_with("openapi:"))
        || !raw.lines().any(|line| line.trim() == "paths:")
    {
        return Err("YAML 未识别为 OpenAPI 文档".into());
    }
    let mut paths = BTreeMap::<String, BTreeSet<String>>::new();
    let mut in_paths = false;
    let mut current_path: Option<String> = None;
    for line in raw.lines() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let indent = line.chars().take_while(|ch| ch.is_whitespace()).count();
        let trimmed = line.trim();
        if indent == 0 {
            in_paths = trimmed == "paths:";
            if !in_paths {
                current_path = None;
            }
            continue;
        }
        if !in_paths {
            continue;
        }
        if indent <= 2 && trimmed.starts_with('/') && trimmed.ends_with(':') {
            let path = trimmed.trim_end_matches(':').trim().to_string();
            if paths.len() >= MAX_OPENAPI_PATHS && !paths.contains_key(&path) {
                return Err(format!("OpenAPI paths 超过 {MAX_OPENAPI_PATHS} 条上限"));
            }
            paths.entry(path.clone()).or_default();
            current_path = Some(path);
            continue;
        }
        if let Some(path) = &current_path {
            let method = trimmed.trim_end_matches(':').to_ascii_lowercase();
            if indent <= 6 && is_openapi_method(&method) {
                paths
                    .entry(path.clone())
                    .or_default()
                    .insert(method.to_ascii_uppercase());
            }
        }
    }
    let surfaces = paths
        .into_iter()
        .filter(|(_, methods)| !methods.is_empty())
        .map(|(path, methods)| {
            let methods = methods.into_iter().collect::<Vec<_>>();
            let shape = normalize_path_shape(&path);
            json!({
                "surfaceId": opaque_surface_id(&shape, &methods.join(",")),
                "pathShape": shape,
                "methods": methods,
                "parameterNames": [],
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "format": "openapi_yaml",
        "surfaceCount": surfaces.len(),
        "surfaces": surfaces,
        "serversOmitted": true,
        "examplesOmitted": true,
        "securityValuesOmitted": true,
    }))
}

fn collect_openapi_parameter_names(value: &Value, out: &mut BTreeSet<String>) {
    if let Some(parameters) = value.get("parameters").and_then(Value::as_array) {
        for parameter in parameters.iter().take(200) {
            if let Some(name) = parameter.get("name").and_then(Value::as_str) {
                if !name.is_empty() && name.len() <= 240 {
                    out.insert(name.to_string());
                }
            }
        }
    }
}

fn is_openapi_method(method: &str) -> bool {
    matches!(
        method.to_ascii_lowercase().as_str(),
        "get" | "head" | "options" | "post" | "put" | "patch" | "delete" | "trace"
    )
}

fn contract_input_from_mission(
    conn: &Connection,
    mission: &AssessmentMission,
) -> Result<super::model::AssessmentContractInput, String> {
    let raw: String = conn
        .query_row(
            "SELECT contract_json FROM assessment_missions WHERE id=?1",
            [mission.id],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    let old: super::model::AssessmentContractPreview =
        serde_json::from_str(&raw).map_err(|error| error.to_string())?;
    Ok(super::model::AssessmentContractInput {
        project_id: mission.project_id,
        start_url: mission.start_url.clone(),
        excluded_paths: old.excluded_paths,
        tls_policy: mission.tls_policy.clone(),
        request_budget: mission.request_budget,
        requests_per_second: mission.requests_per_second,
        identity_a_profile_id: mission.identity_a_profile_id,
        identity_b_profile_id: mission.identity_b_profile_id,
        resource_ownership: old.resource_ownership,
        include_recent_traffic: mission.include_recent_traffic,
        provider_id: mission.provider_id.clone(),
        model: mission.model.clone(),
        max_rounds: mission.max_planning_cycles,
        written_authorization_confirmed: old.written_authorization_confirmed,
    })
}

struct MissionTextContext<'a> {
    project_id: i64,
    identity_a: Option<i64>,
    identity_b: Option<i64>,
    location: &'a str,
    max_len: usize,
}

fn redact_mission_text(
    conn: &Connection,
    secrets: &dyn SecretStore,
    value: &str,
    context: MissionTextContext<'_>,
) -> Result<(String, Vec<String>), String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > context.max_len || trimmed.chars().any(|ch| ch == '\0')
    {
        return Err(format!("文本必须是 1..={} 字符且不含 NUL", context.max_len));
    }
    let mut manifest = RedactionManifest::default();
    let mut safe = redact_fallback_text(trimmed, context.location, true, &mut manifest);
    let mut references = Vec::new();
    for profile_id in [context.identity_a, context.identity_b]
        .into_iter()
        .flatten()
    {
        let identity =
            service::load_runtime_identity(conn, secrets, context.project_id, profile_id)?;
        references.extend(identity.redaction_values());
    }
    let slices = references.iter().map(String::as_str).collect::<Vec<_>>();
    safe = crate::secrets::redact_sensitive(&safe, &slices);
    let mut summary = manifest
        .redactions
        .iter()
        .map(|record| format!("{}:{}:{}", record.location, record.kind, record.count))
        .collect::<Vec<_>>();
    if safe != trimmed && summary.is_empty() {
        summary.push(format!("{}:selected_identity_secret", context.location));
    }
    Ok((safe, summary))
}

fn surface_summary(url: &Url) -> Value {
    let mut query_names = url
        .query_pairs()
        .map(|(name, _)| name.into_owned())
        .collect::<Vec<_>>();
    query_names.sort();
    query_names.dedup();
    let shape = normalize_path_shape(url.path());
    json!({
        "surfaceId": opaque_surface_id(&shape, &query_names.join(",")),
        "pathShape": shape,
        "queryParameterNames": query_names,
        "hasQueryValues": url.query().is_some(),
    })
}

pub(crate) fn normalize_path_shape(path: &str) -> String {
    let segments = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            let decoded = segment.trim();
            if (decoded.len() >= 8 && decoded.chars().all(|ch| ch.is_ascii_digit()))
                || looks_like_uuid(decoded)
                || (decoded.len() >= 16 && decoded.chars().all(|ch| ch.is_ascii_hexdigit()))
            {
                "{id}".to_string()
            } else if decoded.starts_with('{') && decoded.ends_with('}') {
                "{param}".to_string()
            } else {
                decoded.chars().take(120).collect()
            }
        })
        .collect::<Vec<_>>();
    if segments.is_empty() {
        "/".into()
    } else {
        format!("/{}", segments.join("/"))
    }
}

fn looks_like_uuid(value: &str) -> bool {
    let groups = value.split('-').collect::<Vec<_>>();
    groups.len() == 5
        && groups.iter().zip([8, 4, 4, 4, 12]).all(|(group, size)| {
            group.len() == size && group.chars().all(|ch| ch.is_ascii_hexdigit())
        })
}

fn opaque_surface_id(path_shape: &str, shape: &str) -> String {
    format!(
        "surface_{}",
        &sha256(format!("{path_shape}\n{shape}").as_bytes())[..20]
    )
}

fn ensure_resource_mutable(mission: &AssessmentMission) -> Result<(), String> {
    if mission.legacy
        || !matches!(
            mission.status,
            MissionStatus::Draft | MissionStatus::AwaitingContextApproval
        )
    {
        return Err("资源只能在任务发现/上下文确认前附加".into());
    }
    Ok(())
}

fn validate_title(value: &str) -> Result<String, String> {
    let title = value.trim().chars().take(160).collect::<String>();
    if title.is_empty() || title.chars().any(char::is_control) {
        Err("任务标题必须是 1..=160 个可显示字符".into())
    } else {
        Ok(title)
    }
}

fn ensure_revision(current: i64, expected: i64) -> Result<(), String> {
    if current == expected {
        Ok(())
    } else {
        Err(format!(
            "[REVISION_CONFLICT] 期望 revision {expected}，当前为 {current}"
        ))
    }
}

fn ensure_project(conn: &Connection, project_id: i64) -> Result<(), String> {
    let exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM projects WHERE id=?1)",
            [project_id],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if exists {
        Ok(())
    } else {
        Err("项目不存在".into())
    }
}

fn hash_json(value: &Value) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| error.to_string())
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn permission_override_map(
    conn: &Connection,
    project_id: i64,
) -> Result<HashMap<String, String>, String> {
    let mut statement = conn
        .prepare("SELECT tool_id, decision FROM assessment_tool_permissions WHERE project_id=?1")
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([project_id], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(|error| error.to_string())?;
    rows.collect::<Result<HashMap<_, _>, _>>()
        .map_err(|error| error.to_string())
}

fn list_tool_permissions(
    conn: &Connection,
    project_id: i64,
) -> Result<Vec<AssessmentToolPermission>, String> {
    let mut statement = conn
        .prepare(
            "SELECT project_id, tool_id, decision, revision, updated_at
             FROM assessment_tool_permissions WHERE project_id=?1 ORDER BY tool_id",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([project_id], |row| {
            Ok(AssessmentToolPermission {
                project_id: row.get(0)?,
                tool_id: row.get(1)?,
                decision: row.get(2)?,
                revision: row.get(3)?,
                updated_at: row.get(4)?,
            })
        })
        .map_err(|error| error.to_string())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())
}

fn list_messages(conn: &Connection, mission_id: i64) -> Result<Vec<AssessmentMessage>, String> {
    let mut statement = conn
        .prepare(
            "SELECT id, mission_id, role, message_kind, content, content_hash,
                    old_value, new_value, details_json, redaction_manifest_json,
                    revision, created_at
             FROM assessment_messages WHERE mission_id=?1 ORDER BY id",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([mission_id], |row| {
            let details: String = row.get(8)?;
            let manifest: String = row.get(9)?;
            Ok(AssessmentMessage {
                id: row.get(0)?,
                mission_id: row.get(1)?,
                role: row.get(2)?,
                message_kind: row.get(3)?,
                content: row.get(4)?,
                content_hash: row.get(5)?,
                old_value: row.get(6)?,
                new_value: row.get(7)?,
                details: serde_json::from_str(&details).unwrap_or(Value::Null),
                redaction_manifest: serde_json::from_str(&manifest).unwrap_or_default(),
                revision: row.get(10)?,
                created_at: row.get(11)?,
            })
        })
        .map_err(|error| error.to_string())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())
}

fn list_workstreams(
    conn: &Connection,
    mission_id: i64,
) -> Result<Vec<AssessmentWorkstream>, String> {
    let mut statement = conn
        .prepare(
            "SELECT id, mission_id, parent_id, stable_key, title, objective,
                    status, sort_order, created_at, updated_at
             FROM assessment_workstreams WHERE mission_id=?1 ORDER BY sort_order,id",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([mission_id], |row| {
            Ok(AssessmentWorkstream {
                id: row.get(0)?,
                mission_id: row.get(1)?,
                parent_id: row.get(2)?,
                stable_key: row.get(3)?,
                title: row.get(4)?,
                objective: row.get(5)?,
                status: row.get(6)?,
                sort_order: row.get(7)?,
                created_at: row.get(8)?,
                updated_at: row.get(9)?,
            })
        })
        .map_err(|error| error.to_string())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())
}

fn list_actions(conn: &Connection, mission_id: i64) -> Result<Vec<AssessmentAction>, String> {
    let mut statement = conn
        .prepare(&format!(
            "{} WHERE mission_id=?1 ORDER BY id",
            action_select_sql()
        ))
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([mission_id], map_action)
        .map_err(|error| error.to_string())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())
}

fn get_action(
    conn: &Connection,
    project_id: i64,
    mission_id: i64,
    action_id: i64,
) -> Result<AssessmentAction, String> {
    conn.query_row(
        &format!(
            "{} WHERE id=?1 AND mission_id=?2 AND EXISTS(
                SELECT 1 FROM assessment_missions m
                WHERE m.id=assessment_actions.mission_id AND m.project_id=?3)",
            action_select_sql()
        ),
        params![action_id, mission_id, project_id],
        map_action,
    )
    .optional()
    .map_err(|error| error.to_string())?
    .ok_or_else(|| "动作不存在或不属于当前任务".to_string())
}

fn list_resources(
    conn: &Connection,
    mission_id: i64,
) -> Result<Vec<AssessmentMissionResource>, String> {
    let mut statement = conn
        .prepare(
            "SELECT id, mission_id, resource_type, source_id, display_name,
                    media_type, summary_json, content_hash, created_at
             FROM assessment_mission_resources WHERE mission_id=?1 ORDER BY id",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([mission_id], |row| {
            let summary: String = row.get(6)?;
            Ok(AssessmentMissionResource {
                id: row.get(0)?,
                mission_id: row.get(1)?,
                resource_type: row.get(2)?,
                source_id: row.get(3)?,
                display_name: row.get(4)?,
                media_type: row.get(5)?,
                summary: serde_json::from_str(&summary).unwrap_or(Value::Null),
                content_hash: row.get(7)?,
                created_at: row.get(8)?,
            })
        })
        .map_err(|error| error.to_string())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())
}

fn list_surfaces(conn: &Connection, mission_id: i64) -> Result<Vec<AssessmentSurface>, String> {
    let mut statement = conn
        .prepare(
            "SELECT s.id, s.run_id, s.surface_id, s.surface_kind, s.method,
                    s.path_shape, s.query_parameter_names, s.form_fields_json,
                    s.content_types_json, s.identity_visibility_json,
                    s.response_structure_hash, s.source_kinds_json,
                    s.safe_to_request, s.concrete_count, s.created_at, s.updated_at
             FROM assessment_surfaces s
             JOIN assessment_mission_runs mr ON mr.run_id=s.run_id
             WHERE mr.mission_id=?1 ORDER BY s.surface_kind,s.path_shape,s.method,s.id",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([mission_id], |row| {
            let query_names: String = row.get(6)?;
            let fields: String = row.get(7)?;
            let content_types: String = row.get(8)?;
            let visibility: String = row.get(9)?;
            let sources: String = row.get(11)?;
            Ok(AssessmentSurface {
                id: row.get(0)?,
                run_id: row.get(1)?,
                surface_id: row.get(2)?,
                surface_kind: row.get(3)?,
                method: row.get(4)?,
                path_shape: row.get(5)?,
                query_parameter_names: serde_json::from_str(&query_names).unwrap_or_default(),
                form_fields: serde_json::from_str(&fields).unwrap_or_default(),
                content_types: serde_json::from_str(&content_types).unwrap_or_default(),
                identity_visibility: serde_json::from_str(&visibility)
                    .unwrap_or_else(|_| json!({})),
                response_structure_hash: row.get(10)?,
                source_kinds: serde_json::from_str(&sources).unwrap_or_default(),
                safe_to_request: row.get::<_, i64>(12)? != 0,
                concrete_count: row.get(13)?,
                created_at: row.get(14)?,
                updated_at: row.get(15)?,
            })
        })
        .map_err(|error| error.to_string())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())
}

fn list_handoffs(
    conn: &Connection,
    mission_id: i64,
) -> Result<Vec<AssessmentManualHandoff>, String> {
    let mut statement = conn
        .prepare(
            "SELECT h.id, h.action_id, h.recipe_id, h.recipe_version, h.draft_json,
                    h.draft_hash, h.replay_session_id, h.replay_run_id, h.evidence_id,
                    h.status, h.created_at, h.updated_at
             FROM assessment_manual_handoffs h
             JOIN assessment_actions a ON a.id=h.action_id
             WHERE a.mission_id=?1 ORDER BY h.id",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([mission_id], map_handoff)
        .map_err(|error| error.to_string())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())
}

fn get_handoff(
    conn: &Connection,
    project_id: i64,
    mission_id: i64,
    handoff_id: i64,
) -> Result<AssessmentManualHandoff, String> {
    conn.query_row(
        "SELECT h.id, h.action_id, h.recipe_id, h.recipe_version, h.draft_json,
                h.draft_hash, h.replay_session_id, h.replay_run_id, h.evidence_id,
                h.status, h.created_at, h.updated_at
         FROM assessment_manual_handoffs h
         JOIN assessment_actions a ON a.id=h.action_id
         JOIN assessment_missions m ON m.id=a.mission_id
         WHERE h.id=?1 AND m.id=?2 AND m.project_id=?3",
        params![handoff_id, mission_id, project_id],
        map_handoff,
    )
    .optional()
    .map_err(|error| error.to_string())?
    .ok_or_else(|| "人工接力不存在或不属于当前任务".to_string())
}

fn get_handoff_by_action(
    conn: &Connection,
    action_id: i64,
) -> Result<Option<AssessmentManualHandoff>, String> {
    conn.query_row(
        "SELECT id, action_id, recipe_id, recipe_version, draft_json,
                draft_hash, replay_session_id, replay_run_id, evidence_id,
                status, created_at, updated_at
         FROM assessment_manual_handoffs WHERE action_id=?1",
        [action_id],
        map_handoff,
    )
    .optional()
    .map_err(|error| error.to_string())
}

fn coverage_summary(conn: &Connection, mission_id: i64) -> Result<MissionCoverageSummary, String> {
    let (confirmed, suspected, not_observed): (i64, i64, i64) = conn
        .query_row(
            "SELECT
                 SUM(CASE WHEN v.verdict='confirmed' THEN 1 ELSE 0 END),
                 SUM(CASE WHEN v.verdict IN ('suspected','inconclusive') THEN 1 ELSE 0 END),
                 SUM(CASE WHEN v.verdict='not_observed' THEN 1 ELSE 0 END)
             FROM assessment_mission_runs mr
             LEFT JOIN assessment_checks c ON c.run_id=mr.run_id
             LEFT JOIN assessment_verifications v ON v.check_id=c.id
             WHERE mr.mission_id=?1",
            [mission_id],
            |row| {
                Ok((
                    row.get::<_, Option<i64>>(0)?.unwrap_or(0),
                    row.get::<_, Option<i64>>(1)?.unwrap_or(0),
                    row.get::<_, Option<i64>>(2)?.unwrap_or(0),
                ))
            },
        )
        .map_err(|error| error.to_string())?;
    let gaps: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM assessment_coverage_gaps g
             JOIN assessment_mission_runs mr ON mr.run_id=g.run_id
             WHERE mr.mission_id=?1",
            [mission_id],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    Ok(MissionCoverageSummary {
        confirmed: confirmed.max(0) as u32,
        suspected: suspected.max(0) as u32,
        not_observed: not_observed.max(0) as u32,
        coverage_gap: gaps.max(0) as u32,
    })
}

fn map_handoff(row: &Row<'_>) -> rusqlite::Result<AssessmentManualHandoff> {
    let draft: String = row.get(4)?;
    Ok(AssessmentManualHandoff {
        id: row.get(0)?,
        action_id: row.get(1)?,
        recipe_id: row.get(2)?,
        recipe_version: row.get(3)?,
        draft: serde_json::from_str(&draft).unwrap_or(Value::Null),
        draft_hash: row.get(5)?,
        replay_session_id: row.get(6)?,
        replay_run_id: row.get(7)?,
        evidence_id: row.get(8)?,
        status: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
    })
}

fn mission_select_sql() -> &'static str {
    "SELECT id, project_id, title, goal, start_url, exact_origin, status,
            autonomy_mode, budget_profile, request_budget, request_count,
            max_planning_cycles, completed_cycles, requests_per_second,
            identity_a_profile_id, identity_b_profile_id, provider_id, model,
            tls_policy, include_recent_traffic, contract_hash,
            tool_registry_hash, permission_hash, context_hash,
            context_approved_hash, active_run_id, legacy_run_id, legacy,
            revision, pending_steering, stop_reason, created_at, updated_at,
            started_at, ended_at
     FROM assessment_missions"
}

fn map_mission(row: &Row<'_>) -> rusqlite::Result<AssessmentMission> {
    let status: String = row.get(6)?;
    let autonomy: String = row.get(7)?;
    let budget: String = row.get(8)?;
    Ok(AssessmentMission {
        id: row.get(0)?,
        project_id: row.get(1)?,
        title: row.get(2)?,
        goal: row.get(3)?,
        start_url: row.get(4)?,
        exact_origin: row.get(5)?,
        status: MissionStatus::parse(&status).map_err(sql_conversion_error)?,
        autonomy_mode: AutonomyMode::parse(&autonomy).map_err(sql_conversion_error)?,
        budget_profile: BudgetProfile::parse(&budget).map_err(sql_conversion_error)?,
        request_budget: row.get(9)?,
        request_count: row.get(10)?,
        max_planning_cycles: row.get(11)?,
        completed_cycles: row.get(12)?,
        requests_per_second: row.get(13)?,
        identity_a_profile_id: row.get(14)?,
        identity_b_profile_id: row.get(15)?,
        provider_id: row.get(16)?,
        model: row.get(17)?,
        tls_policy: row.get(18)?,
        include_recent_traffic: row.get::<_, i64>(19)? != 0,
        contract_hash: row.get(20)?,
        tool_registry_hash: row.get(21)?,
        permission_hash: row.get(22)?,
        context_hash: row.get(23)?,
        context_approved_hash: row.get(24)?,
        active_run_id: row.get(25)?,
        legacy_run_id: row.get(26)?,
        legacy: row.get::<_, i64>(27)? != 0,
        revision: row.get(28)?,
        pending_steering: row.get::<_, i64>(29)? != 0,
        stop_reason: row.get(30)?,
        created_at: row.get(31)?,
        updated_at: row.get(32)?,
        started_at: row.get(33)?,
        ended_at: row.get(34)?,
    })
}

fn action_select_sql() -> &'static str {
    "SELECT id, mission_id, workstream_id, tool_id, tool_version,
            execution_kind, risk_level, surface_id, identity_mode, parameter_json,
            rationale, expected_signal, request_cost, permission_snapshot,
            permission_hash, approval_status, approval_source, status, policy_reason,
            redacted_request_json, request_hash, redacted_response_json, response_hash,
            result_json, result_hash, revision, created_at, approved_at, started_at, completed_at
     FROM assessment_actions"
}

fn map_action(row: &Row<'_>) -> rusqlite::Result<AssessmentAction> {
    let parameters: String = row.get(9)?;
    let request: Option<String> = row.get(19)?;
    let response: Option<String> = row.get(21)?;
    let result: Option<String> = row.get(23)?;
    Ok(AssessmentAction {
        id: row.get(0)?,
        mission_id: row.get(1)?,
        workstream_id: row.get(2)?,
        tool_id: row.get(3)?,
        tool_version: row.get(4)?,
        execution_kind: row.get(5)?,
        risk_level: row.get(6)?,
        surface_id: row.get(7)?,
        identity_mode: row.get(8)?,
        parameters: serde_json::from_str(&parameters).unwrap_or_else(|_| json!({})),
        rationale: row.get(10)?,
        expected_signal: row.get(11)?,
        request_cost: row.get(12)?,
        permission_snapshot: row.get(13)?,
        permission_hash: row.get(14)?,
        approval_status: row.get(15)?,
        approval_source: row.get(16)?,
        status: row.get(17)?,
        policy_reason: row.get(18)?,
        redacted_request: request.and_then(|raw| serde_json::from_str(&raw).ok()),
        request_hash: row.get(20)?,
        redacted_response: response.and_then(|raw| serde_json::from_str(&raw).ok()),
        response_hash: row.get(22)?,
        result: result.and_then(|raw| serde_json::from_str(&raw).ok()),
        result_hash: row.get(24)?,
        revision: row.get(25)?,
        created_at: row.get(26)?,
        approved_at: row.get(27)?,
        started_at: row.get(28)?,
        completed_at: row.get(29)?,
    })
}

fn sql_conversion_error(error: String) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::MemorySecretStore;
    use base64::Engine as _;

    fn database() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        crate::storage::migrations::migrate(&mut conn).unwrap();
        conn.execute(
            "INSERT INTO projects(id,name,scope) VALUES(1,'mission','[\"example.test\"]')",
            [],
        )
        .unwrap();
        conn
    }

    fn input(mode: &str, goal: &str) -> CreateAssessmentMissionInput {
        CreateAssessmentMissionInput {
            project_id: 1,
            title: None,
            goal: goal.into(),
            start_url: "https://example.test/app/12345678?next=secret".into(),
            excluded_paths: Vec::new(),
            tls_policy: "strict".into(),
            identity_a_profile_id: None,
            identity_b_profile_id: None,
            include_recent_traffic: false,
            autonomy_mode: mode.into(),
            budget_profile: "standard".into(),
            written_authorization_confirmed: true,
        }
    }

    #[test]
    fn create_mission_requires_written_authorization_confirmation() {
        let mut conn = database();
        let store = MemorySecretStore::default();
        let mut mission_input = input("smart", "未确认授权");
        mission_input.written_authorization_confirmed = false;
        let error =
            create_mission(&mut conn, &store, &mission_input, "fixture", "model").unwrap_err();
        assert!(error.contains("AUTHORIZATION_REQUIRED"), "got: {error}");
    }

    #[test]
    fn permissions_are_backend_determined_and_manual_never_auto_executes() {
        let conn = database();
        let smart = permission_state(&conn, 1, AutonomyMode::Smart).unwrap();
        let options = smart
            .tools
            .iter()
            .find(|tool| tool.id == "options_capabilities")
            .unwrap();
        let cors = smart
            .tools
            .iter()
            .find(|tool| tool.id == "credentialed_cors")
            .unwrap();
        let manual = smart
            .tools
            .iter()
            .find(|tool| tool.id == "manual_sqli_recipe")
            .unwrap();
        assert_eq!(options.effective_permission, "execute");
        assert_eq!(cors.effective_permission, "ask");
        assert_eq!(manual.effective_permission, "ask");
        let automatic = permission_state(&conn, 1, AutonomyMode::Automatic).unwrap();
        assert_eq!(
            automatic
                .tools
                .iter()
                .find(|tool| tool.id == "manual_sqli_recipe")
                .unwrap()
                .effective_permission,
            "ask"
        );
    }

    #[test]
    fn budget_profiles_bind_real_two_four_six_round_contracts() {
        let mut conn = database();
        let store = MemorySecretStore::default();
        for (profile, request_budget, rounds) in
            [("quick", 40, 2), ("standard", 120, 4), ("deep", 300, 6)]
        {
            let mut mission_input = input("smart", &format!("{profile} budget fixture"));
            mission_input.budget_profile = profile.into();
            let detail =
                create_mission(&mut conn, &store, &mission_input, "fixture", "model").unwrap();
            assert_eq!(detail.mission.request_budget, request_budget);
            assert_eq!(detail.mission.max_planning_cycles, rounds);
            let raw: String = conn
                .query_row(
                    "SELECT contract_json FROM assessment_missions WHERE id=?1",
                    [detail.mission.id],
                    |row| row.get(0),
                )
                .unwrap();
            let contract: super::super::model::AssessmentContractPreview =
                serde_json::from_str(&raw).unwrap();
            assert_eq!(contract.max_rounds, rounds);
        }
    }

    #[test]
    fn create_confirm_and_reject_actions_never_construct_network_work() {
        let mut conn = database();
        let store = MemorySecretStore::default();
        let created = create_mission(
            &mut conn,
            &store,
            &input("smart", "检查 XSS 和基础边界"),
            "fixture",
            "model",
        )
        .unwrap();
        assert_eq!(
            created.mission.status,
            MissionStatus::AwaitingContextApproval
        );
        let preview = preview_context(&conn, 1, created.mission.id).unwrap();
        assert!(!preview.context_summary.to_string().contains("next=secret"));
        let confirmed = confirm_context(
            &mut conn,
            &store,
            &ConfirmMissionContextInput {
                project_id: 1,
                mission_id: created.mission.id,
                expected_revision: created.mission.revision,
                context_hash: preview.context_hash,
            },
        )
        .unwrap();
        assert_eq!(
            confirmed.mission.status,
            MissionStatus::AwaitingActionApproval
        );
        let action = confirmed
            .actions
            .iter()
            .find(|action| action.approval_status == "pending")
            .unwrap()
            .clone();
        let decided = decide_action(
            &mut conn,
            &DecideAssessmentActionInput {
                project_id: 1,
                mission_id: confirmed.mission.id,
                action_id: action.id,
                expected_mission_revision: confirmed.mission.revision,
                expected_action_revision: action.revision,
                approve: false,
                apply_to_same_tool: false,
            },
        )
        .unwrap();
        assert!(decided
            .actions
            .iter()
            .any(|candidate| candidate.id == action.id && candidate.status == "rejected"));
        let run_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM replay_runs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(run_count, 0);
    }

    #[test]
    fn openapi_import_keeps_only_bounded_structural_summary() {
        let summary = summarize_openapi_json(
            r#"{"openapi":"3.1.0","info":{"title":"Demo"},"servers":[{"url":"https://secret.example"}],"paths":{"/users/{id}":{"get":{"parameters":[{"name":"expand","in":"query","example":"secret"}]}}}}"#,
        )
        .unwrap();
        let text = summary.to_string();
        assert!(text.contains("/users/{param}"));
        assert!(text.contains("expand"));
        assert!(!text.contains("secret.example"));
        assert!(!text.contains("\"secret\""));
    }

    #[test]
    fn identity_secret_and_common_encodings_never_enter_mission_or_report() {
        let mut conn = database();
        let store = MemorySecretStore::default();
        let secret = "Bearer credential-alpha-123456";
        let bare = "credential-alpha-123456";
        let profile = service::create_auth_profile(
            &mut conn,
            &store,
            &super::super::model::CreateAssessmentAuthProfileInput {
                project_id: 1,
                label: "普通用户 A".into(),
                header_name: "Authorization".into(),
                secret: secret.into(),
                source_traffic_id: None,
            },
        )
        .unwrap();
        let url_encoded =
            url::form_urlencoded::byte_serialize(secret.as_bytes()).collect::<String>();
        let base64 = base64::engine::general_purpose::STANDARD.encode(bare.as_bytes());
        let hex = bare
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let variants = vec![
            secret.to_string(),
            bare.to_string(),
            url_encoded,
            base64,
            hex.clone(),
            hex.to_ascii_uppercase(),
        ];
        let mut mission_input = input(
            "smart",
            &format!("验证身份边界；误粘贴凭据变体：{}", variants.join(" | ")),
        );
        mission_input.identity_a_profile_id = Some(profile.id);
        let created =
            create_mission(&mut conn, &store, &mission_input, "fixture", "model").unwrap();
        let context = preview_context(&conn, 1, created.mission.id).unwrap();
        let report =
            crate::report::build_mission_report_bundle(&conn, 1, created.mission.id).unwrap();
        let public_views = format!(
            "{} {} {}",
            serde_json::to_string(&created).unwrap(),
            serde_json::to_string(&context).unwrap(),
            report.json
        );
        let persisted: String = conn
            .query_row(
                "SELECT
                     COALESCE((SELECT group_concat(
                         title || ' ' || goal || ' ' || contract_json || ' ' ||
                         disclosure_manifest_json, ' ')
                         FROM assessment_missions WHERE id=?1), '') || ' ' ||
                     COALESCE((SELECT group_concat(
                         content || ' ' || details_json || ' ' || redaction_manifest_json, ' ')
                         FROM assessment_messages WHERE mission_id=?1), '') || ' ' ||
                     COALESCE((SELECT group_concat(
                         parameter_json || ' ' || rationale || ' ' || expected_signal || ' ' ||
                         policy_reason || ' ' || COALESCE(redacted_request_json, '') || ' ' ||
                         COALESCE(redacted_response_json, '') || ' ' || COALESCE(result_json, ''), ' ')
                         FROM assessment_actions WHERE mission_id=?1), '') || ' ' ||
                     COALESCE((SELECT group_concat(summary_json, ' ')
                         FROM assessment_mission_resources WHERE mission_id=?1), '')",
                [created.mission.id],
                |row| row.get(0),
            )
            .unwrap();
        for variant in variants {
            assert!(
                !public_views.contains(&variant),
                "secret encoding leaked into a public mission/report view"
            );
            assert!(
                !persisted.contains(&variant),
                "secret encoding leaked into SQLite mission state"
            );
        }
    }

    #[test]
    fn manual_handoff_creates_prefilled_draft_without_sending_and_reports_v4() {
        let mut conn = database();
        let store = MemorySecretStore::default();
        let created = create_mission(
            &mut conn,
            &store,
            &input("smart", "检查 XSS 输入点并生成人工配方"),
            "fixture",
            "model",
        )
        .unwrap();
        let preview = preview_context(&conn, 1, created.mission.id).unwrap();
        let confirmed = confirm_context(
            &mut conn,
            &store,
            &ConfirmMissionContextInput {
                project_id: 1,
                mission_id: created.mission.id,
                expected_revision: created.mission.revision,
                context_hash: preview.context_hash,
            },
        )
        .unwrap();
        let mut approved = confirmed;
        while let Some(action) = approved
            .actions
            .iter()
            .find(|action| action.approval_status == "pending")
            .cloned()
        {
            approved = decide_action(
                &mut conn,
                &DecideAssessmentActionInput {
                    project_id: 1,
                    mission_id: approved.mission.id,
                    action_id: action.id,
                    expected_mission_revision: approved.mission.revision,
                    expected_action_revision: action.revision,
                    approve: true,
                    apply_to_same_tool: false,
                },
            )
            .unwrap();
        }
        assert_eq!(approved.mission.status, MissionStatus::Queued);
        let manual = approved
            .actions
            .iter()
            .find(|action| action.tool_id == "manual_xss_recipe")
            .unwrap()
            .clone();
        assert_eq!(manual.status, "queued");
        assert!(create_handoff(
            &mut conn,
            &CreateMissionHandoffInput {
                project_id: 1,
                mission_id: approved.mission.id,
                action_id: manual.id,
                expected_action_revision: manual.revision,
            },
        )
        .is_err());

        let preview = prepare_start(
            &conn,
            &store,
            &MissionControlInput {
                project_id: 1,
                mission_id: approved.mission.id,
                expected_revision: approved.mission.revision,
            },
        )
        .unwrap();
        let run = service::create_run(&mut conn, &preview).unwrap();
        link_run(&mut conn, 1, approved.mission.id, run.id).unwrap();
        service::transition_run(
            &mut conn,
            1,
            run.id,
            super::super::model::AssessmentStatus::Discovering,
            None,
        )
        .unwrap();
        service::transition_run(
            &mut conn,
            1,
            run.id,
            super::super::model::AssessmentStatus::Planning,
            None,
        )
        .unwrap();
        let endpoint_key = "a".repeat(64);
        conn.execute(
            "INSERT INTO assessment_endpoints(
                 run_id, endpoint_key, method, url, path,
                 query_parameter_names, source_kind, status, content_type
             ) VALUES(?1,?2,'GET','https://example.test/search?q=seed',
                      '/search','[\"q\"]','start_url',200,'text/html')",
            params![run.id, endpoint_key],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO assessment_rounds(
                 run_id, round_number, status, input_hash, output_hash,
                 selected_checks, rejection_json, completed_at
             ) VALUES(?1,1,'valid',?2,?2,1,'[]',
                      strftime('%Y-%m-%d %H:%M:%f','now','localtime'))",
            params![run.id, "b".repeat(64)],
        )
        .unwrap();
        let round_id = conn.last_insert_rowid();
        let allowed = allowed_planner_tools_for_run(&conn, run.id)
            .unwrap()
            .unwrap();
        let rejected = select_manual_plans_for_run(
            &mut conn,
            run.id,
            round_id,
            &[PlannedCheck {
                template_id: "manual_xss_recipe".into(),
                endpoint_id: format!("ep_{}", "a".repeat(24)),
                parameter_name: Some("forged_parameter".into()),
                identity_mode: "anonymous".into(),
                rationale: "伪造参数必须被后端拒绝".into(),
                workstream_key: Some("manual".into()),
                expected_signal: "不得创建草稿或 socket".into(),
            }],
            Some(&allowed),
        )
        .unwrap();
        assert_eq!(rejected, 0);
        assert_eq!(
            get_action(&conn, 1, approved.mission.id, manual.id)
                .unwrap()
                .status,
            "queued"
        );
        let selected = select_manual_plans_for_run(
            &mut conn,
            run.id,
            round_id,
            &[PlannedCheck {
                template_id: "manual_xss_recipe".into(),
                endpoint_id: format!("ep_{}", "a".repeat(24)),
                parameter_name: Some("q".into()),
                identity_mode: "anonymous".into(),
                rationale: "为已登记参数创建惰性人工差异草稿".into(),
                workstream_key: Some("manual".into()),
                expected_signal: "由用户比较基线与手动结果".into(),
            }],
            Some(&allowed),
        )
        .unwrap();
        assert_eq!(selected, 1);
        let selected_detail = get_detail(&conn, 1, approved.mission.id).unwrap();
        let manual = selected_detail
            .actions
            .iter()
            .find(|action| action.tool_id == "manual_xss_recipe")
            .unwrap();
        assert_eq!(manual.status, "manual_ready");
        let handoff = create_handoff(
            &mut conn,
            &CreateMissionHandoffInput {
                project_id: 1,
                mission_id: selected_detail.mission.id,
                action_id: manual.id,
                expected_action_revision: manual.revision,
            },
        )
        .unwrap();
        assert_eq!(handoff.draft["sendAutomatically"], false);
        assert_eq!(handoff.draft["requiresUserClick"], true);
        assert_eq!(handoff.draft["request"]["method"], "GET");
        assert!(handoff.draft["request"]["url"]
            .as_str()
            .unwrap()
            .contains("RF_XSS_INERT_REVIEW_20260803"));
        assert!(handoff.replay_session_id.is_some());
        let replay_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM replay_runs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(replay_count, 0, "draft creation must not send a request");

        service::transition_run(
            &mut conn,
            1,
            run.id,
            super::super::model::AssessmentStatus::Completed,
            Some("planning_complete"),
        )
        .unwrap();
        let settled = get_detail(&conn, 1, selected_detail.mission.id).unwrap();
        assert_eq!(settled.mission.status, MissionStatus::AwaitingManualHandoff);
        assert!(settled
            .actions
            .iter()
            .all(|action| action.status != "queued"));

        let report =
            crate::report::build_mission_report_bundle(&conn, 1, settled.mission.id).unwrap();
        assert!(report.json.contains("\"schema_version\": 4"));
        assert!(report.json.contains("manual_xss_recipe"));
        assert!(!report.json.contains("next=secret"));
    }
}
