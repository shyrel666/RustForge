use super::discovery::{self, DiscoveredEndpoint};
use super::executor::{AssessmentExecutor, StopCondition};
use super::model::{AssessmentMissionEvent, AssessmentProgress, AssessmentStatus, MissionStatus};
use super::planner::{self, EndpointForAi, PlannerProviderContext, PriorVerdictForAi};
use super::service;
use super::templates;
use crate::ai::client::OpenAiClient;
use crate::replay::model::TlsPolicy;
use crate::storage::db::Pool;
use chrono::Local;
use rusqlite::OptionalExtension;
use serde_json::json;
use std::sync::Arc;
use tauri::{AppHandle, Emitter};
use tokio::sync::watch;

pub struct AssessmentRunContext {
    pub pool: Pool,
    pub secrets: Arc<dyn crate::secrets::SecretStore>,
    pub app: AppHandle,
    pub project_id: i64,
    pub run_id: i64,
    pub client: OpenAiClient,
    pub provider: PlannerProviderContext,
    pub cancel: watch::Receiver<bool>,
}

pub async fn run(context: AssessmentRunContext) -> Result<(), String> {
    let AssessmentRunContext {
        pool,
        secrets,
        app,
        project_id,
        run_id,
        client,
        provider,
        cancel,
    } = context;
    let run = {
        let conn = pool.get().map_err(|error| error.to_string())?;
        service::get_run(&conn, project_id, run_id)?
    };
    let tls_policy = TlsPolicy::parse(&run.tls_policy)?;
    transition(
        &pool,
        project_id,
        run_id,
        AssessmentStatus::Discovering,
        None,
    )?;
    emit_progress(
        &app,
        &pool,
        project_id,
        run_id,
        AssessmentStatus::Discovering,
        "discovering",
        "正在从起始 URL 发现同源只读端点",
    );
    insert_builtin_coverage_gaps(&pool, run_id)?;
    let session_id = {
        let conn = pool.get().map_err(|error| error.to_string())?;
        crate::replay::service::create_assessment_session(&conn, project_id, run_id, tls_policy)?
    };
    let mut executor = AssessmentExecutor::new(
        pool.clone(),
        secrets,
        project_id,
        run_id,
        session_id,
        cancel,
    )?;
    let discovery = discovery::discover(&pool, &mut executor).await?;
    if executor.is_cancelled() {
        transition(
            &pool,
            project_id,
            run_id,
            AssessmentStatus::Cancelled,
            Some("user_cancelled"),
        )?;
        emit_progress(
            &app,
            &pool,
            project_id,
            run_id,
            AssessmentStatus::Cancelled,
            "cancelled",
            "评估已取消，已保留部分结果",
        );
        return Ok(());
    }
    if let Some(condition) = discovery.stop_condition {
        stop_for_condition(&app, &pool, project_id, run_id, condition)?;
        return Ok(());
    }
    if discovery.endpoints.is_empty() {
        insert_gap(
            &pool,
            run_id,
            None,
            "discovery",
            "no_endpoints_discovered",
            "起始 URL 未形成可评估的同源只读端点",
        )?;
        transition(&pool, project_id, run_id, AssessmentStatus::Planning, None)?;
        transition(
            &pool,
            project_id,
            run_id,
            AssessmentStatus::Completed,
            Some("no_endpoints_discovered"),
        )?;
        emit_progress(
            &app,
            &pool,
            project_id,
            run_id,
            AssessmentStatus::Completed,
            "completed",
            "评估完成，但没有发现可执行端点",
        );
        return Ok(());
    }

    let mut previous = Vec::<PriorVerdictForAi>::new();
    let mut current_status = AssessmentStatus::Discovering;
    let max_rounds = executor.contract().max_rounds;
    for round_number in 1..=max_rounds {
        if executor.is_cancelled() {
            transition(
                &pool,
                project_id,
                run_id,
                AssessmentStatus::Cancelled,
                Some("user_cancelled"),
            )?;
            emit_progress(
                &app,
                &pool,
                project_id,
                run_id,
                AssessmentStatus::Cancelled,
                "cancelled",
                "评估已取消，已保留部分结果",
            );
            return Ok(());
        }
        if current_status != AssessmentStatus::Planning {
            transition(&pool, project_id, run_id, AssessmentStatus::Planning, None)?;
        }
        current_status = AssessmentStatus::Planning;
        emit_progress(
            &app,
            &pool,
            project_id,
            run_id,
            current_status,
            "planning",
            &format!("AI 正在选择第 {round_number}/{max_rounds} 轮安全检查"),
        );
        // AI is an external disclosure boundary too: provider/model, Scope,
        // identities and template registry must still match the confirmed
        // contract before each round begins.
        executor.recheck_contract()?;
        let endpoints_for_ai = endpoints_for_ai(&discovery.endpoints, &executor);
        let (allowed_tools, mission_context) = {
            let conn = pool.get().map_err(|error| error.to_string())?;
            (
                super::mission::allowed_planner_tools_for_run(&conn, run_id)?,
                super::mission::planner_steering_for_run(&conn, run_id)?,
            )
        };
        let audit = planner::plan_round_with_context(
            &client,
            &endpoints_for_ai,
            &previous,
            executor.remaining_requests(),
            provider.supports_json_schema,
            allowed_tools.as_ref(),
            mission_context.as_ref(),
            executor.cancel_receiver(),
        )
        .await?;
        {
            let conn = pool.get().map_err(|error| error.to_string())?;
            super::mission::clear_steering_for_run(&conn, run_id)?;
        }
        let (round_id, _analysis_run_id) = {
            let conn = pool.get().map_err(|error| error.to_string())?;
            planner::persist_round(&conn, project_id, run_id, round_number, &provider, &audit)?
        };
        {
            let conn = pool.get().map_err(|error| error.to_string())?;
            conn.execute(
                "UPDATE assessment_runs SET completed_rounds = ?2 WHERE id = ?1",
                rusqlite::params![run_id, round_number],
            )
            .map_err(|error| error.to_string())?;
        }
        let Some(plans) = audit.checks else {
            insert_gap(
                &pool,
                run_id,
                None,
                "ai",
                "planner_output_invalid_twice",
                "AI 两次输出均未通过有界 DSL 校验；没有执行模型提出的任何网络动作",
            )?;
            break;
        };
        if plans.is_empty() {
            insert_gap(
                &pool,
                run_id,
                None,
                "ai",
                "planner_selected_no_checks",
                "AI 在当前端点与剩余预算内没有选择新的安全检查",
            )?;
            break;
        }
        // Manual recipes share the same bounded DSL, but deliberately bypass
        // check materialization: a validated selection only advances an
        // approved action to `manual_ready` and creates zero sockets.
        let (manual_plans, executable_plans): (Vec<_>, Vec<_>) =
            plans.into_iter().partition(|plan| {
                allowed_tools.is_some()
                    && super::catalog::tool(&plan.template_id)
                        .is_some_and(|tool| tool.execution_kind == "manual_recipe")
            });
        let selected_manual = if manual_plans.is_empty() {
            0
        } else {
            let mut conn = pool.get().map_err(|error| error.to_string())?;
            super::mission::select_manual_plans_for_run(
                &mut conn,
                run_id,
                round_id,
                &manual_plans,
                allowed_tools.as_ref(),
            )?
        };
        if selected_manual > 0 {
            emit_progress(
                &app,
                &pool,
                project_id,
                run_id,
                current_status,
                "planning",
                &format!(
                    "已选择 {selected_manual} 个已审批人工配方；仅等待用户创建并发送 Repeater 草稿"
                ),
            );
        }
        let checks = templates::materialize_checks_with_allowlist(
            &pool,
            &executor,
            round_id,
            executable_plans,
            &discovery.endpoints,
            allowed_tools.as_ref(),
        )?;
        if checks.is_empty() {
            if selected_manual > 0 {
                break;
            }
            continue;
        }
        transition(&pool, project_id, run_id, AssessmentStatus::Executing, None)?;
        current_status = AssessmentStatus::Executing;
        emit_progress(
            &app,
            &pool,
            project_id,
            run_id,
            current_status,
            "executing",
            &format!("正在执行第 {round_number} 轮 {} 个只读检查", checks.len()),
        );
        let mut stop = None;
        for check in &checks {
            let executed = templates::execute_check(&pool, &mut executor, check).await?;
            previous.push(PriorVerdictForAi {
                template_id: check.template.id.into(),
                endpoint_id: check.endpoint.endpoint.endpoint_id.clone(),
                verdict_code: executed.outcome.verdict.as_str().into(),
            });
            if let Some(finding_id) = executed.finding_id {
                let conn = pool.get().map_err(|error| error.to_string())?;
                if let Ok(finding) = crate::evidence::service::load_finding(&conn, finding_id) {
                    let event = if executed.finding_created {
                        "finding:new"
                    } else {
                        "finding:updated"
                    };
                    let _ = app.emit(event, &finding);
                }
            }
            emit_progress(
                &app,
                &pool,
                project_id,
                run_id,
                current_status,
                "executing",
                &format!(
                    "{}：{}",
                    check.template.id,
                    executed.outcome.verdict.as_str()
                ),
            );
            if executed.human_conflict {
                insert_gap(
                    &pool,
                    run_id,
                    Some(check.id),
                    "finding",
                    "human_judgement_conflict",
                    "安全验证器结论与人工 rejected 判断冲突，未自动复活 Finding",
                )?;
            }
            if executed.stop_condition.is_some() {
                stop = executed.stop_condition;
                break;
            }
            if executor.is_cancelled() {
                break;
            }
        }
        transition(&pool, project_id, run_id, AssessmentStatus::Verifying, None)?;
        current_status = AssessmentStatus::Verifying;
        emit_progress(
            &app,
            &pool,
            project_id,
            run_id,
            current_status,
            "verifying",
            "本地确定性验证结果已提交",
        );
        if executor.is_cancelled() {
            transition(
                &pool,
                project_id,
                run_id,
                AssessmentStatus::Cancelled,
                Some("user_cancelled"),
            )?;
            emit_progress(
                &app,
                &pool,
                project_id,
                run_id,
                AssessmentStatus::Cancelled,
                "cancelled",
                "评估已取消，已保留部分结果",
            );
            return Ok(());
        }
        if let Some(condition) = stop {
            stop_for_condition(&app, &pool, project_id, run_id, condition)?;
            return Ok(());
        }
        if executor.remaining_requests() == 0 {
            insert_gap(
                &pool,
                run_id,
                None,
                "budget",
                "request_budget_exhausted",
                "请求预算已用尽，剩余潜在检查未执行",
            )?;
            break;
        }
    }

    if current_status == AssessmentStatus::Planning {
        transition(
            &pool,
            project_id,
            run_id,
            AssessmentStatus::Completed,
            Some("planning_complete"),
        )?;
    } else {
        transition(
            &pool,
            project_id,
            run_id,
            AssessmentStatus::Completed,
            Some("assessment_complete"),
        )?;
    }
    emit_progress(
        &app,
        &pool,
        project_id,
        run_id,
        AssessmentStatus::Completed,
        "completed",
        "AI 非破坏式安全评估完成",
    );
    Ok(())
}

pub fn finalize_error(
    app: &AppHandle,
    pool: &Pool,
    secrets: &Arc<dyn crate::secrets::SecretStore>,
    project_id: i64,
    run_id: i64,
    error: &str,
) {
    let terminal = if error.starts_with("[ASSESSMENT_CANCELLED]") {
        AssessmentStatus::Cancelled
    } else if error.starts_with("[CONTRACT_DRIFT]")
        || error.starts_with("[RUN_RESPONSE_BYTES_EXHAUSTED]")
        || error.starts_with("[REQUEST_BUDGET_EXHAUSTED]")
    {
        AssessmentStatus::Stopped
    } else {
        AssessmentStatus::Failed
    };
    // 错误消息可能回显 URL/Header 等目标内容；把本 run 身份的真实凭据变体
    // 一并纳入脱敏引用，避免敏感值通过 stop_reason 落库。
    let references = pool
        .get()
        .ok()
        .map(|conn| error_redaction_references(&conn, secrets.as_ref(), project_id, run_id))
        .unwrap_or_default();
    let reference_slice = references.iter().map(String::as_str).collect::<Vec<_>>();
    let safe_reason: String = crate::secrets::redact_sensitive(error, &reference_slice)
        .chars()
        .take(1800)
        .collect();
    if let Ok(mut conn) = pool.get() {
        if let Ok(run) = service::get_run(&conn, project_id, run_id) {
            if run.status.is_active() {
                let check_status = if terminal == AssessmentStatus::Cancelled {
                    "cancelled"
                } else {
                    "failed"
                };
                let _ =
                    service::finalize_open_checks(&mut conn, run_id, check_status, &safe_reason);
                let _ = service::transition_run(
                    &mut conn,
                    project_id,
                    run_id,
                    terminal,
                    Some(&safe_reason),
                );
            }
        }
    }
    emit_progress(
        app,
        pool,
        project_id,
        run_id,
        terminal,
        terminal.as_str(),
        &safe_reason,
    );
}

fn transition(
    pool: &Pool,
    project_id: i64,
    run_id: i64,
    status: AssessmentStatus,
    reason: Option<&str>,
) -> Result<(), String> {
    let mut conn = pool.get().map_err(|error| error.to_string())?;
    service::transition_run(&mut conn, project_id, run_id, status, reason)?;
    Ok(())
}

/// 收集本 run 两个身份 profile 的真实凭据及其常见编码变体，供错误消息脱敏。
fn error_redaction_references(
    conn: &rusqlite::Connection,
    secrets: &dyn crate::secrets::SecretStore,
    project_id: i64,
    run_id: i64,
) -> Vec<String> {
    let mut values = Vec::new();
    let profile_ids: Result<(Option<i64>, Option<i64>), _> = conn.query_row(
        "SELECT identity_a_profile_id, identity_b_profile_id
         FROM assessment_runs WHERE id = ?1 AND project_id = ?2",
        rusqlite::params![run_id, project_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    );
    let Ok((identity_a, identity_b)) = profile_ids else {
        return values;
    };
    for profile_id in [identity_a, identity_b].into_iter().flatten() {
        let header_name: Result<String, _> = conn.query_row(
            "SELECT header_name FROM assessment_auth_profiles
             WHERE id = ?1 AND project_id = ?2",
            rusqlite::params![profile_id, project_id],
            |row| row.get(0),
        );
        let Ok(header_name) = header_name else {
            continue;
        };
        let secret_id = crate::secrets::assessment_auth_profile_secret_id(project_id, profile_id);
        let Ok(secret_id) = secret_id else {
            continue;
        };
        if let Ok(Some(secret)) = secrets.get(&secret_id) {
            values.extend(super::service::auth_secret_redaction_values(
                &header_name,
                secret.expose(),
            ));
        }
    }
    values.sort();
    values.dedup();
    values.sort_by_key(|value| std::cmp::Reverse(value.len()));
    values
}

fn endpoints_for_ai(
    endpoints: &[DiscoveredEndpoint],
    executor: &AssessmentExecutor,
) -> Vec<EndpointForAi> {
    endpoints
        .iter()
        .map(|endpoint| EndpointForAi {
            endpoint_id: endpoint.endpoint.endpoint_id.clone(),
            path: executor.redact_target_metadata(&endpoint.endpoint.path),
            query_parameter_names: endpoint
                .endpoint
                .query_parameter_names
                .iter()
                .map(|name| executor.redact_target_metadata(name))
                .collect(),
            status: endpoint.endpoint.status,
            content_type: executor.redact_target_metadata(&endpoint.endpoint.content_type),
            has_authentication: endpoint.endpoint.has_authentication,
            passive_tags: endpoint
                .endpoint
                .passive_tags
                .iter()
                .map(|tag| executor.redact_target_metadata(tag))
                .collect(),
            response_complete: endpoint.endpoint.response_complete,
            has_resource_owner_claim: endpoint.endpoint.resource_owner_profile_id.is_some(),
        })
        .collect()
}

fn stop_for_condition(
    app: &AppHandle,
    pool: &Pool,
    project_id: i64,
    run_id: i64,
    condition: StopCondition,
) -> Result<(), String> {
    let (reason, message) = match condition {
        StopCondition::RateLimited => ("target_rate_limited", "目标返回 429，评估已立即停止"),
        StopCondition::TargetUnstable => (
            "target_unstable",
            "目标连续三次返回 5xx 或超时，评估已立即停止",
        ),
        StopCondition::ResponseBudgetExhausted => (
            "response_byte_budget_exhausted",
            "响应读取总预算已用尽，评估已停止",
        ),
    };
    insert_gap(pool, run_id, None, "safety_stop", reason, message)?;
    transition(
        pool,
        project_id,
        run_id,
        AssessmentStatus::Stopped,
        Some(reason),
    )?;
    emit_progress(
        app,
        pool,
        project_id,
        run_id,
        AssessmentStatus::Stopped,
        "stopped",
        message,
    );
    Ok(())
}

fn insert_builtin_coverage_gaps(pool: &Pool, run_id: i64) -> Result<(), String> {
    let entries = [
        ("sql_command_injection", "SQL/命令注入不会主动测试"),
        ("path_traversal", "目录穿越不会主动测试"),
        ("ssrf", "SSRF 不会主动测试"),
        ("file_upload", "文件上传不会主动测试"),
        ("password_bruteforce", "密码爆破不会主动测试"),
        ("dos", "DoS 与资源耗尽不会主动测试"),
        (
            "state_changing_business_logic",
            "表单、POST 与状态变更业务逻辑不会主动测试",
        ),
        ("browser_script_execution", "不会执行浏览器脚本"),
    ];
    let conn = pool.get().map_err(|error| error.to_string())?;
    for (code, detail) in entries {
        conn.execute(
            "INSERT INTO assessment_coverage_gaps(
                 run_id, category, reason_code, detail
             ) VALUES(?1, 'excluded_test_class', ?2, ?3)",
            rusqlite::params![run_id, code, detail],
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn insert_gap(
    pool: &Pool,
    run_id: i64,
    check_id: Option<i64>,
    category: &str,
    reason_code: &str,
    detail: &str,
) -> Result<(), String> {
    let conn = pool.get().map_err(|error| error.to_string())?;
    conn.execute(
        "INSERT INTO assessment_coverage_gaps(
             run_id, check_id, category, reason_code, detail
         ) VALUES(?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![run_id, check_id, category, reason_code, detail],
    )
    .map_err(|error| error.to_string())?;
    service::append_event(
        &conn,
        run_id,
        check_id,
        "coverage_gap_added",
        None,
        Some(reason_code),
        &json!({"category": category}),
    )?;
    Ok(())
}

fn emit_progress(
    app: &AppHandle,
    pool: &Pool,
    project_id: i64,
    run_id: i64,
    status: AssessmentStatus,
    phase: &str,
    message: &str,
) {
    let (request_count, request_budget, completed_checks, total_checks) = pool
        .get()
        .ok()
        .and_then(|conn| {
            conn.query_row(
                "SELECT ar.request_count, ar.request_budget,
                        (SELECT COUNT(*) FROM assessment_checks c
                         WHERE c.run_id = ar.id AND c.status = 'completed'),
                        (SELECT COUNT(*) FROM assessment_checks c WHERE c.run_id = ar.id)
                 FROM assessment_runs ar WHERE ar.id = ?1 AND ar.project_id = ?2",
                rusqlite::params![run_id, project_id],
                |row| {
                    Ok((
                        row.get::<_, u32>(0)?,
                        row.get::<_, u32>(1)?,
                        row.get::<_, u32>(2)?,
                        row.get::<_, u32>(3)?,
                    ))
                },
            )
            .ok()
        })
        .unwrap_or((0, 0, 0, 0));
    let _ = app.emit(
        "assessment:progress",
        AssessmentProgress {
            project_id,
            run_id,
            status,
            phase: phase.into(),
            message: message.into(),
            request_count,
            request_budget,
            completed_checks,
            total_checks,
            occurred_at: Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
        },
    );
    let mission = pool.get().ok().and_then(|conn| {
        conn.query_row(
            "SELECT m.id, m.revision, m.status
             FROM assessment_missions m
             JOIN assessment_mission_runs mr ON mr.mission_id=m.id
             WHERE mr.run_id=?1 AND m.project_id=?2 AND m.legacy=0",
            rusqlite::params![run_id, project_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()
        .ok()
        .flatten()
    });
    if let Some((mission_id, revision, mission_status)) = mission {
        if let Ok(mission_status) = MissionStatus::parse(&mission_status) {
            let _ = app.emit(
                "assessment:mission-event",
                AssessmentMissionEvent {
                    project_id,
                    mission_id,
                    run_id: Some(run_id),
                    action_id: None,
                    revision,
                    event_type: "mission_progress".into(),
                    status: mission_status,
                    phase: phase.into(),
                    message: message.into(),
                    request_count,
                    request_budget,
                    completed_checks,
                    total_checks,
                    occurred_at: Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
                },
            );
        }
    }
}
