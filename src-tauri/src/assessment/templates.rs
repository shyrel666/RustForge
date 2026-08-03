use super::catalog::{self, SafeTemplate};
use super::discovery::DiscoveredEndpoint;
use super::executor::{AssessmentExecutor, AuthProbeRequest, IdentitySelection, StopCondition};
use super::model::AssessmentVerdict;
use super::planner::PlannedCheck;
use super::policy::RequestPhase;
use super::verifier::{self, ResponseObservation, VerificationOutcome};
use crate::replay::model::{ReplayHeader, ReplayRun};
use crate::storage::db::Pool;
use base64::Engine;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use url::Url;

#[derive(Debug, Clone)]
pub struct MaterializedCheck {
    pub id: i64,
    pub planned: PlannedCheck,
    pub template: &'static SafeTemplate,
    pub endpoint: DiscoveredEndpoint,
}

#[derive(Debug)]
pub struct ExecutedCheck {
    pub check_id: i64,
    pub verification_id: i64,
    pub finding_id: Option<i64>,
    pub finding_created: bool,
    pub finding_confirmed: bool,
    pub human_conflict: bool,
    pub outcome: VerificationOutcome,
    pub stop_condition: Option<StopCondition>,
}

pub fn materialize_checks(
    pool: &Pool,
    executor: &AssessmentExecutor,
    round_id: i64,
    plans: Vec<PlannedCheck>,
    endpoints: &[DiscoveredEndpoint],
) -> Result<Vec<MaterializedCheck>, String> {
    let endpoint_map = endpoints
        .iter()
        .map(|endpoint| (endpoint.endpoint.endpoint_id.as_str(), endpoint))
        .collect::<HashMap<_, _>>();
    let mut accepted = Vec::new();
    let mut reserved_cost = 0_u32;
    let mut seen = HashSet::new();

    for planned in plans {
        let endpoint = endpoint_map.get(planned.endpoint_id.as_str()).copied();
        let template = catalog::template(&planned.template_id);
        let duplicate_key = (
            planned.template_id.clone(),
            planned.endpoint_id.clone(),
            planned.parameter_name.clone(),
            planned.identity_mode.clone(),
        );
        let duplicate_this_batch = !seen.insert(duplicate_key);
        let (policy_result, policy_reason, request_cost) = validate_plan(
            pool,
            executor,
            round_id,
            &planned,
            endpoint,
            template,
            duplicate_this_batch,
            reserved_cost,
        )?;
        // 同一轮内的完全重复由 parse_plan 先行拒绝；此处仍是防御边界：重复
        // check 不落库（否则会与 UNIQUE(run_id, round_id, ...) 约束冲突）。
        if duplicate_this_batch {
            continue;
        }
        let endpoint_db_id = endpoint.map(|endpoint| endpoint.endpoint.id);
        let template_version = template.map_or("unresolved", |template| template.version);
        let conn = pool.get().map_err(|error| error.to_string())?;
        conn.execute(
            "INSERT INTO assessment_checks(
                 run_id, round_id, endpoint_id, requested_endpoint_id,
                 template_id, template_version, parameter_name, identity_mode,
                 rationale, policy_result, policy_reason, status, request_cost
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            rusqlite::params![
                executor.run_id(),
                round_id,
                endpoint_db_id,
                planned.endpoint_id,
                planned.template_id,
                template_version,
                planned.parameter_name,
                planned.identity_mode,
                planned.rationale,
                policy_result,
                policy_reason,
                if policy_result == "allowed" {
                    "queued"
                } else {
                    "skipped"
                },
                request_cost,
            ],
        )
        .map_err(|error| format!("保存 Assessment check 失败: {error}"))?;
        let check_id = conn.last_insert_rowid();
        super::service::append_event(
            &conn,
            executor.run_id(),
            Some(check_id),
            "check_policy_evaluated",
            None,
            Some(policy_result),
            &json!({"reason": policy_reason, "requestCost": request_cost}),
        )?;
        if policy_result != "allowed" {
            conn.execute(
                "INSERT INTO assessment_coverage_gaps(
                     run_id, check_id, category, reason_code, detail
                 ) VALUES(?1, ?2, 'policy', 'ai_check_rejected', ?3)",
                rusqlite::params![executor.run_id(), check_id, policy_reason],
            )
            .map_err(|error| error.to_string())?;
            continue;
        }
        reserved_cost = reserved_cost.saturating_add(request_cost as u32);
        accepted.push(MaterializedCheck {
            id: check_id,
            planned,
            template: template.expect("allowed plan has template"),
            endpoint: endpoint.expect("allowed plan has endpoint").clone(),
        });
    }
    Ok(accepted)
}

#[allow(clippy::too_many_arguments)]
fn validate_plan(
    pool: &Pool,
    executor: &AssessmentExecutor,
    round_id: i64,
    planned: &PlannedCheck,
    endpoint: Option<&DiscoveredEndpoint>,
    template: Option<&'static SafeTemplate>,
    duplicate_this_batch: bool,
    reserved_cost: u32,
) -> Result<(&'static str, String, u8), String> {
    let Some(template) = template else {
        return Ok(("rejected", "unknown_template".into(), 0));
    };
    let Some(endpoint) = endpoint else {
        return Ok(("rejected", "unknown_endpoint".into(), 0));
    };
    if duplicate_this_batch {
        return Ok(("rejected", "duplicate_check".into(), 0));
    }
    let conn = pool.get().map_err(|error| error.to_string())?;
    let prior_duplicate: bool = conn
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM assessment_checks
                 WHERE run_id = ?1 AND round_id <> ?2
                   AND template_id = ?3 AND requested_endpoint_id = ?4
                   AND parameter_name IS ?5 AND identity_mode = ?6
                   AND policy_result = 'allowed'
             )",
            rusqlite::params![
                executor.run_id(),
                round_id,
                planned.template_id,
                planned.endpoint_id,
                planned.parameter_name,
                planned.identity_mode,
            ],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    drop(conn);
    if prior_duplicate {
        return Ok(("rejected", "duplicate_check_from_previous_round".into(), 0));
    }
    if !template
        .allowed_identity_modes
        .contains(&planned.identity_mode.as_str())
    {
        return Ok((
            "rejected",
            "identity_mode_not_allowed_for_template".into(),
            0,
        ));
    }
    match (template.requires_parameter, planned.parameter_name.as_ref()) {
        (true, Some(parameter))
            if endpoint
                .endpoint
                .query_parameter_names
                .iter()
                .any(|name| name == parameter) => {}
        (true, _) => return Ok(("rejected", "parameter_not_in_endpoint_inventory".into(), 0)),
        (false, Some(_)) => {
            return Ok(("rejected", "template_does_not_accept_parameter".into(), 0))
        }
        (false, None) => {}
    }
    if planned.identity_mode == "a" && !executor.identity_available(IdentitySelection::A) {
        return Ok(("skipped", "identity_a_missing".into(), 0));
    }
    if planned.identity_mode == "b" && !executor.identity_available(IdentitySelection::B) {
        return Ok(("skipped", "identity_b_missing".into(), 0));
    }
    if planned.identity_mode == "a_vs_b"
        && (!executor.identity_available(IdentitySelection::A)
            || !executor.identity_available(IdentitySelection::B))
    {
        return Ok(("skipped", "dual_identity_missing".into(), 0));
    }
    if matches!(
        template.id,
        "credentialed_cors" | "jwt_integrity" | "readonly_idor" | "lazy_reflection"
    ) && endpoint.endpoint.method != "GET"
    {
        return Ok(("skipped", "template_requires_get_endpoint".into(), 0));
    }
    if template.id == "security_headers_cookie" && endpoint.discovery_replay_run_id.is_none() {
        return Ok(("skipped", "no_discovery_response_to_reuse".into(), 0));
    }
    if template.id == "credentialed_cors" && !endpoint.endpoint.has_authentication {
        return Ok((
            "skipped",
            "endpoint_not_observed_with_authentication".into(),
            0,
        ));
    }
    if template.id == "jwt_integrity" {
        let identity = if planned.identity_mode == "a" {
            executor.identity_a()
        } else {
            executor.identity_b()
        };
        let valid_jwt = identity
            .map(|identity| identity.live_header())
            .is_some_and(|header| jwt_parts(&header).is_some());
        if !valid_jwt {
            return Ok(("skipped", "selected_identity_is_not_bearer_jwt".into(), 0));
        }
    }
    let request_cost = effective_request_cost(template, endpoint, &planned.identity_mode);
    if reserved_cost.saturating_add(request_cost as u32) > executor.remaining_requests() {
        return Ok(("skipped", "request_budget_insufficient".into(), 0));
    }
    Ok(("allowed", "allowed".into(), request_cost))
}

fn effective_request_cost(
    template: &SafeTemplate,
    endpoint: &DiscoveredEndpoint,
    identity_mode: &str,
) -> u8 {
    if template.id == "credentialed_cors" {
        // 执行需要 anonymous 与 probe 两个新请求；身份 A 且发现响应可复用时
        // 基线请求被复用，否则还要额外发一次 baseline。
        let reusable_a_baseline = identity_mode == "a"
            && endpoint.discovery_replay_run_id.is_some()
            && endpoint.endpoint.has_authentication;
        if reusable_a_baseline {
            2
        } else {
            3
        }
    } else {
        template.request_cost
    }
}

pub async fn execute_check(
    pool: &Pool,
    executor: &mut AssessmentExecutor,
    check: &MaterializedCheck,
) -> Result<ExecutedCheck, String> {
    set_check_status(pool, executor.run_id(), check.id, "executing")?;
    let mut responses = HashMap::<String, ResponseObservation>::new();
    let mut raw_runs = HashMap::<String, ReplayRun>::new();
    let mut stop_condition = None;
    let mut reflection_marker = None;
    let mut reflection_observed = false;

    match check.template.id {
        "security_headers_cookie" => {
            if let Some(run_id) = check.endpoint.discovery_replay_run_id {
                let conn = pool.get().map_err(|error| error.to_string())?;
                let run = crate::replay::service::load_run(&conn, run_id)?;
                drop(conn);
                link_replay(pool, check.id, run.id, "baseline")?;
                responses.insert("baseline".into(), ResponseObservation::from(&run));
                raw_runs.insert("baseline".into(), run);
            }
        }
        "credentialed_cors" => {
            let identity = identity_from_mode(&check.planned.identity_mode)?;
            if identity == IdentitySelection::A {
                if let Some(run_id) = check.endpoint.discovery_replay_run_id {
                    let conn = pool.get().map_err(|error| error.to_string())?;
                    let run = crate::replay::service::load_run(&conn, run_id)?;
                    drop(conn);
                    link_response(
                        pool,
                        check.id,
                        "baseline",
                        run,
                        &mut responses,
                        &mut raw_runs,
                    )?;
                }
            }
            if !responses.contains_key("baseline") {
                perform(
                    pool,
                    executor,
                    check,
                    "baseline",
                    Vec::new(),
                    identity,
                    None,
                    &mut responses,
                    &mut raw_runs,
                    &mut stop_condition,
                )
                .await?;
            }
            // 匿名请求用于判定端点是否真的需要认证：匿名与带身份基线等价时
            // 端点公开，任何 Origin 反射都不能构成凭据型 CORS 漏洞。
            if stop_condition.is_none() {
                perform(
                    pool,
                    executor,
                    check,
                    "anonymous",
                    Vec::new(),
                    IdentitySelection::Anonymous,
                    None,
                    &mut responses,
                    &mut raw_runs,
                    &mut stop_condition,
                )
                .await?;
            }
            if stop_condition.is_none() {
                perform(
                    pool,
                    executor,
                    check,
                    "probe",
                    vec![ReplayHeader {
                        name: "Origin".into(),
                        value: "https://rf-probe.invalid".into(),
                    }],
                    identity,
                    None,
                    &mut responses,
                    &mut raw_runs,
                    &mut stop_condition,
                )
                .await?;
            }
        }
        "jwt_integrity" => {
            let identity = identity_from_mode(&check.planned.identity_mode)?;
            let auth_header = match identity {
                IdentitySelection::A => executor.identity_a(),
                IdentitySelection::B => executor.identity_b(),
                IdentitySelection::Anonymous => None,
            }
            .ok_or_else(|| "JWT 身份不存在".to_string())?
            .live_header();
            let (signature_probe, alg_none_probe) =
                jwt_parts(&auth_header).ok_or_else(|| "JWT 身份格式无效".to_string())?;
            perform(
                pool,
                executor,
                check,
                "baseline",
                Vec::new(),
                identity,
                None,
                &mut responses,
                &mut raw_runs,
                &mut stop_condition,
            )
            .await?;
            if stop_condition.is_none() {
                perform(
                    pool,
                    executor,
                    check,
                    "anonymous",
                    Vec::new(),
                    IdentitySelection::Anonymous,
                    None,
                    &mut responses,
                    &mut raw_runs,
                    &mut stop_condition,
                )
                .await?;
            }
            if stop_condition.is_none() {
                perform(
                    pool,
                    executor,
                    check,
                    "signature_probe",
                    Vec::new(),
                    identity,
                    Some(signature_probe),
                    &mut responses,
                    &mut raw_runs,
                    &mut stop_condition,
                )
                .await?;
            }
            if stop_condition.is_none() {
                perform(
                    pool,
                    executor,
                    check,
                    "alg_none_probe",
                    Vec::new(),
                    identity,
                    Some(alg_none_probe),
                    &mut responses,
                    &mut raw_runs,
                    &mut stop_condition,
                )
                .await?;
            }
        }
        "open_redirect" => {
            let parameter = check
                .planned
                .parameter_name
                .as_deref()
                .expect("validated parameter");
            let probe_url = replace_query_value(
                &check.endpoint.endpoint.url,
                parameter,
                "https://rf-probe.invalid/rf",
            )?;
            perform_url(
                pool,
                executor,
                check,
                "probe",
                &probe_url,
                Vec::new(),
                identity_from_mode(&check.planned.identity_mode)?,
                None,
                &mut responses,
                &mut raw_runs,
                &mut stop_condition,
            )
            .await?;
        }
        "lazy_reflection" => {
            let parameter = check
                .planned
                .parameter_name
                .as_deref()
                .expect("validated parameter");
            let marker = format!(
                "RF{}",
                &sha256(format!("{}:{parameter}", check.id).as_bytes())[..20]
            );
            let probe_url = replace_query_value(&check.endpoint.endpoint.url, parameter, &marker)?;
            perform_url(
                pool,
                executor,
                check,
                "probe",
                &probe_url,
                Vec::new(),
                identity_from_mode(&check.planned.identity_mode)?,
                None,
                &mut responses,
                &mut raw_runs,
                &mut stop_condition,
            )
            .await?;
            reflection_observed = raw_runs
                .get("probe")
                .and_then(|run| run.response_body_text.as_deref())
                .is_some_and(|body| body.contains(&marker));
            reflection_marker = Some(marker);
        }
        "readonly_idor" => {
            perform(
                pool,
                executor,
                check,
                "identity_a",
                Vec::new(),
                IdentitySelection::A,
                None,
                &mut responses,
                &mut raw_runs,
                &mut stop_condition,
            )
            .await?;
            if stop_condition.is_none() {
                perform(
                    pool,
                    executor,
                    check,
                    "identity_b",
                    Vec::new(),
                    IdentitySelection::B,
                    None,
                    &mut responses,
                    &mut raw_runs,
                    &mut stop_condition,
                )
                .await?;
            }
        }
        _ => return Err("安全模板注册表与执行器不一致".into()),
    }

    set_check_status(pool, executor.run_id(), check.id, "verifying")?;
    let outcome = verifier::verify(
        check.template.id,
        &check.endpoint.endpoint,
        &responses,
        reflection_marker.as_deref(),
        reflection_observed,
    );
    let commit = {
        let mut conn = pool.get().map_err(|error| error.to_string())?;
        super::outcome::commit_verification_outcome(
            &mut conn,
            super::outcome::VerificationCommitInput {
                project_id: executor.contract().project_id,
                run_id: executor.run_id(),
                check_id: check.id,
                template_id: check.template.id,
                template_version: check.template.version,
                verifier_id: check.template.verifier_id,
                verifier_version: check.template.verifier_version,
                endpoint_method: &check.endpoint.endpoint.method,
                endpoint_url: &check.endpoint.endpoint.url,
                parameter_name: check.planned.parameter_name.as_deref(),
                outcome: &outcome,
            },
        )?
    };
    set_check_status(pool, executor.run_id(), check.id, "completed")?;
    if outcome.verdict == AssessmentVerdict::Suspected
        && check.template.id == "readonly_idor"
        && check.endpoint.endpoint.resource_owner_profile_id.is_none()
    {
        insert_gap(
            pool,
            executor.run_id(),
            Some(check.id),
            "identity",
            "resource_ownership_missing",
            "A/B 响应等价，但用户未声明资源仅属于身份 A，不能自动确认",
        )?;
    }
    Ok(ExecutedCheck {
        check_id: check.id,
        verification_id: commit.verification_id,
        finding_id: commit.finding_id,
        finding_created: commit.finding_created,
        finding_confirmed: commit.finding_confirmed,
        human_conflict: commit.human_conflict,
        outcome,
        stop_condition,
    })
}

#[allow(clippy::too_many_arguments)]
async fn perform(
    pool: &Pool,
    executor: &mut AssessmentExecutor,
    check: &MaterializedCheck,
    role: &str,
    headers: Vec<ReplayHeader>,
    identity: IdentitySelection,
    auth_probe: Option<String>,
    responses: &mut HashMap<String, ResponseObservation>,
    raw_runs: &mut HashMap<String, ReplayRun>,
    stop: &mut Option<StopCondition>,
) -> Result<(), String> {
    let url = check.endpoint.endpoint.url.clone();
    perform_url(
        pool, executor, check, role, &url, headers, identity, auth_probe, responses, raw_runs, stop,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn perform_url(
    pool: &Pool,
    executor: &mut AssessmentExecutor,
    check: &MaterializedCheck,
    role: &str,
    url: &str,
    headers: Vec<ReplayHeader>,
    identity: IdentitySelection,
    auth_probe: Option<String>,
    responses: &mut HashMap<String, ResponseObservation>,
    raw_runs: &mut HashMap<String, ReplayRun>,
    stop: &mut Option<StopCondition>,
) -> Result<(), String> {
    let result = match auth_probe {
        Some(value) => {
            executor
                .execute_with_auth_probe(AuthProbeRequest {
                    phase: RequestPhase::Verification,
                    method: "GET",
                    url,
                    extra_headers: headers,
                    identity,
                    probe_header_value: value,
                    hash_suffix: &format!("check:{}:{role}", check.id),
                })
                .await?
        }
        None => {
            executor
                .execute(
                    RequestPhase::Verification,
                    "GET",
                    url,
                    headers,
                    identity,
                    &format!("check:{}:{role}", check.id),
                )
                .await?
        }
    };
    let (run, condition) = result;
    link_response(pool, check.id, role, run, responses, raw_runs)?;
    if stop.is_none() {
        *stop = condition;
    }
    Ok(())
}

fn link_response(
    pool: &Pool,
    check_id: i64,
    role: &str,
    run: ReplayRun,
    responses: &mut HashMap<String, ResponseObservation>,
    raw_runs: &mut HashMap<String, ReplayRun>,
) -> Result<(), String> {
    link_replay(pool, check_id, run.id, role)?;
    responses.insert(role.to_string(), ResponseObservation::from(&run));
    raw_runs.insert(role.to_string(), run);
    Ok(())
}

fn link_replay(pool: &Pool, check_id: i64, replay_run_id: i64, role: &str) -> Result<(), String> {
    let conn = pool.get().map_err(|error| error.to_string())?;
    conn.execute(
        "INSERT INTO assessment_check_replays(check_id, replay_run_id, role)
         VALUES(?1, ?2, ?3)",
        rusqlite::params![check_id, replay_run_id, role],
    )
    .map_err(|error| format!("关联 Assessment ReplayRun 失败: {error}"))?;
    Ok(())
}

fn set_check_status(pool: &Pool, run_id: i64, check_id: i64, status: &str) -> Result<(), String> {
    let conn = pool.get().map_err(|error| error.to_string())?;
    let old: String = conn
        .query_row(
            "SELECT status FROM assessment_checks WHERE id = ?1 AND run_id = ?2",
            rusqlite::params![check_id, run_id],
            |row| row.get(0),
        )
        .map_err(|_| "Assessment check 不存在".to_string())?;
    conn.execute(
        "UPDATE assessment_checks
         SET status = ?3,
             completed_at = CASE WHEN ?3 IN ('completed','skipped','cancelled','failed')
                                 THEN strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                                 ELSE completed_at END
         WHERE id = ?1 AND run_id = ?2",
        rusqlite::params![check_id, run_id, status],
    )
    .map_err(|error| error.to_string())?;
    super::service::append_event(
        &conn,
        run_id,
        Some(check_id),
        "check_status_changed",
        Some(&old),
        Some(status),
        &json!({}),
    )?;
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
    Ok(())
}

fn identity_from_mode(mode: &str) -> Result<IdentitySelection, String> {
    match mode {
        "anonymous" => Ok(IdentitySelection::Anonymous),
        "a" => Ok(IdentitySelection::A),
        "b" => Ok(IdentitySelection::B),
        _ => Err("该模板需要单一身份模式".into()),
    }
}

fn replace_query_value(
    raw_url: &str,
    parameter: &str,
    replacement: &str,
) -> Result<String, String> {
    let mut url = Url::parse(raw_url).map_err(|_| "端点 URL 已损坏".to_string())?;
    let pairs = url
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    if !pairs.iter().any(|(name, _)| name == parameter) {
        return Err("端点不包含已验证的 query 参数".into());
    }
    url.set_query(None);
    {
        let mut serializer = url.query_pairs_mut();
        for (name, value) in pairs {
            serializer.append_pair(
                &name,
                if name == parameter {
                    replacement
                } else {
                    &value
                },
            );
        }
    }
    Ok(url.to_string())
}

fn jwt_parts(header: &ReplayHeader) -> Option<(String, String)> {
    if !header.name.eq_ignore_ascii_case("authorization") {
        return None;
    }
    let token = header.value.strip_prefix("Bearer ")?;
    let parts = token.split('.').collect::<Vec<_>>();
    if parts.len() != 3 || parts[0].is_empty() || parts[1].is_empty() || parts[2].is_empty() {
        return None;
    }
    let mut signature = parts[2].as_bytes().to_vec();
    signature[0] = if signature[0] == b'A' { b'B' } else { b'A' };
    let signature = String::from_utf8(signature).ok()?;
    let corrupted = format!("Bearer {}.{}.{}", parts[0], parts[1], signature);
    let none_header =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
    let alg_none = format!("Bearer {none_header}.{}.", parts[1]);
    Some((corrupted, alg_none))
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assessment::model::{AssessmentContractInput, AssessmentEndpoint};
    use crate::replay::model::TlsPolicy;
    use crate::secrets::MemorySecretStore;
    use crate::storage::db::open_pool;
    use std::sync::Arc;
    use tempfile::tempdir;
    use tokio::net::TcpListener;
    use tokio::time::{timeout, Duration};

    #[test]
    fn query_probe_replaces_only_backend_selected_parameter() {
        let replaced = replace_query_value(
            "https://example.test/next?return=%2Fhome&keep=1",
            "return",
            "https://rf-probe.invalid/rf",
        )
        .unwrap();
        let url = Url::parse(&replaced).unwrap();
        let values = url.query_pairs().collect::<HashMap<_, _>>();
        assert_eq!(values.get("return").unwrap(), "https://rf-probe.invalid/rf");
        assert_eq!(values.get("keep").unwrap(), "1");
    }

    #[test]
    fn jwt_probes_are_backend_generated_and_preserve_payload() {
        let header = ReplayHeader {
            name: "Authorization".into(),
            value: "Bearer aaa.bbb.ccc".into(),
        };
        let (signature, none) = jwt_parts(&header).unwrap();
        assert_ne!(signature, header.value);
        assert!(signature.contains(".bbb."));
        assert!(none.ends_with(".bbb."));
    }

    #[tokio::test]
    async fn forged_template_endpoint_and_parameter_are_persisted_rejections_without_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let dir = tempdir().unwrap();
        let pool = open_pool(&dir.path().join("materialize.db")).unwrap();
        let project_id;
        let run_id;
        let round_id;
        let endpoint_db_id;
        {
            let mut conn = pool.get().unwrap();
            conn.execute(
                "INSERT INTO projects(name, target_host, scope)
                 VALUES('p', '127.0.0.1', '[\"127.0.0.1\"]')",
                [],
            )
            .unwrap();
            project_id = conn.last_insert_rowid();
            conn.execute_batch(
                "INSERT INTO settings(key, value) VALUES
                    ('ai_current', 'provider'),
                    ('ai_enabled', 'true'),
                    ('ai_providers',
                     '[{\"id\":\"provider\",\"name\":\"Fixture\",\"base_url\":\"https://provider.test/v1\",\"model\":\"model\",\"note\":\"\",\"supports_json_schema\":true}]');",
            )
            .unwrap();
            let store = MemorySecretStore::default();
            let preview = super::super::service::preview_contract(
                &conn,
                &store,
                &AssessmentContractInput {
                    project_id,
                    start_url: format!("http://{address}/safe?next=/home"),
                    excluded_paths: Vec::new(),
                    tls_policy: "strict".into(),
                    request_budget: 120,
                    requests_per_second: 1.0,
                    identity_a_profile_id: None,
                    identity_b_profile_id: None,
                    resource_ownership: Vec::new(),
                    include_recent_traffic: false,
                    provider_id: "provider".into(),
                    model: "model".into(),
                    max_rounds: 3,
                    written_authorization_confirmed: true,
                },
            )
            .unwrap();
            let run = super::super::service::create_run(&mut conn, &preview).unwrap();
            run_id = run.id;
            conn.execute(
                "INSERT INTO assessment_rounds(
                     run_id, round_number, status, input_hash, output_hash,
                     selected_checks, rejection_json
                 ) VALUES(?1,1,'valid',?2,?2,3,'[]')",
                rusqlite::params![run_id, "a".repeat(64)],
            )
            .unwrap();
            round_id = conn.last_insert_rowid();
            conn.execute(
                "INSERT INTO assessment_endpoints(
                     run_id, endpoint_key, method, url, path,
                     query_parameter_names, source_kind, status, response_complete
                 ) VALUES(?1,?2,'GET',?3,'/safe','[\"next\"]','start_url',200,1)",
                rusqlite::params![
                    run_id,
                    "b".repeat(64),
                    format!("http://{address}/safe?next=/home")
                ],
            )
            .unwrap();
            endpoint_db_id = conn.last_insert_rowid();
        }
        let session_id = {
            let conn = pool.get().unwrap();
            crate::replay::service::create_assessment_session(
                &conn,
                project_id,
                run_id,
                TlsPolicy::Strict,
            )
            .unwrap()
        };
        let (_cancel_tx, cancel) = tokio::sync::watch::channel(false);
        let executor = AssessmentExecutor::new(
            pool.clone(),
            Arc::new(MemorySecretStore::default()),
            project_id,
            run_id,
            session_id,
            cancel,
        )
        .unwrap();
        let endpoint = DiscoveredEndpoint {
            endpoint: AssessmentEndpoint {
                id: endpoint_db_id,
                run_id,
                endpoint_id: "ep_real".into(),
                method: "GET".into(),
                url: format!("http://{address}/safe?next=/home"),
                path: "/safe".into(),
                query_parameter_names: vec!["next".into()],
                source_kind: "start_url".into(),
                status: Some(200),
                content_type: "text/html".into(),
                has_authentication: false,
                passive_tags: Vec::new(),
                response_complete: true,
                resource_owner_profile_id: None,
            },
            discovery_replay_run_id: None,
        };
        let plans = vec![
            PlannedCheck {
                template_id: "model_invented_template".into(),
                endpoint_id: "ep_real".into(),
                parameter_name: None,
                identity_mode: "anonymous".into(),
                rationale: "invented".into(),
            },
            PlannedCheck {
                template_id: "open_redirect".into(),
                endpoint_id: "ep_forged".into(),
                parameter_name: Some("next".into()),
                identity_mode: "anonymous".into(),
                rationale: "forged endpoint".into(),
            },
            PlannedCheck {
                template_id: "open_redirect".into(),
                endpoint_id: "ep_real".into(),
                parameter_name: Some("not_in_inventory".into()),
                identity_mode: "anonymous".into(),
                rationale: "forged parameter".into(),
            },
        ];
        let executable =
            materialize_checks(&pool, &executor, round_id, plans, &[endpoint]).unwrap();
        assert!(executable.is_empty());
        assert!(
            timeout(Duration::from_millis(150), listener.accept())
                .await
                .is_err(),
            "policy-rejected model selections must not open a socket"
        );
        let conn = pool.get().unwrap();
        let states: (i64, i64) = conn
            .query_row(
                "SELECT
                     (SELECT COUNT(*) FROM assessment_checks
                      WHERE run_id=?1 AND policy_result IN ('rejected','skipped')),
                     (SELECT COUNT(*) FROM replay_attempts)",
                [run_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(states, (3, 0));
    }
}
