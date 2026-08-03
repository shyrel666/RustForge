use super::catalog;
use super::model::{
    AssessmentAuthCandidate, AssessmentAuthProfile, AssessmentCheck, AssessmentContractInput,
    AssessmentContractPreview, AssessmentCoverageGap, AssessmentDetail, AssessmentEndpoint,
    AssessmentEvent, AssessmentRound, AssessmentRun, AssessmentStatus, AssessmentVerdict,
    AssessmentVerification, CreateAssessmentAuthProfileInput, ImportAssessmentAuthProfileInput,
    ResourceOwnershipClaim, SetAssessmentAuthProfileInput,
};
use super::policy::{
    normalize_excluded_paths, normalize_start_url, validate_rate, BUILTIN_EXCLUDED_SEGMENTS,
    MAX_RUN_RESPONSE_BYTES,
};
use crate::authorization::load_project_policy;
use crate::secrets::{assessment_auth_profile_secret_id, SecretStore, SecretString};
use base64::Engine;
use rusqlite::{params, Connection, OptionalExtension, Row, TransactionBehavior};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub const MAX_AUTH_SECRET_BYTES: usize = 16 * 1024;
const ALLOWED_AUTH_HEADERS: &[&str] = &["Authorization", "Cookie", "X-API-Key", "X-Auth-Token"];
const ACTIVE_STATUSES_SQL: &str = "'queued','discovering','planning','executing','verifying'";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalContract<'a> {
    contract_version: &'static str,
    project_id: i64,
    normalized_scope: &'a [String],
    start_url: &'a str,
    exact_origin: &'a str,
    excluded_paths: &'a [String],
    builtin_excluded_segments: &'static [&'static str],
    tls_policy: &'a str,
    request_budget: u32,
    discovery_budget: u32,
    requests_per_second_millis: u32,
    max_response_bytes: u64,
    max_run_response_bytes: u64,
    concurrency: u8,
    allowed_methods: &'static [&'static str],
    identity_a_profile_id: Option<i64>,
    identity_a_secret_revision: Option<i64>,
    identity_b_profile_id: Option<i64>,
    identity_b_secret_revision: Option<i64>,
    resource_ownership: &'a [ResourceOwnershipClaim],
    include_recent_traffic: bool,
    provider_id: &'a str,
    model: &'a str,
    ai_input_policy: &'static str,
    max_rounds: u8,
    max_checks_per_round: u8,
    template_registry_version: &'static str,
    template_registry_hash: &'a str,
    written_authorization_confirmed: bool,
}

struct ContractProfile {
    label: String,
    revision: i64,
    secret: SecretString,
}

pub struct RuntimeIdentity {
    pub profile_id: i64,
    pub label: String,
    pub header_name: String,
    pub revision: i64,
    secret: SecretString,
}

impl RuntimeIdentity {
    pub fn live_header(&self) -> crate::replay::model::ReplayHeader {
        crate::replay::model::ReplayHeader {
            name: self.header_name.clone(),
            value: self.secret.expose().to_string(),
        }
    }

    pub fn audit_header(&self) -> crate::replay::model::ReplayHeader {
        crate::replay::model::ReplayHeader {
            name: self.header_name.clone(),
            value: format!("[AUTH_PROFILE:{}]", self.profile_id),
        }
    }

    pub fn request_hash_context(&self) -> String {
        format!("profile:{}:revision:{}", self.profile_id, self.revision)
    }

    pub fn redaction_values(&self) -> Vec<String> {
        auth_secret_redaction_values(&self.header_name, self.secret.expose())
    }
}

/// Exact and common transport encodings of a credential. Derived fragments are
/// included only when long enough to avoid replacing ordinary one-character
/// response data. These values stay in memory and are never persisted.
pub(crate) fn auth_secret_redaction_values(header_name: &str, secret: &str) -> Vec<String> {
    const MIN_FRAGMENT: usize = 8;
    let mut candidates = vec![secret.to_string()];
    if header_name.eq_ignore_ascii_case("authorization") {
        if let Some((_, value)) = secret.split_once(char::is_whitespace) {
            let value = value.trim();
            if value.len() >= MIN_FRAGMENT {
                candidates.push(value.to_string());
            }
        }
    } else if header_name.eq_ignore_ascii_case("cookie") {
        for part in secret.split(';') {
            if let Some((_, value)) = part.trim().split_once('=') {
                let value = value.trim();
                if value.len() >= MIN_FRAGMENT {
                    candidates.push(value.to_string());
                }
            }
        }
    }
    let seed = candidates.clone();
    for value in seed {
        if value.len() < MIN_FRAGMENT || value.len() > 4096 {
            continue;
        }
        candidates.push(url::form_urlencoded::byte_serialize(value.as_bytes()).collect());
        candidates.push(base64::engine::general_purpose::STANDARD.encode(value.as_bytes()));
        candidates.push(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.as_bytes()));
    }
    candidates.retain(|value| !value.is_empty());
    candidates.sort();
    candidates.dedup();
    candidates.sort_by_key(|value| std::cmp::Reverse(value.len()));
    candidates
}

pub fn load_runtime_identity(
    conn: &Connection,
    store: &dyn SecretStore,
    project_id: i64,
    profile_id: i64,
) -> Result<RuntimeIdentity, String> {
    let metadata: Option<(String, String, i64)> = conn
        .query_row(
            "SELECT label, header_name, secret_revision
             FROM assessment_auth_profiles WHERE id = ?1 AND project_id = ?2",
            params![profile_id, project_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let (label, header_name, revision) =
        metadata.ok_or_else(|| "评估身份不存在或不属于项目".to_string())?;
    let secret_id = assessment_auth_profile_secret_id(project_id, profile_id)
        .map_err(|error| error.to_string())?;
    let secret = store
        .get(&secret_id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("评估身份 `{label}` 缺少系统凭据"))?;
    validate_auth_secret(secret.expose())?;
    Ok(RuntimeIdentity {
        profile_id,
        label,
        header_name,
        revision,
        secret,
    })
}

pub fn list_auth_profiles(
    conn: &Connection,
    store: &dyn SecretStore,
    project_id: i64,
) -> Result<Vec<AssessmentAuthProfile>, String> {
    ensure_project(conn, project_id)?;
    let mut statement = conn
        .prepare(
            "SELECT id, project_id, label, source_traffic_id, header_name,
                    secret_revision, created_at, updated_at
             FROM assessment_auth_profiles
             WHERE project_id = ?1
             ORDER BY id",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([project_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
            ))
        })
        .map_err(|error| error.to_string())?;
    let mut profiles = Vec::new();
    for row in rows {
        let (
            id,
            project_id,
            label,
            source_traffic_id,
            header_name,
            revision,
            created_at,
            updated_at,
        ) = row.map_err(|error| error.to_string())?;
        let secret_id =
            assessment_auth_profile_secret_id(project_id, id).map_err(|error| error.to_string())?;
        profiles.push(AssessmentAuthProfile {
            id,
            project_id,
            label,
            source_traffic_id,
            header_name,
            secret_revision: revision,
            has_secret: store
                .get(&secret_id)
                .map_err(|error| error.to_string())?
                .is_some(),
            created_at,
            updated_at,
        });
    }
    Ok(profiles)
}

pub fn create_auth_profile(
    conn: &mut Connection,
    store: &dyn SecretStore,
    input: &CreateAssessmentAuthProfileInput,
) -> Result<AssessmentAuthProfile, String> {
    let label = validate_label(&input.label)?;
    let header_name = normalize_auth_header(&input.header_name)?;
    validate_auth_secret(&input.secret)?;
    ensure_project(conn, input.project_id)?;

    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    tx.execute(
        "INSERT INTO assessment_auth_profiles(
             project_id, label, source_traffic_id, header_name
         ) VALUES(?1, ?2, ?3, ?4)",
        params![
            input.project_id,
            label,
            input.source_traffic_id,
            header_name
        ],
    )
    .map_err(|error| format!("创建评估身份失败: {error}"))?;
    let profile_id = tx.last_insert_rowid();
    let secret_id = assessment_auth_profile_secret_id(input.project_id, profile_id)
        .map_err(|error| error.to_string())?;
    store
        .set(&secret_id, &input.secret)
        .map_err(|error| format!("保存评估身份到系统凭据库失败: {error}"))?;
    if let Err(error) = tx.commit() {
        let cleanup = store.delete(&secret_id);
        return Err(match cleanup {
            Ok(()) => format!("提交评估身份元数据失败: {error}"),
            Err(cleanup_error) => {
                format!("提交评估身份元数据失败且凭据补偿清理失败: {error}; {cleanup_error}")
            }
        });
    }
    get_auth_profile(conn, store, input.project_id, profile_id)
}

pub fn set_auth_profile_secret(
    conn: &mut Connection,
    store: &dyn SecretStore,
    input: &SetAssessmentAuthProfileInput,
) -> Result<AssessmentAuthProfile, String> {
    let header_name = normalize_auth_header(&input.header_name)?;
    validate_auth_secret(&input.secret)?;
    ensure_profile_not_in_active_run(conn, input.project_id, input.profile_id)?;
    let secret_id = assessment_auth_profile_secret_id(input.project_id, input.profile_id)
        .map_err(|error| error.to_string())?;
    let previous = store.get(&secret_id).map_err(|error| error.to_string())?;
    store
        .set(&secret_id, &input.secret)
        .map_err(|error| format!("更新系统凭据库失败: {error}"))?;

    let result = conn.execute(
        "UPDATE assessment_auth_profiles
         SET header_name = ?3,
             secret_revision = secret_revision + 1,
             updated_at = strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
         WHERE id = ?2 AND project_id = ?1",
        params![input.project_id, input.profile_id, header_name],
    );
    match result {
        Ok(1) => get_auth_profile(conn, store, input.project_id, input.profile_id),
        Ok(_) => {
            compensate_secret(store, &secret_id, previous.as_ref())?;
            Err("评估身份不存在".into())
        }
        Err(error) => {
            compensate_secret(store, &secret_id, previous.as_ref())?;
            Err(format!("更新评估身份元数据失败: {error}"))
        }
    }
}

pub fn import_auth_profile_from_traffic(
    conn: &mut Connection,
    store: &dyn SecretStore,
    input: &ImportAssessmentAuthProfileInput,
) -> Result<AssessmentAuthProfile, String> {
    let header_name = normalize_auth_header(&input.header_name)?;
    let headers_json: Option<String> = conn
        .query_row(
            "SELECT req_headers FROM traffic WHERE id = ?1 AND project_id = ?2",
            params![input.traffic_id, input.project_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let headers_json = headers_json.ok_or_else(|| "来源 Traffic 不存在或不属于项目".to_string())?;
    let secret = extract_header_value(&headers_json, &header_name)?;
    create_auth_profile(
        conn,
        store,
        &CreateAssessmentAuthProfileInput {
            project_id: input.project_id,
            label: input.label.clone(),
            header_name,
            secret,
            source_traffic_id: Some(input.traffic_id),
        },
    )
}

/// 扫描最近 Traffic，返回包含指定鉴权 Header（非空值）的候选请求。
/// 只返回请求元数据与"存在性"；Header 值绝不离开服务端，仅在用户选中后
/// 由 import_auth_profile_from_traffic 提取并写入系统凭据库。
pub fn list_auth_candidates(
    conn: &Connection,
    project_id: i64,
    header_name: &str,
) -> Result<Vec<AssessmentAuthCandidate>, String> {
    let header_name = normalize_auth_header(header_name)?;
    ensure_project(conn, project_id)?;
    let mut statement = conn
        .prepare(
            "SELECT id, method, url, status, req_headers, created_at
             FROM traffic
             WHERE project_id = ?1
             ORDER BY id DESC LIMIT 300",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([project_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<u16>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })
        .map_err(|error| error.to_string())?;
    let mut candidates = Vec::new();
    for row in rows {
        let (traffic_id, method, url, status, headers_json, created_at) =
            row.map_err(|error| error.to_string())?;
        if !header_has_value(&headers_json, &header_name) {
            continue;
        }
        candidates.push(AssessmentAuthCandidate {
            traffic_id,
            method,
            url,
            status,
            created_at,
        });
    }
    Ok(candidates)
}

pub fn delete_auth_profile(
    conn: &mut Connection,
    store: &dyn SecretStore,
    project_id: i64,
    profile_id: i64,
) -> Result<(), String> {
    ensure_profile_not_in_active_run(conn, project_id, profile_id)?;
    let exists: bool = conn
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM assessment_auth_profiles WHERE id = ?1 AND project_id = ?2
             )",
            params![profile_id, project_id],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if !exists {
        return Err("评估身份不存在".into());
    }
    let secret_id = assessment_auth_profile_secret_id(project_id, profile_id)
        .map_err(|error| error.to_string())?;
    let previous = store.get(&secret_id).map_err(|error| error.to_string())?;
    store
        .delete(&secret_id)
        .map_err(|error| format!("删除系统凭据失败: {error}"))?;
    match conn.execute(
        "DELETE FROM assessment_auth_profiles WHERE id = ?1 AND project_id = ?2",
        params![profile_id, project_id],
    ) {
        Ok(1) => Ok(()),
        Ok(_) => {
            compensate_secret(store, &secret_id, previous.as_ref())?;
            Err("评估身份不存在".into())
        }
        Err(error) => {
            compensate_secret(store, &secret_id, previous.as_ref())?;
            Err(format!("删除评估身份元数据失败: {error}"))
        }
    }
}

/// Delete project metadata only after every keyring item was removed. On any
/// failure all previously deleted secrets are restored before returning.
pub fn delete_project_with_auth_cleanup(
    conn: &mut Connection,
    store: &dyn SecretStore,
    project_id: i64,
) -> Result<(), String> {
    if project_has_active_run(conn, project_id)? {
        return Err("[ASSESSMENT_ACTIVE] 项目存在活动评估，请先停止评估".into());
    }
    let mut statement = conn
        .prepare("SELECT id FROM assessment_auth_profiles WHERE project_id = ?1 ORDER BY id")
        .map_err(|error| error.to_string())?;
    let ids = statement
        .query_map([project_id], |row| row.get::<_, i64>(0))
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    drop(statement);

    let mut removed = Vec::new();
    for profile_id in ids {
        let secret_id = assessment_auth_profile_secret_id(project_id, profile_id)
            .map_err(|error| error.to_string())?;
        let secret = store.get(&secret_id).map_err(|error| error.to_string())?;
        if let Err(error) = store.delete(&secret_id) {
            restore_removed_secrets(store, &removed)?;
            return Err(format!("删除项目系统凭据失败: {error}"));
        }
        removed.push((secret_id, secret));
    }

    match conn.execute("DELETE FROM projects WHERE id = ?1", [project_id]) {
        Ok(1) => Ok(()),
        Ok(_) => {
            restore_removed_secrets(store, &removed)?;
            Err("项目不存在".into())
        }
        Err(error) => {
            restore_removed_secrets(store, &removed)?;
            Err(format!("删除项目失败: {error}"))
        }
    }
}

pub fn preview_contract(
    conn: &Connection,
    store: &dyn SecretStore,
    input: &AssessmentContractInput,
) -> Result<AssessmentContractPreview, String> {
    if input.project_id <= 0 {
        return Err("项目 ID 无效".into());
    }
    let scope = load_project_policy(conn, input.project_id).map_err(|error| error.to_string())?;
    let normalized_scope = scope.normalized_entries();
    let (normalized_start_url, exact_origin) =
        normalize_start_url(&scope, &input.start_url).map_err(|error| error.to_string())?;
    let excluded_paths =
        normalize_excluded_paths(&input.excluded_paths).map_err(|error| error.to_string())?;
    if input.request_budget == 0 || input.request_budget > 300 {
        return Err("请求预算必须在 1..=300 之间".into());
    }
    validate_rate(input.requests_per_second).map_err(|error| error.to_string())?;
    if !(1..=3).contains(&input.max_rounds) {
        return Err("AI 规划轮次必须在 1..=3 之间".into());
    }
    if !matches!(input.tls_policy.as_str(), "strict" | "ignore_invalid") {
        return Err("TLS 策略只能是 strict 或 ignore_invalid".into());
    }
    let provider_id = validate_bounded_text(&input.provider_id, "AI provider", 120)?;
    let model = validate_bounded_text(&input.model, "AI model", 240)?;

    if input.identity_a_profile_id.is_some()
        && input.identity_a_profile_id == input.identity_b_profile_id
    {
        return Err("身份 A/B 必须选择不同 profile".into());
    }
    let identity_a =
        load_contract_profile(conn, store, input.project_id, input.identity_a_profile_id)?;
    let identity_b =
        load_contract_profile(conn, store, input.project_id, input.identity_b_profile_id)?;
    if let (Some(a), Some(b)) = (&identity_a, &identity_b) {
        if constant_time_eq(a.secret.expose().as_bytes(), b.secret.expose().as_bytes()) {
            return Err("身份 A/B 的秘密值完全相同，无法进行双身份验证".into());
        }
    }

    let resource_ownership = normalize_ownership_claims(
        conn,
        input.project_id,
        &input.resource_ownership,
        input.identity_a_profile_id,
    )?;
    let discovery_budget = 40.min(input.request_budget / 3);
    let registry_hash = catalog::registry_hash();
    // 契约中的速率以毫秒精度表达。下限已在 validate_rate 校验，round 后
    // 至少 1ms，避免极端输入把契约速率折叠成 0 导致 1/0 间隔计算。
    let rate_millis = ((input.requests_per_second * 1000.0).round() as u32).max(1);
    let canonical = CanonicalContract {
        contract_version: "assessment-contract-v1",
        project_id: input.project_id,
        normalized_scope: &normalized_scope,
        start_url: &normalized_start_url,
        exact_origin: &exact_origin,
        excluded_paths: &excluded_paths,
        builtin_excluded_segments: BUILTIN_EXCLUDED_SEGMENTS,
        tls_policy: &input.tls_policy,
        request_budget: input.request_budget,
        discovery_budget,
        requests_per_second_millis: rate_millis,
        max_response_bytes: super::policy::MAX_RESPONSE_BYTES,
        max_run_response_bytes: MAX_RUN_RESPONSE_BYTES,
        concurrency: 1,
        allowed_methods: &["GET", "HEAD", "OPTIONS"],
        identity_a_profile_id: input.identity_a_profile_id,
        identity_a_secret_revision: identity_a.as_ref().map(|profile| profile.revision),
        identity_b_profile_id: input.identity_b_profile_id,
        identity_b_secret_revision: identity_b.as_ref().map(|profile| profile.revision),
        resource_ownership: &resource_ownership,
        include_recent_traffic: input.include_recent_traffic,
        provider_id: &provider_id,
        model: &model,
        ai_input_policy:
            "endpoint_ids_and_metadata_only:no_urls:no_values:no_bodies:no_credentials",
        max_rounds: input.max_rounds,
        max_checks_per_round: 12,
        template_registry_version: catalog::TEMPLATE_REGISTRY_VERSION,
        template_registry_hash: &registry_hash,
        written_authorization_confirmed: input.written_authorization_confirmed,
    };
    let canonical_json = serde_json::to_vec(&canonical).map_err(|error| error.to_string())?;
    let contract_hash = sha256(&canonical_json);

    Ok(AssessmentContractPreview {
        project_id: input.project_id,
        normalized_start_url,
        exact_origin,
        normalized_scope,
        excluded_paths,
        builtin_excluded_segments: BUILTIN_EXCLUDED_SEGMENTS
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        tls_policy: input.tls_policy.clone(),
        request_budget: input.request_budget,
        discovery_budget,
        requests_per_second: rate_millis as f64 / 1000.0,
        identity_a_profile_id: input.identity_a_profile_id,
        identity_a_label: identity_a.as_ref().map(|profile| profile.label.clone()),
        identity_a_secret_revision: identity_a.as_ref().map(|profile| profile.revision),
        identity_b_profile_id: input.identity_b_profile_id,
        identity_b_label: identity_b.as_ref().map(|profile| profile.label.clone()),
        identity_b_secret_revision: identity_b.as_ref().map(|profile| profile.revision),
        resource_ownership,
        include_recent_traffic: input.include_recent_traffic,
        provider_id,
        model,
        max_rounds: input.max_rounds,
        data_disclosure: vec![
            "不透明 endpoint ID".into(),
            "路径与 query 参数名（不含值）".into(),
            "状态码、Content-Type、鉴权存在性与被动标签".into(),
        ],
        template_registry_version: catalog::TEMPLATE_REGISTRY_VERSION.into(),
        template_registry_hash: registry_hash,
        contract_hash,
        written_authorization_confirmed: input.written_authorization_confirmed,
        residual_risk_notice: "RustForge 只发送只读方法且无正文，但客户端无法数学证明目标服务器不会错误地让 GET 产生副作用。".into(),
    })
}

pub fn create_run(
    conn: &mut Connection,
    preview: &AssessmentContractPreview,
) -> Result<AssessmentRun, String> {
    if !preview.written_authorization_confirmed {
        return Err("[AUTHORIZATION_REQUIRED] 必须确认已获得目标的书面授权".into());
    }
    let contract_json = serde_json::to_string(preview).map_err(|error| error.to_string())?;
    conn.execute(
        "INSERT INTO assessment_runs(
             project_id, start_url, exact_origin, contract_json, contract_hash,
             template_registry_hash, identity_a_profile_id, identity_b_profile_id,
             provider_id, model, tls_policy, request_budget, discovery_budget,
             requests_per_second, response_byte_budget, max_rounds
         ) VALUES(
             ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16
         )",
        params![
            preview.project_id,
            preview.normalized_start_url,
            preview.exact_origin,
            contract_json,
            preview.contract_hash,
            preview.template_registry_hash,
            preview.identity_a_profile_id,
            preview.identity_b_profile_id,
            preview.provider_id,
            preview.model,
            preview.tls_policy,
            preview.request_budget,
            preview.discovery_budget,
            preview.requests_per_second,
            MAX_RUN_RESPONSE_BYTES,
            preview.max_rounds,
        ],
    )
    .map_err(|error| {
        if error.to_string().contains("idx_assessment_runs_one_active")
            || error.to_string().contains("UNIQUE constraint failed")
        {
            "[ASSESSMENT_BUSY] 已有评估正在运行".to_string()
        } else {
            format!("创建评估运行失败: {error}")
        }
    })?;
    let run_id = conn.last_insert_rowid();
    append_event(
        conn,
        run_id,
        None,
        "run_created",
        None,
        Some("queued"),
        &json!({ "contractHash": preview.contract_hash }),
    )?;
    get_run(conn, preview.project_id, run_id)
}

pub fn transition_run(
    conn: &mut Connection,
    project_id: i64,
    run_id: i64,
    next: AssessmentStatus,
    stop_reason: Option<&str>,
) -> Result<AssessmentRun, String> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    let current: Option<String> = tx
        .query_row(
            "SELECT status FROM assessment_runs WHERE id = ?1 AND project_id = ?2",
            params![run_id, project_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let current = current.ok_or_else(|| "评估运行不存在".to_string())?;
    validate_transition(&current, next.as_str())?;
    append_event_on(
        &tx,
        run_id,
        None,
        "status_changed",
        Some(&current),
        Some(next.as_str()),
        &json!({ "reason": stop_reason.unwrap_or("") }),
    )?;
    let ended = next.is_terminal();
    tx.execute(
        "UPDATE assessment_runs
         SET status = ?3,
             stop_reason = CASE WHEN ?4 IS NULL THEN stop_reason ELSE ?4 END,
             started_at = CASE
                 WHEN started_at IS NULL AND ?3 <> 'queued'
                 THEN strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                 ELSE started_at
             END,
             ended_at = CASE
                 WHEN ?5 = 1 THEN strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                 ELSE ended_at
             END
         WHERE id = ?1 AND project_id = ?2",
        params![run_id, project_id, next.as_str(), stop_reason, ended],
    )
    .map_err(|error| format!("更新评估状态失败: {error}"))?;
    tx.commit().map_err(|error| error.to_string())?;
    get_run(conn, project_id, run_id)
}

/// Close every check that could otherwise remain visually "running" after a
/// cancelled, stopped, failed, or interrupted assessment. The event and state
/// mutation are committed together so refresh-based progress recovery is
/// unambiguous even when the background task exits unexpectedly.
pub fn finalize_open_checks(
    conn: &mut Connection,
    run_id: i64,
    terminal_status: &str,
    reason: &str,
) -> Result<usize, String> {
    if !matches!(terminal_status, "cancelled" | "failed" | "skipped") {
        return Err("Assessment check 终态无效".into());
    }
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    let count = finalize_open_checks_on(&tx, run_id, terminal_status, reason)?;
    tx.commit().map_err(|error| error.to_string())?;
    Ok(count)
}

fn finalize_open_checks_on(
    conn: &Connection,
    run_id: i64,
    terminal_status: &str,
    reason: &str,
) -> Result<usize, String> {
    let mut statement = conn
        .prepare(
            "SELECT id, status FROM assessment_checks
             WHERE run_id = ?1 AND status IN ('queued','executing','verifying')
             ORDER BY id",
        )
        .map_err(|error| error.to_string())?;
    let checks = statement
        .query_map([run_id], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    drop(statement);
    for (check_id, old_status) in &checks {
        append_event_on(
            conn,
            run_id,
            Some(*check_id),
            "check_status_changed",
            Some(old_status),
            Some(terminal_status),
            &json!({"reason": reason}),
        )?;
        conn.execute(
            "UPDATE assessment_checks
             SET status = ?2,
                 completed_at = strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
             WHERE id = ?1",
            params![check_id, terminal_status],
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(checks.len())
}

pub fn recover_interrupted_runs(conn: &mut Connection) -> Result<usize, String> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    let mut statement = tx
        .prepare(&format!(
            "SELECT id, status FROM assessment_runs WHERE status IN ({ACTIVE_STATUSES_SQL}) ORDER BY id"
        ))
        .map_err(|error| error.to_string())?;
    let active = statement
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    drop(statement);
    for (run_id, old_status) in &active {
        finalize_open_checks_on(&tx, *run_id, "failed", "application_restarted")?;
        append_event_on(
            &tx,
            *run_id,
            None,
            "status_changed",
            Some(old_status),
            Some("interrupted"),
            &json!({ "reason": "application_restarted" }),
        )?;
        tx.execute(
            "UPDATE assessment_runs
             SET status = 'interrupted', stop_reason = 'application_restarted',
                 ended_at = strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
             WHERE id = ?1",
            [run_id],
        )
        .map_err(|error| error.to_string())?;
    }
    tx.commit().map_err(|error| error.to_string())?;
    Ok(active.len())
}

pub fn project_has_active_run(conn: &Connection, project_id: i64) -> Result<bool, String> {
    conn.query_row(
        &format!(
            "SELECT EXISTS(
                 SELECT 1 FROM assessment_runs
                 WHERE project_id = ?1 AND status IN ({ACTIVE_STATUSES_SQL})
             )"
        ),
        [project_id],
        |row| row.get(0),
    )
    .map_err(|error| error.to_string())
}

pub fn list_runs(conn: &Connection, project_id: i64) -> Result<Vec<AssessmentRun>, String> {
    ensure_project(conn, project_id)?;
    let mut statement = conn
        .prepare(
            "SELECT id, project_id, status, start_url, exact_origin, contract_hash,
                    template_registry_hash, provider_id, model, tls_policy,
                    request_budget, request_count, discovery_budget, requests_per_second,
                    response_byte_budget, response_bytes_read, max_rounds, completed_rounds,
                    stop_reason, created_at, started_at, ended_at
             FROM assessment_runs
             WHERE project_id = ?1
             ORDER BY id DESC LIMIT 100",
        )
        .map_err(|error| error.to_string())?;
    let runs = statement
        .query_map([project_id], map_run)
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    Ok(runs)
}

pub fn get_run(conn: &Connection, project_id: i64, run_id: i64) -> Result<AssessmentRun, String> {
    conn.query_row(
        "SELECT id, project_id, status, start_url, exact_origin, contract_hash,
                template_registry_hash, provider_id, model, tls_policy,
                request_budget, request_count, discovery_budget, requests_per_second,
                response_byte_budget, response_bytes_read, max_rounds, completed_rounds,
                stop_reason, created_at, started_at, ended_at
         FROM assessment_runs WHERE id = ?1 AND project_id = ?2",
        params![run_id, project_id],
        map_run,
    )
    .optional()
    .map_err(|error| error.to_string())?
    .ok_or_else(|| "评估运行不存在".to_string())
}

pub fn get_detail(
    conn: &Connection,
    project_id: i64,
    run_id: i64,
) -> Result<AssessmentDetail, String> {
    let run = get_run(conn, project_id, run_id)?;
    Ok(AssessmentDetail {
        run,
        rounds: query_rounds(conn, run_id)?,
        endpoints: query_endpoints(conn, run_id)?,
        checks: query_checks(conn, run_id)?,
        verifications: query_verifications(conn, run_id)?,
        coverage_gaps: query_gaps(conn, run_id)?,
        events: query_events(conn, run_id)?,
    })
}

pub fn append_event(
    conn: &Connection,
    run_id: i64,
    check_id: Option<i64>,
    event_type: &str,
    old_value: Option<&str>,
    new_value: Option<&str>,
    details: &Value,
) -> Result<i64, String> {
    append_event_on(
        conn, run_id, check_id, event_type, old_value, new_value, details,
    )
}

fn append_event_on(
    conn: &Connection,
    run_id: i64,
    check_id: Option<i64>,
    event_type: &str,
    old_value: Option<&str>,
    new_value: Option<&str>,
    details: &Value,
) -> Result<i64, String> {
    let details_json = serde_json::to_string(details).map_err(|error| error.to_string())?;
    conn.execute(
        "INSERT INTO assessment_events(
             run_id, check_id, event_type, old_value, new_value, details_json
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            run_id,
            check_id,
            event_type,
            old_value,
            new_value,
            details_json
        ],
    )
    .map_err(|error| format!("写入评估审计事件失败: {error}"))?;
    Ok(conn.last_insert_rowid())
}

fn get_auth_profile(
    conn: &Connection,
    store: &dyn SecretStore,
    project_id: i64,
    profile_id: i64,
) -> Result<AssessmentAuthProfile, String> {
    list_auth_profiles(conn, store, project_id)?
        .into_iter()
        .find(|profile| profile.id == profile_id)
        .ok_or_else(|| "评估身份不存在".to_string())
}

fn load_contract_profile(
    conn: &Connection,
    store: &dyn SecretStore,
    project_id: i64,
    profile_id: Option<i64>,
) -> Result<Option<ContractProfile>, String> {
    let Some(profile_id) = profile_id else {
        return Ok(None);
    };
    let metadata: Option<(String, i64)> = conn
        .query_row(
            "SELECT label, secret_revision
             FROM assessment_auth_profiles WHERE id = ?1 AND project_id = ?2",
            params![profile_id, project_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let (label, revision) = metadata.ok_or_else(|| "评估身份不存在或不属于项目".to_string())?;
    let secret_id = assessment_auth_profile_secret_id(project_id, profile_id)
        .map_err(|error| error.to_string())?;
    let secret = store
        .get(&secret_id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("评估身份 `{label}` 缺少系统凭据"))?;
    Ok(Some(ContractProfile {
        label,
        revision,
        secret,
    }))
}

fn normalize_ownership_claims(
    conn: &Connection,
    project_id: i64,
    claims: &[ResourceOwnershipClaim],
    identity_a_profile_id: Option<i64>,
) -> Result<Vec<ResourceOwnershipClaim>, String> {
    if claims.len() > 100 {
        return Err("资源归属声明最多 100 条".into());
    }
    let mut normalized = Vec::new();
    let mut seen = HashSet::new();
    for claim in claims {
        let path = normalize_excluded_paths(std::slice::from_ref(&claim.path))
            .map_err(|error| error.to_string())?
            .into_iter()
            .next()
            .expect("single valid path remains present");
        if Some(claim.owner_profile_id) != identity_a_profile_id {
            return Err("首版资源归属声明只能指向本轮身份 A".into());
        }
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM assessment_auth_profiles WHERE id = ?1 AND project_id = ?2
                 )",
                params![claim.owner_profile_id, project_id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if !exists {
            return Err("资源归属身份不存在或不属于项目".into());
        }
        if seen.insert((path.clone(), claim.owner_profile_id)) {
            normalized.push(ResourceOwnershipClaim {
                path,
                owner_profile_id: claim.owner_profile_id,
            });
        }
    }
    normalized.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.owner_profile_id.cmp(&right.owner_profile_id))
    });
    Ok(normalized)
}

fn validate_label(raw: &str) -> Result<String, String> {
    validate_bounded_text(raw, "身份标签", 80)
}

fn validate_bounded_text(raw: &str, field: &str, max: usize) -> Result<String, String> {
    let value = raw.trim();
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(format!("{field} 必须是 1..={max} 字符且不含控制字符"));
    }
    Ok(value.to_string())
}

fn normalize_auth_header(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    ALLOWED_AUTH_HEADERS
        .iter()
        .find(|allowed| allowed.eq_ignore_ascii_case(raw))
        .map(|allowed| (*allowed).to_string())
        .ok_or_else(|| {
            "身份 Header 仅允许 Authorization、Cookie、X-API-Key、X-Auth-Token".to_string()
        })
}

fn validate_auth_secret(secret: &str) -> Result<(), String> {
    if secret.is_empty() || secret.len() > MAX_AUTH_SECRET_BYTES {
        return Err(format!(
            "身份 Header 值必须为 1..={MAX_AUTH_SECRET_BYTES} 字节"
        ));
    }
    if secret.contains(['\r', '\n']) {
        return Err("身份 Header 值不允许包含换行符".into());
    }
    Ok(())
}

fn extract_header_value(headers_json: &str, expected_name: &str) -> Result<String, String> {
    let value: Value = serde_json::from_str(headers_json)
        .map_err(|_| "Traffic 请求 Header 快照格式无效".to_string())?;
    let found = match value {
        Value::Array(headers) => headers.into_iter().find_map(|header| {
            let name = header.get("name")?.as_str()?;
            if !name.eq_ignore_ascii_case(expected_name) {
                return None;
            }
            header.get("value")?.as_str().map(str::to_string)
        }),
        Value::Object(headers) => headers.into_iter().find_map(|(name, value)| {
            if !name.eq_ignore_ascii_case(expected_name) {
                return None;
            }
            match value {
                Value::String(value) => Some(value),
                Value::Array(values) => values.first().and_then(Value::as_str).map(str::to_string),
                _ => None,
            }
        }),
        _ => None,
    }
    .ok_or_else(|| format!("Traffic 中不存在 `{expected_name}` Header"))?;
    validate_auth_secret(&found)?;
    Ok(found)
}

/// 只判断 Header 快照中是否存在可导入的目标 Header 值（非空、不超过
/// MAX_AUTH_SECRET_BYTES、不含换行符），不返回值本身。
/// 与 extract_header_value 兼容数组/对象两种存储形态，且判定与
/// validate_auth_secret 保持一致，保证"列表里能选中的一定能导入"。
fn header_has_value(headers_json: &str, expected_name: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(headers_json) else {
        return false;
    };
    let importable = |value: &str| {
        !value.is_empty()
            && value.len() <= MAX_AUTH_SECRET_BYTES
            && !value.contains(['\r', '\n'])
    };
    match value {
        Value::Array(headers) => headers.iter().any(|header| {
            header
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| name.eq_ignore_ascii_case(expected_name))
                && header
                    .get("value")
                    .and_then(Value::as_str)
                    .is_some_and(importable)
        }),
        Value::Object(headers) => headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case(expected_name)
                && match value {
                    Value::String(value) => importable(value),
                    Value::Array(values) => values
                        .iter()
                        .any(|value| value.as_str().is_some_and(importable)),
                    _ => false,
                }
        }),
        _ => false,
    }
}

fn ensure_project(conn: &Connection, project_id: i64) -> Result<(), String> {
    let exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM projects WHERE id = ?1)",
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

fn ensure_profile_not_in_active_run(
    conn: &Connection,
    project_id: i64,
    profile_id: i64,
) -> Result<(), String> {
    let active: bool = conn
        .query_row(
            &format!(
                "SELECT EXISTS(
                     SELECT 1 FROM assessment_runs
                     WHERE project_id = ?1
                       AND status IN ({ACTIVE_STATUSES_SQL})
                       AND (identity_a_profile_id = ?2 OR identity_b_profile_id = ?2)
                 )"
            ),
            params![project_id, profile_id],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if active {
        Err("活动评估正在使用该身份，不能修改或删除".into())
    } else {
        Ok(())
    }
}

fn compensate_secret(
    store: &dyn SecretStore,
    secret_id: &str,
    previous: Option<&SecretString>,
) -> Result<(), String> {
    match previous {
        Some(previous) => store.set(secret_id, previous.expose()),
        None => store.delete(secret_id),
    }
    .map_err(|error| format!("系统凭据补偿失败: {error}"))
}

fn restore_removed_secrets(
    store: &dyn SecretStore,
    removed: &[(String, Option<SecretString>)],
) -> Result<(), String> {
    for (secret_id, secret) in removed {
        if let Some(secret) = secret {
            store
                .set(secret_id, secret.expose())
                .map_err(|error| format!("系统凭据补偿失败: {error}"))?;
        }
    }
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

fn validate_transition(current: &str, next: &str) -> Result<(), String> {
    let allowed = match current {
        "queued" => matches!(next, "discovering" | "cancelled" | "failed" | "interrupted"),
        "discovering" => matches!(
            next,
            "planning" | "stopped" | "cancelled" | "failed" | "interrupted"
        ),
        "planning" => matches!(
            next,
            "executing" | "completed" | "stopped" | "cancelled" | "failed" | "interrupted"
        ),
        "executing" => matches!(
            next,
            "verifying"
                | "planning"
                | "completed"
                | "stopped"
                | "cancelled"
                | "failed"
                | "interrupted"
        ),
        "verifying" => matches!(
            next,
            "planning" | "completed" | "stopped" | "cancelled" | "failed" | "interrupted"
        ),
        _ => false,
    };
    if allowed {
        Ok(())
    } else {
        Err(format!("不允许评估状态从 {current} 变为 {next}"))
    }
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn map_run(row: &Row<'_>) -> rusqlite::Result<AssessmentRun> {
    let status: String = row.get(2)?;
    Ok(AssessmentRun {
        id: row.get(0)?,
        project_id: row.get(1)?,
        status: AssessmentStatus::parse(&status).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                2,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
            )
        })?,
        start_url: row.get(3)?,
        exact_origin: row.get(4)?,
        contract_hash: row.get(5)?,
        template_registry_hash: row.get(6)?,
        provider_id: row.get(7)?,
        model: row.get(8)?,
        tls_policy: row.get(9)?,
        request_budget: row.get(10)?,
        request_count: row.get(11)?,
        discovery_budget: row.get(12)?,
        requests_per_second: row.get(13)?,
        response_byte_budget: row.get(14)?,
        response_bytes_read: row.get(15)?,
        max_rounds: row.get(16)?,
        completed_rounds: row.get(17)?,
        stop_reason: row.get(18)?,
        created_at: row.get(19)?,
        started_at: row.get(20)?,
        ended_at: row.get(21)?,
    })
}

fn query_rounds(conn: &Connection, run_id: i64) -> Result<Vec<AssessmentRound>, String> {
    let mut statement = conn
        .prepare(
            "SELECT id, run_id, round_number, status, analysis_run_id, input_hash,
                output_hash, selected_checks, rejection_json, created_at, completed_at
         FROM assessment_rounds WHERE run_id = ?1 ORDER BY round_number",
        )
        .map_err(|error| error.to_string())?;
    let rounds = statement
        .query_map([run_id], |row| {
            let rejection: String = row.get(8)?;
            Ok(AssessmentRound {
                id: row.get(0)?,
                run_id: row.get(1)?,
                round_number: row.get(2)?,
                status: row.get(3)?,
                analysis_run_id: row.get(4)?,
                input_hash: row.get(5)?,
                output_hash: row.get(6)?,
                selected_checks: row.get(7)?,
                rejection_json: serde_json::from_str(&rejection).unwrap_or(Value::Null),
                created_at: row.get(9)?,
                completed_at: row.get(10)?,
            })
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    Ok(rounds)
}

fn query_endpoints(conn: &Connection, run_id: i64) -> Result<Vec<AssessmentEndpoint>, String> {
    let mut statement = conn
        .prepare(
            "SELECT id, run_id, endpoint_key, method, url, path, query_parameter_names,
                source_kind, status, content_type, has_authentication, passive_tags,
                response_complete, resource_owner_profile_id
         FROM assessment_endpoints WHERE run_id = ?1 ORDER BY id",
        )
        .map_err(|error| error.to_string())?;
    let endpoints = statement
        .query_map([run_id], |row| {
            let query_names: String = row.get(6)?;
            let tags: String = row.get(11)?;
            let endpoint_key: String = row.get(2)?;
            Ok(AssessmentEndpoint {
                id: row.get(0)?,
                run_id: row.get(1)?,
                endpoint_id: format!("ep_{}", endpoint_key.chars().take(24).collect::<String>()),
                method: row.get(3)?,
                url: row.get(4)?,
                path: row.get(5)?,
                query_parameter_names: serde_json::from_str(&query_names).unwrap_or_default(),
                source_kind: row.get(7)?,
                status: row.get(8)?,
                content_type: row.get(9)?,
                has_authentication: row.get(10)?,
                passive_tags: serde_json::from_str(&tags).unwrap_or_default(),
                response_complete: row.get(12)?,
                resource_owner_profile_id: row.get(13)?,
            })
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    Ok(endpoints)
}

fn query_checks(conn: &Connection, run_id: i64) -> Result<Vec<AssessmentCheck>, String> {
    let mut statement = conn
        .prepare(
            "SELECT id, run_id, round_id, endpoint_id, requested_endpoint_id,
                template_id, template_version,
                parameter_name, identity_mode, rationale, policy_result, policy_reason,
                status, request_cost, created_at, completed_at
         FROM assessment_checks WHERE run_id = ?1 ORDER BY id",
        )
        .map_err(|error| error.to_string())?;
    let checks = statement
        .query_map([run_id], |row| {
            Ok(AssessmentCheck {
                id: row.get(0)?,
                run_id: row.get(1)?,
                round_id: row.get(2)?,
                endpoint_id: row.get(3)?,
                requested_endpoint_id: row.get(4)?,
                template_id: row.get(5)?,
                template_version: row.get(6)?,
                parameter_name: row.get(7)?,
                identity_mode: row.get(8)?,
                rationale: row.get(9)?,
                policy_result: row.get(10)?,
                policy_reason: row.get(11)?,
                status: row.get(12)?,
                request_cost: row.get(13)?,
                created_at: row.get(14)?,
                completed_at: row.get(15)?,
            })
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    Ok(checks)
}

fn query_verifications(
    conn: &Connection,
    run_id: i64,
) -> Result<Vec<AssessmentVerification>, String> {
    let mut statement = conn
        .prepare(
            "SELECT v.id, v.check_id, v.verifier_id, v.verifier_version, v.verdict,
                v.observations_json, v.content_hash, afl.finding_id, afl.relation, v.created_at
         FROM assessment_verifications v
         JOIN assessment_checks c ON c.id = v.check_id
         LEFT JOIN assessment_finding_links afl ON afl.verification_id = v.id
         WHERE c.run_id = ?1 ORDER BY v.id",
        )
        .map_err(|error| error.to_string())?;
    let verifications = statement
        .query_map([run_id], |row| {
            let verdict: String = row.get(4)?;
            let verdict = match verdict.as_str() {
                "confirmed" => AssessmentVerdict::Confirmed,
                "suspected" => AssessmentVerdict::Suspected,
                "not_observed" => AssessmentVerdict::NotObserved,
                "inconclusive" => AssessmentVerdict::Inconclusive,
                _ => AssessmentVerdict::Skipped,
            };
            let observations: String = row.get(5)?;
            Ok(AssessmentVerification {
                id: row.get(0)?,
                check_id: row.get(1)?,
                verifier_id: row.get(2)?,
                verifier_version: row.get(3)?,
                verdict,
                observations: serde_json::from_str(&observations).unwrap_or(Value::Null),
                content_hash: row.get(6)?,
                finding_id: row.get(7)?,
                finding_relation: row.get(8)?,
                created_at: row.get(9)?,
            })
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    Ok(verifications)
}

fn query_gaps(conn: &Connection, run_id: i64) -> Result<Vec<AssessmentCoverageGap>, String> {
    let mut statement = conn
        .prepare(
            "SELECT id, run_id, check_id, category, reason_code, detail, created_at
         FROM assessment_coverage_gaps WHERE run_id = ?1 ORDER BY id",
        )
        .map_err(|error| error.to_string())?;
    let gaps = statement
        .query_map([run_id], |row| {
            Ok(AssessmentCoverageGap {
                id: row.get(0)?,
                run_id: row.get(1)?,
                check_id: row.get(2)?,
                category: row.get(3)?,
                reason_code: row.get(4)?,
                detail: row.get(5)?,
                created_at: row.get(6)?,
            })
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    Ok(gaps)
}

fn query_events(conn: &Connection, run_id: i64) -> Result<Vec<AssessmentEvent>, String> {
    let mut statement = conn.prepare(
        "SELECT id, run_id, check_id, event_type, old_value, new_value, details_json, created_at
         FROM assessment_events WHERE run_id = ?1 ORDER BY id",
    ).map_err(|error| error.to_string())?;
    let events = statement
        .query_map([run_id], |row| {
            let details: String = row.get(6)?;
            Ok(AssessmentEvent {
                id: row.get(0)?,
                run_id: row.get(1)?,
                check_id: row.get(2)?,
                event_type: row.get(3)?,
                old_value: row.get(4)?,
                new_value: row.get(5)?,
                details: serde_json::from_str(&details).unwrap_or(Value::Null),
                created_at: row.get(7)?,
            })
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::{MemorySecretStore, SecretStoreError};
    use crate::storage::migrations;

    fn database() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        migrations::migrate(&mut conn).unwrap();
        conn.execute(
            "INSERT INTO projects(id, name, scope) VALUES(1, 'p', '[\"example.test\"]')",
            [],
        )
        .unwrap();
        conn
    }

    fn profile_input(label: &str, secret: &str) -> CreateAssessmentAuthProfileInput {
        CreateAssessmentAuthProfileInput {
            project_id: 1,
            label: label.into(),
            header_name: "Authorization".into(),
            secret: secret.into(),
            source_traffic_id: None,
        }
    }

    fn contract(a: Option<i64>, b: Option<i64>) -> AssessmentContractInput {
        AssessmentContractInput {
            project_id: 1,
            start_url: "https://example.test/start".into(),
            excluded_paths: vec!["/admin/archive/".into()],
            tls_policy: "strict".into(),
            request_budget: 120,
            requests_per_second: 1.0,
            identity_a_profile_id: a,
            identity_b_profile_id: b,
            resource_ownership: Vec::new(),
            include_recent_traffic: false,
            provider_id: "openai".into(),
            model: "model".into(),
            max_rounds: 3,
            written_authorization_confirmed: true,
        }
    }

    struct FailingSetStore;

    impl SecretStore for FailingSetStore {
        fn get(&self, _secret_id: &str) -> Result<Option<SecretString>, SecretStoreError> {
            Ok(None)
        }

        fn set(&self, _secret_id: &str, _secret: &str) -> Result<(), SecretStoreError> {
            Err(SecretStoreError::OperationFailed)
        }

        fn delete(&self, _secret_id: &str) -> Result<(), SecretStoreError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct FailingDeleteStore {
        inner: MemorySecretStore,
    }

    impl SecretStore for FailingDeleteStore {
        fn get(&self, secret_id: &str) -> Result<Option<SecretString>, SecretStoreError> {
            self.inner.get(secret_id)
        }

        fn set(&self, secret_id: &str, secret: &str) -> Result<(), SecretStoreError> {
            self.inner.set(secret_id, secret)
        }

        fn delete(&self, _secret_id: &str) -> Result<(), SecretStoreError> {
            Err(SecretStoreError::OperationFailed)
        }
    }

    #[test]
    fn profile_secret_never_enters_sqlite_or_profile_view() {
        let mut conn = database();
        let store = MemorySecretStore::default();
        let secret = "Bearer super-secret-value";
        let profile = create_auth_profile(&mut conn, &store, &profile_input("A", secret)).unwrap();
        assert!(profile.has_secret);
        let dump: String = conn
            .query_row(
                "SELECT group_concat(sql, ' ') FROM sqlite_master",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!dump.contains(secret));
        let rows = list_auth_profiles(&conn, &store, 1).unwrap();
        assert!(!serde_json::to_string(&rows).unwrap().contains(secret));
    }

    #[test]
    fn credential_store_failures_roll_back_or_preserve_profile_metadata() {
        let mut conn = database();
        let error = create_auth_profile(
            &mut conn,
            &FailingSetStore,
            &profile_input("will rollback", "Bearer never-persisted"),
        )
        .unwrap_err();
        assert!(error.contains("系统凭据库"));
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM assessment_auth_profiles", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "failed keyring write must roll back metadata");

        let store = FailingDeleteStore::default();
        let profile = create_auth_profile(
            &mut conn,
            &store,
            &profile_input("kept", "Bearer remains-in-keyring"),
        )
        .unwrap();
        let error = delete_auth_profile(&mut conn, &store, 1, profile.id).unwrap_err();
        assert!(error.contains("删除系统凭据失败"));
        assert!(get_auth_profile(&conn, &store, 1, profile.id).is_ok());
        let secret_id = assessment_auth_profile_secret_id(1, profile.id).unwrap();
        assert_eq!(
            store.get(&secret_id).unwrap().unwrap().expose(),
            "Bearer remains-in-keyring"
        );
    }

    #[test]
    fn contract_is_stable_and_rejects_identical_identity_secrets() {
        let mut conn = database();
        let store = MemorySecretStore::default();
        let a = create_auth_profile(&mut conn, &store, &profile_input("A", "Bearer aaa")).unwrap();
        let b = create_auth_profile(&mut conn, &store, &profile_input("B", "Bearer bbb")).unwrap();
        let first = preview_contract(&conn, &store, &contract(Some(a.id), Some(b.id))).unwrap();
        let second = preview_contract(&conn, &store, &contract(Some(a.id), Some(b.id))).unwrap();
        assert_eq!(first.contract_hash, second.contract_hash);

        set_auth_profile_secret(
            &mut conn,
            &store,
            &SetAssessmentAuthProfileInput {
                project_id: 1,
                profile_id: b.id,
                header_name: "Authorization".into(),
                secret: "Bearer aaa".into(),
            },
        )
        .unwrap();
        assert!(preview_contract(&conn, &store, &contract(Some(a.id), Some(b.id))).is_err());
    }

    #[test]
    fn startup_marks_active_runs_interrupted_with_audit_event() {
        let mut conn = database();
        let store = MemorySecretStore::default();
        let preview = preview_contract(&conn, &store, &contract(None, None)).unwrap();
        let run = create_run(&mut conn, &preview).unwrap();
        conn.execute(
            "INSERT INTO assessment_checks(
                 run_id, requested_endpoint_id, template_id, template_version,
                 identity_mode, policy_result, policy_reason, status
             ) VALUES(?1,'ep_pending','open_redirect','1','anonymous',
                      'allowed','allowed','executing')",
            [run.id],
        )
        .unwrap();
        let check_id = conn.last_insert_rowid();
        assert_eq!(recover_interrupted_runs(&mut conn).unwrap(), 1);
        let recovered = get_run(&conn, 1, run.id).unwrap();
        assert_eq!(recovered.status, AssessmentStatus::Interrupted);
        assert_eq!(recovered.stop_reason, "application_restarted");
        assert!(query_events(&conn, run.id)
            .unwrap()
            .iter()
            .any(|event| event.event_type == "status_changed"
                && event.new_value.as_deref() == Some("interrupted")));
        let check_status: String = conn
            .query_row(
                "SELECT status FROM assessment_checks WHERE id = ?1",
                [check_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(check_status, "failed");
        assert!(query_events(&conn, run.id).unwrap().iter().any(|event| {
            event.check_id == Some(check_id)
                && event.event_type == "check_status_changed"
                && event.new_value.as_deref() == Some("failed")
        }));
    }

    #[test]
    fn auth_candidates_list_only_non_empty_matching_headers_without_values() {
        let mut conn = database();
        conn.execute(
            "INSERT INTO projects(id, name, scope) VALUES(2, 'other', '[\"other.test\"]')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO traffic(project_id, method, host, url, req_headers, status) VALUES
             (1, 'GET', 'example.test', 'https://example.test/login', '{}', 200),
             (1, 'GET', 'example.test', 'https://example.test/api/orders',
              '[{\"name\":\"Authorization\",\"value\":\"Bearer abc\"}]', 200),
             (1, 'GET', 'example.test', 'https://example.test/api/profile',
              '{\"authorization\":\"Bearer def\",\"x-extra\":\"1\"}', 200),
             (1, 'GET', 'example.test', 'https://example.test/api/empty',
              '{\"Authorization\":\"\"}', 200),
             (1, 'GET', 'example.test', 'https://example.test/api/array-empty',
              '[{\"name\":\"Authorization\",\"value\":\"\"}]', 200),
             (1, 'GET', 'example.test', 'https://example.test/api/cookie',
              '{\"Cookie\":\"session=xyz\"}', 200),
             (2, 'GET', 'other.test', 'https://other.test/api/orders',
              '[{\"name\":\"Authorization\",\"value\":\"Bearer other\"}]', 200)",
            [],
        )
        .unwrap();
        // 超长与含换行的值不可导入，候选列表必须排除（与 validate_auth_secret 一致）。
        let oversized = "A".repeat(MAX_AUTH_SECRET_BYTES + 1);
        conn.execute(
            "INSERT INTO traffic(project_id, method, host, url, req_headers)
             VALUES(?1, 'GET', 'example.test', 'https://example.test/api/oversized', ?2)",
            params![1, format!(r#"{{"Authorization":"{oversized}"}}"#)],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO traffic(project_id, method, host, url, req_headers)
             VALUES(?1, 'GET', 'example.test', 'https://example.test/api/crlf', ?2)",
            params![1, r#"{"Authorization":"Bearer abc\r\nX-Evil: 1"}"#],
        )
        .unwrap();

        let candidates = list_auth_candidates(&conn, 1, "authorization").unwrap();
        assert_eq!(candidates.len(), 2, "只保留可导入的非空值两条");
        assert_eq!(candidates[0].traffic_id, 3, "按 id 倒序，最新的在前");
        assert!(candidates[0].url.contains("profile"));
        assert_eq!(candidates[1].traffic_id, 2);
        assert!(candidates[1].url.contains("orders"));
        assert!(candidates[0].created_at.len() >= 10);

        let cookie = list_auth_candidates(&conn, 1, "Cookie").unwrap();
        assert_eq!(cookie.len(), 1);
        assert_eq!(cookie[0].traffic_id, 6);

        let none = list_auth_candidates(&conn, 1, "X-API-Key").unwrap();
        assert!(none.is_empty(), "项目 1 没有 X-API-Key 流量");

        let other = list_auth_candidates(&conn, 2, "Authorization").unwrap();
        assert_eq!(other.len(), 1, "其他项目的流量互不可见");
        assert_eq!(other[0].traffic_id, 7);
    }
}
