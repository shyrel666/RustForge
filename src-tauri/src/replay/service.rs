use super::model::{
    ReplayBodySnapshot, ReplayHeader, ReplayRequestInput, ReplayRequestInputSnapshot, ReplayRun,
    ReplayRunDiff, ReplayRunPage, ReplayRunSummary, ReplayScopeSnapshot, ReplaySession,
    ReplayValueDiff, TlsPolicy,
};
use crate::assessment::model::AssessmentContractPreview;
use crate::assessment::policy::{AssessmentPolicy, AssessmentRequestCandidate, MAX_RESPONSE_BYTES};
use crate::authorization::{load_project_policy, AuthorizationError, ScopeMatchKind};
use crate::proxy::body_capture::{
    capture_complete_bytes, capture_complete_wire_bytes, BodyMetadata, CaptureHandle, CapturedBody,
    CapturedWireBody, MAX_WIRE_CAPTURE_BYTES,
};
use crate::storage::db::Pool;
use base64::Engine;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;

const MAX_SESSION_TITLE_CHARS: usize = 120;
const MAX_STORED_URL_BYTES: usize = 8192;
const MAX_STORED_METHOD_BYTES: usize = 64;
const DEFAULT_RUNS_PER_PAGE: i64 = 50;
const MAX_RUNS_PER_PAGE: i64 = 200;
const MAX_REQUEST_INPUT_CAPTURE_BYTES: usize = MAX_WIRE_CAPTURE_BYTES;

const RUN_DETAIL_SELECT: &str = "\
r.id, r.attempt_id, r.session_id, r.project_id, r.method, r.url, r.request_headers,
r.request_wire_body, r.req_wire_captured_size, r.req_wire_truncated, r.request_input,
r.request_body, r.req_wire_size, r.req_captured_size, r.req_truncated,
r.req_decode_status, r.tls_policy, r.scope_decision, r.outcome,
r.error_code, r.error_message, r.status, r.status_text, r.response_headers,
r.response_body, r.resp_wire_size, r.resp_captured_size, r.resp_truncated,
r.resp_decode_status, r.duration_ms, r.request_hash, r.req_body_hash,
r.response_hash, r.resp_body_hash, r.created_at";

const RUN_SUMMARY_SELECT: &str = "\
r.id, r.session_id, r.project_id, r.method, r.url, r.tls_policy, r.outcome,
r.error_code, r.error_message, r.status, r.status_text,
r.req_wire_size, r.req_wire_captured_size, r.req_wire_truncated, r.req_decode_status,
r.resp_wire_size, r.resp_captured_size, r.resp_truncated, r.resp_decode_status,
r.duration_ms, r.request_hash, r.response_hash, r.created_at";

static ATTEMPT_COUNTER: AtomicU64 = AtomicU64::new(1);
static ACTIVE_ATTEMPT_TOKENS: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

#[derive(Debug, Clone)]
struct SessionContext {
    project_id: i64,
    tls_policy: TlsPolicy,
}

#[derive(Debug, Clone)]
pub struct AssessmentReplayRequest {
    pub method: String,
    pub url: String,
    /// Headers actually sent on the wire. Values in this vector are never persisted.
    pub live_headers: Vec<ReplayHeader>,
    /// Redacted headers persisted in attempt/run snapshots.
    pub audit_headers: Vec<ReplayHeader>,
    /// Non-secret profile IDs and secret revisions included in the request hash.
    pub request_hash_context: String,
    /// Per-request read ceiling, additionally bounded by the hard 1 MiB limit.
    pub max_response_bytes: u64,
}

#[derive(Debug)]
struct PreparedRequest {
    method: String,
    url: String,
    headers: Vec<ReplayHeader>,
    header_map: HeaderMap,
    body: Option<Vec<u8>>,
    wire: CapturedWireBody,
    captured: CapturedBody,
    input: ReplayRequestInputSnapshot,
    body_hash: Option<String>,
    request_hash: String,
}

struct PreparedRequestFailure {
    error_code: String,
    error_message: String,
    fallback: Box<PreparedRequest>,
}

struct PreflightFailure {
    method: String,
    url: String,
    request: ReplayRequestInput,
    request_input: ReplayRequestInputSnapshot,
    request_hash: String,
    error: AuthorizationError,
}

struct PersistRun {
    attempt_id: Option<i64>,
    session_id: i64,
    project_id: i64,
    method: String,
    url: String,
    request_headers: Vec<ReplayHeader>,
    request_wire_body: Option<Vec<u8>>,
    req_wire_captured_size: i64,
    req_wire_truncated: bool,
    request_input: ReplayRequestInputSnapshot,
    request_body: Option<Vec<u8>>,
    req_wire_size: i64,
    req_captured_size: i64,
    req_truncated: bool,
    req_decode_status: String,
    tls_policy: TlsPolicy,
    scope_decision: ReplayScopeSnapshot,
    outcome: &'static str,
    error_code: Option<String>,
    error_message: Option<String>,
    status: Option<u16>,
    status_text: String,
    response_headers: Vec<ReplayHeader>,
    response_body: Option<Vec<u8>>,
    resp_wire_size: i64,
    resp_captured_size: i64,
    resp_truncated: bool,
    resp_decode_status: String,
    duration_ms: i64,
    request_hash: String,
    req_body_hash: Option<String>,
    response_hash: Option<String>,
    resp_body_hash: Option<String>,
}

struct ActiveAttemptGuard {
    token: String,
}

impl Drop for ActiveAttemptGuard {
    fn drop(&mut self) {
        if let Ok(mut active) = active_attempt_tokens().lock() {
            active.remove(&self.token);
        }
    }
}

pub fn list_sessions(conn: &Connection, project_id: i64) -> Result<Vec<ReplaySession>, String> {
    recover_interrupted_attempts(conn)?;
    ensure_project_exists(conn, project_id)?;
    let mut statement = conn
        .prepare(
            "SELECT s.id, s.project_id, s.title, s.source_traffic_id, s.tls_policy,
                    s.is_selected,
                    (SELECT COUNT(*) FROM replay_runs r WHERE r.session_id = s.id),
                    (SELECT MAX(r.created_at) FROM replay_runs r WHERE r.session_id = s.id),
                    s.created_at, s.updated_at
             FROM replay_sessions s
             WHERE s.project_id = ?1 AND s.owner_kind = 'manual'
             ORDER BY s.created_at, s.id",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([project_id], |row| {
            Ok(ReplaySession {
                id: row.get(0)?,
                project_id: row.get(1)?,
                title: row.get(2)?,
                source_traffic_id: row.get(3)?,
                tls_policy: row.get(4)?,
                is_selected: row.get(5)?,
                run_count: row.get(6)?,
                last_run_at: row.get(7)?,
                created_at: row.get(8)?,
                updated_at: row.get(9)?,
            })
        })
        .map_err(|error| error.to_string())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())
}

pub fn create_session(
    conn: &mut Connection,
    project_id: i64,
    title: &str,
    source_traffic_id: Option<i64>,
    tls_policy: TlsPolicy,
) -> Result<ReplaySession, String> {
    let title = validate_title(title)?;
    let transaction = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    ensure_project_exists(&transaction, project_id)?;
    if let Some(traffic_id) = source_traffic_id {
        let valid: bool = transaction
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM traffic WHERE id = ?1 AND project_id = ?2
                 )",
                rusqlite::params![traffic_id, project_id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if !valid {
            return Err(format!("项目 #{project_id} 内不存在来源流量 #{traffic_id}"));
        }
    }
    transaction
        .execute(
            "UPDATE replay_sessions SET is_selected = 0
             WHERE project_id = ?1 AND owner_kind = 'manual'",
            [project_id],
        )
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "INSERT INTO replay_sessions(
                 project_id, title, source_traffic_id, tls_policy, is_selected
             ) VALUES(?1,?2,?3,?4,1)",
            rusqlite::params![project_id, title, source_traffic_id, tls_policy.as_str()],
        )
        .map_err(|error| error.to_string())?;
    let id = transaction.last_insert_rowid();
    transaction.commit().map_err(|error| error.to_string())?;
    load_session(conn, id)
}

pub fn update_session(
    conn: &Connection,
    session_id: i64,
    title: &str,
    tls_policy: TlsPolicy,
) -> Result<ReplaySession, String> {
    let title = validate_title(title)?;
    let changed = conn
        .execute(
            "UPDATE replay_sessions
             SET title = ?1, tls_policy = ?2,
                 updated_at = strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
             WHERE id = ?3 AND owner_kind = 'manual'",
            rusqlite::params![title, tls_policy.as_str(), session_id],
        )
        .map_err(|error| error.to_string())?;
    if changed == 0 {
        return Err(format!("Repeater 会话 #{session_id} 不存在"));
    }
    load_session(conn, session_id)
}

pub fn select_session(conn: &mut Connection, session_id: i64) -> Result<ReplaySession, String> {
    let project_id: i64 = conn
        .query_row(
            "SELECT project_id FROM replay_sessions
             WHERE id = ?1 AND owner_kind = 'manual'",
            [session_id],
            |row| row.get(0),
        )
        .map_err(|_| format!("Repeater 会话 #{session_id} 不存在"))?;
    let transaction = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "UPDATE replay_sessions SET is_selected = 0
             WHERE project_id = ?1 AND owner_kind = 'manual'",
            [project_id],
        )
        .map_err(|error| error.to_string())?;
    let changed = transaction
        .execute(
            "UPDATE replay_sessions
             SET is_selected = 1,
                 updated_at = strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
             WHERE id = ?1 AND owner_kind = 'manual'",
            [session_id],
        )
        .map_err(|error| error.to_string())?;
    if changed == 0 {
        return Err(format!("Repeater 会话 #{session_id} 不存在"));
    }
    transaction.commit().map_err(|error| error.to_string())?;
    load_session(conn, session_id)
}

pub fn delete_session(conn: &mut Connection, session_id: i64) -> Result<(), String> {
    recover_interrupted_attempts(conn)?;
    let (project_id, selected): (i64, bool) = conn
        .query_row(
            "SELECT project_id, is_selected FROM replay_sessions
             WHERE id = ?1 AND owner_kind = 'manual'",
            [session_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| format!("Repeater 会话 #{session_id} 不存在"))?;
    let transaction = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    transaction
        .execute("DELETE FROM replay_sessions WHERE id = ?1", [session_id])
        .map_err(|error| error.to_string())?;
    if selected {
        let replacement: Option<i64> = transaction
            .query_row(
                "SELECT id FROM replay_sessions
                 WHERE project_id = ?1 AND owner_kind = 'manual'
                 ORDER BY updated_at DESC, id DESC LIMIT 1",
                [project_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some(replacement) = replacement {
            transaction
                .execute(
                    "UPDATE replay_sessions SET is_selected = 1 WHERE id = ?1",
                    [replacement],
                )
                .map_err(|error| error.to_string())?;
        }
    }
    transaction.commit().map_err(|error| error.to_string())
}

pub fn list_runs(
    conn: &Connection,
    session_id: i64,
    before_id: Option<i64>,
    limit: Option<i64>,
) -> Result<ReplayRunPage, String> {
    recover_interrupted_attempts(conn)?;
    ensure_session_exists(conn, session_id)?;
    let limit = limit
        .unwrap_or(DEFAULT_RUNS_PER_PAGE)
        .clamp(1, MAX_RUNS_PER_PAGE);
    let mut statement = conn
        .prepare(&format!(
            "SELECT {RUN_SUMMARY_SELECT} FROM replay_runs r
             WHERE r.session_id = ?1
               AND (?2 IS NULL OR r.id < ?2)
             ORDER BY r.id DESC LIMIT ?3"
        ))
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map(
            rusqlite::params![session_id, before_id, limit.saturating_add(1)],
            replay_run_summary_from_row,
        )
        .map_err(|error| error.to_string())?;
    let mut runs = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    let has_more = runs.len() > limit as usize;
    if has_more {
        runs.truncate(limit as usize);
    }
    let next_before_id = has_more.then(|| runs.last().map(|run| run.id)).flatten();
    Ok(ReplayRunPage {
        runs,
        next_before_id,
    })
}

pub fn load_run(conn: &Connection, run_id: i64) -> Result<ReplayRun, String> {
    conn.query_row(
        &format!("SELECT {RUN_DETAIL_SELECT} FROM replay_runs r WHERE r.id = ?1"),
        [run_id],
        replay_run_from_row,
    )
    .map_err(|error| format!("Repeater run #{run_id} 不存在或已损坏: {error}"))
}

pub fn load_run_for_project(
    conn: &Connection,
    project_id: i64,
    run_id: i64,
) -> Result<ReplayRun, String> {
    load_project_run(conn, project_id, run_id)
}

pub fn compare_runs(
    conn: &Connection,
    project_id: i64,
    left_run_id: i64,
    right_run_id: i64,
) -> Result<ReplayRunDiff, String> {
    if left_run_id == right_run_id {
        return Err("请选择两次不同的 Repeater run 进行比较".to_string());
    }
    let left = load_project_run(conn, project_id, left_run_id)?;
    let right = load_project_run(conn, project_id, right_run_id)?;
    Ok(build_diff(left, right))
}

/// Create a hidden Repeater session owned by one immutable Assessment run.
/// It is intentionally not selected and cannot be opened by manual APIs.
pub fn create_assessment_session(
    conn: &Connection,
    project_id: i64,
    assessment_run_id: i64,
    tls_policy: TlsPolicy,
) -> Result<i64, String> {
    let run_matches: bool = conn
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM assessment_runs
                 WHERE id = ?1 AND project_id = ?2
             )",
            rusqlite::params![assessment_run_id, project_id],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if !run_matches {
        return Err("Assessment run 不存在或不属于项目".into());
    }
    conn.execute(
        "INSERT INTO replay_sessions(
             project_id, title, tls_policy, is_selected, owner_kind, assessment_run_id
         ) VALUES(?1, ?2, ?3, 0, 'assessment', ?4)",
        rusqlite::params![
            project_id,
            format!("AI Assessment #{assessment_run_id}"),
            tls_policy.as_str(),
            assessment_run_id
        ],
    )
    .map_err(|error| format!("创建 Assessment Replay 会话失败: {error}"))?;
    Ok(conn.last_insert_rowid())
}

/// Assessment-only transport. The request is rechecked by both AssessmentPolicy
/// and ScopePolicy, persists an attempt before polling the network future, and
/// stores only audit headers. Cancellation produces a final immutable run.
pub async fn execute_assessment_request(
    pool: Pool,
    project_id: i64,
    assessment_run_id: i64,
    session_id: i64,
    request: AssessmentReplayRequest,
    mut cancel: watch::Receiver<bool>,
) -> Result<ReplayRun, String> {
    let (context, preview) = {
        let conn = pool.get().map_err(|error| error.to_string())?;
        load_assessment_session_context(&conn, project_id, assessment_run_id, session_id)?
    };
    validate_assessment_header_views(&request.live_headers, &request.audit_headers)?;
    if request.max_response_bytes == 0 || request.max_response_bytes > MAX_RESPONSE_BYTES {
        return Err("Assessment 响应读取上限无效".into());
    }

    let scope = {
        let conn = pool.get().map_err(|error| error.to_string())?;
        load_project_policy(&conn, project_id).map_err(|error| error.to_string())?
    };
    let assessment_policy = AssessmentPolicy::new(&preview.exact_origin, &preview.excluded_paths)
        .map_err(|error| error.to_string())?;
    let authorized = assessment_policy
        .authorize(
            &scope,
            AssessmentRequestCandidate {
                method: request.method.clone(),
                url: request.url.clone(),
                headers: request.audit_headers.clone(),
                has_body: false,
            },
        )
        .map_err(|error| error.to_string())?;
    let scope_decision = allowed_scope_snapshot(&authorized.scope_decision);
    let stored_method = bounded_non_empty(&authorized.method, MAX_STORED_METHOD_BYTES, "<invalid>");
    let stored_url = bounded_non_empty(
        authorized.url.as_str(),
        MAX_STORED_URL_BYTES,
        "<invalid-url>",
    );
    let audit_input = ReplayRequestInput {
        method: stored_method.clone(),
        url: stored_url.clone(),
        headers: request.audit_headers.clone(),
        body_text: None,
        body_base64: None,
    };
    let request_input = request_input_snapshot(&audit_input)?;
    let initial_hash = hash_request_input(
        &stored_method,
        &stored_url,
        &request.audit_headers,
        None,
        None,
        context.tls_policy,
    )?;
    let mut prepared = prepare_request(
        stored_method,
        stored_url,
        request.audit_headers,
        None,
        None,
        request_input,
        initial_hash,
    )
    .map_err(|failure| failure.error_message)?;
    let (live_header_map, _) = validated_header_map(&request.live_headers)
        .map_err(|_| "Assessment 线上 Header 无效".to_string())?;
    prepared.header_map = live_header_map;
    prepared.request_hash = hash_assessment_effective_request(
        &prepared.method,
        &prepared.url,
        &prepared.headers,
        context.tls_policy,
        &request.request_hash_context,
    )?;

    let http_method = reqwest::Method::from_bytes(prepared.method.as_bytes())
        .map_err(|_| "Assessment HTTP 方法无效".to_string())?;
    let client = assessment_http_client(context.tls_policy)?;
    let mut outgoing = client.request(http_method, authorized.url);
    for (name, value) in &prepared.header_map {
        outgoing = outgoing.header(name, value);
    }

    let known_secrets = assessment_header_secrets(&request.live_headers, &prepared.headers);
    let (attempt_id, _attempt_guard) =
        persist_attempt(&pool, &context, session_id, &prepared, &scope_decision)?;
    if *cancel.borrow() {
        return persist_request_failure(
            &pool,
            &context,
            session_id,
            Some(attempt_id),
            prepared,
            scope_decision,
            "ASSESSMENT_CANCELLED",
            "用户在请求发送前取消了 Assessment",
            0,
        );
    }

    let started = Instant::now();
    let send_result = tokio::select! {
        biased;
        _ = cancel.changed() => None,
        result = outgoing.send() => Some(result),
    };
    let mut response = match send_result {
        None => {
            return persist_request_failure(
                &pool,
                &context,
                session_id,
                Some(attempt_id),
                prepared,
                scope_decision,
                "ASSESSMENT_CANCELLED",
                "用户取消了正在等待的 Assessment 请求",
                elapsed_millis(started),
            );
        }
        Some(Err(error)) => {
            let (code, message) = safe_reqwest_error(&error);
            return persist_request_failure(
                &pool,
                &context,
                session_id,
                Some(attempt_id),
                prepared,
                scope_decision,
                code,
                &message,
                elapsed_millis(started),
            );
        }
        Some(Ok(response)) => response,
    };

    let status = response.status();
    let response_headers = response
        .headers()
        .iter()
        .map(|(name, value)| ReplayHeader {
            name: name.as_str().to_string(),
            value: redact_known_text(&header_value_for_storage(value), &known_secrets),
        })
        .collect::<Vec<_>>();
    let response_metadata = BodyMetadata::from_headers(response.headers());
    let response_capture = CaptureHandle::default();
    let mut incomplete_code: Option<&'static str> = None;
    let mut observed = 0_usize;
    loop {
        let next = tokio::select! {
            biased;
            _ = cancel.changed() => {
                incomplete_code = Some("ASSESSMENT_CANCELLED");
                None
            },
            chunk = response.chunk() => Some(chunk),
        };
        match next {
            None => {
                response_capture.mark_error();
                break;
            }
            Some(Ok(Some(chunk))) => {
                let remaining = (request.max_response_bytes as usize).saturating_sub(observed);
                if chunk.len() > remaining {
                    if remaining > 0 {
                        response_capture.observe_chunk(&chunk[..remaining]);
                    }
                    incomplete_code = Some("RESPONSE_LIMIT");
                    response_capture.mark_error();
                    break;
                }
                response_capture.observe_chunk(&chunk);
                observed += chunk.len();
            }
            Some(Ok(None)) => {
                response_capture.mark_complete();
                break;
            }
            Some(Err(_)) => {
                incomplete_code = Some("RESPONSE_STREAM");
                response_capture.mark_error();
                break;
            }
        }
    }
    let mut captured_response = response_capture.finish(&response_metadata);
    // Keep exact-response comparisons meaningful without persisting the raw body.
    // A target may reflect profile A/B credentials; hashing only the redacted
    // snapshot would make two different responses look identical.
    let raw_complete_body_hash = incomplete_code
        .is_none()
        .then(|| sha256(&captured_response.bytes));
    captured_response.bytes = redact_known_bytes(&captured_response.bytes, &known_secrets);
    captured_response.captured_size =
        i64::try_from(captured_response.bytes.len()).unwrap_or(i64::MAX);
    let response_headers_json =
        serde_json::to_string(&response_headers).map_err(|error| error.to_string())?;
    let mut response_hasher = Sha256::new();
    response_hasher.update(status.as_u16().to_be_bytes());
    response_hasher.update(response_headers_json.as_bytes());
    response_hasher.update(&captured_response.bytes);
    let response_hash = format!("{:x}", response_hasher.finalize());
    let resp_body_hash = raw_complete_body_hash;
    let error_message = match incomplete_code {
        Some("ASSESSMENT_CANCELLED") => Some("用户取消后停止读取响应；该响应不完整".to_string()),
        Some("RESPONSE_LIMIT") => {
            Some("响应超过 1 MiB，已立即停止读取；该响应不能用于自动确认".to_string())
        }
        Some("RESPONSE_STREAM") => Some("读取响应时连接中断；该响应不能用于自动确认".to_string()),
        _ => None,
    };

    persist_run(
        &pool,
        PersistRun {
            attempt_id: Some(attempt_id),
            session_id,
            project_id: context.project_id,
            method: prepared.method,
            url: prepared.url,
            request_headers: prepared.headers,
            request_wire_body: None,
            req_wire_captured_size: 0,
            req_wire_truncated: false,
            request_input: prepared.input,
            request_body: None,
            req_wire_size: 0,
            req_captured_size: 0,
            req_truncated: false,
            req_decode_status: "empty".to_string(),
            tls_policy: context.tls_policy,
            scope_decision,
            outcome: if incomplete_code.is_some() {
                "response_incomplete"
            } else {
                "completed"
            },
            error_code: incomplete_code.map(str::to_string),
            error_message,
            status: Some(status.as_u16()),
            status_text: status.canonical_reason().unwrap_or("").to_string(),
            response_headers,
            response_body: bytes_or_none(captured_response.bytes),
            resp_wire_size: captured_response.wire_size,
            resp_captured_size: captured_response.captured_size,
            resp_truncated: captured_response.truncated,
            resp_decode_status: captured_response.decode_status.to_string(),
            duration_ms: elapsed_millis(started),
            request_hash: prepared.request_hash,
            req_body_hash: prepared.body_hash,
            response_hash: Some(response_hash),
            resp_body_hash,
        },
    )
}

/// Assessment 专用 HTTP 客户端按 TLS 策略缓存复用。Client 是廉价 Arc，
/// 复用可避免每个目标请求重新建连与握手；策略配置（跟随重定向、禁用
/// 压缩、30s 超时）在运行期间固定。
fn assessment_http_client(tls_policy: TlsPolicy) -> Result<reqwest::Client, String> {
    static CLIENTS: OnceLock<std::sync::Mutex<HashMap<TlsPolicy, reqwest::Client>>> =
        OnceLock::new();
    let clients = CLIENTS.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    let mut clients = clients
        .lock()
        .map_err(|_| "Assessment HTTP 客户端缓存已损坏".to_string())?;
    if let Some(client) = clients.get(&tls_policy) {
        return Ok(client.clone());
    }
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(tls_policy == TlsPolicy::IgnoreInvalid)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .build()
        .map_err(|_| "Assessment HTTP 客户端初始化失败".to_string())?;
    clients.insert(tls_policy, client.clone());
    Ok(client)
}

#[allow(clippy::too_many_arguments)]
pub async fn execute_request(
    pool: Pool,
    project_id: i64,
    session_id: i64,
    request: ReplayRequestInput,
) -> Result<ReplayRun, String> {
    let context = {
        let conn = pool.get().map_err(|error| error.to_string())?;
        load_session_context(&conn, project_id, session_id)?
    };

    let normalized_method = request.method.trim().to_ascii_uppercase();
    let invalid_method =
        normalized_method.is_empty() || normalized_method.len() > MAX_STORED_METHOD_BYTES;
    let oversized_url = request.url.trim().len() > MAX_STORED_URL_BYTES;
    let stored_method = bounded_non_empty(&normalized_method, MAX_STORED_METHOD_BYTES, "<invalid>");
    let stored_url = bounded_non_empty(request.url.trim(), MAX_STORED_URL_BYTES, "<invalid-url>");
    let request_input = request_input_snapshot(&request)?;
    let request_hash = hash_request_input(
        &request.method,
        &request.url,
        &request.headers,
        request.body_text.as_deref(),
        request.body_base64.as_deref(),
        context.tls_policy,
    )?;

    let policy = {
        let conn = pool.get().map_err(|error| error.to_string())?;
        load_project_policy(&conn, context.project_id)
    };
    let policy = match policy {
        Ok(policy) => policy,
        Err(error) => {
            return persist_preflight_failure(
                &pool,
                &context,
                session_id,
                PreflightFailure {
                    method: stored_method,
                    url: stored_url,
                    request,
                    request_input,
                    request_hash,
                    error,
                },
            );
        }
    };

    // This authorization happens before building an HTTP client/request or
    // parsing user-provided headers. The returned URL is the only URL used for
    // the network operation.
    let authorized = match policy.authorize_url(&request.url) {
        Ok(authorized) => authorized,
        Err(error) => {
            return persist_preflight_failure(
                &pool,
                &context,
                session_id,
                PreflightFailure {
                    method: stored_method,
                    url: stored_url,
                    request,
                    request_input,
                    request_hash,
                    error,
                },
            );
        }
    };
    let scope_decision = allowed_scope_snapshot(&authorized.decision);

    if invalid_method || oversized_url {
        let fallback = fallback_from_input(
            stored_method,
            stored_url,
            request,
            request_input,
            request_hash,
        );
        let (code, message) = if invalid_method {
            (
                "INVALID_METHOD",
                format!("HTTP 方法必须为 1–{MAX_STORED_METHOD_BYTES} 个 ASCII 字节"),
            )
        } else {
            (
                "URL_TOO_LONG",
                format!("请求 URL 不能超过 {MAX_STORED_URL_BYTES} 字节"),
            )
        };
        return persist_request_failure(
            &pool,
            &context,
            session_id,
            None,
            fallback,
            scope_decision,
            code,
            &message,
            0,
        );
    }

    let mut prepared = match prepare_request(
        stored_method,
        stored_url,
        request.headers,
        request.body_text,
        request.body_base64,
        request_input,
        request_hash,
    ) {
        Ok(prepared) => prepared,
        Err(failure) => {
            let fallback = *failure.fallback;
            return persist_run(
                &pool,
                PersistRun {
                    attempt_id: None,
                    session_id,
                    project_id: context.project_id,
                    method: fallback.method,
                    url: fallback.url,
                    request_headers: fallback.headers,
                    request_wire_body: bytes_or_none(fallback.wire.bytes),
                    req_wire_captured_size: fallback.wire.captured_size,
                    req_wire_truncated: fallback.wire.truncated,
                    request_input: fallback.input,
                    request_body: bytes_or_none(fallback.captured.bytes),
                    req_wire_size: fallback.wire.wire_size,
                    req_captured_size: fallback.captured.captured_size,
                    req_truncated: fallback.captured.truncated,
                    req_decode_status: fallback.captured.decode_status.to_string(),
                    tls_policy: context.tls_policy,
                    scope_decision,
                    outcome: "request_failed",
                    error_code: Some(failure.error_code),
                    error_message: Some(failure.error_message),
                    status: None,
                    status_text: String::new(),
                    response_headers: Vec::new(),
                    response_body: None,
                    resp_wire_size: 0,
                    resp_captured_size: 0,
                    resp_truncated: false,
                    resp_decode_status: "not_received".to_string(),
                    duration_ms: 0,
                    request_hash: fallback.request_hash,
                    req_body_hash: fallback.body_hash,
                    response_hash: None,
                    resp_body_hash: None,
                },
            );
        }
    };
    prepared.request_hash = hash_effective_request(
        &prepared.method,
        &prepared.url,
        &prepared.headers,
        prepared.body.as_deref(),
        context.tls_policy,
    )?;

    let http_method = match reqwest::Method::from_bytes(prepared.method.as_bytes()) {
        Ok(method) => method,
        Err(_) => {
            return persist_request_failure(
                &pool,
                &context,
                session_id,
                None,
                prepared,
                scope_decision,
                "INVALID_METHOD",
                "HTTP 方法无效",
                0,
            );
        }
    };
    let client = match reqwest::Client::builder()
        .danger_accept_invalid_certs(context.tls_policy == TlsPolicy::IgnoreInvalid)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .build()
    {
        Ok(client) => client,
        Err(_) => {
            return persist_request_failure(
                &pool,
                &context,
                session_id,
                None,
                prepared,
                scope_decision,
                "CLIENT_INIT",
                "HTTP 客户端初始化失败",
                0,
            );
        }
    };

    let mut request = client.request(http_method, authorized.url);
    for (name, value) in &prepared.header_map {
        request = request.header(name, value);
    }
    if let Some(body) = prepared.body.clone() {
        request = request.body(body);
    }

    let (attempt_id, _attempt_guard) =
        persist_attempt(&pool, &context, session_id, &prepared, &scope_decision)?;
    let started = Instant::now();
    let mut response = match request.send().await {
        Ok(response) => response,
        Err(error) => {
            let duration_ms = elapsed_millis(started);
            let (code, message) = safe_reqwest_error(&error);
            return persist_request_failure(
                &pool,
                &context,
                session_id,
                Some(attempt_id),
                prepared,
                scope_decision,
                code,
                &message,
                duration_ms,
            );
        }
    };

    let status = response.status();
    let response_headers = response
        .headers()
        .iter()
        .map(|(name, value)| ReplayHeader {
            name: name.as_str().to_string(),
            value: header_value_for_storage(value),
        })
        .collect::<Vec<_>>();
    let response_headers_json =
        serde_json::to_string(&response_headers).map_err(|error| error.to_string())?;
    let response_metadata = BodyMetadata::from_headers(response.headers());
    let response_capture = CaptureHandle::default();
    let mut response_hasher = Sha256::new();
    let mut response_body_hasher = Sha256::new();
    response_hasher.update(status.as_u16().to_be_bytes());
    response_hasher.update(response_headers_json.as_bytes());
    let mut stream_error = false;
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                response_hasher.update(&chunk);
                response_body_hasher.update(&chunk);
                response_capture.observe_chunk(&chunk);
            }
            Ok(None) => {
                response_capture.mark_complete();
                break;
            }
            Err(_) => {
                response_capture.mark_error();
                stream_error = true;
                break;
            }
        }
    }
    let captured_response = response_capture.finish(&response_metadata);
    let duration_ms = elapsed_millis(started);
    let response_hash = format!("{:x}", response_hasher.finalize());
    let resp_body_hash = (!stream_error).then(|| format!("{:x}", response_body_hasher.finalize()));

    persist_run(
        &pool,
        PersistRun {
            attempt_id: Some(attempt_id),
            session_id,
            project_id: context.project_id,
            method: prepared.method,
            url: prepared.url,
            request_headers: prepared.headers,
            request_wire_body: bytes_or_none(prepared.wire.bytes),
            req_wire_captured_size: prepared.wire.captured_size,
            req_wire_truncated: prepared.wire.truncated,
            request_input: prepared.input,
            request_body: bytes_or_none(prepared.captured.bytes),
            req_wire_size: prepared.wire.wire_size,
            req_captured_size: prepared.captured.captured_size,
            req_truncated: prepared.captured.truncated,
            req_decode_status: prepared.captured.decode_status.to_string(),
            tls_policy: context.tls_policy,
            scope_decision,
            outcome: if stream_error {
                "response_incomplete"
            } else {
                "completed"
            },
            error_code: stream_error.then(|| "RESPONSE_STREAM".to_string()),
            error_message: stream_error
                .then(|| "读取响应正文时连接中断；已保留有界前缀".to_string()),
            status: Some(status.as_u16()),
            status_text: status.canonical_reason().unwrap_or("").to_string(),
            response_headers,
            response_body: bytes_or_none(captured_response.bytes),
            resp_wire_size: captured_response.wire_size,
            resp_captured_size: captured_response.captured_size,
            resp_truncated: captured_response.truncated,
            resp_decode_status: captured_response.decode_status.to_string(),
            duration_ms,
            request_hash: prepared.request_hash,
            req_body_hash: prepared.body_hash,
            response_hash: Some(response_hash),
            resp_body_hash,
        },
    )
}

fn prepare_request(
    method: String,
    url: String,
    headers: Vec<ReplayHeader>,
    body_text: Option<String>,
    body_base64: Option<String>,
    input: ReplayRequestInputSnapshot,
    request_hash: String,
) -> Result<PreparedRequest, PreparedRequestFailure> {
    let body = match decode_body(body_text, body_base64) {
        Ok(body) => body,
        Err(message) => {
            return Err(PreparedRequestFailure {
                error_code: "INVALID_REPLAY_BODY".to_string(),
                error_message: message,
                fallback: Box::new(fallback_request(method, url, headers, input, request_hash)),
            });
        }
    };
    let (header_map, effective_headers) = match validated_header_map(&headers) {
        Ok(headers) => headers,
        Err(message) => {
            let fallback = request_with_capture(
                method,
                url,
                headers,
                HeaderMap::new(),
                body,
                input,
                request_hash,
            );
            return Err(PreparedRequestFailure {
                error_code: "INVALID_HEADER".to_string(),
                error_message: message,
                fallback: Box::new(fallback),
            });
        }
    };
    Ok(request_with_capture(
        method,
        url,
        effective_headers,
        header_map,
        body,
        input,
        request_hash,
    ))
}

fn request_with_capture(
    method: String,
    url: String,
    headers: Vec<ReplayHeader>,
    header_map: HeaderMap,
    body: Option<Vec<u8>>,
    input: ReplayRequestInputSnapshot,
    request_hash: String,
) -> PreparedRequest {
    let metadata = BodyMetadata::from_headers(&header_map);
    let body_bytes = body.as_deref().unwrap_or_default();
    let wire = capture_complete_wire_bytes(body_bytes);
    let captured = capture_complete_bytes(body_bytes, &metadata);
    let body_hash = Some(sha256(body_bytes));
    PreparedRequest {
        method,
        url,
        headers,
        header_map,
        body,
        wire,
        captured,
        input,
        body_hash,
        request_hash,
    }
}

fn fallback_request(
    method: String,
    url: String,
    headers: Vec<ReplayHeader>,
    input: ReplayRequestInputSnapshot,
    request_hash: String,
) -> PreparedRequest {
    PreparedRequest {
        method,
        url,
        headers,
        header_map: HeaderMap::new(),
        body: None,
        wire: capture_complete_wire_bytes(&[]),
        captured: CapturedBody::not_received(),
        input,
        body_hash: None,
        request_hash,
    }
}

fn fallback_from_input(
    method: String,
    url: String,
    request: ReplayRequestInput,
    input: ReplayRequestInputSnapshot,
    request_hash: String,
) -> PreparedRequest {
    match decode_body(request.body_text, request.body_base64) {
        Ok(body) => {
            let header_map = lenient_header_map(&request.headers);
            request_with_capture(
                method,
                url,
                request.headers,
                header_map,
                body,
                input,
                request_hash,
            )
        }
        Err(_) => fallback_request(method, url, request.headers, input, request_hash),
    }
}

fn persist_preflight_failure(
    pool: &Pool,
    context: &SessionContext,
    session_id: i64,
    failure: PreflightFailure,
) -> Result<ReplayRun, String> {
    let fallback = fallback_from_input(
        failure.method,
        failure.url,
        failure.request,
        failure.request_input,
        failure.request_hash,
    );
    let scope_decision = denied_scope_snapshot(&failure.error);
    persist_run(
        pool,
        PersistRun {
            attempt_id: None,
            session_id,
            project_id: context.project_id,
            method: fallback.method,
            url: fallback.url,
            request_headers: fallback.headers,
            request_wire_body: bytes_or_none(fallback.wire.bytes),
            req_wire_captured_size: fallback.wire.captured_size,
            req_wire_truncated: fallback.wire.truncated,
            request_input: fallback.input,
            request_body: bytes_or_none(fallback.captured.bytes),
            req_wire_size: fallback.wire.wire_size,
            req_captured_size: fallback.captured.captured_size,
            req_truncated: fallback.captured.truncated,
            req_decode_status: fallback.captured.decode_status.to_string(),
            tls_policy: context.tls_policy,
            scope_decision,
            outcome: "scope_rejected",
            error_code: Some(failure.error.code().to_string()),
            error_message: Some(failure.error.to_string()),
            status: None,
            status_text: String::new(),
            response_headers: Vec::new(),
            response_body: None,
            resp_wire_size: 0,
            resp_captured_size: 0,
            resp_truncated: false,
            resp_decode_status: "not_received".to_string(),
            duration_ms: 0,
            request_hash: fallback.request_hash,
            req_body_hash: fallback.body_hash,
            response_hash: None,
            resp_body_hash: None,
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn persist_request_failure(
    pool: &Pool,
    context: &SessionContext,
    session_id: i64,
    attempt_id: Option<i64>,
    prepared: PreparedRequest,
    scope_decision: ReplayScopeSnapshot,
    code: &str,
    message: &str,
    duration_ms: i64,
) -> Result<ReplayRun, String> {
    persist_run(
        pool,
        PersistRun {
            attempt_id,
            session_id,
            project_id: context.project_id,
            method: prepared.method,
            url: prepared.url,
            request_headers: prepared.headers,
            request_wire_body: bytes_or_none(prepared.wire.bytes),
            req_wire_captured_size: prepared.wire.captured_size,
            req_wire_truncated: prepared.wire.truncated,
            request_input: prepared.input,
            request_body: bytes_or_none(prepared.captured.bytes),
            req_wire_size: prepared.wire.wire_size,
            req_captured_size: prepared.captured.captured_size,
            req_truncated: prepared.captured.truncated,
            req_decode_status: prepared.captured.decode_status.to_string(),
            tls_policy: context.tls_policy,
            scope_decision,
            outcome: "request_failed",
            error_code: Some(code.to_string()),
            error_message: Some(message.to_string()),
            status: None,
            status_text: String::new(),
            response_headers: Vec::new(),
            response_body: None,
            resp_wire_size: 0,
            resp_captured_size: 0,
            resp_truncated: false,
            resp_decode_status: "not_received".to_string(),
            duration_ms,
            request_hash: prepared.request_hash,
            req_body_hash: prepared.body_hash,
            response_hash: None,
            resp_body_hash: None,
        },
    )
}

fn active_attempt_tokens() -> &'static Mutex<HashSet<String>> {
    ACTIVE_ATTEMPT_TOKENS.get_or_init(|| Mutex::new(HashSet::new()))
}

fn next_attempt_token() -> String {
    let sequence = ATTEMPT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("{}-{nanos}-{sequence}", std::process::id())
}

fn persist_attempt(
    pool: &Pool,
    context: &SessionContext,
    session_id: i64,
    prepared: &PreparedRequest,
    scope_decision: &ReplayScopeSnapshot,
) -> Result<(i64, ActiveAttemptGuard), String> {
    let request_headers =
        serde_json::to_string(&prepared.headers).map_err(|error| error.to_string())?;
    let request_input =
        serde_json::to_string(&prepared.input).map_err(|error| error.to_string())?;
    let scope_decision =
        serde_json::to_string(scope_decision).map_err(|error| error.to_string())?;
    let req_body_hash = prepared
        .body_hash
        .as_deref()
        .ok_or_else(|| "可发送请求缺少完整正文哈希".to_string())?;
    let token = next_attempt_token();
    let mut conn = pool.get().map_err(|error| error.to_string())?;
    let mut active = active_attempt_tokens()
        .lock()
        .map_err(|_| "Repeater attempt 状态锁已损坏".to_string())?;
    let transaction = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "INSERT INTO replay_attempts(
                 execution_token, session_id, project_id, method, url, request_headers,
                 request_wire_body, req_wire_size, req_wire_captured_size,
                 req_wire_truncated, request_input, request_body, req_captured_size,
                 req_truncated, req_decode_status, tls_policy, scope_decision,
                 request_hash, req_body_hash
             ) VALUES(
                 ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,
                 ?17,?18,?19
             )",
            rusqlite::params![
                token,
                session_id,
                context.project_id,
                prepared.method,
                prepared.url,
                request_headers,
                bytes_or_none(prepared.wire.bytes.clone()),
                prepared.wire.wire_size,
                prepared.wire.captured_size,
                prepared.wire.truncated,
                request_input,
                bytes_or_none(prepared.captured.bytes.clone()),
                prepared.captured.captured_size,
                prepared.captured.truncated,
                prepared.captured.decode_status.to_string(),
                context.tls_policy.as_str(),
                scope_decision,
                prepared.request_hash,
                req_body_hash,
            ],
        )
        .map_err(|error| error.to_string())?;
    let attempt_id = transaction.last_insert_rowid();
    transaction.commit().map_err(|error| error.to_string())?;
    active.insert(token.clone());
    drop(active);
    Ok((attempt_id, ActiveAttemptGuard { token }))
}

/// Convert attempts left without a final immutable run into an explicit
/// interruption record. The in-process token set prevents a concurrent UI
/// query or delete from recovering a request that is still running.
pub fn recover_interrupted_attempts(conn: &Connection) -> Result<usize, String> {
    let active = active_attempt_tokens()
        .lock()
        .map_err(|_| "Repeater attempt 状态锁已损坏".to_string())?;
    let candidates = {
        let mut statement = conn
            .prepare(
                "SELECT a.id, a.execution_token, a.session_id
                 FROM replay_attempts a
                 WHERE NOT EXISTS(
                     SELECT 1 FROM replay_runs r WHERE r.attempt_id = a.id
                 )
                 ORDER BY a.id",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(|error| error.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?
    };

    let mut recovered = 0;
    for (attempt_id, token, session_id) in candidates {
        if active.contains(&token) {
            continue;
        }
        let inserted = conn
            .execute(
                "INSERT OR IGNORE INTO replay_runs(
                     attempt_id, session_id, project_id, method, url, request_headers,
                     request_wire_body, req_wire_captured_size, req_wire_truncated,
                     request_input, request_body, req_wire_size, req_captured_size,
                     req_truncated, req_decode_status, tls_policy, scope_allowed,
                     scope_decision, outcome, error_code, error_message, status,
                     status_text, response_headers, response_body, resp_wire_size,
                     resp_captured_size, resp_truncated, resp_decode_status, duration_ms,
                     request_hash, req_body_hash, response_hash, resp_body_hash, created_at
                 )
                 SELECT
                     a.id, a.session_id, a.project_id, a.method, a.url, a.request_headers,
                     a.request_wire_body, a.req_wire_captured_size, a.req_wire_truncated,
                     a.request_input, a.request_body, a.req_wire_size, a.req_captured_size,
                     a.req_truncated, a.req_decode_status, a.tls_policy, 1,
                     a.scope_decision, 'request_failed', 'APP_INTERRUPTED',
                     '应用在请求完成记录写入前中断；该请求可能已产生网络副作用',
                     NULL, '', '[]', NULL, 0, 0, 0, 'not_received', 0,
                     a.request_hash, a.req_body_hash, NULL, NULL, a.created_at
                 FROM replay_attempts a
                 WHERE a.id = ?1
                   AND NOT EXISTS(
                       SELECT 1 FROM replay_runs r WHERE r.attempt_id = a.id
                   )",
                [attempt_id],
            )
            .map_err(|error| error.to_string())?;
        if inserted > 0 {
            conn.execute(
                "UPDATE replay_sessions
                 SET updated_at = strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                 WHERE id = ?1",
                [session_id],
            )
            .map_err(|error| error.to_string())?;
            recovered += 1;
        }
    }
    Ok(recovered)
}

fn persist_run(pool: &Pool, run: PersistRun) -> Result<ReplayRun, String> {
    let request_headers =
        serde_json::to_string(&run.request_headers).map_err(|error| error.to_string())?;
    let request_input =
        serde_json::to_string(&run.request_input).map_err(|error| error.to_string())?;
    let response_headers =
        serde_json::to_string(&run.response_headers).map_err(|error| error.to_string())?;
    let scope_decision =
        serde_json::to_string(&run.scope_decision).map_err(|error| error.to_string())?;
    let mut conn = pool.get().map_err(|error| error.to_string())?;
    let transaction = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "INSERT INTO replay_runs(
                 attempt_id, session_id, project_id, method, url, request_headers,
                 request_wire_body, req_wire_captured_size, req_wire_truncated,
                 request_input, request_body, req_wire_size, req_captured_size,
                 req_truncated, req_decode_status, tls_policy, scope_allowed,
                 scope_decision, outcome, error_code, error_message, status,
                 status_text, response_headers, response_body, resp_wire_size,
                 resp_captured_size, resp_truncated, resp_decode_status, duration_ms,
                 request_hash, req_body_hash, response_hash, resp_body_hash, created_at
             ) VALUES(
                 ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,
                 ?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,?30,
                 ?31,?32,?33,?34,
                 COALESCE(
                     (SELECT created_at FROM replay_attempts WHERE id = ?1),
                     strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                 )
             )",
            rusqlite::params![
                run.attempt_id,
                run.session_id,
                run.project_id,
                run.method,
                run.url,
                request_headers,
                run.request_wire_body,
                run.req_wire_captured_size,
                run.req_wire_truncated,
                request_input,
                run.request_body,
                run.req_wire_size,
                run.req_captured_size,
                run.req_truncated,
                run.req_decode_status,
                run.tls_policy.as_str(),
                run.scope_decision.allowed,
                scope_decision,
                run.outcome,
                run.error_code,
                run.error_message,
                run.status,
                run.status_text,
                response_headers,
                run.response_body,
                run.resp_wire_size,
                run.resp_captured_size,
                run.resp_truncated,
                run.resp_decode_status,
                run.duration_ms,
                run.request_hash,
                run.req_body_hash,
                run.response_hash,
                run.resp_body_hash,
            ],
        )
        .map_err(|error| error.to_string())?;
    let run_id = transaction.last_insert_rowid();
    transaction
        .execute(
            "UPDATE replay_sessions
             SET updated_at = strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
             WHERE id = ?1",
            [run.session_id],
        )
        .map_err(|error| error.to_string())?;
    transaction.commit().map_err(|error| error.to_string())?;
    load_run(&conn, run_id)
}

fn replay_run_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ReplayRun> {
    let request_headers_json: String = row.get(6)?;
    let request_headers = parse_json_column(&request_headers_json, 6)?;
    let request_wire_body: Option<Vec<u8>> = row.get(7)?;
    let request_input_json: String = row.get(10)?;
    let request_input = parse_json_column(&request_input_json, 10)?;
    let request_body: Option<Vec<u8>> = row.get(11)?;
    let request_decode_status: String = row.get(15)?;
    let (request_wire_body_text, request_wire_body_base64) =
        wire_body_representation(request_wire_body.as_deref(), &request_decode_status);
    let (request_body_text, request_body_base64) =
        body_representation(request_body.as_deref(), &request_decode_status);
    let scope_json: String = row.get(17)?;
    let scope_decision = parse_json_column(&scope_json, 17)?;
    let response_headers_json: String = row.get(23)?;
    let response_headers = parse_json_column(&response_headers_json, 23)?;
    let response_body: Option<Vec<u8>> = row.get(24)?;
    let response_decode_status: String = row.get(28)?;
    let (response_body_text, response_body_base64) =
        body_representation(response_body.as_deref(), &response_decode_status);
    let status = status_from_row(row, 21)?;

    Ok(ReplayRun {
        id: row.get(0)?,
        attempt_id: row.get(1)?,
        session_id: row.get(2)?,
        project_id: row.get(3)?,
        method: row.get(4)?,
        url: row.get(5)?,
        request_headers,
        request_wire_body_text,
        request_wire_body_base64,
        req_wire_captured_size: row.get(8)?,
        req_wire_truncated: row.get(9)?,
        request_input,
        request_body_text,
        request_body_base64,
        req_wire_size: row.get(12)?,
        req_captured_size: row.get(13)?,
        req_truncated: row.get(14)?,
        req_decode_status: request_decode_status,
        tls_policy: row.get(16)?,
        scope_decision,
        outcome: row.get(18)?,
        error_code: row.get(19)?,
        error_message: row.get(20)?,
        status,
        status_text: row.get(22)?,
        response_headers,
        response_body_text,
        response_body_base64,
        resp_wire_size: row.get(25)?,
        resp_captured_size: row.get(26)?,
        resp_truncated: row.get(27)?,
        resp_decode_status: response_decode_status,
        duration_ms: row.get(29)?,
        request_hash: row.get(30)?,
        req_body_hash: row.get(31)?,
        response_hash: row.get(32)?,
        resp_body_hash: row.get(33)?,
        created_at: row.get(34)?,
    })
}

fn replay_run_summary_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ReplayRunSummary> {
    Ok(ReplayRunSummary {
        id: row.get(0)?,
        session_id: row.get(1)?,
        project_id: row.get(2)?,
        method: row.get(3)?,
        url: row.get(4)?,
        tls_policy: row.get(5)?,
        outcome: row.get(6)?,
        error_code: row.get(7)?,
        error_message: row.get(8)?,
        status: status_from_row(row, 9)?,
        status_text: row.get(10)?,
        req_wire_size: row.get(11)?,
        req_wire_captured_size: row.get(12)?,
        req_wire_truncated: row.get(13)?,
        req_decode_status: row.get(14)?,
        resp_wire_size: row.get(15)?,
        resp_captured_size: row.get(16)?,
        resp_truncated: row.get(17)?,
        resp_decode_status: row.get(18)?,
        duration_ms: row.get(19)?,
        request_hash: row.get(20)?,
        response_hash: row.get(21)?,
        created_at: row.get(22)?,
    })
}

fn status_from_row(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Option<u16>> {
    let raw_status: Option<i64> = row.get(index)?;
    raw_status.map(u16::try_from).transpose().map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}

fn parse_json_column<T: serde::de::DeserializeOwned>(
    value: &str,
    index: usize,
) -> rusqlite::Result<T> {
    serde_json::from_str(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}

fn load_session(conn: &Connection, session_id: i64) -> Result<ReplaySession, String> {
    conn.query_row(
        "SELECT s.id, s.project_id, s.title, s.source_traffic_id, s.tls_policy,
                s.is_selected,
                (SELECT COUNT(*) FROM replay_runs r WHERE r.session_id = s.id),
                (SELECT MAX(r.created_at) FROM replay_runs r WHERE r.session_id = s.id),
                s.created_at, s.updated_at
         FROM replay_sessions s WHERE s.id = ?1 AND s.owner_kind = 'manual'",
        [session_id],
        |row| {
            Ok(ReplaySession {
                id: row.get(0)?,
                project_id: row.get(1)?,
                title: row.get(2)?,
                source_traffic_id: row.get(3)?,
                tls_policy: row.get(4)?,
                is_selected: row.get(5)?,
                run_count: row.get(6)?,
                last_run_at: row.get(7)?,
                created_at: row.get(8)?,
                updated_at: row.get(9)?,
            })
        },
    )
    .map_err(|_| format!("Repeater 会话 #{session_id} 不存在"))
}

fn load_session_context(
    conn: &Connection,
    project_id: i64,
    session_id: i64,
) -> Result<SessionContext, String> {
    let (actual_project_id, tls_policy): (i64, String) = conn
        .query_row(
            "SELECT project_id, tls_policy FROM replay_sessions
             WHERE id = ?1 AND owner_kind = 'manual'",
            [session_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| format!("Repeater 会话 #{session_id} 不存在"))?;
    if actual_project_id != project_id {
        return Err("Repeater 会话不属于当前项目".to_string());
    }
    Ok(SessionContext {
        project_id,
        tls_policy: TlsPolicy::parse(&tls_policy)?,
    })
}

fn load_assessment_session_context(
    conn: &Connection,
    project_id: i64,
    assessment_run_id: i64,
    session_id: i64,
) -> Result<(SessionContext, AssessmentContractPreview), String> {
    let row: Option<(i64, String, String, String)> = conn
        .query_row(
            "SELECT s.project_id, s.tls_policy, ar.contract_json, ar.status
             FROM replay_sessions s
             JOIN assessment_runs ar ON ar.id = s.assessment_run_id
             WHERE s.id = ?1
               AND s.owner_kind = 'assessment'
               AND s.assessment_run_id = ?2
               AND ar.project_id = ?3",
            rusqlite::params![session_id, assessment_run_id, project_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let (actual_project_id, tls_policy, contract_json, status) =
        row.ok_or_else(|| "Assessment Replay 会话不存在或运行上下文不匹配".to_string())?;
    if !matches!(
        status.as_str(),
        "discovering" | "planning" | "executing" | "verifying"
    ) {
        return Err("Assessment run 当前状态不允许目标请求".into());
    }
    let preview: AssessmentContractPreview = serde_json::from_str(&contract_json)
        .map_err(|_| "Assessment 运行契约快照已损坏".to_string())?;
    Ok((
        SessionContext {
            project_id: actual_project_id,
            tls_policy: TlsPolicy::parse(&tls_policy)?,
        },
        preview,
    ))
}

fn load_project_run(conn: &Connection, project_id: i64, run_id: i64) -> Result<ReplayRun, String> {
    conn.query_row(
        &format!(
            "SELECT {RUN_DETAIL_SELECT} FROM replay_runs r
             JOIN replay_sessions s ON s.id = r.session_id
             WHERE r.id = ?1 AND r.project_id = ?2 AND s.owner_kind = 'manual'"
        ),
        rusqlite::params![run_id, project_id],
        replay_run_from_row,
    )
    .map_err(|_| format!("当前项目内不存在 Repeater run #{run_id}"))
}

fn ensure_project_exists(conn: &Connection, project_id: i64) -> Result<(), String> {
    let exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM projects WHERE id = ?1)",
            [project_id],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    exists
        .then_some(())
        .ok_or_else(|| format!("项目 #{project_id} 不存在"))
}

fn ensure_session_exists(conn: &Connection, session_id: i64) -> Result<(), String> {
    let exists: bool = conn
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM replay_sessions WHERE id = ?1 AND owner_kind = 'manual'
             )",
            [session_id],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    exists
        .then_some(())
        .ok_or_else(|| format!("Repeater 会话 #{session_id} 不存在"))
}

fn validate_title(title: &str) -> Result<String, String> {
    let title = title.trim();
    if title.is_empty() || title.chars().count() > MAX_SESSION_TITLE_CHARS {
        return Err(format!(
            "Repeater 会话标题必须为 1–{MAX_SESSION_TITLE_CHARS} 个字符"
        ));
    }
    Ok(title.to_string())
}

fn request_input_snapshot(
    request: &ReplayRequestInput,
) -> Result<ReplayRequestInputSnapshot, String> {
    let encoding = match (&request.body_text, &request.body_base64) {
        (None, None) => "none",
        (Some(_), None) => "text",
        (None, Some(_)) => "base64",
        (Some(_), Some(_)) => "ambiguous",
    };
    let canonical = serde_json::to_vec(&json!({
        "body_text": request.body_text,
        "body_base64": request.body_base64
    }))
    .map_err(|error| error.to_string())?;
    let original_size = request
        .body_text
        .as_ref()
        .map_or(0, String::len)
        .saturating_add(request.body_base64.as_ref().map_or(0, String::len));
    let mut remaining = MAX_REQUEST_INPUT_CAPTURE_BYTES;
    let text = request.body_text.as_deref().map(|value| {
        let captured = utf8_prefix(value, remaining);
        remaining = remaining.saturating_sub(captured.len());
        captured
    });
    let base64 = request.body_base64.as_deref().map(|value| {
        let captured = utf8_prefix(value, remaining);
        remaining = remaining.saturating_sub(captured.len());
        captured
    });
    let captured_size = text
        .as_ref()
        .map_or(0, String::len)
        .saturating_add(base64.as_ref().map_or(0, String::len));
    Ok(ReplayRequestInputSnapshot {
        encoding: encoding.to_string(),
        text,
        base64,
        original_size: i64::try_from(original_size).unwrap_or(i64::MAX),
        captured_size: i64::try_from(captured_size).unwrap_or(i64::MAX),
        truncated: captured_size < original_size,
        content_hash: sha256(&canonical),
    })
}

fn utf8_prefix(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

fn decode_body(
    body_text: Option<String>,
    body_base64: Option<String>,
) -> Result<Option<Vec<u8>>, String> {
    let body_text = body_text.filter(|body| !body.is_empty());
    let body_base64 = body_base64.filter(|body| !body.trim().is_empty());
    match (body_text, body_base64) {
        (Some(_), Some(_)) => Err("文本正文与 Base64 正文不能同时提交".to_string()),
        (Some(body), None) => Ok(Some(body.into_bytes())),
        (None, Some(body)) => {
            let compact: String = body
                .chars()
                .filter(|character| !character.is_ascii_whitespace())
                .collect();
            base64::engine::general_purpose::STANDARD
                .decode(compact)
                .map(Some)
                .map_err(|_| "Base64 请求体格式无效".to_string())
        }
        (None, None) => Ok(None),
    }
}

fn validated_header_map(
    headers: &[ReplayHeader],
) -> Result<(HeaderMap, Vec<ReplayHeader>), String> {
    let mut map = HeaderMap::new();
    let mut effective = Vec::new();
    for header in headers {
        let name = header.name.trim();
        if name.is_empty()
            || name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("host")
        {
            continue;
        }
        let name =
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| "请求头名称无效".to_string())?;
        let value =
            HeaderValue::from_str(&header.value).map_err(|_| "请求头值包含非法字节".to_string())?;
        map.append(name, value);
        effective.push(ReplayHeader {
            name: header.name.trim().to_string(),
            value: header.value.clone(),
        });
    }
    Ok((map, effective))
}

fn lenient_header_map(headers: &[ReplayHeader]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for header in headers {
        let Ok(name) = HeaderName::from_bytes(header.name.trim().as_bytes()) else {
            continue;
        };
        let Ok(value) = HeaderValue::from_str(&header.value) else {
            continue;
        };
        map.append(name, value);
    }
    map
}

fn allowed_scope_snapshot(decision: &crate::authorization::ScopeDecision) -> ReplayScopeSnapshot {
    ReplayScopeSnapshot {
        allowed: true,
        normalized_host: Some(decision.normalized_host.clone()),
        matched_scope: Some(decision.matched_scope.clone()),
        match_kind: Some(
            match decision.match_kind {
                ScopeMatchKind::Exact => "exact",
                ScopeMatchKind::Wildcard => "wildcard",
            }
            .to_string(),
        ),
        reason_code: None,
        reason: None,
    }
}

fn denied_scope_snapshot(error: &AuthorizationError) -> ReplayScopeSnapshot {
    let normalized_host = match error {
        AuthorizationError::OutOfScope(host) => Some(host.clone()),
        _ => None,
    };
    ReplayScopeSnapshot {
        allowed: false,
        normalized_host,
        matched_scope: None,
        match_kind: None,
        reason_code: Some(error.code().to_string()),
        reason: Some(error.to_string()),
    }
}

fn hash_request_input(
    method: &str,
    url: &str,
    headers: &[ReplayHeader],
    body_text: Option<&str>,
    body_base64: Option<&str>,
    tls_policy: TlsPolicy,
) -> Result<String, String> {
    let body = match (body_text, body_base64) {
        (Some(text), None) => json!({
            "encoding": "text",
            "sha256": sha256(text.as_bytes()),
            "input_bytes": text.len()
        }),
        (None, Some(base64)) => json!({
            "encoding": "base64",
            "sha256": sha256(base64.as_bytes()),
            "input_bytes": base64.len()
        }),
        (Some(text), Some(base64)) => json!({
            "encoding": "ambiguous",
            "text_sha256": sha256(text.as_bytes()),
            "base64_sha256": sha256(base64.as_bytes())
        }),
        (None, None) => Value::Null,
    };
    let canonical = serde_json::to_vec(&json!({
        "method": method,
        "url": url,
        "headers": headers,
        "body": body,
        "tls_policy": tls_policy.as_str()
    }))
    .map_err(|error| error.to_string())?;
    Ok(sha256(&canonical))
}

fn hash_effective_request(
    method: &str,
    url: &str,
    headers: &[ReplayHeader],
    body: Option<&[u8]>,
    tls_policy: TlsPolicy,
) -> Result<String, String> {
    let body = body.unwrap_or_default();
    let canonical = serde_json::to_vec(&json!({
        "method": method,
        "url": url,
        "headers": headers,
        "body_sha256": sha256(body),
        "body_wire_size": body.len(),
        "tls_policy": tls_policy.as_str()
    }))
    .map_err(|error| error.to_string())?;
    Ok(sha256(&canonical))
}

fn hash_assessment_effective_request(
    method: &str,
    url: &str,
    audit_headers: &[ReplayHeader],
    tls_policy: TlsPolicy,
    request_hash_context: &str,
) -> Result<String, String> {
    let canonical = serde_json::to_vec(&json!({
        "mode": "assessment",
        "method": method,
        "url": url,
        "headers": audit_headers,
        "body_sha256": sha256(&[]),
        "body_wire_size": 0,
        "tls_policy": tls_policy.as_str(),
        "profile_revision_context": request_hash_context
    }))
    .map_err(|error| error.to_string())?;
    Ok(sha256(&canonical))
}

fn validate_assessment_header_views(
    live_headers: &[ReplayHeader],
    audit_headers: &[ReplayHeader],
) -> Result<(), String> {
    if live_headers.len() != audit_headers.len() || live_headers.len() > 64 {
        return Err("Assessment 线上 Header 与审计 Header 结构不一致".into());
    }
    for (live, audit) in live_headers.iter().zip(audit_headers) {
        if !live.name.eq_ignore_ascii_case(&audit.name)
            || live.name.contains(['\r', '\n'])
            || live.value.contains(['\r', '\n'])
            || audit.name.contains(['\r', '\n'])
            || audit.value.contains(['\r', '\n'])
        {
            return Err("Assessment 线上 Header 与审计 Header 结构不一致".into());
        }
        if is_auth_header(&live.name) {
            if !is_auth_profile_placeholder(&audit.value) {
                return Err("Assessment 鉴权 Header 必须使用 profile 占位符审计".into());
            }
        } else if live.value != audit.value {
            return Err("非鉴权 Header 的线上值与审计值必须完全一致".into());
        }
    }
    Ok(())
}

fn is_auth_header(name: &str) -> bool {
    matches!(
        name.trim().to_ascii_lowercase().as_str(),
        "authorization" | "cookie" | "x-api-key" | "x-auth-token"
    )
}

fn is_auth_profile_placeholder(value: &str) -> bool {
    value
        .strip_prefix("[AUTH_PROFILE:")
        .and_then(|value| value.strip_suffix(']'))
        .is_some_and(|id| !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit()))
}

fn assessment_header_secrets(
    live_headers: &[ReplayHeader],
    audit_headers: &[ReplayHeader],
) -> Vec<String> {
    let mut values = live_headers
        .iter()
        .zip(audit_headers)
        .filter(|(live, _)| is_auth_header(&live.name))
        .flat_map(|(live, _)| {
            crate::assessment::service::auth_secret_redaction_values(&live.name, &live.value)
        })
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values.sort_by_key(|value| std::cmp::Reverse(value.len()));
    values
}

fn redact_known_text(value: &str, known_secrets: &[String]) -> String {
    let references = known_secrets.iter().map(String::as_str).collect::<Vec<_>>();
    crate::secrets::redact_sensitive(value, &references)
}

fn redact_known_bytes(value: &[u8], known_secrets: &[String]) -> Vec<u8> {
    let mut redacted = value.to_vec();
    for secret in known_secrets {
        if !secret.is_empty() {
            redacted = replace_bytes(&redacted, secret.as_bytes(), b"[REDACTED]");
        }
    }
    redacted
}

fn replace_bytes(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        return haystack.to_vec();
    }
    let mut output = Vec::with_capacity(haystack.len());
    let mut start = 0;
    while let Some(offset) = haystack[start..]
        .windows(needle.len())
        .position(|window| window == needle)
    {
        let position = start + offset;
        output.extend_from_slice(&haystack[start..position]);
        output.extend_from_slice(replacement);
        start = position + needle.len();
    }
    output.extend_from_slice(&haystack[start..]);
    output
}

fn safe_reqwest_error(error: &reqwest::Error) -> (&'static str, String) {
    if error.is_timeout() {
        ("TIMEOUT", "请求超时（30 秒）".to_string())
    } else if error.is_connect() {
        (
            "CONNECT_FAILED",
            "无法连接目标或 TLS 握手失败；未保存可能含敏感参数的底层 URL".to_string(),
        )
    } else if error.is_request() {
        ("REQUEST_FAILED", "构造或发送 HTTP 请求失败".to_string())
    } else {
        ("NETWORK_FAILED", "HTTP 请求未完成".to_string())
    }
}

fn header_value_for_storage(value: &HeaderValue) -> String {
    value.to_str().map(str::to_string).unwrap_or_else(|_| {
        format!(
            "base64:{}",
            base64::engine::general_purpose::STANDARD.encode(value.as_bytes())
        )
    })
}

fn elapsed_millis(started: Instant) -> i64 {
    i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX)
}

fn bytes_or_none(bytes: Vec<u8>) -> Option<Vec<u8>> {
    (!bytes.is_empty()).then_some(bytes)
}

fn bounded_non_empty(value: &str, max_bytes: usize, fallback: &str) -> String {
    let value = if value.is_empty() { fallback } else { value };
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

fn body_representation(
    body: Option<&[u8]>,
    decode_status: &str,
) -> (Option<String>, Option<String>) {
    let Some(body) = body else {
        return (None, None);
    };
    if is_text_status(decode_status) {
        if let Ok(text) = std::str::from_utf8(body) {
            return (Some(text.to_string()), None);
        }
    }
    (
        None,
        Some(base64::engine::general_purpose::STANDARD.encode(body)),
    )
}

fn wire_body_representation(
    body: Option<&[u8]>,
    decode_status: &str,
) -> (Option<String>, Option<String>) {
    let Some(body) = body else {
        return (None, None);
    };
    if matches!(decode_status, "empty" | "identity_text") {
        if let Ok(text) = std::str::from_utf8(body) {
            return (Some(text.to_string()), None);
        }
    }
    (
        None,
        Some(base64::engine::general_purpose::STANDARD.encode(body)),
    )
}

fn is_text_status(status: &str) -> bool {
    matches!(status, "empty" | "identity_text" | "decoded_text")
}

fn build_diff(left: ReplayRun, right: ReplayRun) -> ReplayRunDiff {
    ReplayRunDiff {
        left_run_id: left.id,
        right_run_id: right.id,
        method: ReplayValueDiff::new(left.method.clone(), right.method.clone()),
        url: ReplayValueDiff::new(left.url.clone(), right.url.clone()),
        request_headers: ReplayValueDiff::new(
            left.request_headers.clone(),
            right.request_headers.clone(),
        ),
        request_body: body_diff(&left, &right, true),
        tls_policy: ReplayValueDiff::new(left.tls_policy.clone(), right.tls_policy.clone()),
        scope_decision: ReplayValueDiff::new(
            left.scope_decision.clone(),
            right.scope_decision.clone(),
        ),
        outcome: ReplayValueDiff::new(left.outcome.clone(), right.outcome.clone()),
        status: ReplayValueDiff::new(left.status, right.status),
        duration_ms: ReplayValueDiff::new(left.duration_ms, right.duration_ms),
        response_headers: ReplayValueDiff::new(
            left.response_headers.clone(),
            right.response_headers.clone(),
        ),
        response_body: body_diff(&left, &right, false),
    }
}

fn body_diff(
    left: &ReplayRun,
    right: &ReplayRun,
    request: bool,
) -> ReplayValueDiff<ReplayBodySnapshot> {
    let left_snapshot = body_snapshot(left, request);
    let right_snapshot = body_snapshot(right, request);
    let (changed, indeterminate) = match (
        left_snapshot.full_hash.as_deref(),
        right_snapshot.full_hash.as_deref(),
    ) {
        (Some(left_hash), Some(right_hash)) => (left_hash != right_hash, false),
        _ if body_observation_equal(&left_snapshot, &right_snapshot) => {
            (false, left_snapshot.truncated || right_snapshot.truncated)
        }
        _ => (true, false),
    };
    ReplayValueDiff {
        changed,
        indeterminate,
        left: left_snapshot,
        right: right_snapshot,
    }
}

fn body_observation_equal(left: &ReplayBodySnapshot, right: &ReplayBodySnapshot) -> bool {
    left.encoding == right.encoding
        && left.text == right.text
        && left.base64 == right.base64
        && left.wire_size == right.wire_size
        && left.captured_size == right.captured_size
        && left.truncated == right.truncated
        && left.decode_status == right.decode_status
        && left.captured_hash == right.captured_hash
}

fn body_snapshot(run: &ReplayRun, request: bool) -> ReplayBodySnapshot {
    let (text, base64, wire_size, captured_size, truncated, decode_status, full_hash) = if request {
        (
            run.request_body_text.clone(),
            run.request_body_base64.clone(),
            run.req_wire_size,
            run.req_captured_size,
            run.req_truncated,
            run.req_decode_status.clone(),
            run.req_body_hash
                .clone()
                .or_else(|| Some(run.request_input.content_hash.clone())),
        )
    } else {
        (
            run.response_body_text.clone(),
            run.response_body_base64.clone(),
            run.resp_wire_size,
            run.resp_captured_size,
            run.resp_truncated,
            run.resp_decode_status.clone(),
            run.resp_body_hash.clone(),
        )
    };
    let (encoding, captured_bytes) = if let Some(text) = &text {
        ("text", text.as_bytes().to_vec())
    } else if let Some(encoded) = &base64 {
        (
            "base64",
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .unwrap_or_default(),
        )
    } else {
        ("empty", Vec::new())
    };
    ReplayBodySnapshot {
        encoding: encoding.to_string(),
        text,
        base64,
        wire_size,
        captured_size,
        truncated,
        decode_status,
        captured_hash: sha256(&captured_bytes),
        full_hash,
    }
}

pub(crate) fn headers_to_multimap_json(headers: &[ReplayHeader]) -> Result<String, String> {
    let mut grouped = serde_json::Map::new();
    for header in headers {
        let name = header.name.trim().to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }
        match grouped.get_mut(&name) {
            Some(Value::String(existing)) => {
                let first = std::mem::take(existing);
                grouped.insert(
                    name,
                    Value::Array(vec![
                        Value::String(first),
                        Value::String(header.value.clone()),
                    ]),
                );
            }
            Some(Value::Array(values)) => values.push(Value::String(header.value.clone())),
            Some(_) => {}
            None => {
                grouped.insert(name, Value::String(header.value.clone()));
            }
        }
    }
    serde_json::to_string(&Value::Object(grouped)).map_err(|error| error.to_string())
}

fn sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assessment::model::AssessmentContractInput;
    use crate::evidence::{self, EvidenceSourceType};
    use crate::secrets::MemorySecretStore;
    use crate::storage::db::open_pool;
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write as _;
    use std::path::Path;
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio::time::{timeout, Duration};

    fn test_pool(dir: &TempDir) -> Pool {
        open_pool(&dir.path().join("replay.db")).unwrap()
    }

    fn insert_project(pool: &Pool, scope: &[String]) -> i64 {
        let conn = pool.get().unwrap();
        conn.execute(
            "INSERT INTO projects(name, scope) VALUES('p', ?1)",
            [serde_json::to_string(scope).unwrap()],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    fn create_test_session(pool: &Pool, project_id: i64) -> ReplaySession {
        let mut conn = pool.get().unwrap();
        create_session(
            &mut conn,
            project_id,
            "session",
            None,
            TlsPolicy::IgnoreInvalid,
        )
        .unwrap()
    }

    fn create_test_assessment(pool: &Pool, project_id: i64, start_url: &str) -> (i64, i64) {
        let store = MemorySecretStore::default();
        let mut conn = pool.get().unwrap();
        let preview = crate::assessment::service::preview_contract(
            &conn,
            &store,
            &AssessmentContractInput {
                project_id,
                start_url: start_url.into(),
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
        let run = crate::assessment::service::create_run(&mut conn, &preview).unwrap();
        crate::assessment::service::transition_run(
            &mut conn,
            project_id,
            run.id,
            crate::assessment::model::AssessmentStatus::Discovering,
            None,
        )
        .unwrap();
        let session_id =
            create_assessment_session(&conn, project_id, run.id, TlsPolicy::Strict).unwrap();
        (run.id, session_id)
    }

    fn assessment_request(
        url: String,
        live_headers: Vec<ReplayHeader>,
        audit_headers: Vec<ReplayHeader>,
        context: &str,
        max_response_bytes: u64,
    ) -> AssessmentReplayRequest {
        AssessmentReplayRequest {
            method: "GET".into(),
            url,
            live_headers,
            audit_headers,
            request_hash_context: context.into(),
            max_response_bytes,
        }
    }

    fn empty_input_snapshot() -> ReplayRequestInputSnapshot {
        request_input_snapshot(&ReplayRequestInput {
            method: "GET".into(),
            url: "https://example.test/".into(),
            headers: Vec::new(),
            body_text: None,
            body_base64: None,
        })
        .unwrap()
    }

    fn persist_denied_test_run(pool: &Pool, session_id: i64, project_id: i64) -> ReplayRun {
        persist_run(
            pool,
            PersistRun {
                attempt_id: None,
                session_id,
                project_id,
                method: "GET".into(),
                url: "https://outside.test/".into(),
                request_headers: Vec::new(),
                request_wire_body: None,
                req_wire_captured_size: 0,
                req_wire_truncated: false,
                request_input: empty_input_snapshot(),
                request_body: None,
                req_wire_size: 0,
                req_captured_size: 0,
                req_truncated: false,
                req_decode_status: "empty".into(),
                tls_policy: TlsPolicy::Strict,
                scope_decision: ReplayScopeSnapshot {
                    allowed: false,
                    normalized_host: Some("outside.test".into()),
                    matched_scope: None,
                    match_kind: None,
                    reason_code: Some("OUT_OF_SCOPE".into()),
                    reason: Some("[OUT_OF_SCOPE] denied".into()),
                },
                outcome: "scope_rejected",
                error_code: Some("OUT_OF_SCOPE".into()),
                error_message: Some("[OUT_OF_SCOPE] denied".into()),
                status: None,
                status_text: String::new(),
                response_headers: Vec::new(),
                response_body: None,
                resp_wire_size: 0,
                resp_captured_size: 0,
                resp_truncated: false,
                resp_decode_status: "not_received".into(),
                duration_ms: 0,
                request_hash: "a".repeat(64),
                req_body_hash: Some(sha256(&[])),
                response_hash: None,
                resp_body_hash: None,
            },
        )
        .unwrap()
    }

    #[test]
    fn sessions_history_and_selected_state_survive_reopen_and_cascade_cleanly() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("persistent.db");
        let pool = open_pool(&path).unwrap();
        let project_id = insert_project(&pool, &["example.test".to_string()]);
        let second_id;
        {
            let mut conn = pool.get().unwrap();
            create_session(&mut conn, project_id, "first", None, TlsPolicy::Strict).unwrap();
            let second = create_session(
                &mut conn,
                project_id,
                "second",
                None,
                TlsPolicy::IgnoreInvalid,
            )
            .unwrap();
            assert!(second.is_selected);
            second_id = second.id;
        }
        persist_denied_test_run(&pool, second_id, project_id);
        drop(pool);

        let reopened = open_pool(Path::new(&path)).unwrap();
        let mut conn = reopened.get().unwrap();
        let sessions = list_sessions(&conn, project_id).unwrap();
        assert_eq!(sessions.len(), 2);
        assert!(!sessions[0].is_selected);
        assert!(sessions[1].is_selected);
        assert_eq!(sessions[1].tls_policy, "ignore_invalid");
        let runs = list_runs(&conn, second_id, None, None).unwrap();
        assert_eq!(runs.runs.len(), 1);
        assert_eq!(runs.runs[0].outcome, "scope_rejected");
        assert!(
            conn.execute("DELETE FROM replay_runs WHERE id = ?1", [runs.runs[0].id])
                .is_err(),
            "run 在会话存续期间不能被单独删除"
        );

        delete_session(&mut conn, second_id).unwrap();
        assert!(list_runs(&conn, second_id, None, None).is_err());
        let run_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM replay_runs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(run_count, 0, "删除会话应级联删除不可变 run");

        let remaining = list_sessions(&conn, project_id).unwrap();
        assert_eq!(remaining.len(), 1);
        assert!(remaining[0].is_selected);
        persist_denied_test_run(&reopened, remaining[0].id, project_id);
        conn.execute("DELETE FROM projects WHERE id = ?1", [project_id])
            .unwrap();
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM replay_runs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 0, "项目生命周期级联必须能清理 run");
    }

    #[tokio::test]
    async fn out_of_scope_click_is_persisted_without_network_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let dir = TempDir::new().unwrap();
        let pool = test_pool(&dir);
        let project_id = insert_project(&pool, &["example.test".to_string()]);
        let session = create_test_session(&pool, project_id);

        let run = execute_request(
            pool.clone(),
            project_id,
            session.id,
            ReplayRequestInput {
                method: "GET".into(),
                url: format!("http://{address}/must-not-connect"),
                headers: Vec::new(),
                body_text: None,
                body_base64: None,
            },
        )
        .await
        .unwrap();

        assert_eq!(run.outcome, "scope_rejected");
        assert_eq!(run.error_code.as_deref(), Some("OUT_OF_SCOPE"));
        assert!(run.status.is_none());
        assert!(run.response_headers.is_empty());
        assert!(
            timeout(Duration::from_millis(150), listener.accept())
                .await
                .is_err(),
            "Scope 拒绝后不应建立 TCP 连接"
        );
        let conn = pool.get().unwrap();
        assert_eq!(
            list_runs(&conn, session.id, None, None).unwrap().runs.len(),
            1
        );
    }

    #[tokio::test]
    async fn assessment_policy_rejection_never_creates_a_socket_or_attempt() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let dir = TempDir::new().unwrap();
        let pool = test_pool(&dir);
        let project_id = insert_project(&pool, &["127.0.0.1".to_string()]);
        let (run_id, session_id) =
            create_test_assessment(&pool, project_id, &format!("http://{address}/safe"));
        let (_cancel_tx, cancel) = watch::channel(false);
        let error = execute_assessment_request(
            pool.clone(),
            project_id,
            run_id,
            session_id,
            assessment_request(
                format!("http://{address}/account/%2564elete"),
                Vec::new(),
                Vec::new(),
                "anonymous:policy-test",
                1024,
            ),
            cancel,
        )
        .await
        .unwrap_err();
        assert!(error.contains("DESTRUCTIVE_PATH"));
        assert!(
            timeout(Duration::from_millis(150), listener.accept())
                .await
                .is_err(),
            "AssessmentPolicy 拒绝必须发生在 socket 创建之前"
        );
        let conn = pool.get().unwrap();
        let attempts: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM replay_attempts WHERE session_id = ?1",
                [session_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(attempts, 0);
    }

    #[tokio::test]
    async fn assessment_uses_live_credentials_but_persists_only_placeholders() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let first_secret = "Bearer credential-alpha-123456";
        let second_secret = "Bearer credential-beta-654321";
        let expected = vec![first_secret.to_string(), second_secret.to_string()];
        let server = tokio::spawn(async move {
            let mut observed = Vec::new();
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let mut chunk = [0_u8; 1024];
                    let read = socket.read(&mut chunk).await.unwrap();
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let request_text = String::from_utf8_lossy(&request);
                let authorization = request_text
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("authorization: ")
                            .or_else(|| line.strip_prefix("Authorization: "))
                    })
                    .unwrap()
                    .trim()
                    .to_string();
                observed.push(authorization.clone());
                let bare = authorization.split_once(' ').unwrap().1;
                let encoded = base64::engine::general_purpose::STANDARD.encode(bare);
                let body = format!("full={authorization}; bare={bare}; encoded={encoded}");
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Reflected: {bare}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
            observed
        });

        let dir = TempDir::new().unwrap();
        let pool = test_pool(&dir);
        let project_id = insert_project(&pool, &["127.0.0.1".to_string()]);
        let url = format!("http://{address}/credential-reflection");
        let (run_id, session_id) = create_test_assessment(&pool, project_id, &url);
        let audit = vec![ReplayHeader {
            name: "Authorization".into(),
            value: "[AUTH_PROFILE:7]".into(),
        }];
        let mut runs = Vec::new();
        for secret in [first_secret, second_secret] {
            let (_cancel_tx, cancel) = watch::channel(false);
            runs.push(
                execute_assessment_request(
                    pool.clone(),
                    project_id,
                    run_id,
                    session_id,
                    assessment_request(
                        url.clone(),
                        vec![ReplayHeader {
                            name: "Authorization".into(),
                            value: secret.into(),
                        }],
                        audit.clone(),
                        "profile:7:revision:1",
                        4096,
                    ),
                    cancel,
                )
                .await
                .unwrap(),
            );
        }
        assert_eq!(server.await.unwrap(), expected);
        assert_eq!(runs[0].request_hash, runs[1].request_hash);
        assert_ne!(
            runs[0].resp_body_hash, runs[1].resp_body_hash,
            "raw response hashes must not collapse after credential redaction"
        );
        for (run, secret) in runs.iter().zip([first_secret, second_secret]) {
            let serialized = serde_json::to_string(run).unwrap();
            let bare = secret.split_once(' ').unwrap().1;
            let encoded = base64::engine::general_purpose::STANDARD.encode(bare);
            assert!(!serialized.contains(secret));
            assert!(!serialized.contains(bare));
            assert!(!serialized.contains(&encoded));
            assert!(serialized.contains("[AUTH_PROFILE:7]"));
            assert!(serialized.contains("[REDACTED]"));
        }
        let conn = pool.get().unwrap();
        let persisted: String = conn
            .query_row(
                "SELECT group_concat(
                     request_headers || ' ' || response_headers || ' ' ||
                     COALESCE(CAST(response_body AS TEXT), '') || ' ' ||
                     COALESCE(error_message, '') || ' ' || request_hash,
                     ' '
                 ) FROM replay_runs WHERE session_id = ?1",
                [session_id],
                |row| row.get(0),
            )
            .unwrap();
        for secret in [first_secret, second_secret] {
            assert!(!persisted.contains(secret));
            assert!(!persisted.contains(secret.split_once(' ').unwrap().1));
        }
    }

    #[tokio::test]
    async fn assessment_does_not_follow_redirects() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (follow_tx, follow_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 2048];
            let _ = socket.read(&mut request).await.unwrap();
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{address}/must-not-follow\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            let followed = timeout(Duration::from_millis(250), listener.accept())
                .await
                .is_ok();
            let _ = follow_tx.send(followed);
        });
        let dir = TempDir::new().unwrap();
        let pool = test_pool(&dir);
        let project_id = insert_project(&pool, &["127.0.0.1".to_string()]);
        let url = format!("http://{address}/redirect");
        let (run_id, session_id) = create_test_assessment(&pool, project_id, &url);
        let (_cancel_tx, cancel) = watch::channel(false);
        let run = execute_assessment_request(
            pool,
            project_id,
            run_id,
            session_id,
            assessment_request(url, Vec::new(), Vec::new(), "anonymous", 1024),
            cancel,
        )
        .await
        .unwrap();
        assert_eq!(run.status, Some(302));
        assert!(!follow_rx.await.unwrap());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn assessment_response_limit_and_cancellation_are_audited_as_incomplete() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 2048];
            let _ = socket.read(&mut request).await.unwrap();
            let body = vec![b'x'; 16 * 1024];
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            socket.write_all(headers.as_bytes()).await.unwrap();
            let _ = socket.write_all(&body).await;
        });
        let dir = TempDir::new().unwrap();
        let pool = test_pool(&dir);
        let project_id = insert_project(&pool, &["127.0.0.1".to_string()]);
        let url = format!("http://{address}/large");
        let (run_id, session_id) = create_test_assessment(&pool, project_id, &url);
        let (_cancel_tx, cancel) = watch::channel(false);
        let limited = execute_assessment_request(
            pool.clone(),
            project_id,
            run_id,
            session_id,
            assessment_request(url, Vec::new(), Vec::new(), "anonymous", 1024),
            cancel,
        )
        .await
        .unwrap();
        server.await.unwrap();
        assert_eq!(limited.outcome, "response_incomplete");
        assert_eq!(limited.error_code.as_deref(), Some("RESPONSE_LIMIT"));
        assert!(limited.resp_captured_size <= 1024);
        assert!(limited.resp_body_hash.is_none());

        let waiting_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let waiting_address = waiting_listener.local_addr().unwrap();
        let (accepted_tx, accepted_rx) = oneshot::channel();
        let waiting_server = tokio::spawn(async move {
            let (mut socket, _) = waiting_listener.accept().await.unwrap();
            let mut request = [0_u8; 2048];
            let _ = socket.read(&mut request).await.unwrap();
            let _ = accepted_tx.send(());
            tokio::time::sleep(Duration::from_secs(2)).await;
        });
        // A new run is required because the persisted exact origin is immutable.
        {
            let mut conn = pool.get().unwrap();
            crate::assessment::service::transition_run(
                &mut conn,
                project_id,
                run_id,
                crate::assessment::model::AssessmentStatus::Cancelled,
                Some("fixture_complete"),
            )
            .unwrap();
        }
        let waiting_url = format!("http://{waiting_address}/wait");
        let (waiting_run_id, waiting_session_id) =
            create_test_assessment(&pool, project_id, &waiting_url);
        let (cancel_tx, cancel) = watch::channel(false);
        let request_task = tokio::spawn(execute_assessment_request(
            pool.clone(),
            project_id,
            waiting_run_id,
            waiting_session_id,
            assessment_request(waiting_url, Vec::new(), Vec::new(), "anonymous", 1024),
            cancel,
        ));
        accepted_rx.await.unwrap();
        cancel_tx.send(true).unwrap();
        let cancelled = request_task.await.unwrap().unwrap();
        waiting_server.abort();
        assert_eq!(cancelled.outcome, "request_failed");
        assert_eq!(
            cancelled.error_code.as_deref(),
            Some("ASSESSMENT_CANCELLED")
        );
        assert!(cancelled.attempt_id.is_some());
    }

    #[tokio::test]
    async fn invalid_base64_is_persisted_with_original_input_without_network() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let dir = TempDir::new().unwrap();
        let pool = test_pool(&dir);
        let project_id = insert_project(&pool, &["127.0.0.1".to_string()]);
        let session = create_test_session(&pool, project_id);
        let original = "%%% definitely-not-base64 %%%";

        let run = execute_request(
            pool,
            project_id,
            session.id,
            ReplayRequestInput {
                method: "POST".into(),
                url: format!("http://{address}/must-not-connect"),
                headers: Vec::new(),
                body_text: None,
                body_base64: Some(original.into()),
            },
        )
        .await
        .unwrap();

        assert_eq!(run.outcome, "request_failed");
        assert_eq!(run.error_code.as_deref(), Some("INVALID_REPLAY_BODY"));
        assert_eq!(run.request_input.encoding, "base64");
        assert_eq!(run.request_input.base64.as_deref(), Some(original));
        assert_eq!(run.request_input.original_size, original.len() as i64);
        assert!(!run.request_input.truncated);
        assert!(run.request_wire_body_text.is_none());
        assert!(run.request_wire_body_base64.is_none());
        assert_eq!(run.req_decode_status, "not_received");
        assert!(
            timeout(Duration::from_millis(150), listener.accept())
                .await
                .is_err(),
            "Base64 构造失败不能建立 TCP 连接"
        );
    }

    #[tokio::test]
    async fn compressed_request_persists_wire_bytes_separately_from_decoded_preview() {
        let plain = b"the exact decoded request preview".repeat(8);
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&plain).unwrap();
        let compressed = encoder.finish().unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&compressed);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 8192];
            let _ = socket.read(&mut request).await.unwrap();
            socket
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        });

        let dir = TempDir::new().unwrap();
        let pool = test_pool(&dir);
        let project_id = insert_project(&pool, &["127.0.0.1".to_string()]);
        let session = create_test_session(&pool, project_id);
        let run = execute_request(
            pool,
            project_id,
            session.id,
            ReplayRequestInput {
                method: "POST".into(),
                url: format!("http://{address}/compressed"),
                headers: vec![
                    ReplayHeader {
                        name: "Content-Type".into(),
                        value: "text/plain; charset=utf-8".into(),
                    },
                    ReplayHeader {
                        name: "Content-Encoding".into(),
                        value: "gzip".into(),
                    },
                ],
                body_text: None,
                body_base64: Some(encoded),
            },
        )
        .await
        .unwrap();
        server.await.unwrap();

        assert_eq!(run.outcome, "completed");
        assert_eq!(run.req_decode_status, "decoded_text");
        assert_eq!(
            run.request_body_text.as_deref(),
            std::str::from_utf8(&plain).ok()
        );
        assert!(run.request_wire_body_text.is_none());
        let restored_wire = base64::engine::general_purpose::STANDARD
            .decode(run.request_wire_body_base64.as_deref().unwrap())
            .unwrap();
        assert_eq!(restored_wire, compressed);
        assert_eq!(run.req_wire_captured_size, compressed.len() as i64);
        assert_eq!(
            run.req_body_hash.as_deref(),
            Some(sha256(&compressed).as_str())
        );
        assert!(run.request_headers.iter().any(|header| header
            .name
            .eq_ignore_ascii_case("content-encoding")
            && header.value == "gzip"));
    }

    #[tokio::test]
    async fn request_attempt_is_durable_before_the_server_observes_network() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let dir = TempDir::new().unwrap();
        let pool = test_pool(&dir);
        let project_id = insert_project(&pool, &["127.0.0.1".to_string()]);
        let session = create_test_session(&pool, project_id);
        let audit_pool = pool.clone();
        let session_id = session.id;
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let conn = audit_pool.get().unwrap();
            let state: (i64, i64) = conn
                .query_row(
                    "SELECT
                         (SELECT COUNT(*) FROM replay_attempts WHERE session_id = ?1),
                         (SELECT COUNT(*) FROM replay_runs WHERE session_id = ?1)",
                    [session_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            drop(conn);
            let expected_body = b"audit-before-network";
            let mut request = Vec::new();
            loop {
                let mut chunk = [0; 1024];
                let read = socket.read(&mut chunk).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
                if request
                    .windows(expected_body.len())
                    .any(|window| window == expected_body)
                {
                    break;
                }
            }
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
            state
        });

        let run = execute_request(
            pool,
            project_id,
            session.id,
            ReplayRequestInput {
                method: "POST".into(),
                url: format!("http://{address}/side-effect"),
                headers: Vec::new(),
                body_text: Some("audit-before-network".into()),
                body_base64: None,
            },
        )
        .await
        .unwrap();
        let observed = server.await.unwrap();

        assert_eq!(
            observed,
            (1, 0),
            "目标接受连接时 attempt 必须已提交，最终 run 尚未产生"
        );
        assert_eq!(run.outcome, "completed");
        assert!(run.attempt_id.is_some());
    }

    #[test]
    fn pending_attempt_blocks_deletion_and_recovers_as_interrupted_run() {
        let dir = TempDir::new().unwrap();
        let pool = test_pool(&dir);
        let project_id = insert_project(&pool, &["example.test".to_string()]);
        let session = create_test_session(&pool, project_id);
        let request = ReplayRequestInput {
            method: "POST".into(),
            url: "https://example.test/side-effect".into(),
            headers: Vec::new(),
            body_text: Some("payload".into()),
            body_base64: None,
        };
        let input = request_input_snapshot(&request).unwrap();
        let prepared = request_with_capture(
            request.method,
            request.url,
            Vec::new(),
            HeaderMap::new(),
            Some(b"payload".to_vec()),
            input,
            "a".repeat(64),
        );
        let scope = ReplayScopeSnapshot {
            allowed: true,
            normalized_host: Some("example.test".into()),
            matched_scope: Some("example.test".into()),
            match_kind: Some("exact".into()),
            reason_code: None,
            reason: None,
        };
        let context = SessionContext {
            project_id,
            tls_policy: TlsPolicy::IgnoreInvalid,
        };
        let (attempt_id, guard) =
            persist_attempt(&pool, &context, session.id, &prepared, &scope).unwrap();

        let mut conn = pool.get().unwrap();
        assert_eq!(recover_interrupted_attempts(&conn).unwrap(), 0);
        let delete_error = delete_session(&mut conn, session.id).unwrap_err();
        assert!(delete_error.contains("in-flight request"));

        drop(guard);
        assert_eq!(recover_interrupted_attempts(&conn).unwrap(), 1);
        let page = list_runs(&conn, session.id, None, None).unwrap();
        assert_eq!(page.runs.len(), 1);
        let recovered = load_run(&conn, page.runs[0].id).unwrap();
        assert_eq!(recovered.attempt_id, Some(attempt_id));
        assert_eq!(recovered.outcome, "request_failed");
        assert_eq!(recovered.error_code.as_deref(), Some("APP_INTERRUPTED"));
        assert_eq!(recovered.request_wire_body_text.as_deref(), Some("payload"));
        assert!(recovered
            .error_message
            .as_deref()
            .unwrap()
            .contains("可能已产生网络副作用"));

        delete_session(&mut conn, session.id).unwrap();
    }

    #[test]
    fn failed_replay_evidence_cannot_confirm_a_finding() {
        let dir = TempDir::new().unwrap();
        let pool = test_pool(&dir);
        let project_id = insert_project(&pool, &["example.test".to_string()]);
        let session = create_test_session(&pool, project_id);
        let failed = persist_denied_test_run(&pool, session.id, project_id);
        let mut conn = pool.get().unwrap();
        conn.execute(
            "INSERT INTO findings(project_id, source, title)
             VALUES(?1, 'rule', 'candidate')",
            [project_id],
        )
        .unwrap();
        let finding_id = conn.last_insert_rowid();

        let item = evidence::service::create_finding_evidence(
            &mut conn,
            finding_id,
            EvidenceSourceType::ReplayRun,
            failed.id,
            "仅记录 Scope 拒绝",
            "analyst",
        )
        .unwrap();
        assert!(!item.qualifies_for_confirmation);
        let accepted = evidence::service::set_finding_evidence_accepted(
            &mut conn,
            finding_id,
            item.id,
            true,
            "接受为审计记录",
            "analyst",
        )
        .unwrap();
        assert!(accepted.accepted);
        assert!(!accepted.qualifies_for_confirmation);

        let error = evidence::service::update_finding_status(
            &mut conn,
            finding_id,
            "confirmed",
            Some("attempted confirmation"),
            "analyst",
        )
        .unwrap_err();
        assert!(error.contains("具备响应验证结果"));
        let direct_error = conn
            .execute(
                "UPDATE findings SET status = 'confirmed' WHERE id = ?1",
                [finding_id],
            )
            .unwrap_err();
        assert!(direct_error
            .to_string()
            .contains("confirmed finding requires accepted evidence"));
    }

    #[tokio::test]
    async fn every_run_keeps_its_request_snapshot_and_can_become_evidence() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = vec![0; 4096];
                let _ = socket.read(&mut request).await.unwrap();
                socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await
                    .unwrap();
            }
        });

        let dir = TempDir::new().unwrap();
        let pool = test_pool(&dir);
        let project_id = insert_project(&pool, &["127.0.0.1".to_string()]);
        let session = create_test_session(&pool, project_id);
        let url = format!("http://{address}/echo");
        let first = execute_request(
            pool.clone(),
            project_id,
            session.id,
            ReplayRequestInput {
                method: "POST".into(),
                url: url.clone(),
                headers: vec![
                    ReplayHeader {
                        name: "Content-Type".into(),
                        value: "text/plain".into(),
                    },
                    ReplayHeader {
                        name: "Authorization".into(),
                        value: "Bearer replay-secret-token".into(),
                    },
                ],
                body_text: Some("first".into()),
                body_base64: None,
            },
        )
        .await
        .unwrap();
        let second = execute_request(
            pool.clone(),
            project_id,
            session.id,
            ReplayRequestInput {
                method: "POST".into(),
                url,
                headers: Vec::new(),
                body_text: Some("second".into()),
                body_base64: None,
            },
        )
        .await
        .unwrap();
        server.await.unwrap();

        assert_eq!(first.request_body_text.as_deref(), Some("first"));
        assert_eq!(second.request_body_text.as_deref(), Some("second"));
        assert_ne!(first.request_hash, second.request_hash);
        assert_eq!(first.tls_policy, "ignore_invalid");
        let mut conn = pool.get().unwrap();
        conn.execute(
            "INSERT INTO findings(project_id, source, title)
             VALUES(?1, 'rule', 'candidate')",
            [project_id],
        )
        .unwrap();
        let finding_id = conn.last_insert_rowid();
        let evidence = evidence::service::create_finding_evidence(
            &mut conn,
            finding_id,
            EvidenceSourceType::ReplayRun,
            first.id,
            "人工重放返回 200",
            "user:local",
        )
        .unwrap();
        assert_eq!(evidence.source_type, "replay_run");
        assert!(evidence.source_available);
        assert_eq!(evidence.redacted_snapshot["source"]["id"], first.id);
        assert!(
            !evidence
                .redacted_snapshot
                .to_string()
                .contains("replay-secret-token"),
            "Replay Evidence 必须使用脱敏快照"
        );

        conn.execute(
            "INSERT INTO task_nodes(project_id, title) VALUES(?1, 'verify')",
            [project_id],
        )
        .unwrap();
        let task_id = conn.last_insert_rowid();
        let task_evidence_id = evidence::service::create_task_evidence(
            &mut conn,
            task_id,
            EvidenceSourceType::ReplayRun,
            second.id,
            "任务重放观察",
            "user:local",
        )
        .unwrap();
        let linked: bool = conn
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM task_evidence
                     WHERE task_id = ?1 AND evidence_id = ?2
                 )",
                rusqlite::params![task_id, task_evidence_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(linked);

        delete_session(&mut conn, session.id).unwrap();
        let retained = evidence::service::list_finding_evidence(&conn, finding_id).unwrap();
        assert_eq!(retained.len(), 1);
        assert!(!retained[0].source_available);
        assert_eq!(retained[0].redacted_snapshot["source"]["id"], first.id);
    }

    #[tokio::test]
    async fn replay_response_capture_is_bounded_while_wire_size_keeps_counting() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let body = vec![b'x'; crate::proxy::body_capture::MAX_WIRE_CAPTURE_BYTES + 64 * 1024];
        let body_len = body.len();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 2048];
            let _ = socket.read(&mut request).await.unwrap();
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nContent-Length: {body_len}\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            socket.write_all(&body).await.unwrap();
        });

        let dir = TempDir::new().unwrap();
        let pool = test_pool(&dir);
        let project_id = insert_project(&pool, &["127.0.0.1".to_string()]);
        let session = create_test_session(&pool, project_id);
        let run = execute_request(
            pool,
            project_id,
            session.id,
            ReplayRequestInput {
                method: "GET".into(),
                url: format!("http://{address}/large"),
                headers: Vec::new(),
                body_text: None,
                body_base64: None,
            },
        )
        .await
        .unwrap();
        server.await.unwrap();

        assert_eq!(run.resp_wire_size as usize, body_len);
        assert_eq!(
            run.resp_captured_size as usize,
            crate::proxy::body_capture::MAX_WIRE_CAPTURE_BYTES
        );
        assert!(run.resp_truncated);
        assert_eq!(run.resp_decode_status, "identity_text");
        let cookies = run
            .response_headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case("set-cookie"))
            .collect::<Vec<_>>();
        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies[0].value, "a=1");
        assert_eq!(cookies[1].value, "b=2");
    }

    #[test]
    fn request_capture_uses_the_shared_body_limit() {
        let body = vec![b'a'; crate::proxy::body_capture::MAX_WIRE_CAPTURE_BYTES + 1024];
        let input = request_input_snapshot(&ReplayRequestInput {
            method: "POST".into(),
            url: "https://example.test/".into(),
            headers: Vec::new(),
            body_text: Some(String::from_utf8(body.clone()).unwrap()),
            body_base64: None,
        })
        .unwrap();
        let prepared = request_with_capture(
            "POST".into(),
            "https://example.test/".into(),
            vec![ReplayHeader {
                name: "Content-Type".into(),
                value: "text/plain".into(),
            }],
            lenient_header_map(&[ReplayHeader {
                name: "Content-Type".into(),
                value: "text/plain".into(),
            }]),
            Some(body.clone()),
            input,
            "a".repeat(64),
        );
        assert_eq!(prepared.captured.wire_size as usize, body.len());
        assert_eq!(
            prepared.captured.captured_size as usize,
            crate::proxy::body_capture::MAX_WIRE_CAPTURE_BYTES
        );
        assert!(prepared.captured.truncated);
    }

    #[test]
    fn run_history_uses_stable_cursor_pages_of_body_free_summaries() {
        let dir = TempDir::new().unwrap();
        let pool = test_pool(&dir);
        let project_id = insert_project(&pool, &["example.test".to_string()]);
        let session = create_test_session(&pool, project_id);
        for _ in 0..55 {
            persist_denied_test_run(&pool, session.id, project_id);
        }

        let conn = pool.get().unwrap();
        let first = list_runs(&conn, session.id, None, Some(20)).unwrap();
        assert_eq!(first.runs.len(), 20);
        let cursor = first.next_before_id.expect("第一页必须有下一页");
        assert_eq!(first.runs.last().unwrap().id, cursor);

        let second = list_runs(&conn, session.id, Some(cursor), Some(20)).unwrap();
        assert_eq!(second.runs.len(), 20);
        assert!(first
            .runs
            .iter()
            .all(|left| second.runs.iter().all(|right| left.id != right.id)));
        let third = list_runs(&conn, session.id, second.next_before_id, Some(20)).unwrap();
        assert_eq!(third.runs.len(), 15);
        assert!(third.next_before_id.is_none());
        assert!(
            !RUN_SUMMARY_SELECT.contains("request_body")
                && !RUN_SUMMARY_SELECT.contains("response_body")
                && !RUN_SUMMARY_SELECT.contains("request_input"),
            "历史列表不能把最多 1 MiB 的正文或原始输入一起加载"
        );
    }

    #[test]
    fn diff_preserves_repeated_headers_and_degrades_binary_stably() {
        let base = ReplayRun {
            id: 1,
            attempt_id: None,
            session_id: 1,
            project_id: 1,
            method: "GET".into(),
            url: "https://example.test/".into(),
            request_headers: vec![
                ReplayHeader {
                    name: "X-Test".into(),
                    value: "one".into(),
                },
                ReplayHeader {
                    name: "X-Test".into(),
                    value: "two".into(),
                },
            ],
            request_wire_body_text: None,
            request_wire_body_base64: Some("AP8=".into()),
            req_wire_captured_size: 2,
            req_wire_truncated: false,
            request_input: ReplayRequestInputSnapshot {
                encoding: "base64".into(),
                text: None,
                base64: Some("AP8=".into()),
                original_size: 4,
                captured_size: 4,
                truncated: false,
                content_hash: "c".repeat(64),
            },
            request_body_text: None,
            request_body_base64: Some("AP8=".into()),
            req_wire_size: 2,
            req_captured_size: 2,
            req_truncated: false,
            req_decode_status: "identity_binary".into(),
            tls_policy: "strict".into(),
            scope_decision: ReplayScopeSnapshot {
                allowed: true,
                normalized_host: Some("example.test".into()),
                matched_scope: Some("example.test".into()),
                match_kind: Some("exact".into()),
                reason_code: None,
                reason: None,
            },
            outcome: "completed".into(),
            error_code: None,
            error_message: None,
            status: Some(200),
            status_text: "OK".into(),
            response_headers: Vec::new(),
            response_body_text: None,
            response_body_base64: Some("AAE=".into()),
            resp_wire_size: 2,
            resp_captured_size: 2,
            resp_truncated: false,
            resp_decode_status: "identity_binary".into(),
            duration_ms: 1,
            request_hash: "a".repeat(64),
            req_body_hash: Some(sha256(&[0, 255])),
            response_hash: Some("b".repeat(64)),
            resp_body_hash: Some(sha256(&[0, 1])),
            created_at: String::new(),
        };
        let mut right = base.clone();
        right.id = 2;
        right.method = "POST".into();
        right.url = "https://example.test/changed".into();
        right.request_headers.swap(0, 1);
        right.response_body_base64 = Some("AAI=".into());
        right.resp_body_hash = Some(sha256(&[0, 2]));
        right.status = Some(201);
        right.duration_ms = 2;
        let diff = build_diff(base, right);
        assert!(diff.method.changed);
        assert!(diff.url.changed);
        assert!(diff.request_headers.changed);
        assert!(diff.status.changed);
        assert!(diff.duration_ms.changed);
        assert!(diff.response_body.changed);
        assert_eq!(diff.response_body.left.encoding, "base64");
        assert_eq!(diff.response_body.left.base64.as_deref(), Some("AAE="));
        assert_eq!(diff.response_body.left.captured_hash.len(), 64);
    }

    #[test]
    fn diff_uses_full_hashes_and_marks_unknown_truncated_equality() {
        let mut left = ReplayRun {
            id: 1,
            attempt_id: None,
            session_id: 1,
            project_id: 1,
            method: "POST".into(),
            url: "https://example.test/".into(),
            request_headers: Vec::new(),
            request_wire_body_text: Some("same-prefix".into()),
            request_wire_body_base64: None,
            req_wire_captured_size: 11,
            req_wire_truncated: true,
            request_input: ReplayRequestInputSnapshot {
                encoding: "text".into(),
                text: Some("same-prefix".into()),
                base64: None,
                original_size: 100,
                captured_size: 11,
                truncated: true,
                content_hash: "1".repeat(64),
            },
            request_body_text: Some("same-prefix".into()),
            request_body_base64: None,
            req_wire_size: 100,
            req_captured_size: 11,
            req_truncated: true,
            req_decode_status: "identity_text".into(),
            tls_policy: "strict".into(),
            scope_decision: ReplayScopeSnapshot {
                allowed: true,
                normalized_host: Some("example.test".into()),
                matched_scope: Some("example.test".into()),
                match_kind: Some("exact".into()),
                reason_code: None,
                reason: None,
            },
            outcome: "completed".into(),
            error_code: None,
            error_message: None,
            status: Some(200),
            status_text: "OK".into(),
            response_headers: Vec::new(),
            response_body_text: None,
            response_body_base64: None,
            resp_wire_size: 0,
            resp_captured_size: 0,
            resp_truncated: false,
            resp_decode_status: "empty".into(),
            duration_ms: 1,
            request_hash: "a".repeat(64),
            req_body_hash: Some("2".repeat(64)),
            response_hash: Some("b".repeat(64)),
            resp_body_hash: Some(sha256(&[])),
            created_at: String::new(),
        };
        let mut right = left.clone();
        right.id = 2;
        right.req_body_hash = Some("3".repeat(64));

        let changed = build_diff(left.clone(), right.clone());
        assert!(changed.request_body.changed);
        assert!(!changed.request_body.indeterminate);

        left.response_body_text = Some("same-prefix".into());
        right.response_body_text = Some("same-prefix".into());
        left.resp_wire_size = 100;
        right.resp_wire_size = 100;
        left.resp_captured_size = 11;
        right.resp_captured_size = 11;
        left.resp_truncated = true;
        right.resp_truncated = true;
        left.resp_decode_status = "stream_error".into();
        right.resp_decode_status = "stream_error".into();
        left.resp_body_hash = None;
        right.resp_body_hash = None;
        let unknown = build_diff(left, right);
        assert!(!unknown.response_body.changed);
        assert!(unknown.response_body.indeterminate);
    }
}
