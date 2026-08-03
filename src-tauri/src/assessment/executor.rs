use super::catalog;
use super::model::AssessmentContractPreview;
use super::policy::{
    AssessmentPolicy, AssessmentRequestCandidate, RequestBudget, RequestPhase, MAX_RESPONSE_BYTES,
};
use super::service::{self, RuntimeIdentity};
use crate::authorization::{load_project_policy, ScopePolicy};
use crate::replay::model::{ReplayHeader, ReplayRun};
use crate::replay::service::{execute_assessment_request, AssessmentReplayRequest};
use crate::storage::db::Pool;
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentitySelection {
    Anonymous,
    A,
    B,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopCondition {
    RateLimited,
    TargetUnstable,
    ResponseBudgetExhausted,
}

pub struct AuthProbeRequest<'a> {
    pub phase: RequestPhase,
    pub method: &'a str,
    pub url: &'a str,
    pub extra_headers: Vec<ReplayHeader>,
    pub identity: IdentitySelection,
    pub probe_header_value: String,
    pub hash_suffix: &'a str,
}

pub struct AssessmentExecutor {
    pool: Pool,
    project_id: i64,
    run_id: i64,
    session_id: i64,
    preview: AssessmentContractPreview,
    scope: ScopePolicy,
    policy: AssessmentPolicy,
    identity_a: Option<RuntimeIdentity>,
    identity_b: Option<RuntimeIdentity>,
    cancel: watch::Receiver<bool>,
    budget: RequestBudget,
    request_interval: Duration,
    last_request_started: Option<Instant>,
    consecutive_target_failures: u8,
}

impl AssessmentExecutor {
    pub fn new(
        pool: Pool,
        secrets: Arc<dyn crate::secrets::SecretStore>,
        project_id: i64,
        run_id: i64,
        session_id: i64,
        cancel: watch::Receiver<bool>,
    ) -> Result<Self, String> {
        let conn = pool.get().map_err(|error| error.to_string())?;
        let contract_json: String = conn
            .query_row(
                "SELECT contract_json FROM assessment_runs WHERE id = ?1 AND project_id = ?2",
                rusqlite::params![run_id, project_id],
                |row| row.get(0),
            )
            .map_err(|_| "评估运行不存在".to_string())?;
        let preview: AssessmentContractPreview = serde_json::from_str(&contract_json)
            .map_err(|_| "评估运行契约快照已损坏".to_string())?;
        if preview.template_registry_hash != catalog::registry_hash() {
            return Err("[CONTRACT_DRIFT] 安全模板注册表已变化".into());
        }
        let scope = load_project_policy(&conn, project_id).map_err(|error| error.to_string())?;
        if scope.normalized_entries() != preview.normalized_scope {
            return Err("[CONTRACT_DRIFT] 项目 Scope 已变化".into());
        }
        crate::commands::ensure_assessment_ai_contract_current(
            &conn,
            &preview.provider_id,
            &preview.model,
        )?;
        let policy = AssessmentPolicy::new(&preview.exact_origin, &preview.excluded_paths)
            .map_err(|error| error.to_string())?;
        let identity_a = preview
            .identity_a_profile_id
            .map(|id| service::load_runtime_identity(&conn, secrets.as_ref(), project_id, id))
            .transpose()?;
        let identity_b = preview
            .identity_b_profile_id
            .map(|id| service::load_runtime_identity(&conn, secrets.as_ref(), project_id, id))
            .transpose()?;
        let request_interval = {
            let seconds = 1.0 / preview.requests_per_second;
            if !seconds.is_finite() || seconds <= 0.0 {
                return Err("运行契约请求速率无效，无法构造限速间隔".into());
            }
            Duration::from_secs_f64(seconds)
        };
        let budget =
            RequestBudget::new(preview.request_budget).map_err(|error| error.to_string())?;
        drop(conn);
        Ok(Self {
            pool,
            project_id,
            run_id,
            session_id,
            preview,
            scope,
            policy,
            identity_a,
            identity_b,
            cancel,
            budget,
            request_interval,
            last_request_started: None,
            consecutive_target_failures: 0,
        })
    }

    pub fn identity_available(&self, selection: IdentitySelection) -> bool {
        match selection {
            IdentitySelection::Anonymous => true,
            IdentitySelection::A => self.identity_a.is_some(),
            IdentitySelection::B => self.identity_b.is_some(),
        }
    }

    pub fn identity_a(&self) -> Option<&RuntimeIdentity> {
        self.identity_a.as_ref()
    }

    pub fn identity_b(&self) -> Option<&RuntimeIdentity> {
        self.identity_b.as_ref()
    }

    pub fn request_count(&self) -> u32 {
        self.budget.used()
    }

    pub fn run_id(&self) -> i64 {
        self.run_id
    }

    pub fn remaining_requests(&self) -> u32 {
        self.budget.remaining()
    }

    pub fn response_bytes_read(&self) -> u64 {
        self.budget.bytes_used()
    }

    pub fn discovery_limit(&self) -> u32 {
        self.budget.discovery_limit()
    }

    pub fn contract(&self) -> &AssessmentContractPreview {
        &self.preview
    }

    /// Remove any exact credential representation from target-controlled
    /// metadata before it can enter an AI prompt or its persisted audit copy.
    pub fn redact_target_metadata(&self, value: &str) -> String {
        let mut values = Vec::new();
        if let Some(identity) = &self.identity_a {
            values.extend(identity.redaction_values());
        }
        if let Some(identity) = &self.identity_b {
            values.extend(identity.redaction_values());
        }
        values.sort();
        values.dedup();
        values.sort_by_key(|value| std::cmp::Reverse(value.len()));
        let references = values.iter().map(String::as_str).collect::<Vec<_>>();
        crate::secrets::redact_sensitive(value, &references)
    }

    pub fn authorize_candidate(
        &self,
        method: &str,
        url: &str,
        headers: Vec<ReplayHeader>,
    ) -> Result<(), String> {
        self.policy
            .authorize(
                &self.scope,
                AssessmentRequestCandidate {
                    method: method.to_string(),
                    url: url.to_string(),
                    headers,
                    has_body: false,
                },
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn cancel_receiver(&self) -> watch::Receiver<bool> {
        self.cancel.clone()
    }

    pub fn is_cancelled(&self) -> bool {
        *self.cancel.borrow()
    }

    pub async fn execute(
        &mut self,
        phase: RequestPhase,
        method: &str,
        url: &str,
        extra_headers: Vec<ReplayHeader>,
        identity: IdentitySelection,
        hash_suffix: &str,
    ) -> Result<(ReplayRun, Option<StopCondition>), String> {
        self.execute_internal(
            phase,
            method,
            url,
            extra_headers,
            identity,
            None,
            hash_suffix,
        )
        .await
    }

    pub async fn execute_with_auth_probe(
        &mut self,
        request: AuthProbeRequest<'_>,
    ) -> Result<(ReplayRun, Option<StopCondition>), String> {
        if request.identity == IdentitySelection::Anonymous
            || request.probe_header_value.is_empty()
            || request.probe_header_value.len() > super::service::MAX_AUTH_SECRET_BYTES
            || request.probe_header_value.contains(['\r', '\n'])
        {
            return Err("Assessment 鉴权探针无效".into());
        }
        self.execute_internal(
            request.phase,
            request.method,
            request.url,
            request.extra_headers,
            request.identity,
            Some(request.probe_header_value),
            request.hash_suffix,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_internal(
        &mut self,
        phase: RequestPhase,
        method: &str,
        url: &str,
        extra_headers: Vec<ReplayHeader>,
        identity: IdentitySelection,
        auth_override: Option<String>,
        hash_suffix: &str,
    ) -> Result<(ReplayRun, Option<StopCondition>), String> {
        if *self.cancel.borrow() {
            return Err("[ASSESSMENT_CANCELLED] 用户取消了评估".into());
        }
        self.recheck_contract()?;
        let (live_headers, audit_headers, identity_context) =
            self.headers(identity, extra_headers, auth_override)?;
        // Policy rejection occurs before budget reservation, pacing and transport construction.
        self.policy
            .authorize(
                &self.scope,
                AssessmentRequestCandidate {
                    method: method.to_string(),
                    url: url.to_string(),
                    headers: audit_headers.clone(),
                    has_body: false,
                },
            )
            .map_err(|error| error.to_string())?;
        if self.budget.remaining_response_bytes() == 0 {
            return Err("[RUN_RESPONSE_BYTES_EXHAUSTED] 本轮响应读取预算已用尽".into());
        }
        // 先等待限速槽再预留预算：若在等待期间取消，预算不会被未发出的请求
        // 占用，request_count 与实际网络请求保持一致。
        self.wait_for_rate_slot().await?;
        self.budget
            .reserve_request(phase)
            .map_err(|error| error.to_string())?;
        self.last_request_started = Some(Instant::now());
        let max_response_bytes = MAX_RESPONSE_BYTES.min(self.budget.remaining_response_bytes());
        let run = execute_assessment_request(
            self.pool.clone(),
            self.project_id,
            self.run_id,
            self.session_id,
            AssessmentReplayRequest {
                method: method.to_string(),
                url: url.to_string(),
                live_headers,
                audit_headers,
                request_hash_context: format!("{identity_context}:{hash_suffix}"),
                max_response_bytes,
            },
            self.cancel.clone(),
        )
        .await?;
        self.budget
            .record_response_bytes(run.resp_wire_size.max(0) as u64)
            .map_err(|error| error.to_string())?;
        self.persist_counters_and_event(&run)?;
        let stop = self.observe_stop_condition(&run);
        Ok((run, stop))
    }

    fn headers(
        &self,
        selection: IdentitySelection,
        extra_headers: Vec<ReplayHeader>,
        auth_override: Option<String>,
    ) -> Result<(Vec<ReplayHeader>, Vec<ReplayHeader>, String), String> {
        let mut live = extra_headers.clone();
        let mut audit = extra_headers;
        let identity = match selection {
            IdentitySelection::Anonymous => None,
            IdentitySelection::A => Some(
                self.identity_a
                    .as_ref()
                    .ok_or_else(|| "身份 A 未配置".to_string())?,
            ),
            IdentitySelection::B => Some(
                self.identity_b
                    .as_ref()
                    .ok_or_else(|| "身份 B 未配置".to_string())?,
            ),
        };
        if let Some(identity) = identity {
            let mut live_header = identity.live_header();
            if let Some(value) = auth_override {
                live_header.value = value;
            }
            live.push(live_header);
            audit.push(identity.audit_header());
            Ok((live, audit, identity.request_hash_context()))
        } else {
            Ok((live, audit, "anonymous".into()))
        }
    }

    pub fn recheck_contract(&mut self) -> Result<(), String> {
        if catalog::registry_hash() != self.preview.template_registry_hash {
            return Err("[CONTRACT_DRIFT] 安全模板注册表已变化".into());
        }
        let conn = self.pool.get().map_err(|error| error.to_string())?;
        let current_scope = load_project_policy(&conn, self.project_id)
            .map_err(|error| format!("[CONTRACT_DRIFT] {error}"))?;
        if current_scope.normalized_entries() != self.preview.normalized_scope {
            return Err("[CONTRACT_DRIFT] 项目 Scope 已变化".into());
        }
        crate::commands::ensure_assessment_ai_contract_current(
            &conn,
            &self.preview.provider_id,
            &self.preview.model,
        )?;
        for identity in [self.identity_a.as_ref(), self.identity_b.as_ref()]
            .into_iter()
            .flatten()
        {
            let current_revision: Option<i64> = conn
                .query_row(
                    "SELECT secret_revision FROM assessment_auth_profiles
                     WHERE id = ?1 AND project_id = ?2",
                    rusqlite::params![identity.profile_id, self.project_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| error.to_string())?;
            if current_revision != Some(identity.revision) {
                return Err("[CONTRACT_DRIFT] 评估身份修订号已变化".into());
            }
        }
        self.scope = current_scope;
        Ok(())
    }

    async fn wait_for_rate_slot(&mut self) -> Result<(), String> {
        if *self.cancel.borrow() {
            return Err("[ASSESSMENT_CANCELLED] 用户取消了评估".into());
        }
        let Some(last) = self.last_request_started else {
            return Ok(());
        };
        let remaining = self.request_interval.saturating_sub(last.elapsed());
        if remaining.is_zero() {
            return Ok(());
        }
        tokio::select! {
            biased;
            _ = self.cancel.changed() => Err("[ASSESSMENT_CANCELLED] 用户取消了评估".into()),
            _ = tokio::time::sleep(remaining) => Ok(()),
        }
    }

    fn persist_counters_and_event(&self, run: &ReplayRun) -> Result<(), String> {
        let conn = self.pool.get().map_err(|error| error.to_string())?;
        conn.execute(
            "UPDATE assessment_runs
             SET request_count = ?3, response_bytes_read = ?4
             WHERE id = ?1 AND project_id = ?2",
            rusqlite::params![
                self.run_id,
                self.project_id,
                self.budget.used(),
                self.budget.bytes_used()
            ],
        )
        .map_err(|error| error.to_string())?;
        service::append_event(
            &conn,
            self.run_id,
            None,
            "target_request_completed",
            None,
            Some(run.outcome.as_str()),
            &json!({
                "replayRunId": run.id,
                "method": run.method,
                "status": run.status,
                "responseComplete": run.outcome == "completed",
                "requestCount": self.budget.used(),
            }),
        )?;
        Ok(())
    }

    fn observe_stop_condition(&mut self, run: &ReplayRun) -> Option<StopCondition> {
        if run.status == Some(429) {
            return Some(StopCondition::RateLimited);
        }
        let unstable = run.status.is_some_and(|status| status >= 500)
            || run.error_code.as_deref() == Some("TIMEOUT");
        if unstable {
            self.consecutive_target_failures = self.consecutive_target_failures.saturating_add(1);
        } else {
            self.consecutive_target_failures = 0;
        }
        if self.consecutive_target_failures >= 3 {
            Some(StopCondition::TargetUnstable)
        } else if self.budget.remaining_response_bytes() == 0 {
            Some(StopCondition::ResponseBudgetExhausted)
        } else {
            None
        }
    }
}

use rusqlite::OptionalExtension;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assessment::model::{AssessmentContractInput, AssessmentStatus};
    use crate::replay::model::TlsPolicy;
    use crate::secrets::MemorySecretStore;
    use crate::storage::db::open_pool;
    use std::sync::Arc;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn executor_for(
        pool: &Pool,
        start_url: &str,
        rate: f64,
    ) -> (AssessmentExecutor, watch::Sender<bool>) {
        let project_id;
        let run_id;
        {
            let mut conn = pool.get().unwrap();
            conn.execute(
                "INSERT INTO projects(name, target_host, scope)
                 VALUES('executor', '127.0.0.1', '[\"127.0.0.1\"]')",
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
            let preview = service::preview_contract(
                &conn,
                &store,
                &AssessmentContractInput {
                    project_id,
                    start_url: start_url.into(),
                    excluded_paths: Vec::new(),
                    tls_policy: "strict".into(),
                    request_budget: 20,
                    requests_per_second: rate,
                    identity_a_profile_id: None,
                    identity_b_profile_id: None,
                    resource_ownership: Vec::new(),
                    include_recent_traffic: false,
                    provider_id: "provider".into(),
                    model: "model".into(),
                    max_rounds: 1,
                    written_authorization_confirmed: true,
                },
            )
            .unwrap();
            let run = service::create_run(&mut conn, &preview).unwrap();
            run_id = run.id;
            service::transition_run(
                &mut conn,
                project_id,
                run_id,
                AssessmentStatus::Discovering,
                None,
            )
            .unwrap();
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
        let (cancel_tx, cancel) = watch::channel(false);
        (
            AssessmentExecutor::new(
                pool.clone(),
                Arc::new(MemorySecretStore::default()),
                project_id,
                run_id,
                session_id,
                cancel,
            )
            .unwrap(),
            cancel_tx,
        )
    }

    #[tokio::test]
    async fn target_requests_are_serial_rate_limited_and_three_5xx_stop() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut accepted_at = Vec::new();
            for _ in 0..3 {
                let (mut socket, _) = listener.accept().await.unwrap();
                accepted_at.push(Instant::now());
                let mut request = [0_u8; 2048];
                let _ = socket.read(&mut request).await.unwrap();
                socket
                    .write_all(
                        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .unwrap();
            }
            accepted_at
        });
        let dir = tempdir().unwrap();
        let pool = open_pool(&dir.path().join("rate.db")).unwrap();
        let url = format!("http://{address}/health");
        let (mut executor, _cancel_tx) = executor_for(&pool, &url, 2.0);
        let mut conditions = Vec::new();
        for index in 0..3 {
            let (_, condition) = executor
                .execute(
                    RequestPhase::Verification,
                    "GET",
                    &url,
                    Vec::new(),
                    IdentitySelection::Anonymous,
                    &format!("fixture-{index}"),
                )
                .await
                .unwrap();
            conditions.push(condition);
        }
        let accepted_at = server.await.unwrap();
        assert_eq!(conditions[0], None);
        assert_eq!(conditions[1], None);
        assert_eq!(conditions[2], Some(StopCondition::TargetUnstable));
        for pair in accepted_at.windows(2) {
            assert!(
                pair[1].duration_since(pair[0]) >= Duration::from_millis(430),
                "2 requests/second hard ceiling must be enforced"
            );
        }
        assert_eq!(executor.request_count(), 3);
        let conn = pool.get().unwrap();
        let persisted: u32 = conn
            .query_row(
                "SELECT request_count FROM assessment_runs WHERE id=?1",
                [executor.run_id()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(persisted, 3);
    }

    #[tokio::test]
    async fn first_429_is_an_immediate_stop_condition() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 2048];
            let _ = socket.read(&mut request).await.unwrap();
            socket
                .write_all(
                    b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let dir = tempdir().unwrap();
        let pool = open_pool(&dir.path().join("rate-limit.db")).unwrap();
        let url = format!("http://{address}/limited");
        let (mut executor, _cancel_tx) = executor_for(&pool, &url, 2.0);
        let (_, condition) = executor
            .execute(
                RequestPhase::Verification,
                "GET",
                &url,
                Vec::new(),
                IdentitySelection::Anonymous,
                "fixture-429",
            )
            .await
            .unwrap();
        server.await.unwrap();
        assert_eq!(condition, Some(StopCondition::RateLimited));
    }
}
