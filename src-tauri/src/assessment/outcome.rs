use super::finding_identity::security_baseline_fingerprint;
use super::model::AssessmentVerdict;
use super::verifier::VerificationOutcome;
use crate::evidence::EvidenceSourceType;
use crate::rules::fingerprint::{finding_fingerprint, fingerprint_for_url};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use serde_json::json;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct VerificationCommitInput<'a> {
    pub project_id: i64,
    pub run_id: i64,
    pub check_id: i64,
    pub template_id: &'a str,
    pub template_version: &'a str,
    pub verifier_id: &'a str,
    pub verifier_version: &'a str,
    pub endpoint_method: &'a str,
    pub endpoint_url: &'a str,
    pub parameter_name: Option<&'a str>,
    pub outcome: &'a VerificationOutcome,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationCommitResult {
    pub verification_id: i64,
    pub finding_id: Option<i64>,
    pub finding_created: bool,
    pub finding_confirmed: bool,
    pub human_conflict: bool,
    pub evidence_id: Option<i64>,
}

/// Atomically commits the immutable verification and, for confirmed/suspected
/// outcomes, its Finding/Evidence closure. AI analysis evidence never enters
/// this path; callers supply only a registered deterministic verifier outcome.
pub fn commit_verification_outcome(
    conn: &mut Connection,
    input: VerificationCommitInput<'_>,
) -> Result<VerificationCommitResult, String> {
    let actor = format!(
        "safe_verifier:{}@{}",
        input.template_id, input.verifier_version
    );
    if actor.len() > 120 {
        return Err("安全验证器 actor 标识过长".into());
    }
    let observations_json =
        serde_json::to_string(&input.outcome.observations).map_err(|error| error.to_string())?;
    let content_hash = sha256(
        &serde_json::to_vec(&json!({
            "checkId": input.check_id,
            "templateId": input.template_id,
            "templateVersion": input.template_version,
            "verifierId": input.verifier_id,
            "verifierVersion": input.verifier_version,
            "verdict": input.outcome.verdict.as_str(),
            "observations": input.outcome.observations,
        }))
        .map_err(|error| error.to_string())?,
    );
    let transaction = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    let exact_origin: Option<String> = transaction
        .query_row(
            "SELECT ar.exact_origin
                 FROM assessment_checks c
                 JOIN assessment_runs ar ON ar.id = c.run_id
                 WHERE c.id = ?1 AND c.run_id = ?2 AND ar.project_id = ?3
                   AND c.template_id = ?4 AND c.template_version = ?5
             ",
            rusqlite::params![
                input.check_id,
                input.run_id,
                input.project_id,
                input.template_id,
                input.template_version,
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some(exact_origin) = exact_origin else {
        return Err("验证结果与 Assessment check 上下文不匹配".into());
    };
    transaction
        .execute(
            "INSERT INTO assessment_verifications(
                 check_id, verifier_id, verifier_version, verdict,
                 observations_json, content_hash
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                input.check_id,
                input.verifier_id,
                input.verifier_version,
                input.outcome.verdict.as_str(),
                observations_json,
                content_hash,
            ],
        )
        .map_err(|error| format!("保存安全验证结果失败: {error}"))?;
    let verification_id = transaction.last_insert_rowid();

    let creates_finding = matches!(
        input.outcome.verdict,
        AssessmentVerdict::Confirmed | AssessmentVerdict::Suspected
    );
    let mut result = VerificationCommitResult {
        verification_id,
        finding_id: None,
        finding_created: false,
        finding_confirmed: false,
        human_conflict: false,
        evidence_id: None,
    };
    if creates_finding {
        let field_path = input.parameter_name.unwrap_or("response");
        let hit = fingerprint_for_url(
            &format!("safe_verifier:{}", input.template_id),
            input.endpoint_method,
            input.endpoint_url,
            field_path,
        );
        // Endpoint-specific verifiers retain their original identity. The
        // response-baseline verifier is intentionally aggregated by exact
        // origin and semantic gap set because it runs over every discovered
        // static resource and page.
        let fingerprint = security_baseline_fingerprint(
            input.project_id,
            input.template_id,
            &exact_origin,
            &input.outcome.observations,
        )
        .unwrap_or_else(|| finding_fingerprint(input.project_id, &hit));
        let existing: Option<(i64, String)> = transaction
            .query_row(
                "SELECT id, status FROM findings WHERE fingerprint = ?1",
                [&fingerprint],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let (finding_id, status, created) = if let Some((id, status)) = existing {
            transaction
                .execute(
                    "UPDATE findings
                     SET occurrences = occurrences + 1,
                         last_seen_at = datetime('now', 'localtime'),
                         updated_at = datetime('now', 'localtime')
                     WHERE id = ?1",
                    [id],
                )
                .map_err(|error| error.to_string())?;
            (id, status, false)
        } else {
            transaction
                .execute(
                    "INSERT INTO findings(
                         project_id, source, producer, title, vuln_type,
                         standard_references, severity, confidence, reasoning,
                         verify_steps, fingerprint
                     ) VALUES(
                         ?1, 'rule', 'safe_verifier', ?2, ?3, '[]', ?4, ?5, ?6, ?7, ?8
                     )",
                    rusqlite::params![
                        input.project_id,
                        input.outcome.title,
                        input.outcome.vuln_type,
                        input.outcome.severity,
                        input.outcome.confidence,
                        input.outcome.reasoning,
                        format!(
                            "由 {}@{} 的只读确定性检查复核；可在 Evidence 中查看脱敏 ReplayRun。",
                            input.verifier_id, input.verifier_version
                        ),
                        fingerprint,
                    ],
                )
                .map_err(|error| error.to_string())?;
            (transaction.last_insert_rowid(), "pending".to_string(), true)
        };
        let human_conflict = status == "rejected";
        transaction
            .execute(
                "INSERT INTO assessment_finding_links(
                     verification_id, finding_id, relation
                 ) VALUES(?1, ?2, ?3)",
                rusqlite::params![
                    verification_id,
                    finding_id,
                    if human_conflict {
                        "human_conflict"
                    } else {
                        "supports"
                    }
                ],
            )
            .map_err(|error| error.to_string())?;

        let evidence_id = match input.outcome.evidence_replay_run_id {
            Some(replay_run_id) => {
                // 验证器 Evidence 只能引用与本 check 正式关联的 ReplayRun；
                // 该不变量在 Rust 层先行校验（SQLite 触发器是纵深防御）。
                let replay_linked: bool = transaction
                    .query_row(
                        "SELECT EXISTS(
                             SELECT 1 FROM assessment_check_replays
                             WHERE check_id = ?1 AND replay_run_id = ?2
                         )",
                        rusqlite::params![input.check_id, replay_run_id],
                        |row| row.get(0),
                    )
                    .map_err(|error| error.to_string())?;
                if !replay_linked {
                    return Err(
                        "验证 Evidence 的 ReplayRun 未与本 check 关联，禁止引用为证据".into(),
                    );
                }
                let observation = format!("{}：{}", input.outcome.title, input.outcome.reasoning);
                let evidence_id = crate::evidence::service::insert_evidence(
                    &transaction,
                    input.project_id,
                    EvidenceSourceType::ReplayRun,
                    replay_run_id,
                    &observation,
                    &actor,
                )?;
                transaction
                    .execute(
                        "INSERT INTO finding_evidence(
                             finding_id, evidence_id, acceptance_kind, verification_id
                         ) VALUES(?1, ?2, 'safe_verifier', ?3)",
                        rusqlite::params![finding_id, evidence_id, verification_id],
                    )
                    .map_err(|error| error.to_string())?;
                Some(evidence_id)
            }
            None if input.outcome.verdict == AssessmentVerdict::Confirmed => {
                return Err("confirmed 安全验证缺少合格 ReplayRun Evidence".into());
            }
            None => None,
        };

        let should_confirm = input.outcome.verdict == AssessmentVerdict::Confirmed
            && !human_conflict
            && evidence_id.is_some();
        if should_confirm {
            let evidence_id = evidence_id.expect("checked");
            let note = format!(
                "{}@{} 确定性验证条件已满足",
                input.verifier_id, input.verifier_version
            );
            let old_value = format!("evidence:{evidence_id}:unaccepted");
            let new_value = format!("evidence:{evidence_id}:accepted");
            append_finding_event(
                &transaction,
                finding_id,
                "evidence_accepted",
                Some(&old_value),
                Some(&new_value),
                &note,
                &actor,
            )?;
            transaction
                .execute(
                    "UPDATE finding_evidence
                     SET accepted = 1, acceptance_note = ?1, accepted_by = ?2,
                         accepted_at = strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                     WHERE finding_id = ?3 AND evidence_id = ?4",
                    rusqlite::params![note, actor, finding_id, evidence_id],
                )
                .map_err(|error| error.to_string())?;
            if status == "pending" {
                append_finding_event(
                    &transaction,
                    finding_id,
                    "status_changed",
                    Some("pending"),
                    Some("confirmed"),
                    &note,
                    &actor,
                )?;
                transaction
                    .execute(
                        "UPDATE findings
                         SET status = 'confirmed', updated_at = datetime('now', 'localtime')
                         WHERE id = ?1",
                        [finding_id],
                    )
                    .map_err(|error| error.to_string())?;
            }
        }

        result.finding_id = Some(finding_id);
        result.finding_created = created;
        result.finding_confirmed = should_confirm && status != "confirmed";
        result.human_conflict = human_conflict;
        result.evidence_id = evidence_id;
    }

    super::service::append_event(
        &transaction,
        input.run_id,
        Some(input.check_id),
        "verification_committed",
        None,
        Some(input.outcome.verdict.as_str()),
        &json!({
            "verificationId": verification_id,
            "contentHash": content_hash,
            "findingId": result.finding_id,
            "humanConflict": result.human_conflict,
        }),
    )?;
    transaction.commit().map_err(|error| error.to_string())?;
    Ok(result)
}

fn append_finding_event(
    conn: &Connection,
    finding_id: i64,
    event_type: &str,
    old_value: Option<&str>,
    new_value: Option<&str>,
    reason: &str,
    actor: &str,
) -> Result<(), String> {
    conn.execute(
        "INSERT INTO finding_events(
             finding_id, event_type, old_value, new_value, reason, actor
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![finding_id, event_type, old_value, new_value, reason, actor],
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assessment::model::AssessmentVerdict;
    use rusqlite::{params, Connection};
    use serde_json::json;

    struct Fixture {
        conn: Connection,
        project_id: i64,
        run_id: i64,
        replay_run_id: i64,
    }

    impl Fixture {
        fn new() -> Self {
            let mut conn = Connection::open_in_memory().unwrap();
            crate::storage::migrations::migrate(&mut conn).unwrap();
            conn.execute(
                "INSERT INTO projects(name, target_host, scope)
                 VALUES('assessment', 'example.test', '[\"example.test\"]')",
                [],
            )
            .unwrap();
            let project_id = conn.last_insert_rowid();
            let hash = "0".repeat(64);
            conn.execute(
                "INSERT INTO assessment_runs(
                     project_id, start_url, exact_origin, contract_json,
                     contract_hash, template_registry_hash, provider_id, model,
                     request_budget, discovery_budget, requests_per_second
                 ) VALUES(?1, 'https://example.test/', 'https://example.test:443',
                          '{}', ?2, ?2, 'provider', 'model', 120, 40, 1.0)",
                params![project_id, hash],
            )
            .unwrap();
            let run_id = conn.last_insert_rowid();
            conn.execute(
                "INSERT INTO replay_sessions(
                     project_id, title, tls_policy, owner_kind, assessment_run_id
                 ) VALUES(?1, 'assessment transport', 'strict', 'assessment', ?2)",
                params![project_id, run_id],
            )
            .unwrap();
            let session_id = conn.last_insert_rowid();
            let snapshot = json!({
                "encoding": "none",
                "text": null,
                "base64": null,
                "original_size": 0,
                "captured_size": 0,
                "truncated": false,
                "content_hash": "0".repeat(64),
            })
            .to_string();
            let scope = json!({
                "allowed": true,
                "normalized_host": "example.test",
                "matched_scope": "example.test",
                "match_kind": "exact",
                "reason_code": null,
                "reason": null,
            })
            .to_string();
            conn.execute(
                "INSERT INTO replay_runs(
                     session_id, project_id, method, url, request_headers,
                     request_input, tls_policy, scope_allowed, scope_decision,
                     outcome, status, status_text, response_headers, response_body,
                     resp_wire_size, resp_captured_size, resp_decode_status,
                     request_hash, req_body_hash, response_hash, resp_body_hash
                 ) VALUES(
                     ?1, ?2, 'GET', 'https://example.test/account', '[]',
                     ?3, 'strict', 1, ?4, 'completed', 200, 'OK',
                     '[{\"name\":\"content-type\",\"value\":\"text/plain\"}]',
                     ?6, 13, 13, 'identity_text', ?5, ?5, ?5, ?5
                 )",
                params![
                    session_id,
                    project_id,
                    snapshot,
                    scope,
                    hash,
                    b"safe response".as_slice(),
                ],
            )
            .unwrap();
            let replay_run_id = conn.last_insert_rowid();
            Self {
                conn,
                project_id,
                run_id,
                replay_run_id,
            }
        }

        fn check(&self, template_id: &str, link_replay: bool) -> i64 {
            self.conn
                .execute(
                    "INSERT INTO assessment_checks(
                         run_id, requested_endpoint_id, template_id, template_version,
                         identity_mode, policy_result, policy_reason, status, request_cost
                     ) VALUES(?1, ?2, ?3, '1', 'anonymous', 'allowed', 'allowed',
                              'verifying', 1)",
                    params![
                        self.run_id,
                        format!("ep_{}", self.conn.last_insert_rowid() + 1),
                        template_id,
                    ],
                )
                .unwrap();
            let check_id = self.conn.last_insert_rowid();
            if link_replay {
                self.conn
                    .execute(
                        "INSERT INTO assessment_check_replays(check_id, replay_run_id, role)
                         VALUES(?1, ?2, 'probe')",
                        params![check_id, self.replay_run_id],
                    )
                    .unwrap();
            }
            check_id
        }

        fn commit(
            &mut self,
            check_id: i64,
            template_id: &str,
            verdict: AssessmentVerdict,
        ) -> Result<VerificationCommitResult, String> {
            let evidence_replay_run_id = matches!(
                verdict,
                AssessmentVerdict::Confirmed | AssessmentVerdict::Suspected
            )
            .then_some(self.replay_run_id);
            let outcome = VerificationOutcome {
                verdict,
                observations: json!({"fixture": true}),
                title: format!("{template_id} finding"),
                vuln_type: "fixture_vulnerability".into(),
                severity: "low".into(),
                confidence: 100,
                reasoning: "deterministic fixture outcome".into(),
                evidence_replay_run_id,
            };
            commit_verification_outcome(
                &mut self.conn,
                VerificationCommitInput {
                    project_id: self.project_id,
                    run_id: self.run_id,
                    check_id,
                    template_id,
                    template_version: "1",
                    verifier_id: template_id,
                    verifier_version: "1",
                    endpoint_method: "GET",
                    endpoint_url: "https://example.test/account",
                    parameter_name: None,
                    outcome: &outcome,
                },
            )
        }
    }

    #[test]
    fn confirmed_safe_verifier_atomically_accepts_evidence_and_confirms_finding() {
        let mut fixture = Fixture::new();
        let check_id = fixture.check("security_headers_cookie", true);
        let result = fixture
            .commit(
                check_id,
                "security_headers_cookie",
                AssessmentVerdict::Confirmed,
            )
            .unwrap();
        assert!(result.finding_created);
        assert!(result.finding_confirmed);
        let finding_id = result.finding_id.unwrap();
        let finding: (String, String) = fixture
            .conn
            .query_row(
                "SELECT status, producer FROM findings WHERE id = ?1",
                [finding_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(finding, ("confirmed".into(), "safe_verifier".into()));
        let link: (bool, String, Option<i64>) = fixture
            .conn
            .query_row(
                "SELECT accepted, acceptance_kind, verification_id
                 FROM finding_evidence WHERE finding_id = ?1",
                [finding_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            link,
            (true, "safe_verifier".into(), Some(result.verification_id))
        );
        let events: i64 = fixture
            .conn
            .query_row(
                "SELECT COUNT(*) FROM finding_events
                 WHERE finding_id = ?1 AND event_type IN ('evidence_accepted','status_changed')",
                [finding_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(events, 2);
        assert!(fixture
            .conn
            .execute(
                "UPDATE assessment_verifications SET verdict = 'suspected' WHERE id = ?1",
                [result.verification_id],
            )
            .is_err());
    }

    #[test]
    fn security_baseline_groups_endpoints_by_origin_and_gap_set() {
        let mut fixture = Fixture::new();
        let observations = json!({
            "facts": [{"kind": "missing_nosniff", "applicable": true}],
            "suspectedFacts": [],
            "responseComplete": true
        });
        let outcome = VerificationOutcome {
            verdict: AssessmentVerdict::Confirmed,
            observations: observations.clone(),
            title: "缺少 X-Content-Type-Options: nosniff".into(),
            vuln_type: "security_misconfiguration".into(),
            severity: "low".into(),
            confidence: 100,
            reasoning: "deterministic baseline fixture".into(),
            evidence_replay_run_id: Some(fixture.replay_run_id),
        };
        let first_check = fixture.check("security_headers_cookie", true);
        let first = commit_verification_outcome(
            &mut fixture.conn,
            VerificationCommitInput {
                project_id: fixture.project_id,
                run_id: fixture.run_id,
                check_id: first_check,
                template_id: "security_headers_cookie",
                template_version: "1",
                verifier_id: "security_headers_cookie",
                verifier_version: "1",
                endpoint_method: "GET",
                endpoint_url: "https://example.test/static/a.js",
                parameter_name: None,
                outcome: &outcome,
            },
        )
        .unwrap();
        let second_check = fixture.check("security_headers_cookie", true);
        let second = commit_verification_outcome(
            &mut fixture.conn,
            VerificationCommitInput {
                project_id: fixture.project_id,
                run_id: fixture.run_id,
                check_id: second_check,
                template_id: "security_headers_cookie",
                template_version: "1",
                verifier_id: "security_headers_cookie",
                verifier_version: "1",
                endpoint_method: "GET",
                endpoint_url: "https://example.test/static/b.js",
                parameter_name: None,
                outcome: &outcome,
            },
        )
        .unwrap();

        assert!(first.finding_created);
        assert!(!second.finding_created);
        assert_eq!(second.finding_id, first.finding_id);
        let finding_id = first.finding_id.unwrap();
        let aggregate: (i64, i64, i64) = fixture
            .conn
            .query_row(
                "SELECT f.occurrences,
                        (SELECT COUNT(*) FROM assessment_finding_links afl
                         WHERE afl.finding_id = f.id),
                        (SELECT COUNT(*) FROM finding_evidence fe
                         WHERE fe.finding_id = f.id)
                 FROM findings f WHERE f.id = ?1",
                [finding_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(aggregate, (2, 2, 2));

        let distinct_outcome = VerificationOutcome {
            observations: json!({
                "facts": [
                    {"kind": "missing_nosniff", "applicable": true},
                    {"kind": "missing_frame_embedding_protection", "applicable": true}
                ],
                "suspectedFacts": [{"kind": "content_security_policy_not_observed"}],
                "responseComplete": true
            }),
            ..outcome
        };
        let third_check = fixture.check("security_headers_cookie", true);
        let third = commit_verification_outcome(
            &mut fixture.conn,
            VerificationCommitInput {
                project_id: fixture.project_id,
                run_id: fixture.run_id,
                check_id: third_check,
                template_id: "security_headers_cookie",
                template_version: "1",
                verifier_id: "security_headers_cookie",
                verifier_version: "1",
                endpoint_method: "GET",
                endpoint_url: "https://example.test/login",
                parameter_name: None,
                outcome: &distinct_outcome,
            },
        )
        .unwrap();
        assert_ne!(third.finding_id, first.finding_id);
        let finding_count: i64 = fixture
            .conn
            .query_row("SELECT COUNT(*) FROM findings", [], |row| row.get(0))
            .unwrap();
        assert_eq!(finding_count, 2);
    }

    #[test]
    fn suspected_outcome_keeps_evidence_unaccepted_and_finding_pending() {
        let mut fixture = Fixture::new();
        let check_id = fixture.check("lazy_reflection", true);
        let result = fixture
            .commit(check_id, "lazy_reflection", AssessmentVerdict::Suspected)
            .unwrap();
        assert!(!result.finding_confirmed);
        let finding_id = result.finding_id.unwrap();
        let state: (String, bool, String) = fixture
            .conn
            .query_row(
                "SELECT f.status, fe.accepted, fe.acceptance_kind
                 FROM findings f JOIN finding_evidence fe ON fe.finding_id = f.id
                 WHERE f.id = ?1",
                [finding_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(state, ("pending".into(), false, "safe_verifier".into()));
    }

    #[test]
    fn human_rejected_finding_is_not_revived_by_later_confirmation() {
        let mut fixture = Fixture::new();
        let first_check = fixture.check("readonly_idor", true);
        let first = fixture
            .commit(first_check, "readonly_idor", AssessmentVerdict::Suspected)
            .unwrap();
        let finding_id = first.finding_id.unwrap();
        crate::evidence::service::update_finding_status(
            &mut fixture.conn,
            finding_id,
            "rejected",
            Some("人工确认不是越权"),
            "human:test",
        )
        .unwrap();

        let second_check = fixture.check("readonly_idor", true);
        let second = fixture
            .commit(second_check, "readonly_idor", AssessmentVerdict::Confirmed)
            .unwrap();
        assert_eq!(second.finding_id, Some(finding_id));
        assert!(second.human_conflict);
        assert!(!second.finding_confirmed);
        let status: String = fixture
            .conn
            .query_row(
                "SELECT status FROM findings WHERE id = ?1",
                [finding_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, "rejected");
    }

    #[test]
    fn replay_from_another_check_cannot_authorize_verifier_evidence() {
        let mut fixture = Fixture::new();
        let linked_check = fixture.check("open_redirect", true);
        assert!(linked_check > 0);
        let unlinked_check = fixture.check("credentialed_cors", false);
        let error = fixture
            .commit(
                unlinked_check,
                "credentialed_cors",
                AssessmentVerdict::Confirmed,
            )
            .unwrap_err();
        assert!(
            error.contains("未与本 check 关联") || error.contains("same-check verification replay"),
            "unexpected error: {error}"
        );
        let verifications: i64 = fixture
            .conn
            .query_row(
                "SELECT COUNT(*) FROM assessment_verifications WHERE check_id = ?1",
                [unlinked_check],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(verifications, 0, "failed commit must roll back atomically");
    }
}
