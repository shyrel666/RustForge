//! Evidence-backed report v2.
//!
//! The report is built once as a deterministic structured document and then
//! rendered to Markdown (primary) and JSON (machine-readable backup). The
//! default path only uses immutable redacted Evidence snapshots. Live raw
//! sources are appended only for a request-scoped, explicitly confirmed export.

use crate::ai::redaction::{redact_fallback_text, redact_url, RedactionManifest};
use crate::knowledge;
use crate::knowledge::StandardReference;
use base64::Engine;
use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

pub const REPORT_SCHEMA_VERSION: u32 = 2;
const RAW_FIELD_MAX_BYTES: usize = 8 * 1024;
const RAW_HEADER_MAX_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone, Copy, Default)]
pub struct ReportOptions {
    include_sensitive_evidence: bool,
}

impl ReportOptions {
    pub fn redacted() -> Self {
        Self::default()
    }

    /// 只能在后端原生确认框返回肯定结果后构造，不能作为 IPC 参数暴露。
    pub(crate) fn confirmed_sensitive() -> Self {
        Self {
            include_sensitive_evidence: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReportBundle {
    pub markdown: String,
    pub json: String,
    pub project_name: String,
    pub contains_sensitive_evidence: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ReportDocument {
    pub schema_version: u32,
    pub generated_at: String,
    pub classification: ReportClassification,
    pub project: ReportProject,
    pub methodology: ReportMethodology,
    pub summary: ReportSummary,
    pub timeline: Vec<ReportTimelineEntry>,
    pub confirmed_findings: Vec<ReportFinding>,
    pub pending_appendix: Vec<ReportFinding>,
    pub test_plan: ReportTestPlan,
    pub provenance: ReportProvenance,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReportClassification {
    pub sensitivity: String,
    pub uses_redacted_evidence_by_default: bool,
    pub contains_live_raw_source_snapshots: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReportProject {
    pub id: i64,
    pub name: String,
    pub target_host: String,
    pub authorized_scope: Vec<String>,
    pub excluded_scope: Vec<String>,
    pub testing_limitations: Vec<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReportMethodology {
    pub methods: Vec<ReportMethod>,
    pub tools: Vec<ReportToolVersion>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReportMethod {
    pub id: String,
    pub label: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReportToolVersion {
    pub tool: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReportSummary {
    pub traffic_count: i64,
    pub confirmed_findings: usize,
    pub pending_findings_in_appendix: usize,
    pub rejected_findings_omitted: usize,
    pub confirmed_risk_distribution: Vec<RiskCount>,
    pub accepted_supporting_evidence: usize,
    pub test_plan_terminal: usize,
    pub test_plan_total: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RiskCount {
    pub severity: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReportTimelineEntry {
    pub occurred_at: String,
    pub kind: String,
    pub reference: String,
    pub summary: String,
    #[serde(skip)]
    order: i64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ReportFinding {
    pub id: i64,
    pub identity: String,
    pub fingerprint: Option<String>,
    pub title: String,
    pub vulnerability_type: String,
    pub status: String,
    pub severity: String,
    pub confidence: i64,
    pub occurrences: i64,
    pub affected_targets: Vec<ReportTarget>,
    pub standard_references: Vec<StandardReference>,
    pub hypothesis_reasoning: String,
    pub suggested_validation_steps: String,
    pub executed_reproduction: Vec<ReportObservation>,
    pub evidence: Vec<ReportEvidence>,
    pub remediation: String,
    pub retest: ReportRetestStatus,
    pub analyst_notes: String,
    pub source: ReportFindingSource,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
pub struct ReportTarget {
    pub traffic_id: Option<i64>,
    pub method: String,
    pub url: String,
    pub observed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReportObservation {
    pub evidence_id: i64,
    pub observation: String,
    pub accepted: bool,
    pub qualifies_for_confirmation: bool,
    pub observed_at: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ReportEvidence {
    pub id: i64,
    pub source_type: String,
    pub source_id: i64,
    pub source_available: bool,
    pub observation: String,
    pub accepted: bool,
    pub qualifies_for_confirmation: bool,
    pub acceptance_note: String,
    pub accepted_by: Option<String>,
    pub accepted_at: Option<String>,
    pub content_hash: String,
    pub snapshot_hash_verified: bool,
    pub created_by: String,
    pub created_at: String,
    pub redacted_snapshot: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sensitive_live_source_snapshot: Option<Value>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReportRetestStatus {
    pub status: String,
    pub statement: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReportFindingSource {
    pub source_type: String,
    pub requires_human_review: bool,
    pub ai_run: Option<AiSourceVersion>,
    pub rule_hits: Vec<RuleSourceVersion>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct AiSourceVersion {
    pub analysis_run_id: i64,
    pub provider_id: String,
    pub model: String,
    pub prompt_id: String,
    pub prompt_version: i64,
    pub input_hash: String,
    pub validation_status: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct RuleSourceVersion {
    pub hit_id: i64,
    pub pack_id: String,
    pub pack_version: String,
    pub rule_id: String,
    pub rule_version: String,
    pub field_path: String,
    pub evidence_excerpt: String,
    pub confidence: i64,
    pub incomplete_evidence: bool,
    pub hit_fingerprint: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReportTestPlan {
    pub revision: i64,
    pub needs_update: bool,
    pub update_reason: String,
    pub total_nodes: usize,
    pub terminal_nodes: usize,
    pub coverage_percent: usize,
    pub status_distribution: Vec<StatusCount>,
    pub unfinished_items: Vec<ReportTaskItem>,
    pub blocked_items: Vec<ReportTaskItem>,
    pub excluded_items: Vec<ReportTaskItem>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StatusCount {
    pub status: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReportTaskItem {
    pub id: i64,
    pub stable_key: String,
    pub title: String,
    pub status: String,
    pub priority: i64,
    pub reason: String,
    pub expected_observation: String,
    pub actual_observation: String,
    pub evidence_count: i64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReportProvenance {
    pub standard_versions: Vec<StandardSourceVersion>,
    pub ai_runs: Vec<AiSourceVersion>,
    pub rule_versions: Vec<RulePackVersion>,
    pub review_notice: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct StandardSourceVersion {
    pub framework: String,
    pub version: String,
    pub pack_title: String,
    pub published_at: String,
    pub source_url: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct RulePackVersion {
    pub pack_id: String,
    pub pack_version: String,
    pub rule_id: String,
    pub rule_version: String,
}

#[derive(Debug)]
struct FindingRow {
    id: i64,
    source: String,
    title: String,
    vulnerability_type: String,
    standard_references: Vec<StandardReference>,
    severity: String,
    confidence: i64,
    reasoning: String,
    verify_steps: String,
    status: String,
    analyst_notes: String,
    fingerprint: Option<String>,
    occurrences: i64,
    created_at: String,
    updated_at: String,
    ai_run: Option<AiSourceVersion>,
}

/// Build the default redacted Markdown preview.
pub fn build_markdown(conn: &Connection, project_id: i64) -> Result<String, String> {
    Ok(build_bundle(conn, project_id, ReportOptions::redacted())?.markdown)
}

/// Build the default redacted structured JSON backup.
pub fn build_json(conn: &Connection, project_id: i64) -> Result<String, String> {
    Ok(build_bundle(conn, project_id, ReportOptions::redacted())?.json)
}

pub fn build_bundle(
    conn: &Connection,
    project_id: i64,
    options: ReportOptions,
) -> Result<ReportBundle, String> {
    let generated_at = chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false);
    build_bundle_at(conn, project_id, options, &generated_at)
}

fn build_bundle_at(
    conn: &Connection,
    project_id: i64,
    options: ReportOptions,
    generated_at: &str,
) -> Result<ReportBundle, String> {
    let document = build_document(conn, project_id, options, generated_at)?;
    let markdown = render_markdown(&document);
    let json = serde_json::to_string_pretty(&document)
        .map_err(|error| format!("序列化结构化报告失败: {error}"))?;
    Ok(ReportBundle {
        markdown,
        json,
        project_name: document.project.name.clone(),
        contains_sensitive_evidence: document.classification.contains_live_raw_source_snapshots,
    })
}

fn build_document(
    conn: &Connection,
    project_id: i64,
    options: ReportOptions,
    generated_at: &str,
) -> Result<ReportDocument, String> {
    let (project_name, target_host, scope_json, project_created_at): (
        String,
        String,
        String,
        String,
    ) = conn
        .query_row(
            "SELECT name, target_host, scope, created_at FROM projects WHERE id = ?1",
            [project_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| format!("项目 #{project_id} 不存在"))?;
    let scope: Vec<String> = serde_json::from_str(&scope_json)
        .map_err(|error| format!("项目授权范围数据损坏: {error}"))?;

    let traffic_count = conn
        .query_row(
            "SELECT COUNT(*) FROM traffic WHERE project_id = ?1",
            [project_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|error| error.to_string())?;
    let findings = load_finding_rows(conn, project_id)?;
    let rejected_findings_omitted = findings
        .iter()
        .filter(|finding| finding.status == "rejected")
        .count();

    let mut targets = load_targets(conn, project_id)?;
    let mut evidence = load_evidence(conn, project_id, options)?;
    let mut rule_hits = load_rule_hits(conn, project_id)?;
    let test_plan = load_test_plan(conn, project_id)?;

    let mut confirmed_findings = Vec::new();
    let mut pending_appendix = Vec::new();
    for row in findings
        .into_iter()
        .filter(|finding| finding.status != "rejected")
    {
        let finding_evidence = evidence.remove(&row.id).unwrap_or_default();
        if row.status == "confirmed"
            && !finding_evidence.iter().any(|item| {
                item.accepted && item.qualifies_for_confirmation && item.snapshot_hash_verified
            })
        {
            return Err(format!(
                "Finding #{} 已确认但没有已接受、可用于确认且哈希有效的 Evidence，拒绝生成报告",
                row.id
            ));
        }

        let mut affected_targets = targets.remove(&row.id).unwrap_or_default();
        add_snapshot_targets(&mut affected_targets, &finding_evidence);
        affected_targets.sort_by(|left, right| {
            (
                left.method.as_str(),
                left.url.as_str(),
                left.traffic_id.unwrap_or(i64::MAX),
            )
                .cmp(&(
                    right.method.as_str(),
                    right.url.as_str(),
                    right.traffic_id.unwrap_or(i64::MAX),
                ))
        });
        affected_targets.dedup_by(|left, right| {
            left.method == right.method
                && left.url == right.url
                && left.traffic_id == right.traffic_id
        });

        let source = ReportFindingSource {
            source_type: row.source.clone(),
            requires_human_review: true,
            ai_run: row.ai_run.clone(),
            rule_hits: rule_hits.remove(&row.id).unwrap_or_default(),
        };
        let executed_reproduction = finding_evidence
            .iter()
            .map(|item| ReportObservation {
                evidence_id: item.id,
                observation: item.observation.clone(),
                accepted: item.accepted,
                qualifies_for_confirmation: item.qualifies_for_confirmation,
                observed_at: item.created_at.clone(),
            })
            .collect();
        let remediation = knowledge::remediation_for(&row.standard_references)?;
        let report_finding = ReportFinding {
            id: row.id,
            identity: row
                .fingerprint
                .clone()
                .unwrap_or_else(|| format!("finding:{}", row.id)),
            fingerprint: row.fingerprint,
            title: sanitize_text(&row.title, "report.finding.title"),
            vulnerability_type: sanitize_text(
                &row.vulnerability_type,
                "report.finding.vulnerability_type",
            ),
            status: row.status.clone(),
            severity: row.severity,
            confidence: row.confidence,
            occurrences: row.occurrences,
            affected_targets,
            standard_references: row.standard_references,
            hypothesis_reasoning: sanitize_text(
                &row.reasoning,
                "report.finding.hypothesis_reasoning",
            ),
            suggested_validation_steps: sanitize_text(
                &row.verify_steps,
                "report.finding.suggested_validation_steps",
            ),
            executed_reproduction,
            evidence: finding_evidence,
            remediation,
            retest: ReportRetestStatus {
                status: "not_recorded".to_string(),
                statement:
                    "当前数据模型未记录独立的修复后复测结论；测试计划完成状态不等同于复测通过。"
                        .to_string(),
            },
            analyst_notes: sanitize_text(&row.analyst_notes, "report.finding.analyst_notes"),
            source,
            created_at: row.created_at,
            updated_at: row.updated_at,
        };
        if report_finding.status == "confirmed" {
            confirmed_findings.push(report_finding);
        } else {
            pending_appendix.push(report_finding);
        }
    }

    sort_findings(&mut confirmed_findings);
    sort_findings(&mut pending_appendix);

    let accepted_supporting_evidence = confirmed_findings
        .iter()
        .flat_map(|finding| &finding.evidence)
        .filter(|item| item.accepted && item.qualifies_for_confirmation)
        .count();
    let risk_distribution = risk_distribution(&confirmed_findings);
    let testing_limitations =
        build_limitations(conn, project_id, &scope, pending_appendix.len(), &test_plan)?;
    let methodology = build_methodology(
        traffic_count,
        &confirmed_findings,
        &pending_appendix,
        &test_plan,
    );
    let timeline = build_timeline(
        conn,
        project_id,
        &project_created_at,
        traffic_count,
        &confirmed_findings,
        &pending_appendix,
        &test_plan,
    )?;
    let provenance = build_provenance(&confirmed_findings, &pending_appendix)?;

    Ok(ReportDocument {
        schema_version: REPORT_SCHEMA_VERSION,
        generated_at: generated_at.to_string(),
        classification: ReportClassification {
            sensitivity: if options.include_sensitive_evidence {
                "包含经单次明确确认导出的原始来源内容".to_string()
            } else {
                "默认脱敏".to_string()
            },
            uses_redacted_evidence_by_default: true,
            contains_live_raw_source_snapshots: options.include_sensitive_evidence,
        },
        project: ReportProject {
            id: project_id,
            name: sanitize_text(&project_name, "report.project.name"),
            target_host: sanitize_text(&target_host, "report.project.target_host"),
            authorized_scope: scope
                .iter()
                .map(|entry| sanitize_text(entry, "report.project.scope"))
                .collect(),
            excluded_scope: vec![
                "当前项目模型未单独记录排除项；所有未列入授权范围的目标均视为排除范围。"
                    .to_string(),
            ],
            testing_limitations,
            created_at: project_created_at,
        },
        methodology,
        summary: ReportSummary {
            traffic_count,
            confirmed_findings: confirmed_findings.len(),
            pending_findings_in_appendix: pending_appendix.len(),
            rejected_findings_omitted,
            confirmed_risk_distribution: risk_distribution,
            accepted_supporting_evidence,
            test_plan_terminal: test_plan.terminal_nodes,
            test_plan_total: test_plan.total_nodes,
        },
        timeline,
        confirmed_findings,
        pending_appendix,
        test_plan,
        provenance,
    })
}

fn load_finding_rows(conn: &Connection, project_id: i64) -> Result<Vec<FindingRow>, String> {
    let mut statement = conn
        .prepare(
            "SELECT f.id, f.source, f.title, f.vuln_type, f.standard_references,
                    f.severity, f.confidence, f.reasoning, f.verify_steps, f.status,
                    f.analyst_notes, f.fingerprint, f.occurrences, f.created_at, f.updated_at,
                    run.id, run.provider_id, run.model, run.prompt_id, run.prompt_version,
                    run.input_hash, run.validation_status, run.created_at
             FROM findings f
             LEFT JOIN analysis_runs run ON run.id = f.analysis_run_id
             WHERE f.project_id = ?1
             ORDER BY f.id",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([project_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, Option<String>>(11)?,
                row.get::<_, i64>(12)?,
                row.get::<_, String>(13)?,
                row.get::<_, String>(14)?,
                row.get::<_, Option<i64>>(15)?,
                row.get::<_, Option<String>>(16)?,
                row.get::<_, Option<String>>(17)?,
                row.get::<_, Option<String>>(18)?,
                row.get::<_, Option<i64>>(19)?,
                row.get::<_, Option<String>>(20)?,
                row.get::<_, Option<String>>(21)?,
                row.get::<_, Option<String>>(22)?,
            ))
        })
        .map_err(|error| error.to_string())?;

    rows.map(|row| {
        let row = row.map_err(|error| error.to_string())?;
        let ai_run = match row.15 {
            Some(analysis_run_id) => Some(AiSourceVersion {
                analysis_run_id,
                provider_id: row
                    .16
                    .ok_or_else(|| format!("AI Finding #{} 的 provider 审计缺失", row.0))?,
                model: row
                    .17
                    .ok_or_else(|| format!("AI Finding #{} 的 model 审计缺失", row.0))?,
                prompt_id: row
                    .18
                    .ok_or_else(|| format!("AI Finding #{} 的 prompt 审计缺失", row.0))?,
                prompt_version: row
                    .19
                    .ok_or_else(|| format!("AI Finding #{} 的 prompt 版本缺失", row.0))?,
                input_hash: row
                    .20
                    .ok_or_else(|| format!("AI Finding #{} 的输入哈希缺失", row.0))?,
                validation_status: row
                    .21
                    .ok_or_else(|| format!("AI Finding #{} 的校验审计缺失", row.0))?,
                created_at: row
                    .22
                    .ok_or_else(|| format!("AI Finding #{} 的运行时间缺失", row.0))?,
            }),
            None => None,
        };
        if row.1 == "ai" && ai_run.is_none() {
            return Err(format!("AI Finding #{} 无法追溯到 AnalysisRun", row.0));
        }
        Ok(FindingRow {
            id: row.0,
            source: row.1,
            title: row.2,
            vulnerability_type: row.3,
            standard_references: knowledge::references_from_json(&row.4)?,
            severity: row.5,
            confidence: row.6,
            reasoning: row.7,
            verify_steps: row.8,
            status: row.9,
            analyst_notes: row.10,
            fingerprint: row.11,
            occurrences: row.12,
            created_at: row.13,
            updated_at: row.14,
            ai_run,
        })
    })
    .collect()
}

fn load_targets(
    conn: &Connection,
    project_id: i64,
) -> Result<HashMap<i64, Vec<ReportTarget>>, String> {
    let mut statement = conn
        .prepare(
            "SELECT finding_id, traffic_id, method, url, created_at
             FROM (
                 SELECT f.id AS finding_id, t.id AS traffic_id, t.method, t.url, t.created_at
                  FROM findings f
                  JOIN traffic t ON t.id = f.traffic_id
                  WHERE f.project_id = ?1
                    AND t.project_id = f.project_id
                  UNION
                 SELECT ft.finding_id, t.id, t.method, t.url, t.created_at
                 FROM finding_traffic ft
                 JOIN findings f ON f.id = ft.finding_id
                 JOIN traffic t ON t.id = ft.traffic_id
                  WHERE f.project_id = ?1
                    AND t.project_id = f.project_id
             )
             ORDER BY finding_id, traffic_id",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([project_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(|error| error.to_string())?;
    let mut result: HashMap<i64, Vec<ReportTarget>> = HashMap::new();
    for row in rows {
        let (finding_id, traffic_id, method, raw_url, created_at) =
            row.map_err(|error| error.to_string())?;
        result.entry(finding_id).or_default().push(ReportTarget {
            traffic_id: Some(traffic_id),
            method: sanitize_text(&method, "report.target.method"),
            url: redact_report_url(&raw_url),
            observed_at: Some(created_at),
        });
    }
    Ok(result)
}

fn load_evidence(
    conn: &Connection,
    project_id: i64,
    options: ReportOptions,
) -> Result<HashMap<i64, Vec<ReportEvidence>>, String> {
    let mut statement = conn
        .prepare(
            "SELECT fe.finding_id, e.id, e.source_type, e.source_id,
                    CASE e.source_type
                        WHEN 'traffic' THEN EXISTS(SELECT 1 FROM traffic WHERE id=e.source_id)
                        WHEN 'analysis_run' THEN EXISTS(SELECT 1 FROM analysis_runs WHERE id=e.source_id)
                        WHEN 'replay_run' THEN EXISTS(SELECT 1 FROM replay_runs WHERE id=e.source_id)
                        ELSE 0
                    END,
                    e.observation, fe.accepted, e.qualifies_for_confirmation,
                    fe.acceptance_note, fe.accepted_by, fe.accepted_at,
                    e.content_hash, e.created_by, e.created_at, e.redacted_snapshot
             FROM finding_evidence fe
             JOIN findings f ON f.id = fe.finding_id
             JOIN evidence e ON e.id = fe.evidence_id
             WHERE f.project_id = ?1
             ORDER BY fe.finding_id, fe.accepted DESC, e.created_at, e.id",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([project_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, bool>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, bool>(6)?,
                row.get::<_, bool>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, Option<String>>(10)?,
                row.get::<_, String>(11)?,
                row.get::<_, String>(12)?,
                row.get::<_, String>(13)?,
                row.get::<_, String>(14)?,
            ))
        })
        .map_err(|error| error.to_string())?;

    let mut result: HashMap<i64, Vec<ReportEvidence>> = HashMap::new();
    for row in rows {
        let row = row.map_err(|error| error.to_string())?;
        let snapshot: Value = serde_json::from_str(&row.14)
            .map_err(|error| format!("Evidence #{} 快照 JSON 损坏: {error}", row.1))?;
        let canonical_snapshot = serde_json::to_string(&snapshot)
            .map_err(|error| format!("Evidence #{} 快照无法规范化: {error}", row.1))?;
        let snapshot_hash_verified = sha256(canonical_snapshot.as_bytes()) == row.11;
        if !snapshot_hash_verified {
            return Err(format!(
                "Evidence #{} 的快照哈希校验失败，拒绝生成报告",
                row.1
            ));
        }
        let sensitive_live_source_snapshot = if options.include_sensitive_evidence {
            Some(load_sensitive_source_snapshot(
                conn, project_id, &row.2, row.3,
            )?)
        } else {
            None
        };
        result.entry(row.0).or_default().push(ReportEvidence {
            id: row.1,
            source_type: row.2,
            source_id: row.3,
            source_available: row.4,
            observation: sanitize_text(&row.5, "report.evidence.observation"),
            accepted: row.6,
            qualifies_for_confirmation: row.7,
            acceptance_note: sanitize_text(&row.8, "report.evidence.acceptance_note"),
            accepted_by: row
                .9
                .map(|value| sanitize_text(&value, "report.evidence.accepted_by")),
            accepted_at: row.10,
            content_hash: row.11,
            snapshot_hash_verified,
            created_by: sanitize_text(&row.12, "report.evidence.created_by"),
            created_at: row.13,
            redacted_snapshot: snapshot,
            sensitive_live_source_snapshot,
        });
    }
    Ok(result)
}

fn load_rule_hits(
    conn: &Connection,
    project_id: i64,
) -> Result<HashMap<i64, Vec<RuleSourceVersion>>, String> {
    let mut statement = conn
        .prepare(
            "SELECT hit.finding_id, hit.id, hit.pack_id, hit.pack_version,
                    hit.rule_id, hit.rule_version, hit.field_path, hit.evidence,
                    hit.confidence, hit.incomplete_evidence, hit.hit_fingerprint,
                    hit.created_at
             FROM finding_rule_hits hit
             JOIN findings f ON f.id = hit.finding_id
             WHERE f.project_id = ?1
             ORDER BY hit.finding_id, hit.created_at, hit.id",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([project_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                RuleSourceVersion {
                    hit_id: row.get(1)?,
                    pack_id: row.get(2)?,
                    pack_version: row.get(3)?,
                    rule_id: row.get(4)?,
                    rule_version: row.get(5)?,
                    field_path: row.get(6)?,
                    evidence_excerpt: row.get(7)?,
                    confidence: row.get(8)?,
                    incomplete_evidence: row.get(9)?,
                    hit_fingerprint: row.get(10)?,
                    created_at: row.get(11)?,
                },
            ))
        })
        .map_err(|error| error.to_string())?;
    let mut result: HashMap<i64, Vec<RuleSourceVersion>> = HashMap::new();
    for row in rows {
        let (finding_id, mut hit) = row.map_err(|error| error.to_string())?;
        hit.field_path = sanitize_text(&hit.field_path, "report.rule.field_path");
        hit.evidence_excerpt = sanitize_text(&hit.evidence_excerpt, "report.rule.evidence_excerpt");
        result.entry(finding_id).or_default().push(hit);
    }
    Ok(result)
}

fn load_test_plan(conn: &Connection, project_id: i64) -> Result<ReportTestPlan, String> {
    let header = conn
        .query_row(
            "SELECT revision, needs_update, update_reason
             FROM test_plans WHERE project_id = ?1",
            [project_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, bool>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|error| error.to_string())?
        .unwrap_or((0, false, String::new()));
    let mut statement = conn
        .prepare(
            "SELECT node.id, node.stable_key, node.title, node.status, node.priority,
                    node.blocker_reason, node.expected_observation, node.actual_observation,
                    (SELECT COUNT(*) FROM task_evidence te WHERE te.task_id=node.id)
             FROM task_nodes node
             WHERE node.project_id = ?1 AND node.archived = 0
             ORDER BY node.priority, node.created_at, node.id",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([project_id], |row| {
            Ok(ReportTaskItem {
                id: row.get(0)?,
                stable_key: row.get(1)?,
                title: row.get(2)?,
                status: row.get(3)?,
                priority: row.get(4)?,
                reason: row.get(5)?,
                expected_observation: row.get(6)?,
                actual_observation: row.get(7)?,
                evidence_count: row.get(8)?,
            })
        })
        .map_err(|error| error.to_string())?;
    let mut nodes = Vec::new();
    for row in rows {
        let mut node = row.map_err(|error| error.to_string())?;
        node.stable_key = sanitize_text(&node.stable_key, "report.task.stable_key");
        node.title = sanitize_text(&node.title, "report.task.title");
        node.reason = sanitize_text(&node.reason, "report.task.reason");
        node.expected_observation = sanitize_text(
            &node.expected_observation,
            "report.task.expected_observation",
        );
        node.actual_observation =
            sanitize_text(&node.actual_observation, "report.task.actual_observation");
        nodes.push(node);
    }

    let ordered_statuses = [
        "todo",
        "in_progress",
        "done",
        "blocked",
        "skipped",
        "not_applicable",
    ];
    let mut counts = BTreeMap::<String, usize>::new();
    for node in &nodes {
        *counts.entry(node.status.clone()).or_default() += 1;
    }
    let status_distribution = ordered_statuses
        .iter()
        .map(|status| StatusCount {
            status: (*status).to_string(),
            count: counts.get(*status).copied().unwrap_or_default(),
        })
        .collect();
    let terminal_nodes = nodes
        .iter()
        .filter(|node| matches!(node.status.as_str(), "done" | "skipped" | "not_applicable"))
        .count();
    let total_nodes = nodes.len();
    let coverage_percent = if total_nodes == 0 {
        0
    } else {
        terminal_nodes * 100 / total_nodes
    };

    Ok(ReportTestPlan {
        revision: header.0,
        needs_update: header.1,
        update_reason: sanitize_text(&header.2, "report.test_plan.update_reason"),
        total_nodes,
        terminal_nodes,
        coverage_percent,
        status_distribution,
        unfinished_items: nodes
            .iter()
            .filter(|node| matches!(node.status.as_str(), "todo" | "in_progress"))
            .cloned()
            .collect(),
        blocked_items: nodes
            .iter()
            .filter(|node| node.status == "blocked")
            .cloned()
            .collect(),
        excluded_items: nodes
            .into_iter()
            .filter(|node| matches!(node.status.as_str(), "skipped" | "not_applicable"))
            .collect(),
    })
}

fn add_snapshot_targets(targets: &mut Vec<ReportTarget>, evidence: &[ReportEvidence]) {
    let existing: HashSet<(String, String)> = targets
        .iter()
        .map(|target| (target.method.clone(), target.url.clone()))
        .collect();
    let mut added = HashSet::new();
    for item in evidence {
        let Some(request) = item.redacted_snapshot.get("request") else {
            continue;
        };
        let Some(method) = request.get("method").and_then(Value::as_str) else {
            continue;
        };
        let Some(url) = request.get("url").and_then(Value::as_str) else {
            continue;
        };
        let key = (method.to_string(), url.to_string());
        if existing.contains(&key) || !added.insert(key.clone()) {
            continue;
        }
        targets.push(ReportTarget {
            traffic_id: (item.source_type == "traffic").then_some(item.source_id),
            method: sanitize_text(method, "report.target.snapshot_method"),
            url: redact_report_url(url),
            observed_at: item
                .redacted_snapshot
                .get("source_created_at")
                .and_then(Value::as_str)
                .map(ToString::to_string),
        });
    }
}

fn sort_findings(findings: &mut [ReportFinding]) {
    findings.sort_by(|left, right| {
        (severity_rank(&left.severity), left.id).cmp(&(severity_rank(&right.severity), right.id))
    });
}

fn risk_distribution(findings: &[ReportFinding]) -> Vec<RiskCount> {
    ["critical", "high", "medium", "low", "info"]
        .iter()
        .map(|severity| RiskCount {
            severity: (*severity).to_string(),
            count: findings
                .iter()
                .filter(|finding| finding.severity == *severity)
                .count(),
        })
        .collect()
}

fn build_limitations(
    conn: &Connection,
    project_id: i64,
    scope: &[String],
    pending_count: usize,
    test_plan: &ReportTestPlan,
) -> Result<Vec<String>, String> {
    let (truncated_count, decode_limited_count): (i64, i64) = conn
        .query_row(
            "SELECT
                 COALESCE(SUM(req_truncated = 1 OR resp_truncated = 1), 0),
                 COALESCE(SUM(
                     req_decode_status NOT IN ('empty','identity_text','decoded_text')
                     OR resp_decode_status NOT IN (
                         'not_received','empty','identity_text','decoded_text'
                     )
                 ), 0)
             FROM traffic WHERE project_id = ?1",
            [project_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| error.to_string())?;
    let mut limitations = Vec::new();
    if scope.is_empty() {
        limitations.push("项目未记录授权范围；报告不能据此证明任何目标已获授权。".to_string());
    }
    if truncated_count > 0 {
        limitations.push(format!(
            "{truncated_count} 条流量存在请求或响应截断；相关正文不能视为完整内容。"
        ));
    }
    if decode_limited_count > 0 {
        limitations.push(format!(
            "{decode_limited_count} 条流量包含二进制、解码失败或其他受限捕获状态。"
        ));
    }
    if pending_count > 0 {
        limitations.push(format!(
            "{pending_count} 条 Finding 尚未人工确认，仅列入待验证附录，不作为报告结论。"
        ));
    }
    if !test_plan.unfinished_items.is_empty() {
        limitations.push(format!(
            "{} 个测试计划节点尚未完成。",
            test_plan.unfinished_items.len()
        ));
    }
    if !test_plan.blocked_items.is_empty() {
        limitations.push(format!(
            "{} 个测试计划节点受阻；阻塞原因见测试计划章节。",
            test_plan.blocked_items.len()
        ));
    }
    if limitations.is_empty() {
        limitations.push("未记录额外测试限制；这不代表授权范围外目标已被测试。".to_string());
    }
    Ok(limitations)
}

fn build_methodology(
    traffic_count: i64,
    confirmed: &[ReportFinding],
    pending: &[ReportFinding],
    test_plan: &ReportTestPlan,
) -> ReportMethodology {
    let findings = confirmed.iter().chain(pending);
    let has_ai = findings
        .clone()
        .any(|finding| finding.source.ai_run.is_some());
    let has_rules = findings
        .clone()
        .any(|finding| !finding.source.rule_hits.is_empty());
    let has_replay = findings.clone().any(|finding| {
        finding
            .evidence
            .iter()
            .any(|evidence| evidence.source_type == "replay_run")
    });
    let mut methods = Vec::new();
    if traffic_count > 0 {
        methods.push(ReportMethod {
            id: "bounded_traffic_capture".to_string(),
            label: "有界流量采集".to_string(),
            description: "在授权 Scope 内保存带捕获、截断和解码状态的 HTTP 流量。".to_string(),
        });
    }
    if has_rules {
        methods.push(ReportMethod {
            id: "passive_rules".to_string(),
            label: "被动声明式规则".to_string(),
            description: "规则命中只产生待验证假设；规则包、规则版本和字段路径均保留。".to_string(),
        });
    }
    if has_ai {
        methods.push(ReportMethod {
            id: "ai_hypothesis".to_string(),
            label: "AI 辅助假设".to_string(),
            description: "模型输出经过结构校验并保留模型、提示词版本和输入哈希；不自动确认漏洞。"
                .to_string(),
        });
    }
    if has_replay {
        methods.push(ReportMethod {
            id: "authorized_replay".to_string(),
            label: "授权 Repeater 重放".to_string(),
            description: "用户明确触发的 Scope 内请求运行可形成不可变 Evidence 快照。".to_string(),
        });
    }
    methods.push(ReportMethod {
        id: "human_evidence_review".to_string(),
        label: "人工 Evidence 复核".to_string(),
        description: "只有已接受且具备确认资格的 Evidence 才能支撑 confirmed 结论。".to_string(),
    });
    if test_plan.total_nodes > 0 {
        methods.push(ReportMethod {
            id: "evidence_driven_test_plan".to_string(),
            label: "证据驱动测试计划".to_string(),
            description: "计划节点、未完成项和阻塞项按当前持久化 revision 汇总。".to_string(),
        });
    }
    ReportMethodology {
        methods,
        tools: vec![
            ReportToolVersion {
                tool: "RustForge".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            ReportToolVersion {
                tool: "SQLite".to_string(),
                version: rusqlite::version().to_string(),
            },
            ReportToolVersion {
                tool: "Evidence Report Schema".to_string(),
                version: REPORT_SCHEMA_VERSION.to_string(),
            },
        ],
    }
}

fn build_timeline(
    conn: &Connection,
    project_id: i64,
    project_created_at: &str,
    traffic_count: i64,
    confirmed: &[ReportFinding],
    pending: &[ReportFinding],
    test_plan: &ReportTestPlan,
) -> Result<Vec<ReportTimelineEntry>, String> {
    let mut entries = vec![ReportTimelineEntry {
        occurred_at: project_created_at.to_string(),
        kind: "project_created".to_string(),
        reference: format!("project:{project_id}"),
        summary: "项目及授权边界记录已创建。".to_string(),
        order: 0,
    }];
    if traffic_count > 0 {
        let range: (String, String) = conn
            .query_row(
                "SELECT MIN(created_at), MAX(created_at)
                 FROM traffic WHERE project_id = ?1",
                [project_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| error.to_string())?;
        entries.push(ReportTimelineEntry {
            occurred_at: range.0,
            kind: "traffic_capture_started".to_string(),
            reference: format!("traffic-count:{traffic_count}"),
            summary: format!("开始记录授权范围内流量；本报告共统计 {traffic_count} 条。"),
            order: 0,
        });
        if range.1 != entries.last().expect("timeline entry exists").occurred_at {
            entries.push(ReportTimelineEntry {
                occurred_at: range.1,
                kind: "traffic_capture_latest".to_string(),
                reference: format!("traffic-count:{traffic_count}"),
                summary: "报告数据中的最近一条流量已记录。".to_string(),
                order: 0,
            });
        }
    }

    let titles: HashMap<i64, &str> = confirmed
        .iter()
        .chain(pending)
        .map(|finding| (finding.id, finding.title.as_str()))
        .collect();
    let finding_events = {
        let mut statement = conn
            .prepare(
                "SELECT event.id, event.finding_id, event.event_type,
                        event.old_value, event.new_value, event.created_at
                 FROM finding_events event
                 JOIN findings finding ON finding.id = event.finding_id
                 WHERE finding.project_id = ?1
                   AND finding.status <> 'rejected'
                 ORDER BY event.created_at, event.id",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([project_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        rows
    };
    for (event_id, finding_id, event_type, old_value, new_value, created_at) in finding_events {
        let Some(title) = titles.get(&finding_id) else {
            continue;
        };
        let evidence_id = new_value.as_deref().and_then(|value| {
            let mut parts = value.split(':');
            (parts.next() == Some("evidence"))
                .then(|| parts.next()?.parse::<i64>().ok())
                .flatten()
        });
        let (kind, reference, summary) = match event_type.as_str() {
            "created" => (
                "finding_created".to_string(),
                format!("finding:{finding_id}"),
                format!("创建待确认 Finding：{title}。"),
            ),
            "status_changed" => {
                let status = new_value.as_deref().unwrap_or("unknown");
                let kind = match status {
                    "confirmed" => "finding_confirmed",
                    "rejected" => "finding_rejected",
                    "pending" => "finding_reopened",
                    _ => "finding_status_changed",
                };
                (
                    kind.to_string(),
                    format!("finding:{finding_id}"),
                    format!(
                        "Finding 状态由「{}」变为「{}」。",
                        finding_status_cn(old_value.as_deref().unwrap_or("unknown")),
                        finding_status_cn(status)
                    ),
                )
            }
            "severity_changed" => (
                "finding_severity_changed".to_string(),
                format!("finding:{finding_id}"),
                format!(
                    "Finding 风险等级由「{}」调整为「{}」。",
                    old_value.as_deref().unwrap_or("unknown"),
                    new_value.as_deref().unwrap_or("unknown")
                ),
            ),
            "notes_changed" => (
                "finding_notes_changed".to_string(),
                format!("finding:{finding_id}"),
                "Finding 的分析员备注已更新。".to_string(),
            ),
            "evidence_accepted" => (
                "evidence_accepted".to_string(),
                evidence_id
                    .map(|id| format!("evidence:{id}"))
                    .unwrap_or_else(|| format!("finding:{finding_id}")),
                evidence_id
                    .map(|id| format!("Evidence #{id} 经人工接受。"))
                    .unwrap_or_else(|| "Finding Evidence 经人工接受。".to_string()),
            ),
            "evidence_revoked" => (
                "evidence_revoked".to_string(),
                evidence_id
                    .map(|id| format!("evidence:{id}"))
                    .unwrap_or_else(|| format!("finding:{finding_id}")),
                evidence_id
                    .map(|id| format!("Evidence #{id} 的接受判断已撤销。"))
                    .unwrap_or_else(|| "Finding Evidence 的接受判断已撤销。".to_string()),
            ),
            _ => continue,
        };
        entries.push(ReportTimelineEntry {
            occurred_at: created_at,
            kind,
            reference,
            summary,
            order: event_id,
        });
    }

    for finding in confirmed.iter().chain(pending) {
        for evidence in &finding.evidence {
            entries.push(ReportTimelineEntry {
                occurred_at: evidence.created_at.clone(),
                kind: "evidence_created".to_string(),
                reference: format!("evidence:{}", evidence.id),
                summary: format!(
                    "为 Finding #{} 创建 {} Evidence 快照。",
                    finding.id, evidence.source_type
                ),
                order: 0,
            });
        }
    }
    if test_plan.revision > 0 {
        let rows = {
            let mut statement = conn
                .prepare(
                    "SELECT revision, summary, created_at
                     FROM task_plan_revisions WHERE project_id = ?1
                     ORDER BY revision",
                )
                .map_err(|error| error.to_string())?;
            let rows = statement
                .query_map([project_id], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .map_err(|error| error.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?;
            rows
        };
        for (revision, summary, created_at) in rows {
            entries.push(ReportTimelineEntry {
                occurred_at: created_at,
                kind: "test_plan_revision".to_string(),
                reference: format!("test-plan-revision:{revision}"),
                summary: if summary.trim().is_empty() {
                    format!("测试计划 revision {revision} 已应用。")
                } else {
                    sanitize_text(&summary, "report.timeline.plan_summary")
                },
                order: revision,
            });
        }
    }
    entries.sort_by(|left, right| {
        (
            left.occurred_at.as_str(),
            left.order,
            left.kind.as_str(),
            left.reference.as_str(),
        )
            .cmp(&(
                right.occurred_at.as_str(),
                right.order,
                right.kind.as_str(),
                right.reference.as_str(),
            ))
    });
    Ok(entries)
}

fn build_provenance(
    confirmed: &[ReportFinding],
    pending: &[ReportFinding],
) -> Result<ReportProvenance, String> {
    let mut standards = BTreeMap::<(String, String), StandardSourceVersion>::new();
    let mut ai_runs = BTreeSet::new();
    let mut rules = BTreeSet::new();
    for finding in confirmed.iter().chain(pending) {
        for card in knowledge::lookup(&finding.standard_references)? {
            standards
                .entry((
                    card.reference.framework.clone(),
                    card.reference.version.clone(),
                ))
                .or_insert(StandardSourceVersion {
                    framework: card.reference.framework,
                    version: card.reference.version,
                    pack_title: card.pack_title,
                    published_at: card.published_at,
                    source_url: card.source_url,
                });
        }
        if let Some(run) = &finding.source.ai_run {
            ai_runs.insert(run.clone());
        }
        for hit in &finding.source.rule_hits {
            rules.insert(RulePackVersion {
                pack_id: hit.pack_id.clone(),
                pack_version: hit.pack_version.clone(),
                rule_id: hit.rule_id.clone(),
                rule_version: hit.rule_version.clone(),
            });
        }
    }
    Ok(ReportProvenance {
        standard_versions: standards.into_values().collect(),
        ai_runs: ai_runs.into_iter().collect(),
        rule_versions: rules.into_iter().collect(),
        review_notice: "AI 与被动规则只产生待验证假设。报告中的 confirmed 状态来自人工接受 Evidence 后的显式状态变更；仍需由具备授权和专业能力的人员复核。"
            .to_string(),
    })
}

fn load_sensitive_source_snapshot(
    conn: &Connection,
    project_id: i64,
    source_type: &str,
    source_id: i64,
) -> Result<Value, String> {
    match source_type {
        "traffic" => load_sensitive_traffic_snapshot(conn, project_id, source_id),
        "replay_run" => load_sensitive_replay_snapshot(conn, project_id, source_id),
        "analysis_run" => Ok(json!({
            "available": false,
            "reason": "模型原始输出未被持久化；AnalysisRun Evidence 只保留审计元数据和哈希。"
        })),
        _ => Err(format!("不支持的 Evidence 来源类型: {source_type}")),
    }
}

fn load_sensitive_traffic_snapshot(
    conn: &Connection,
    project_id: i64,
    source_id: i64,
) -> Result<Value, String> {
    type TrafficRaw = (
        String,
        String,
        String,
        Option<Vec<u8>>,
        Option<i64>,
        Option<String>,
        Option<Vec<u8>>,
        bool,
        bool,
        String,
    );
    let row: Option<TrafficRaw> = conn
        .query_row(
            "SELECT method, url, req_headers, req_body, status, resp_headers, resp_body,
                    req_truncated, resp_truncated, created_at
             FROM traffic WHERE id = ?1 AND project_id = ?2",
            rusqlite::params![source_id, project_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                ))
            },
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some(row) = row else {
        return Ok(json!({
            "available": false,
            "reason": "原 traffic 已删除；不可变脱敏 Evidence 快照仍保留。"
        }));
    };
    Ok(json!({
        "available": true,
        "warning": "本对象包含未经报告层脱敏的有界实时来源内容。",
        "source": {"type": "traffic", "id": source_id},
        "request": {
            "method": row.0,
            "url": cap_raw_text(&row.1, RAW_FIELD_MAX_BYTES),
            "headers": cap_raw_text(&row.2, RAW_HEADER_MAX_BYTES),
            "body": raw_body(row.3.as_deref(), RAW_FIELD_MAX_BYTES),
            "source_truncated": row.7
        },
        "response": {
            "status": row.4,
            "headers": row.5.as_deref().map(|value| cap_raw_text(value, RAW_HEADER_MAX_BYTES)),
            "body": raw_body(row.6.as_deref(), RAW_FIELD_MAX_BYTES),
            "source_truncated": row.8
        },
        "source_created_at": row.9
    }))
}

fn load_sensitive_replay_snapshot(
    conn: &Connection,
    project_id: i64,
    source_id: i64,
) -> Result<Value, String> {
    type ReplayRaw = (
        String,
        String,
        String,
        Option<Vec<u8>>,
        String,
        Option<i64>,
        String,
        Option<Vec<u8>>,
        bool,
        bool,
        String,
    );
    let row: Option<ReplayRaw> = conn
        .query_row(
            "SELECT method, url, request_headers, request_body, outcome, status,
                    response_headers, response_body, req_truncated, resp_truncated, created_at
             FROM replay_runs WHERE id = ?1 AND project_id = ?2",
            rusqlite::params![source_id, project_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                ))
            },
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some(row) = row else {
        return Ok(json!({
            "available": false,
            "reason": "原 Repeater run 已删除；不可变脱敏 Evidence 快照仍保留。"
        }));
    };
    Ok(json!({
        "available": true,
        "warning": "本对象包含未经报告层脱敏的有界实时来源内容。",
        "source": {"type": "replay_run", "id": source_id},
        "request": {
            "method": row.0,
            "url": cap_raw_text(&row.1, RAW_FIELD_MAX_BYTES),
            "headers": cap_raw_text(&row.2, RAW_HEADER_MAX_BYTES),
            "body": raw_body(row.3.as_deref(), RAW_FIELD_MAX_BYTES),
            "source_truncated": row.8
        },
        "response": {
            "outcome": row.4,
            "status": row.5,
            "headers": cap_raw_text(&row.6, RAW_HEADER_MAX_BYTES),
            "body": raw_body(row.7.as_deref(), RAW_FIELD_MAX_BYTES),
            "source_truncated": row.9
        },
        "source_created_at": row.10
    }))
}

fn raw_body(body: Option<&[u8]>, max_bytes: usize) -> Value {
    let Some(body) = body else {
        return Value::Null;
    };
    let original_size = body.len();
    let bounded = &body[..body.len().min(max_bytes)];
    if let Ok(text) = std::str::from_utf8(bounded) {
        json!({
            "encoding": "utf8",
            "text": text,
            "original_size": original_size,
            "report_truncated": original_size > bounded.len()
        })
    } else {
        json!({
            "encoding": "base64",
            "base64": base64::engine::general_purpose::STANDARD.encode(bounded),
            "original_size": original_size,
            "report_truncated": original_size > bounded.len()
        })
    }
}

fn cap_raw_text(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n[OMITTED:raw_report_limit]", &value[..end])
}

fn sanitize_text(value: &str, location: &str) -> String {
    let mut manifest = RedactionManifest::default();
    redact_fallback_text(value, location, true, &mut manifest)
}

fn redact_report_url(value: &str) -> String {
    let mut manifest = RedactionManifest::default();
    redact_url(value, true, &mut manifest)
}

fn sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        "info" => 4,
        _ => 5,
    }
}

fn source_cn(source: &str) -> &str {
    match source {
        "ai" => "AI 分析",
        "rule" => "被动规则",
        _ => source,
    }
}

fn finding_status_cn(status: &str) -> &str {
    match status {
        "pending" => "待验证",
        "confirmed" => "已确认",
        "rejected" => "已排除",
        _ => status,
    }
}

fn task_status_cn(status: &str) -> &str {
    match status {
        "todo" => "待做",
        "in_progress" => "进行中",
        "done" => "完成",
        "blocked" => "受阻",
        "skipped" => "已跳过",
        "not_applicable" => "不适用",
        _ => status,
    }
}

fn format_references(references: &[StandardReference]) -> String {
    if references.is_empty() {
        "—".to_string()
    } else {
        references
            .iter()
            .map(StandardReference::display_key)
            .map(|value| markdown_text(&value))
            .collect::<Vec<_>>()
            .join("、")
    }
}

fn render_markdown(document: &ReportDocument) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# 证据化安全测试报告：{}\n\n",
        markdown_text(&document.project.name)
    ));
    out.push_str(&format!(
        "- 报告格式：Evidence Report Schema v{}\n",
        document.schema_version
    ));
    out.push_str(&format!(
        "- 报告生成时间：{}\n",
        inline_code(&document.generated_at)
    ));
    out.push_str(&format!(
        "- 内容分级：{}\n\n",
        markdown_text(&document.classification.sensitivity)
    ));
    out.push_str(
        "> **授权与复核声明**：本报告仅适用于项目中明确记录的授权范围。AI 与被动规则只产生待验证假设；confirmed 结论来自人工接受的真实 Evidence，但仍需专业人员复核。禁止将本报告用于未授权目标。\n\n",
    );
    if document.classification.contains_live_raw_source_snapshots {
        out.push_str(
            "> **敏感内容警告**：本次导出经单次明确确认，除不可变脱敏快照外还附加了当前可用来源的有界原始内容。请按敏感资料保管。\n\n",
        );
    }

    out.push_str("## 1. 授权范围、排除范围和测试限制\n\n");
    out.push_str(&format!(
        "- 项目 ID：{}\n- 目标主机：{}\n- 项目创建时间：{}\n",
        inline_code(&document.project.id.to_string()),
        value_or_dash(&document.project.target_host),
        inline_code(&document.project.created_at)
    ));
    out.push_str("- 授权范围：\n");
    render_string_list(&mut out, &document.project.authorized_scope, "（未记录）");
    out.push_str("- 排除范围：\n");
    render_string_list(&mut out, &document.project.excluded_scope, "（未记录）");
    out.push_str("- 测试限制：\n");
    render_string_list(
        &mut out,
        &document.project.testing_limitations,
        "（未记录）",
    );
    out.push('\n');

    out.push_str("## 2. 时间线、方法与工具版本\n\n");
    out.push_str("### 时间线\n\n");
    if document.timeline.is_empty() {
        out.push_str("> 暂无可追溯时间线记录。\n\n");
    } else {
        for entry in &document.timeline {
            out.push_str(&format!(
                "- {} · {} · {}：{}\n",
                inline_code(&entry.occurred_at),
                markdown_text(&entry.kind),
                inline_code(&entry.reference),
                markdown_text(&entry.summary)
            ));
        }
        out.push('\n');
    }
    out.push_str("### 使用的方法\n\n");
    for method in &document.methodology.methods {
        out.push_str(&format!(
            "- **{}**（{}）：{}\n",
            markdown_text(&method.label),
            inline_code(&method.id),
            markdown_text(&method.description)
        ));
    }
    out.push_str("\n### 工具版本\n\n");
    for tool in &document.methodology.tools {
        out.push_str(&format!(
            "- {}：{}\n",
            markdown_text(&tool.tool),
            inline_code(&tool.version)
        ));
    }
    out.push('\n');

    out.push_str("## 3. 执行摘要与风险分布\n\n");
    out.push_str(&format!(
        "- 已记录流量：{} 条\n- 已确认 Finding：{} 条\n- 待验证附录：{} 条\n- 默认省略 rejected Finding：{} 条\n- 已接受且可支撑确认的 Evidence：{} 项\n- 测试计划覆盖：{}/{} 个节点已终结\n",
        document.summary.traffic_count,
        document.summary.confirmed_findings,
        document.summary.pending_findings_in_appendix,
        document.summary.rejected_findings_omitted,
        document.summary.accepted_supporting_evidence,
        document.summary.test_plan_terminal,
        document.summary.test_plan_total
    ));
    out.push_str("- confirmed 风险分布：");
    out.push_str(
        &document
            .summary
            .confirmed_risk_distribution
            .iter()
            .map(|item| format!("{} {}", item.severity, item.count))
            .collect::<Vec<_>>()
            .join("，"),
    );
    out.push_str("\n\n");

    out.push_str("## 4. 已确认 Findings\n\n");
    if document.confirmed_findings.is_empty() {
        out.push_str("> 暂无已确认 Finding。\n\n");
    } else {
        for (index, finding) in document.confirmed_findings.iter().enumerate() {
            render_finding(&mut out, index + 1, finding, true);
        }
    }

    out.push_str("## 5. 测试计划覆盖、未完成项与阻塞项\n\n");
    render_test_plan(&mut out, &document.test_plan);

    out.push_str("## 6. 来源版本与人工复核说明\n\n");
    out.push_str(&format!(
        "> {}\n\n",
        markdown_text(&document.provenance.review_notice)
    ));
    out.push_str("### 标准版本\n\n");
    if document.provenance.standard_versions.is_empty() {
        out.push_str("> 本报告没有标准引用。\n\n");
    } else {
        for standard in &document.provenance.standard_versions {
            out.push_str(&format!(
                "- {} {} · {} · 发布 {} · {}\n",
                markdown_text(&standard.framework),
                inline_code(&standard.version),
                markdown_text(&standard.pack_title),
                inline_code(&standard.published_at),
                safe_external_link("标准来源", &standard.source_url)
            ));
        }
        out.push('\n');
    }
    out.push_str("### AI 模型与提示词版本\n\n");
    if document.provenance.ai_runs.is_empty() {
        out.push_str("> 本报告没有 AI 来源 Finding。\n\n");
    } else {
        for run in &document.provenance.ai_runs {
            out.push_str(&format!(
                "- AnalysisRun {} · provider {} · model {} · prompt {} v{} · input hash {}\n",
                inline_code(&run.analysis_run_id.to_string()),
                inline_code(&run.provider_id),
                inline_code(&run.model),
                inline_code(&run.prompt_id),
                run.prompt_version,
                inline_code(&run.input_hash)
            ));
        }
        out.push('\n');
    }
    out.push_str("### 规则版本\n\n");
    if document.provenance.rule_versions.is_empty() {
        out.push_str("> 本报告没有规则来源 Finding。\n\n");
    } else {
        for rule in &document.provenance.rule_versions {
            out.push_str(&format!(
                "- pack {} {} · rule {} {}\n",
                inline_code(&rule.pack_id),
                inline_code(&rule.pack_version),
                inline_code(&rule.rule_id),
                inline_code(&rule.rule_version)
            ));
        }
        out.push('\n');
    }

    out.push_str("## 附录 A. 待验证 Findings（不作为已确认结论）\n\n");
    if document.pending_appendix.is_empty() {
        out.push_str("> 暂无待验证 Finding。\n\n");
    } else {
        for (index, finding) in document.pending_appendix.iter().enumerate() {
            render_finding(&mut out, index + 1, finding, false);
        }
    }
    out
}

fn render_finding(out: &mut String, index: usize, finding: &ReportFinding, confirmed: bool) {
    out.push_str(&format!(
        "### {}. [{}] {}\n\n",
        index,
        markdown_text(&finding.severity),
        markdown_text(&finding.title)
    ));
    out.push_str("#### 身份、目标与风险\n\n");
    out.push_str(&format!(
        "- Finding ID：{}\n- 稳定身份：{}\n- 状态：{}\n- 类型：{}\n- 风险：{}　置信度：{}　累计出现：{}\n- 来源：{}（需人工复核）\n- 标准引用：{}\n",
        inline_code(&finding.id.to_string()),
        inline_code(&finding.identity),
        markdown_text(finding_status_cn(&finding.status)),
        value_or_dash(&finding.vulnerability_type),
        inline_code(&finding.severity),
        finding.confidence,
        finding.occurrences,
        markdown_text(source_cn(&finding.source.source_type)),
        format_references(&finding.standard_references)
    ));
    if let Some(fingerprint) = &finding.fingerprint {
        out.push_str(&format!("- 指纹：{}\n", inline_code(fingerprint)));
    }
    out.push_str("- 受影响目标：\n");
    if finding.affected_targets.is_empty() {
        out.push_str("  - （来源已删除或未记录目标）\n");
    } else {
        for target in &finding.affected_targets {
            out.push_str(&format!(
                "  - {} {}\n",
                inline_code(&target.method),
                inline_code(&target.url)
            ));
        }
    }
    out.push_str("\n#### 假设依据（不等同于实际复现）\n\n");
    out.push_str(&format!(
        "{}\n\n",
        paragraph_or_placeholder(&finding.hypothesis_reasoning, "（未记录假设依据）")
    ));
    out.push_str("#### 建议验证步骤（计划性内容）\n\n");
    out.push_str(&format!(
        "{}\n\n",
        paragraph_or_placeholder(
            &finding.suggested_validation_steps,
            "（未记录建议验证步骤）"
        )
    ));
    out.push_str("#### 已执行复现与实际 Evidence\n\n");
    if finding.evidence.is_empty() {
        out.push_str("> 尚未关联实际 Evidence；该条目只能保留为待验证假设。\n\n");
    } else {
        for evidence in &finding.evidence {
            render_evidence(out, evidence);
        }
    }
    if confirmed {
        let support_count = finding
            .evidence
            .iter()
            .filter(|evidence| evidence.accepted && evidence.qualifies_for_confirmation)
            .count();
        out.push_str(&format!(
            "> 本结论由 {} 项已接受且具备确认资格的 Evidence 支撑。\n\n",
            support_count
        ));
    }
    out.push_str("#### 修复建议与复测状态\n\n");
    out.push_str(&format!(
        "- 修复建议：{}\n- 复测状态：{}（{}）\n",
        value_or_dash(&finding.remediation),
        inline_code(&finding.retest.status),
        markdown_text(&finding.retest.statement)
    ));
    if !finding.analyst_notes.trim().is_empty() {
        out.push_str(&format!(
            "- 人工备注：{}\n",
            markdown_text(&finding.analyst_notes)
        ));
    }
    out.push('\n');
    render_source_details(out, &finding.source);
}

fn render_evidence(out: &mut String, evidence: &ReportEvidence) {
    out.push_str(&format!(
        "##### Evidence {} · {} {}\n\n",
        inline_code(&evidence.id.to_string()),
        inline_code(&evidence.source_type),
        inline_code(&evidence.source_id.to_string())
    ));
    out.push_str(&format!(
        "- 实际观察：{}\n- 人工接受：{}　可用于确认：{}　来源仍可用：{}\n- 快照 SHA-256：{}（校验{}）\n- 创建者：{}　创建时间：{}\n",
        value_or_dash(&evidence.observation),
        yes_no(evidence.accepted),
        yes_no(evidence.qualifies_for_confirmation),
        yes_no(evidence.source_available),
        inline_code(&evidence.content_hash),
        if evidence.snapshot_hash_verified { "通过" } else { "失败" },
        inline_code(&evidence.created_by),
        inline_code(&evidence.created_at)
    ));
    if !evidence.acceptance_note.trim().is_empty() {
        out.push_str(&format!(
            "- 接受说明：{}\n",
            markdown_text(&evidence.acceptance_note)
        ));
    }
    out.push_str("\n**不可变脱敏请求/响应快照（默认报告内容）**\n\n");
    let snapshot = serde_json::to_string_pretty(&evidence.redacted_snapshot)
        .unwrap_or_else(|_| "{\"error\":\"snapshot serialization failed\"}".to_string());
    push_code_block(out, "json", &snapshot);
    if let Some(raw) = &evidence.sensitive_live_source_snapshot {
        out.push_str("\n**原始来源快照（敏感；本次请求已明确确认，内容有报告级上限）**\n\n");
        let raw = serde_json::to_string_pretty(raw)
            .unwrap_or_else(|_| "{\"error\":\"raw serialization failed\"}".to_string());
        push_code_block(out, "json", &raw);
    }
    out.push('\n');
}

fn render_source_details(out: &mut String, source: &ReportFindingSource) {
    out.push_str("#### 来源审计\n\n");
    if let Some(run) = &source.ai_run {
        out.push_str(&format!(
            "- AI：AnalysisRun {} · provider {} · model {} · prompt {} v{} · validation {}\n",
            inline_code(&run.analysis_run_id.to_string()),
            inline_code(&run.provider_id),
            inline_code(&run.model),
            inline_code(&run.prompt_id),
            run.prompt_version,
            inline_code(&run.validation_status)
        ));
    }
    for hit in &source.rule_hits {
        out.push_str(&format!(
            "- 规则命中 {}：pack {} {} · rule {} {} · 字段 {} · 置信度 {}{}\n",
            inline_code(&hit.hit_id.to_string()),
            inline_code(&hit.pack_id),
            inline_code(&hit.pack_version),
            inline_code(&hit.rule_id),
            inline_code(&hit.rule_version),
            inline_code(&hit.field_path),
            hit.confidence,
            if hit.incomplete_evidence {
                " · 不完整证据"
            } else {
                ""
            }
        ));
        if !hit.evidence_excerpt.trim().is_empty() {
            out.push_str(&format!(
                "  - 规则证据片段（仅为假设来源）：{}\n",
                markdown_text(&hit.evidence_excerpt)
            ));
        }
    }
    if source.ai_run.is_none() && source.rule_hits.is_empty() {
        out.push_str("> 未找到更细粒度的来源版本记录。\n");
    }
    out.push('\n');
}

fn render_test_plan(out: &mut String, plan: &ReportTestPlan) {
    out.push_str(&format!(
        "- 当前 revision：{}\n- 待更新：{}{}\n- 覆盖率：{}%（{}/{} 个节点已终结）\n- 状态分布：{}\n\n",
        plan.revision,
        yes_no(plan.needs_update),
        if plan.update_reason.trim().is_empty() {
            String::new()
        } else {
            format!("（{}）", markdown_text(&plan.update_reason))
        },
        plan.coverage_percent,
        plan.terminal_nodes,
        plan.total_nodes,
        plan.status_distribution
            .iter()
            .map(|item| format!("{} {}", item.status, item.count))
            .collect::<Vec<_>>()
            .join("，")
    ));
    out.push_str("### 未完成项\n\n");
    render_task_items(out, &plan.unfinished_items, "暂无未完成项。");
    out.push_str("### 阻塞项\n\n");
    render_task_items(out, &plan.blocked_items, "暂无阻塞项。");
    out.push_str("### 已跳过 / 不适用项\n\n");
    render_task_items(out, &plan.excluded_items, "暂无已跳过或不适用项。");
}

fn render_task_items(out: &mut String, items: &[ReportTaskItem], empty: &str) {
    if items.is_empty() {
        out.push_str(&format!("> {empty}\n\n"));
        return;
    }
    for item in items {
        out.push_str(&format!(
            "- {} · {} · {} · priority {} · Evidence {}",
            inline_code(&item.stable_key),
            markdown_text(task_status_cn(&item.status)),
            markdown_text(&item.title),
            item.priority,
            item.evidence_count
        ));
        if !item.reason.trim().is_empty() {
            out.push_str(&format!(" · 原因：{}", markdown_text(&item.reason)));
        }
        if !item.actual_observation.trim().is_empty() {
            out.push_str(&format!(
                " · 实际观察：{}",
                markdown_text(&item.actual_observation)
            ));
        }
        out.push('\n');
    }
    out.push('\n');
}

fn render_string_list(out: &mut String, values: &[String], empty: &str) {
    if values.is_empty() {
        out.push_str(&format!("  - {empty}\n"));
    } else {
        for value in values {
            out.push_str(&format!("  - {}\n", markdown_text(value)));
        }
    }
}

fn value_or_dash(value: &str) -> String {
    if value.trim().is_empty() {
        "—".to_string()
    } else {
        markdown_text(value)
    }
}

fn paragraph_or_placeholder(value: &str, placeholder: &str) -> String {
    if value.trim().is_empty() {
        placeholder.to_string()
    } else {
        markdown_text(value)
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "是"
    } else {
        "否"
    }
}

/// Escape untrusted text without turning the Markdown source into an unreadable
/// wall of entities. Structural Markdown punctuation is escaped everywhere;
/// HTML delimiters are encoded.
fn markdown_text(value: &str) -> String {
    let value = value.replace('&', "&amp;");
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' | '`' | '*' | '_' | '[' | ']' | '#' | '|' => {
                escaped.push('\\');
                escaped.push(character);
            }
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            _ => escaped.push(character),
        }
    }
    escaped
        .lines()
        .map(escape_markdown_line_prefix)
        .collect::<Vec<_>>()
        .join("\n")
}

fn escape_markdown_line_prefix(line: &str) -> String {
    let offset = line.len() - line.trim_start().len();
    let (leading, content) = line.split_at(offset);
    let ordered_list = content
        .split_once(". ")
        .is_some_and(|(number, _)| number.chars().all(|character| character.is_ascii_digit()));
    if ordered_list {
        let (number, rest) = content.split_once(". ").expect("ordered list checked");
        format!("{leading}{number}\\. {rest}")
    } else if content.starts_with("- ") || content.starts_with("+ ") {
        format!("{leading}\\{content}")
    } else {
        line.to_string()
    }
}

fn inline_code(value: &str) -> String {
    let value = value.replace(['\r', '\n'], " ");
    let fence_len = longest_run(&value, '`') + 1;
    let fence = "`".repeat(fence_len.max(1));
    if value.starts_with('`')
        || value.ends_with('`')
        || value.starts_with(' ')
        || value.ends_with(' ')
    {
        format!("{fence} {value} {fence}")
    } else {
        format!("{fence}{value}{fence}")
    }
}

fn push_code_block(out: &mut String, language: &str, value: &str) {
    let fence = "`".repeat((longest_run(value, '`') + 1).max(3));
    out.push_str(&format!("{fence}{language}\n{value}\n{fence}\n"));
}

fn longest_run(value: &str, needle: char) -> usize {
    let mut longest = 0;
    let mut current = 0;
    for character in value.chars() {
        if character == needle {
            current += 1;
            longest = longest.max(current);
        } else {
            current = 0;
        }
    }
    longest
}

fn safe_external_link(label: &str, raw_url: &str) -> String {
    let Ok(url) = url::Url::parse(raw_url) else {
        return format!("{}（无有效链接）", markdown_text(label));
    };
    if !matches!(url.scheme(), "http" | "https") {
        return format!("{}（已拒绝非 HTTP(S) 链接）", markdown_text(label));
    }
    let destination = url
        .as_str()
        .replace('<', "%3C")
        .replace('>', "%3E")
        .replace('\\', "%5C");
    format!("[{}](<{}>)", markdown_text(label), destination)
}

/// Convert a project name into a single, bounded filename component. The final
/// export name is always prefixed by RustForge, so Windows reserved names cannot
/// become the full basename.
pub fn safe_file_component(project_name: &str, project_id: i64) -> String {
    let mut result = String::new();
    let mut separator_pending = false;
    for character in project_name.trim().chars() {
        if character.is_alphanumeric() || matches!(character, '-' | '_') {
            if separator_pending && !result.is_empty() && !result.ends_with('-') {
                result.push('-');
            }
            separator_pending = false;
            result.push(character);
        } else {
            separator_pending = true;
        }
        if result.chars().count() >= 48 {
            break;
        }
    }
    let result = result.trim_matches(['-', '_']);
    if result.is_empty() {
        format!("project-{project_id}")
    } else {
        result.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{self, EvidenceSourceType};
    use crate::storage::db::Db;
    use rusqlite::params;
    use tempfile::TempDir;

    struct Fixture {
        _dir: TempDir,
        db: Db,
        project_id: i64,
        confirmed_id: i64,
        pending_id: i64,
        rejected_title: String,
        raw_secret: String,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let mut db = Db::open(&dir.path().join("report.db")).unwrap();
        db.conn
            .execute(
                "INSERT INTO projects(id, name, target_host, scope, created_at)
                 VALUES(7, '<script>alert(1)</script> 演示/项目', 'demo.test',
                        '[\"demo.test\",\"api.demo.test\"]', '2026-07-24 09:00:00')",
                [],
            )
            .unwrap();
        let project_id = 7;
        let raw_secret = "report-secret-token-123456".to_string();
        db.conn
            .execute(
                "INSERT INTO traffic(
                    id, project_id, method, scheme, host, path, url, req_headers, req_body,
                    status, resp_headers, resp_body, content_type,
                    req_wire_size, resp_wire_size, req_captured_size, resp_captured_size,
                    req_truncated, resp_truncated, req_decode_status, resp_decode_status,
                    created_at
                 ) VALUES(
                    11,?1,'POST','https','demo.test','/login',
                    'https://demo.test/login?api_key=report-secret-token-123456',
                    ?2,?3,500,?4,?5,'application/json',
                    20000,24000,20000,8192,0,1,'identity_text','identity_text',
                    '2026-07-24 09:10:00'
                 )",
                params![
                    project_id,
                    format!(
                        r#"{{"Authorization":"Bearer {raw_secret}","Cookie":"sid={raw_secret}","Content-Type":"application/json"}}"#
                    ),
                    format!(r#"{{"username":"admin","api_key":"{raw_secret}"}}"#).into_bytes(),
                    r#"{"Content-Type":"application/json","Set-Cookie":"sid=secret-cookie"}"#,
                    br#"{"error":"SQL syntax near username","padding":"captured prefix"}"#.to_vec()
                ],
            )
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO analysis_runs(
                    id, project_id, traffic_id, provider_id, provider_base_url, model,
                    prompt_id, prompt_version, input_hash, policy_json, manifest_json,
                    validation_status, validation_json, raw_output_hash, created_at
                 ) VALUES(
                    21,?1,11,'test-provider','https://provider.test/v1','model-v2',
                    'traffic_analysis',3,?2,'{}','{}','valid','{}',?3,
                    '2026-07-24 09:12:00'
                 )",
                params![project_id, "a".repeat(64), "b".repeat(64)],
            )
            .unwrap();
        let references_json = knowledge::references_to_json(&[
            StandardReference::new("owasp-top10", "2021", "A03"),
            StandardReference::new("cwe", "4.20", "CWE-89"),
        ])
        .unwrap();
        db.conn
            .execute(
                "INSERT INTO findings(
                    id, project_id, traffic_id, analysis_run_id, source, title, vuln_type,
                    standard_references, severity, confidence, reasoning, verify_steps,
                    analyst_notes, created_at, updated_at
                 ) VALUES(
                    31,?1,11,21,'ai','登录存在 SQL 注入 # 标题','SQL 注入',?2,'high',87,
                    'AI 假设：参数 username 可能触发报错，不是已执行结果。',
                    '1. 在授权环境输入单引号\n2. 对比响应',
                    '由分析员复核。','2026-07-24 09:13:00','2026-07-24 09:13:00'
                 )",
                params![project_id, references_json],
            )
            .unwrap();
        let confirmed_id = 31;
        let evidence = evidence::service::create_finding_evidence(
            &mut db.conn,
            confirmed_id,
            EvidenceSourceType::Traffic,
            11,
            "人工观察到 500 与 SQL 错误片段；Authorization: Bearer report-secret-token-123456",
            "test:analyst",
        )
        .unwrap();
        evidence::service::set_finding_evidence_accepted(
            &mut db.conn,
            confirmed_id,
            evidence.id,
            true,
            "响应差异可重复",
            "test:analyst",
        )
        .unwrap();
        evidence::service::update_finding_status(
            &mut db.conn,
            confirmed_id,
            "confirmed",
            Some("Evidence 已人工复核"),
            "test:analyst",
        )
        .unwrap();
        db.conn
            .execute(
                "UPDATE findings SET updated_at='2026-07-24 09:20:00' WHERE id=31",
                [],
            )
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO findings(
                    id, project_id, traffic_id, analysis_run_id, source, title, vuln_type,
                    standard_references, severity, confidence, reasoning, verify_steps,
                    created_at, updated_at
                 ) VALUES(
                    32,?1,11,21,'ai','待确认的会话问题','会话管理','[]','medium',55,
                    '仅为待验证假设。','检查会话轮换。','2026-07-24 09:14:00',
                    '2026-07-24 09:14:00'
                 )",
                [project_id],
            )
            .unwrap();
        let pending_id = 32;
        let rejected_title = "绝不能出现在默认报告中的误报".to_string();
        db.conn
            .execute(
                "INSERT INTO findings(
                    id, project_id, source, title, standard_references, severity, confidence,
                    created_at, updated_at
                 ) VALUES(33,?1,'rule',?2,'[]','low',20,
                          '2026-07-24 09:15:00','2026-07-24 09:15:00')",
                params![project_id, rejected_title],
            )
            .unwrap();
        evidence::service::update_finding_status(
            &mut db.conn,
            33,
            "rejected",
            Some("人工确认是误报"),
            "test:analyst",
        )
        .unwrap();

        db.conn
            .execute(
                "INSERT INTO test_plans(project_id, revision, needs_update, update_reason)
                 VALUES(?1,1,1,'新 Evidence 到达')
                 ON CONFLICT(project_id) DO UPDATE SET
                    revision=excluded.revision,
                    needs_update=excluded.needs_update,
                    update_reason=excluded.update_reason",
                [project_id],
            )
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO task_plan_revisions(project_id, revision, actor, summary, created_at)
                 VALUES(?1,1,'test:analyst','初始测试计划','2026-07-24 09:16:00')",
                [project_id],
            )
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO task_nodes(
                    id, project_id, stable_key, title, status, priority, source,
                    created_revision, updated_revision, created_at, updated_at
                 ) VALUES
                    (41,?1,'test:login','验证登录注入','done',10,'manual',1,1,
                     '2026-07-24 09:16:00','2026-07-24 09:19:00'),
                    (42,?1,'test:session','验证会话轮换','todo',20,'ai',1,1,
                     '2026-07-24 09:16:00','2026-07-24 09:16:00'),
                    (43,?1,'test:admin','验证管理员路径','blocked',30,'manual',1,1,
                     '2026-07-24 09:16:00','2026-07-24 09:16:00')",
                [project_id],
            )
            .unwrap_err();
        db.conn
            .execute(
                "INSERT INTO task_nodes(
                    id, project_id, stable_key, title, status, priority, blocker_reason, source,
                    created_revision, updated_revision, created_at, updated_at
                 ) VALUES
                    (41,?1,'test:login','验证登录注入','done',10,'','manual',1,1,
                     '2026-07-24 09:16:00','2026-07-24 09:19:00'),
                    (42,?1,'test:session','验证会话轮换','todo',20,'','ai',1,1,
                     '2026-07-24 09:16:00','2026-07-24 09:16:00'),
                    (43,?1,'test:admin','验证管理员路径','blocked',30,'缺少授权账号','manual',1,1,
                     '2026-07-24 09:16:00','2026-07-24 09:16:00')",
                [project_id],
            )
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO task_findings(task_id, finding_id) VALUES(41,31)",
                [],
            )
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO task_evidence(task_id, evidence_id) VALUES(41,?1)",
                [evidence.id],
            )
            .unwrap();

        Fixture {
            _dir: dir,
            db,
            project_id,
            confirmed_id,
            pending_id,
            rejected_title,
            raw_secret,
        }
    }

    #[test]
    fn report_snapshot_covers_statuses_empty_evidence_truncation_and_multiple_standards() {
        let fixture = fixture();
        let mut document = build_document(
            &fixture.db.conn,
            fixture.project_id,
            ReportOptions::redacted(),
            "2026-07-28T12:00:00+08:00",
        )
        .unwrap();
        normalize_fixture_times(&mut document);
        let markdown = render_markdown(&document);
        let json = serde_json::to_string_pretty(&document).unwrap();
        let expected_markdown =
            include_str!("../tests/fixtures/report/evidence-report-v2.md").replace("\r\n", "\n");
        let expected_json =
            include_str!("../tests/fixtures/report/evidence-report-v2.json").replace("\r\n", "\n");
        assert_eq!(markdown.trim_end(), expected_markdown.trim_end());
        assert_eq!(json, expected_json.trim_end());
        assert!(!markdown.contains(&fixture.rejected_title));
        assert!(!json.contains(&fixture.rejected_title));
        assert!(!markdown.contains(&fixture.raw_secret));
        assert!(!json.contains(&fixture.raw_secret));
        assert!(markdown.contains("\"truncated\": true"));
        assert!(markdown.contains("A03:2021"));
        assert!(markdown.contains("CWE-89 (v4.20)"));
        assert!(markdown.contains("待确认的会话问题"));
    }

    #[test]
    fn confirmed_finding_without_supporting_evidence_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("invalid.db")).unwrap();
        db.conn
            .execute(
                "INSERT INTO projects(id,name,target_host,scope) VALUES(1,'x','x','[\"x\"]')",
                [],
            )
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO findings(id,project_id,source,title) VALUES(1,1,'rule','bad')",
                [],
            )
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO finding_events(
                    finding_id,event_type,old_value,new_value,reason,actor
                 ) VALUES(1,'status_changed','pending','confirmed','bad fixture','test')",
                [],
            )
            .unwrap();
        db.conn
            .execute("DROP TRIGGER trg_finding_confirmed_requires_evidence", [])
            .unwrap();
        db.conn
            .execute("UPDATE findings SET status='confirmed' WHERE id=1", [])
            .unwrap();
        let error = build_markdown(&db.conn, 1).unwrap_err();
        assert!(error.contains("没有已接受、可用于确认且哈希有效的 Evidence"));
    }

    #[test]
    fn finding_timeline_uses_immutable_events_instead_of_updated_at() {
        let mut fixture = fixture();
        let event_time: String = fixture
            .db
            .conn
            .query_row(
                "SELECT created_at
                 FROM finding_events
                 WHERE finding_id=?1
                   AND event_type='status_changed'
                   AND new_value='confirmed'
                 ORDER BY id DESC LIMIT 1",
                [fixture.confirmed_id],
                |row| row.get(0),
            )
            .unwrap();
        let before = build_document(
            &fixture.db.conn,
            fixture.project_id,
            ReportOptions::redacted(),
            "before",
        )
        .unwrap();
        let confirmed_time = before
            .timeline
            .iter()
            .find(|entry| {
                entry.kind == "finding_confirmed"
                    && entry.reference == format!("finding:{}", fixture.confirmed_id)
            })
            .unwrap()
            .occurred_at
            .clone();
        assert_eq!(confirmed_time, event_time);

        fixture
            .db
            .conn
            .execute(
                "UPDATE findings SET updated_at='2099-01-01 00:00:00' WHERE id=?1",
                [fixture.confirmed_id],
            )
            .unwrap();
        let after_touch = build_document(
            &fixture.db.conn,
            fixture.project_id,
            ReportOptions::redacted(),
            "after",
        )
        .unwrap();
        assert_eq!(
            after_touch
                .timeline
                .iter()
                .find(|entry| {
                    entry.kind == "finding_confirmed"
                        && entry.reference == format!("finding:{}", fixture.confirmed_id)
                })
                .unwrap()
                .occurred_at,
            confirmed_time
        );

        evidence::service::update_finding_status(
            &mut fixture.db.conn,
            fixture.confirmed_id,
            "pending",
            Some("重新复核"),
            "test:analyst",
        )
        .unwrap();
        evidence::service::update_finding_status(
            &mut fixture.db.conn,
            fixture.confirmed_id,
            "confirmed",
            Some("再次确认"),
            "test:analyst",
        )
        .unwrap();
        let replayed = build_document(
            &fixture.db.conn,
            fixture.project_id,
            ReportOptions::redacted(),
            "replayed",
        )
        .unwrap();
        let transitions: Vec<&str> = replayed
            .timeline
            .iter()
            .filter(|entry| entry.reference == format!("finding:{}", fixture.confirmed_id))
            .filter_map(|entry| match entry.kind.as_str() {
                "finding_confirmed" | "finding_reopened" => Some(entry.kind.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            transitions,
            vec!["finding_confirmed", "finding_reopened", "finding_confirmed"]
        );
    }

    #[test]
    fn backend_confirmed_sensitive_export_includes_live_sources() {
        let fixture = fixture();
        let options = ReportOptions::confirmed_sensitive();
        let bundle = build_bundle_at(
            &fixture.db.conn,
            fixture.project_id,
            options,
            "2026-07-28T12:00:00+08:00",
        )
        .unwrap();
        assert!(bundle.contains_sensitive_evidence);
        assert!(bundle.markdown.contains("敏感内容警告"));
        assert!(bundle.markdown.contains(&fixture.raw_secret));
        assert!(bundle.json.contains(&fixture.raw_secret));
    }

    #[test]
    fn repeated_build_is_stable_except_for_generation_time() {
        let fixture = fixture();
        let first = build_document(
            &fixture.db.conn,
            fixture.project_id,
            ReportOptions::redacted(),
            "first",
        )
        .unwrap();
        let second = build_document(
            &fixture.db.conn,
            fixture.project_id,
            ReportOptions::redacted(),
            "second",
        )
        .unwrap();
        assert_ne!(first.generated_at, second.generated_at);
        let mut first = first;
        let mut second = second;
        first.generated_at.clear();
        second.generated_at.clear();
        assert_eq!(first, second);
    }

    #[test]
    fn rule_pack_and_rule_versions_are_traceable() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("rule-report.db")).unwrap();
        db.conn
            .execute(
                "INSERT INTO projects(id,name,target_host,scope)
                 VALUES(1,'rule report','rules.test','[\"rules.test\"]')",
                [],
            )
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO traffic(id,project_id,method,host,url,created_at)
                 VALUES(2,1,'GET','rules.test','https://rules.test/health',
                        '2026-07-24 10:00:00')",
                [],
            )
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO findings(
                    id,project_id,traffic_id,source,title,severity,confidence,created_at,updated_at
                 ) VALUES(
                    3,1,2,'rule','错误信息泄露','low',60,
                    '2026-07-24 10:01:00','2026-07-24 10:01:00'
                 )",
                [],
            )
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO rule_evaluations(
                    id,project_id,traffic_id,pack_id,pack_version,status,
                    hit_count,finding_count,duration_ms
                 ) VALUES(4,1,2,'builtin','1.2.3','completed',1,1,2)",
                [],
            )
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO finding_rule_hits(
                    id,finding_id,evaluation_id,traffic_id,pack_id,pack_version,
                    rule_id,rule_version,field_path,evidence,confidence,
                    incomplete_evidence,hit_fingerprint,created_at
                 ) VALUES(
                    5,3,4,2,'builtin','1.2.3','error-leak','2.4.0',
                    'response.body','SQLSTATE [REDACTED]',60,0,?1,
                    '2026-07-24 10:01:00'
                 )",
                ["c".repeat(64)],
            )
            .unwrap();

        let document = build_document(
            &db.conn,
            1,
            ReportOptions::redacted(),
            "2026-07-28T12:00:00+08:00",
        )
        .unwrap();
        let hit = &document.pending_appendix[0].source.rule_hits[0];
        assert_eq!(hit.pack_version, "1.2.3");
        assert_eq!(hit.rule_version, "2.4.0");
        assert_eq!(document.provenance.rule_versions.len(), 1);
        let markdown = render_markdown(&document);
        assert!(markdown.contains("pack `builtin` `1.2.3`"));
        assert!(markdown.contains("rule `error-leak` `2.4.0`"));
    }

    #[test]
    fn markdown_and_filename_escape_untrusted_content() {
        assert_eq!(
            safe_file_component("../../CON:<bad>|name?.md", 9),
            "CON-bad-name-md"
        );
        assert_eq!(safe_file_component(" ... ", 9), "project-9");
        let escaped = markdown_text("<script>[x](javascript:alert(1))\n# heading\n- item");
        assert!(!escaped.contains("<script>"));
        assert!(escaped.contains("&lt;script&gt;"));
        assert!(!escaped.contains("[x]("));
        assert!(escaped.contains("\\# heading"));
        assert!(escaped.contains("\\- item"));
        assert!(safe_external_link("x", "javascript:alert(1)").contains("已拒绝"));
    }

    #[test]
    fn fixture_exercises_confirmed_and_pending_rows() {
        let fixture = fixture();
        let document = build_document(
            &fixture.db.conn,
            fixture.project_id,
            ReportOptions::redacted(),
            "fixed",
        )
        .unwrap();
        assert_eq!(document.confirmed_findings[0].id, fixture.confirmed_id);
        assert_eq!(document.pending_appendix[0].id, fixture.pending_id);
        assert!(document.pending_appendix[0].evidence.is_empty());
    }

    fn normalize_fixture_times(document: &mut ReportDocument) {
        for finding in document
            .confirmed_findings
            .iter_mut()
            .chain(document.pending_appendix.iter_mut())
        {
            for observation in &mut finding.executed_reproduction {
                observation.observed_at = "2026-07-24 09:18:00.000".to_string();
            }
            for evidence in &mut finding.evidence {
                evidence.created_at = "2026-07-24 09:18:00.000".to_string();
                if evidence.accepted_at.is_some() {
                    evidence.accepted_at = Some("2026-07-24 09:19:00.000".to_string());
                }
            }
        }
        for entry in &mut document.timeline {
            match entry.kind.as_str() {
                "evidence_created" => entry.occurred_at = "2026-07-24 09:18:00.000".to_string(),
                "evidence_accepted" => entry.occurred_at = "2026-07-24 09:19:00.000".to_string(),
                "finding_confirmed" => entry.occurred_at = "2026-07-24 09:20:00.000".to_string(),
                _ => {}
            }
        }
        document.timeline.sort_by(|left, right| {
            (
                left.occurred_at.as_str(),
                left.order,
                left.kind.as_str(),
                left.reference.as_str(),
            )
                .cmp(&(
                    right.occurred_at.as_str(),
                    right.order,
                    right.kind.as_str(),
                    right.reference.as_str(),
                ))
        });
    }
}
