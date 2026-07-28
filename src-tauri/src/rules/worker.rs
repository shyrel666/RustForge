//! 被动规则的后台求值。
//!
//! 三条硬约束：
//! 1. **不占代理的写事务。** 代理只用一个短事务把流量落库然后立刻提交；规则
//!    任务经有界队列投递到这里，用独立连接求值和写库。
//! 2. **不阻塞转发。** 投递一律 `try_send`，队列满就计入 `dropped_evaluations`
//!    并丢弃这次求值，绝不让响应回调等待。
//! 3. **可重试、不重复。** `(traffic_id, pack_id, pack_version)` 是幂等键；求值
//!    在事务外完成，写库时先抢这把键，抢不到就说明已经处理过。

use crate::knowledge;
use crate::rules::engine::{self, EvaluationReport, TrafficView};
use crate::rules::fingerprint::finding_fingerprint;
use crate::rules::loader::{self, PackStatus};
use crate::rules::schema::Severity;
use crate::secrets::redact_sensitive;
use crate::storage::db::Pool;
use crate::storage::models::{Finding, TrafficTagsUpdate};
use rusqlite::OptionalExtension;
use serde::Serialize;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// 待求值队列容量。满了就降级丢弃——保住转发延迟比保住一条初筛结果重要。
pub const RULE_QUEUE_CAPACITY: usize = 256;

/// 求值产出的回调（写库之后触发），生产环境转成 Tauri 事件。
pub trait RuleSink: Send + Sync + 'static {
    fn on_finding(&self, _finding: &Finding) {}
    /// 同一指纹再次命中：关联流量或命中审计更新了，但不是新问题。
    fn on_finding_updated(&self, _finding: &Finding) {}
    fn on_traffic_tags(&self, _update: &TrafficTagsUpdate) {}
}

/// 一次待求值任务：流量已经落库，队列只携带稳定身份。正文等有界快照由
/// worker 消费任务时从数据库读取，避免队列容量乘以正文上限形成内存尖峰。
#[derive(Debug, Clone)]
pub struct RuleJob {
    pub project_id: i64,
    pub traffic_id: i64,
}

#[derive(Debug)]
struct RuleInput {
    pub method: String,
    pub url: String,
    pub req_headers: String,
    pub resp_headers: Option<String>,
    pub req_body: Vec<u8>,
    pub resp_body: Option<Vec<u8>>,
    pub status: Option<u16>,
    pub content_type: Option<String>,
    pub req_truncated: bool,
    pub resp_truncated: bool,
    pub req_decode_status: String,
    pub resp_decode_status: String,
}

impl RuleInput {
    fn view(&self) -> TrafficView<'_> {
        TrafficView {
            method: &self.method,
            url: &self.url,
            req_headers: &self.req_headers,
            resp_headers: self.resp_headers.as_deref(),
            req_body: &self.req_body,
            resp_body: self.resp_body.as_deref(),
            status: self.status,
            content_type: self.content_type.as_deref(),
            req_truncated: self.req_truncated,
            resp_truncated: self.resp_truncated,
            req_decode_status: &self.req_decode_status,
            resp_decode_status: &self.resp_decode_status,
        }
    }
}

#[derive(Debug, Default)]
struct Counters {
    submitted: AtomicU64,
    completed: AtomicU64,
    dropped: AtomicU64,
    timed_out: AtomicU64,
    failed: AtomicU64,
}

/// 队列与计数器。`TrafficHandler` 每个请求都会 clone 一次，所以这里只持有
/// `Arc`/`SyncSender`，不会重复起线程。
#[derive(Debug, Clone)]
pub struct RuleQueue {
    sender: SyncSender<RuleJob>,
    counters: Arc<Counters>,
    capacity: usize,
}

impl RuleQueue {
    /// 投递一次求值。永不阻塞：队列满或消费端已退出都立刻返回 false。
    pub fn try_submit(&self, job: RuleJob) -> bool {
        self.counters.submitted.fetch_add(1, Ordering::Relaxed);
        match self.sender.try_send(job) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.counters.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    pub fn snapshot(&self) -> QueueMetrics {
        snapshot(&self.counters, self.capacity)
    }
}

fn snapshot(counters: &Counters, capacity: usize) -> QueueMetrics {
    let submitted = counters.submitted.load(Ordering::Relaxed);
    let completed = counters.completed.load(Ordering::Relaxed);
    let dropped = counters.dropped.load(Ordering::Relaxed);
    QueueMetrics {
        submitted_evaluations: submitted,
        completed_evaluations: completed,
        dropped_evaluations: dropped,
        timed_out_evaluations: counters.timed_out.load(Ordering::Relaxed),
        failed_evaluations: counters.failed.load(Ordering::Relaxed),
        queue_capacity: capacity,
        queue_depth: submitted.saturating_sub(completed).saturating_sub(dropped),
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct QueueMetrics {
    pub submitted_evaluations: u64,
    pub completed_evaluations: u64,
    pub dropped_evaluations: u64,
    pub timed_out_evaluations: u64,
    pub failed_evaluations: u64,
    pub queue_capacity: usize,
    pub queue_depth: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RulePackStatusInfo {
    pub pack_id: String,
    pub version: String,
    pub rule_count: usize,
    pub loaded: bool,
    pub disabled_reason: Option<String>,
}

/// 一次持久化规则求值的可诊断摘要。正文和原始证据仍只保存在 traffic/Finding，
/// 这里不复制敏感数据。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RuleEvaluationInfo {
    pub id: i64,
    pub project_id: i64,
    pub traffic_id: i64,
    pub pack_id: String,
    pub pack_version: String,
    pub status: String,
    pub hit_count: i64,
    pub finding_count: i64,
    pub duration_ms: i64,
    pub diagnostics: Vec<String>,
    pub created_at: String,
}

/// 给 UI 的规则运行状况：坏包原因、超时次数、队列丢弃计数一次给全。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RuleDiagnostics {
    pub packs: Vec<RulePackStatusInfo>,
    #[serde(flatten)]
    pub metrics: QueueMetrics,
    /// 后台求值最近一次失败原因（已脱敏）。
    pub last_error: Option<String>,
    /// 当前项目最近的持久化求值记录，由 IPC 命令按项目补入。
    pub recent_evaluations: Vec<RuleEvaluationInfo>,
    /// 代理未运行时为 false；上一轮 worker 的累计计数仍保留到下一次启动。
    pub worker_running: bool,
}

fn pack_info(status: &PackStatus) -> RulePackStatusInfo {
    RulePackStatusInfo {
        pack_id: status.pack_id().to_string(),
        version: status
            .pack()
            .map(|pack| pack.version.clone())
            .unwrap_or_default(),
        rule_count: status.pack().map_or(0, |pack| pack.rules.len()),
        loaded: status.is_loaded(),
        disabled_reason: status.disabled_reason().map(str::to_string),
    }
}

fn pack_identity(status: &PackStatus) -> (&str, &str) {
    match status {
        PackStatus::Loaded(pack) => (pack.pack_id.as_str(), pack.version.as_str()),
        PackStatus::Disabled { pack_id, .. } => (pack_id.as_str(), ""),
    }
}

/// 当前或最近一轮 worker 的观测点。只保留一份很小的状态快照，使代理停止后
/// 仍能看到刚才发生的丢弃/超时；下次启动会原子替换它。
static ACTIVE: Mutex<Option<Arc<WorkerState>>> = Mutex::new(None);

#[derive(Debug)]
struct WorkerState {
    counters: Arc<Counters>,
    capacity: usize,
    last_error: Mutex<Option<String>>,
    packs: Arc<Vec<PackStatus>>,
    running: AtomicBool,
}

/// 规则诊断快照。没有活跃 worker 时仍然返回内置包状态。
pub fn diagnostics() -> RuleDiagnostics {
    let active = ACTIVE.lock().ok().and_then(|guard| guard.clone());
    match active {
        Some(state) => RuleDiagnostics {
            packs: state.packs.iter().map(pack_info).collect(),
            metrics: snapshot(&state.counters, state.capacity),
            last_error: state.last_error.lock().ok().and_then(|error| error.clone()),
            recent_evaluations: Vec::new(),
            worker_running: state.running.load(Ordering::Relaxed),
        },
        None => RuleDiagnostics {
            packs: vec![pack_info(loader::builtin_pack())],
            metrics: QueueMetrics {
                queue_capacity: RULE_QUEUE_CAPACITY,
                ..QueueMetrics::default()
            },
            last_error: None,
            recent_evaluations: Vec::new(),
            worker_running: false,
        },
    }
}

/// 后台求值线程。
///
/// 独立 OS 线程而不是 tokio task：规则求值是 CPU 密集 + 阻塞式 SQLite 写入，
/// 放在异步运行时里会顶住转发用的工作线程。
pub struct RuleWorker {
    db: Pool,
    sink: Arc<dyn RuleSink>,
    state: Arc<WorkerState>,
}

impl RuleWorker {
    /// 起一个 worker，返回投递句柄。所有句柄 drop 后线程自然退出。
    pub fn spawn(db: Pool, sink: Arc<dyn RuleSink>) -> RuleQueue {
        Self::spawn_with(
            db,
            sink,
            Arc::new(vec![loader::builtin_pack().clone()]),
            RULE_QUEUE_CAPACITY,
        )
    }

    pub fn spawn_with(
        db: Pool,
        sink: Arc<dyn RuleSink>,
        packs: Arc<Vec<PackStatus>>,
        capacity: usize,
    ) -> RuleQueue {
        let (queue, receiver) = new_queue(capacity);
        let state = Arc::new(WorkerState {
            counters: Arc::clone(&queue.counters),
            capacity,
            last_error: Mutex::new(None),
            packs,
            running: AtomicBool::new(true),
        });
        if let Ok(mut active) = ACTIVE.lock() {
            *active = Some(Arc::clone(&state));
        }
        let worker = Self { db, sink, state };
        std::thread::Builder::new()
            .name("rustforge-rules".to_string())
            .spawn(move || worker.run(receiver))
            .expect("规则求值线程必须能启动");
        queue
    }

    fn run(self, receiver: Receiver<RuleJob>) {
        while let Ok(job) = receiver.recv() {
            self.process(&job);
            self.state
                .counters
                .completed
                .fetch_add(1, Ordering::Relaxed);
        }
        self.state.running.store(false, Ordering::Relaxed);
    }

    fn process(&self, job: &RuleJob) {
        for pack in self.state.packs.iter() {
            if let Err(error) = self.evaluate_and_store(job, pack) {
                self.state.counters.failed.fetch_add(1, Ordering::Relaxed);
                let redacted = redact_sensitive(&error, &[]);
                eprintln!("[rules] 后台求值失败: {redacted}");
                if let Ok(mut last) = self.state.last_error.lock() {
                    *last = Some(redacted);
                }
            }
        }
    }

    fn evaluate_and_store(&self, job: &RuleJob, pack: &PackStatus) -> Result<(), String> {
        // 重启或显式重试同一任务时，先用独立只读连接查幂等键。连接在求值前
        // 释放；随后只在当前任务真正需要求值时读取一次正文快照。
        if self.was_evaluated(job, pack)? {
            return Ok(());
        }

        // 求值不持有任何数据库连接，更不持有事务
        let input = self.load_rule_input(job)?;
        let started = Instant::now();
        let view = input.view();
        let report = engine::evaluate_status(pack, &view);
        let duration_ms = started.elapsed().as_millis() as i64;
        if report.timed_out {
            self.state
                .counters
                .timed_out
                .fetch_add(1, Ordering::Relaxed);
        }

        let outcome = self.store(job, pack, &report, duration_ms)?;
        for finding in &outcome.created {
            self.sink.on_finding(finding);
        }
        for finding in &outcome.updated {
            self.sink.on_finding_updated(finding);
        }
        if let Some(update) = &outcome.tags {
            self.sink.on_traffic_tags(update);
        }
        Ok(())
    }

    fn load_rule_input(&self, job: &RuleJob) -> Result<RuleInput, String> {
        let db = self.db.get().map_err(|error| error.to_string())?;
        db.query_row(
            "SELECT method, url, req_headers, resp_headers, req_body, resp_body,
                    status, content_type, req_truncated, resp_truncated,
                    req_decode_status, resp_decode_status
             FROM traffic
             WHERE id = ?1 AND project_id = ?2",
            rusqlite::params![job.traffic_id, job.project_id],
            |row| {
                Ok(RuleInput {
                    method: row.get(0)?,
                    url: row.get(1)?,
                    req_headers: row.get(2)?,
                    resp_headers: row.get(3)?,
                    req_body: row.get::<_, Option<Vec<u8>>>(4)?.unwrap_or_default(),
                    resp_body: row.get(5)?,
                    status: row.get(6)?,
                    content_type: row.get(7)?,
                    req_truncated: row.get(8)?,
                    resp_truncated: row.get(9)?,
                    req_decode_status: row.get(10)?,
                    resp_decode_status: row.get(11)?,
                })
            },
        )
        .map_err(|error| {
            format!(
                "规则任务引用的流量 #{} 不存在或无法读取: {error}",
                job.traffic_id
            )
        })
    }

    fn was_evaluated(&self, job: &RuleJob, pack: &PackStatus) -> Result<bool, String> {
        let (pack_id, pack_version) = pack_identity(pack);
        let db = self.db.get().map_err(|error| error.to_string())?;
        db.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM rule_evaluations
                 WHERE traffic_id = ?1 AND pack_id = ?2 AND pack_version = ?3
             )",
            rusqlite::params![job.traffic_id, pack_id, pack_version],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())
    }

    fn store(
        &self,
        job: &RuleJob,
        pack: &PackStatus,
        report: &EvaluationReport<'_>,
        duration_ms: i64,
    ) -> Result<StoreOutcome, String> {
        let mut db = self.db.get().map_err(|e| e.to_string())?;
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;

        let (pack_id, pack_version) = pack_identity(pack);
        let status = if !pack.is_loaded() {
            "pack_disabled"
        } else if report.timed_out {
            "timed_out"
        } else {
            "completed"
        };
        let diagnostics: Vec<String> = report
            .diagnostics
            .iter()
            .map(|diagnostic| {
                format!(
                    "{}: {}",
                    diagnostic.code,
                    redact_sensitive(&diagnostic.message, &[])
                )
            })
            .collect();

        // 抢幂等键。抢不到 = 这条流量的这个包版本已经处理过，直接结束。
        let claimed = tx
            .execute(
                "INSERT OR IGNORE INTO rule_evaluations(
                     project_id, traffic_id, pack_id, pack_version, status,
                     hit_count, finding_count, duration_ms, diagnostics)
                 VALUES(?1,?2,?3,?4,?5,?6,0,?7,?8)",
                rusqlite::params![
                    job.project_id,
                    job.traffic_id,
                    pack_id,
                    pack_version,
                    status,
                    report.hits.len() as i64,
                    duration_ms,
                    serde_json::to_string(&diagnostics).unwrap_or_else(|_| "[]".to_string()),
                ],
            )
            .map_err(|e| e.to_string())?;
        if claimed == 0 {
            return Ok(StoreOutcome::default());
        }
        let evaluation_id = tx.last_insert_rowid();

        let mut outcome = StoreOutcome::default();
        let raw_tags: String = tx
            .query_row(
                "SELECT rule_tags FROM traffic WHERE id = ?1 AND project_id = ?2",
                rusqlite::params![job.traffic_id, job.project_id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let mut tags: Vec<String> =
            serde_json::from_str(&raw_tags).map_err(|error| error.to_string())?;
        let previous_tag_count = tags.len();
        for hit in &report.hits {
            if !tags.iter().any(|tag| tag == &hit.rule.tag) {
                tags.push(hit.rule.tag.clone());
            }
        }
        if tags.len() != previous_tag_count {
            tx.execute(
                "UPDATE traffic SET rule_tags = ?1 WHERE id = ?2",
                rusqlite::params![
                    serde_json::to_string(&tags).unwrap_or_else(|_| "[]".to_string()),
                    job.traffic_id
                ],
            )
            .map_err(|e| e.to_string())?;
            outcome.tags = Some(TrafficTagsUpdate {
                id: job.traffic_id,
                project_id: job.project_id,
                rule_tags: tags,
            });
        }

        // 中危及以上才升级成待验证 Finding；同一规则在同一字段产生多个匹配窗口
        // 时仍只对应一个 Finding 身份。
        let mut processed_fingerprints = HashSet::new();
        for hit in &report.hits {
            let rule = hit.rule;
            if rule.severity < Severity::Medium {
                continue;
            }
            let references = match knowledge::validate_references(&rule.references) {
                Ok(references) => references,
                Err(error) => {
                    eprintln!(
                        "[rules] 规则 `{}` 的标准引用无效，已跳过 Finding: {}",
                        rule.rule_id,
                        redact_sensitive(&error, &[])
                    );
                    continue;
                }
            };
            let fingerprint = finding_fingerprint(job.project_id, &hit.fingerprint);
            if !processed_fingerprints.insert(fingerprint.clone()) {
                continue;
            }
            let completeness = if hit.incomplete_evidence {
                "；捕获正文已截断，仅能作为不完整证据"
            } else {
                ""
            };
            let reasoning = format!(
                "{}（规则：{}@{}；命中位置：{}；脱敏证据：{}；指纹：{}{completeness}）",
                rule.description,
                rule.rule_id,
                rule.version,
                hit.field_path,
                hit.evidence,
                hit.fingerprint
            );
            let references_json =
                serde_json::to_string(&references).unwrap_or_else(|_| "[]".to_string());

            // 已存在同一身份：追加关联/命中审计，绝不改 status——人工判过
            // 误报的 Finding 不能因为再次命中被拉回 pending。
            let existing: Option<i64> = tx
                .query_row(
                    "SELECT id FROM findings WHERE fingerprint = ?1",
                    [&fingerprint],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| e.to_string())?;

            let (finding_id, created) = match existing {
                Some(id) => (id, false),
                None => {
                    tx.execute(
                        "INSERT INTO findings(project_id, traffic_id, source, title, vuln_type,
                                              standard_references, severity, confidence, reasoning,
                                              verify_steps, fingerprint)
                         VALUES(?1,?2,'rule',?3,?4,?5,?6,?7,?8,?9,?10)",
                        rusqlite::params![
                            job.project_id,
                            job.traffic_id,
                            &rule.name,
                            &rule.vuln_type,
                            references_json,
                            rule.severity.as_str(),
                            hit.confidence as i64,
                            &reasoning,
                            &rule.verify_hint,
                            &fingerprint,
                        ],
                    )
                    .map_err(|e| e.to_string())?;
                    (tx.last_insert_rowid(), true)
                }
            };
            let linked = tx
                .execute(
                    "INSERT OR IGNORE INTO finding_traffic(finding_id, traffic_id) VALUES(?1,?2)",
                    rusqlite::params![finding_id, job.traffic_id],
                )
                .map_err(|e| e.to_string())?;
            if created && linked != 1 {
                return Err("新建 Finding 未能关联首次命中流量".to_string());
            }
            if !created {
                tx.execute(
                    "UPDATE findings
                     SET occurrences = occurrences + ?2,
                         last_seen_at = datetime('now', 'localtime'),
                         updated_at = datetime('now', 'localtime')
                     WHERE id = ?1",
                    rusqlite::params![finding_id, linked as i64],
                )
                .map_err(|e| e.to_string())?;
            }

            tx.execute(
                "INSERT INTO finding_rule_hits(
                     finding_id, evaluation_id, traffic_id, pack_id, pack_version,
                     rule_id, rule_version, field_path, evidence, confidence,
                     incomplete_evidence, hit_fingerprint
                 ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                rusqlite::params![
                    finding_id,
                    evaluation_id,
                    job.traffic_id,
                    pack_id,
                    pack_version,
                    &rule.rule_id,
                    &rule.version,
                    &hit.field_path,
                    &hit.evidence,
                    hit.confidence as i64,
                    hit.incomplete_evidence,
                    &hit.fingerprint,
                ],
            )
            .map_err(|error| error.to_string())?;

            let finding = load_finding(&tx, finding_id)?;
            outcome.finding_count += 1;
            if created {
                outcome.created.push(finding);
            } else {
                outcome.updated.push(finding);
            }
        }

        tx.execute(
            "UPDATE rule_evaluations SET finding_count = ?1 WHERE id = ?2",
            rusqlite::params![outcome.finding_count as i64, evaluation_id],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(outcome)
    }
}

#[derive(Debug, Default)]
struct StoreOutcome {
    created: Vec<Finding>,
    updated: Vec<Finding>,
    tags: Option<TrafficTagsUpdate>,
    finding_count: usize,
}

fn load_finding(conn: &rusqlite::Connection, id: i64) -> Result<Finding, String> {
    conn.query_row(
        &format!("SELECT {} FROM findings WHERE id = ?1", Finding::COLUMNS),
        [id],
        Finding::from_row,
    )
    .map_err(|e| e.to_string())
}

/// 读取项目最近的规则求值摘要。限制在 1..=100，避免诊断页意外拉取无界数据。
pub fn recent_evaluations(
    conn: &rusqlite::Connection,
    project_id: i64,
    limit: usize,
) -> Result<Vec<RuleEvaluationInfo>, String> {
    let limit = limit.clamp(1, 100) as i64;
    let mut stmt = conn
        .prepare(
            "SELECT id, project_id, traffic_id, pack_id, pack_version, status,
                    hit_count, finding_count, duration_ms, diagnostics, created_at
             FROM rule_evaluations
             WHERE project_id = ?1
             ORDER BY id DESC
             LIMIT ?2",
        )
        .map_err(|error| error.to_string())?;
    let rows = stmt
        .query_map(rusqlite::params![project_id, limit], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, String>(10)?,
            ))
        })
        .map_err(|error| error.to_string())?;

    let mut evaluations = Vec::new();
    for row in rows {
        let row = row.map_err(|error| error.to_string())?;
        evaluations.push(RuleEvaluationInfo {
            id: row.0,
            project_id: row.1,
            traffic_id: row.2,
            pack_id: row.3,
            pack_version: row.4,
            status: row.5,
            hit_count: row.6,
            finding_count: row.7,
            duration_ms: row.8,
            diagnostics: serde_json::from_str(&row.9)
                .map_err(|error| format!("规则求值 #{} 的诊断数据损坏: {error}", row.0))?,
            created_at: row.10,
        });
    }
    Ok(evaluations)
}

/// 只建队列不起线程。生产走 [`RuleWorker::spawn`]，这里给测试构造可控背压。
pub fn new_queue(capacity: usize) -> (RuleQueue, Receiver<RuleJob>) {
    let (sender, receiver) = sync_channel(capacity);
    (
        RuleQueue {
            sender,
            counters: Arc::new(Counters::default()),
            capacity,
        },
        receiver,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::loader::BUILTIN_PACK_JSON;
    use crate::storage::db::open_pool;

    #[derive(Default)]
    struct VecRuleSink {
        created: Mutex<Vec<Finding>>,
        updated: Mutex<Vec<Finding>>,
    }

    impl RuleSink for VecRuleSink {
        fn on_finding(&self, finding: &Finding) {
            self.created.lock().unwrap().push(finding.clone());
        }

        fn on_finding_updated(&self, finding: &Finding) {
            self.updated.lock().unwrap().push(finding.clone());
        }
    }

    fn test_pool(label: &str) -> Pool {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "rustforge-rule-worker-{}-{label}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        open_pool(&dir.join("worker.db")).unwrap()
    }

    fn insert_project(pool: &Pool) -> i64 {
        let db = pool.get().unwrap();
        db.execute(
            "INSERT INTO projects(name, target_host, scope)
             VALUES('worker-test', 'example.test', '[\"example.test\"]')",
            [],
        )
        .unwrap();
        db.last_insert_rowid()
    }

    fn insert_traffic(pool: &Pool, project_id: i64, id: Option<i64>, query: &str) -> i64 {
        let db = pool.get().unwrap();
        let url = format!("https://example.test/items?id={query}");
        match id {
            Some(id) => db
                .execute(
                    "INSERT INTO traffic(
                         id, project_id, method, host, path, url, status, content_type,
                         resp_body, resp_captured_size, resp_decode_status)
                     VALUES(?1,?2,'GET','example.test','/items',?3,500,'text/plain',
                            ?4,?5,'identity_text')",
                    rusqlite::params![
                        id,
                        project_id,
                        url,
                        b"You have an error in your SQL syntax".as_slice(),
                        36_i64,
                    ],
                )
                .unwrap(),
            None => db
                .execute(
                    "INSERT INTO traffic(
                         project_id, method, host, path, url, status, content_type,
                         resp_body, resp_captured_size, resp_decode_status)
                     VALUES(?1,'GET','example.test','/items',?2,500,'text/plain',
                            ?3,?4,'identity_text')",
                    rusqlite::params![
                        project_id,
                        url,
                        b"You have an error in your SQL syntax".as_slice(),
                        36_i64,
                    ],
                )
                .unwrap(),
        };
        id.unwrap_or_else(|| db.last_insert_rowid())
    }

    fn sql_error_job(project_id: i64, traffic_id: i64) -> RuleJob {
        RuleJob {
            project_id,
            traffic_id,
        }
    }

    fn test_worker(pool: Pool, sink: Arc<VecRuleSink>) -> RuleWorker {
        let packs = Arc::new(vec![loader::builtin_pack().clone()]);
        RuleWorker {
            db: pool,
            sink,
            state: Arc::new(WorkerState {
                counters: Arc::new(Counters::default()),
                capacity: RULE_QUEUE_CAPACITY,
                last_error: Mutex::new(None),
                packs,
                running: AtomicBool::new(false),
            }),
        }
    }

    #[test]
    fn a_full_queue_drops_instead_of_blocking_the_caller() {
        // 保留 receiver 但不消费，制造队列打满的背压场景
        let (queue, _receiver) = new_queue(1);
        let job = RuleJob {
            project_id: 1,
            traffic_id: 1,
        };
        assert_eq!(
            std::mem::size_of::<RuleJob>(),
            std::mem::size_of::<[i64; 2]>(),
            "队列任务不得重新携带头部或正文快照"
        );

        let started = Instant::now();
        assert!(queue.try_submit(job.clone()));
        assert!(!queue.try_submit(job.clone()));
        assert!(!queue.try_submit(job));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "投递必须立刻返回，绝不能等待消费端"
        );

        let metrics = queue.snapshot();
        assert_eq!(metrics.submitted_evaluations, 3);
        assert_eq!(metrics.dropped_evaluations, 2);
        assert_eq!(metrics.queue_capacity, 1);
    }

    #[test]
    fn a_disconnected_worker_degrades_instead_of_failing_the_proxy() {
        let (queue, receiver) = new_queue(4);
        drop(receiver);
        let job = RuleJob {
            project_id: 1,
            traffic_id: 1,
        };
        assert!(!queue.try_submit(job));
        assert_eq!(queue.snapshot().dropped_evaluations, 1);
    }

    #[test]
    fn diagnostics_expose_builtin_pack_status_without_a_running_worker() {
        let diagnostics = diagnostics();
        let builtin = diagnostics
            .packs
            .iter()
            .find(|pack| pack.pack_id == loader::BUILTIN_PACK_ID)
            .expect("内置包必须出现在诊断里");
        assert!(builtin.loaded);
        assert_eq!(builtin.rule_count, 14);
        assert!(builtin.disabled_reason.is_none());
    }

    #[test]
    fn a_disabled_pack_reports_its_reason_in_diagnostics() {
        let status = loader::load_pack_status("broken.json", "{ nope");
        let info = pack_info(&status);
        assert!(!info.loaded);
        assert_eq!(info.rule_count, 0);
        assert!(info.disabled_reason.unwrap().contains("不是有效 JSON"));
    }

    #[test]
    fn repeated_hits_aggregate_traffic_survive_patch_versions_and_preserve_rejection() {
        let pool = test_pool("dedupe");
        let project_id = insert_project(&pool);
        let traffic_ids: Vec<i64> = (0..64)
            .map(|index| insert_traffic(&pool, project_id, None, &index.to_string()))
            .collect();
        let sink = Arc::new(VecRuleSink::default());
        let worker = test_worker(pool.clone(), Arc::clone(&sink));

        let builtin = loader::builtin_pack();
        let first = sql_error_job(project_id, traffic_ids[0]);
        worker.evaluate_and_store(&first, builtin).unwrap();
        worker.evaluate_and_store(&first, builtin).unwrap();
        for traffic_id in traffic_ids.iter().copied().skip(1) {
            worker
                .evaluate_and_store(&sql_error_job(project_id, traffic_id), builtin)
                .unwrap();
        }

        let mut db = pool.get().unwrap();
        let finding_id: i64 = db
            .query_row("SELECT id FROM findings", [], |row| row.get(0))
            .unwrap();
        crate::evidence::service::update_finding_status(
            &mut db,
            finding_id,
            "rejected",
            Some("测试确认误报"),
            "test:analyst",
        )
        .unwrap();
        drop(db);

        // 只升包/规则补丁版本；rule_id、端点和字段都不变。
        let mut patch: serde_json::Value = serde_json::from_str(BUILTIN_PACK_JSON).unwrap();
        patch["version"] = serde_json::Value::String("1.0.1".into());
        for rule in patch["rules"].as_array_mut().unwrap() {
            rule["version"] = serde_json::Value::String("1.0.1".into());
        }
        let patch = loader::load_pack_status("builtin-v1.0.1.json", &patch.to_string());
        assert!(patch.is_loaded());
        worker
            .evaluate_and_store(
                &sql_error_job(project_id, *traffic_ids.last().unwrap()),
                &patch,
            )
            .unwrap();

        let db = pool.get().unwrap();
        let finding: (i64, String, i64) = db
            .query_row(
                "SELECT COUNT(*), status, occurrences FROM findings",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(finding, (1, "rejected".into(), 64));
        let links: i64 = db
            .query_row("SELECT COUNT(*) FROM finding_traffic", [], |row| row.get(0))
            .unwrap();
        assert_eq!(links, 64, "大量重复端点流量都应关联到同一个 Finding");
        let evaluations: i64 = db
            .query_row("SELECT COUNT(*) FROM rule_evaluations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(evaluations, 65, "同包同流量幂等，补丁包则留下独立求值审计");
        let hit_occurrences: i64 = db
            .query_row("SELECT COUNT(*) FROM finding_rule_hits", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(
            hit_occurrences, 65,
            "每次有效求值都必须保留当时的规则版本和脱敏证据"
        );
        let latest_hit: (String, String, i64, String) = db
            .query_row(
                "SELECT pack_version, rule_version, traffic_id, evidence
                 FROM finding_rule_hits ORDER BY id DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(latest_hit.0, "1.0.1");
        assert_eq!(latest_hit.1, "1.0.1");
        assert_eq!(latest_hit.2, *traffic_ids.last().unwrap());
        assert!(latest_hit.3.contains("SQL syntax"));
        let recent = recent_evaluations(&db, project_id, 20).unwrap();
        assert_eq!(recent.len(), 20, "诊断查询必须遵守有界窗口");
        assert_eq!(recent[0].pack_version, "1.0.1");
        assert!(recent
            .iter()
            .all(|evaluation| evaluation.finding_count == 1));
        assert_eq!(sink.created.lock().unwrap().len(), 1);
        assert_eq!(
            sink.updated.lock().unwrap().len(),
            64,
            "新关联流量和补丁版本命中都应推送一次可追溯更新"
        );
    }

    #[test]
    fn a_failed_store_does_not_claim_the_idempotency_key_and_can_be_retried() {
        let pool = test_pool("retry");
        let project_id = insert_project(&pool);
        let sink = Arc::new(VecRuleSink::default());
        let worker = test_worker(pool.clone(), sink);
        let job = sql_error_job(project_id, 99);

        assert!(
            worker
                .evaluate_and_store(&job, loader::builtin_pack())
                .is_err(),
            "traffic 外键不存在时整次写入必须失败"
        );
        {
            let db = pool.get().unwrap();
            let evaluations: i64 = db
                .query_row("SELECT COUNT(*) FROM rule_evaluations", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(evaluations, 0, "失败事务不得留下已处理占位");
        }

        insert_traffic(&pool, project_id, Some(99), "retry");
        worker
            .evaluate_and_store(&job, loader::builtin_pack())
            .unwrap();
        let db = pool.get().unwrap();
        let evaluations: i64 = db
            .query_row("SELECT COUNT(*) FROM rule_evaluations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(evaluations, 1);
        let findings: i64 = db
            .query_row("SELECT COUNT(*) FROM findings", [], |row| row.get(0))
            .unwrap();
        assert_eq!(findings, 1);
    }
}
