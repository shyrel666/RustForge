//! 流量拦截器：hudsucker HttpHandler 实现。
//! 设计红线：只有命中当前项目 Scope 白名单的 host 才会被解密和记录，
//! 其余流量 CONNECT 阶段直接盲转发（should_intercept_connect 返回 false）。
//!
//! 生命周期说明（已对照 hudsucker 0.25 源码 internal.rs 确认）：
//! 每个请求都会 clone 一次 handler，同一请求的 handle_request/handle_response
//! 作用于同一个 clone，因此可以用 self.pending 暂存请求侧数据。

use crate::rules::engine::{self, Severity, TrafficView};
use crate::storage::db::Db;
use crate::storage::models::{Finding, TrafficSummary};
use hudsucker::hyper::body::Bytes;
use hudsucker::hyper::{Request, Response};
use hudsucker::{Body, HttpContext, HttpHandler, RequestOrResponse};
use http_body_util::BodyExt;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tauri::{AppHandle, Emitter};

/// 单个方向 body 的最大存储字节数，超出截断（防止大文件下载撑爆数据库）
const MAX_STORED_BODY: usize = 1024 * 1024;

/// 流量产出回调：Tauri 运行时推事件给前端，测试时收集断言。
/// 抽这个 trait 是为了让拦截管线可以在无 GUI 环境下做端到端测试。
pub trait FlowSink: Send + Sync + 'static {
    fn on_flow(&self, summary: &TrafficSummary);
    /// 规则/AI 产出新 Finding 时回调（默认忽略）
    fn on_finding(&self, _finding: &Finding) {}
}

/// 生产环境实现：转发为 Tauri 事件 "traffic:new" / "finding:new"
pub struct TauriSink(pub AppHandle);

impl FlowSink for TauriSink {
    fn on_flow(&self, summary: &TrafficSummary) {
        let _ = self.0.emit("traffic:new", summary);
    }
    fn on_finding(&self, finding: &Finding) {
        let _ = self.0.emit("finding:new", finding);
    }
}

/// 请求侧暂存数据，等响应回来后合成完整记录
#[derive(Clone)]
struct PendingReq {
    project_id: i64,
    method: String,
    scheme: String,
    host: String,
    port: u16,
    path: String,
    url: String,
    req_headers: String,
    req_body: Vec<u8>,
    req_size: usize,
    start: Instant,
}

#[derive(Clone)]
pub struct TrafficHandler {
    db: Arc<Mutex<Db>>,
    sink: Arc<dyn FlowSink>,
    pending: Option<PendingReq>,
}

impl TrafficHandler {
    pub fn new(db: Arc<Mutex<Db>>, sink: Arc<dyn FlowSink>) -> Self {
        Self { db, sink, pending: None }
    }

    /// 当前项目 + Scope。没有打开的项目 = 没有授权目标 = 一律不拦截
    fn current_project_scope(&self) -> Option<(i64, Vec<String>)> {
        let db = self.db.lock().ok()?;
        let project_id: i64 = db
            .conn
            .query_row(
                "SELECT value FROM settings WHERE key = 'current_project_id'",
                [],
                |row| row.get::<_, String>(0),
            )
            .ok()?
            .parse()
            .ok()?;
        let scope_json: String = db
            .conn
            .query_row(
                "SELECT scope FROM projects WHERE id = ?1",
                [project_id],
                |row| row.get(0),
            )
            .ok()?;
        let scope: Vec<String> = serde_json::from_str(&scope_json).unwrap_or_default();
        Some((project_id, scope))
    }

    fn in_scope(&self, host: &str) -> Option<i64> {
        let (project_id, scope) = self.current_project_scope()?;
        if host_matches_scope(&scope, host) {
            Some(project_id)
        } else {
            None
        }
    }

    /// 合成完整记录写库并推送事件；随后跑被动规则：打标 + 中危以上建 Finding
    fn store_and_emit(
        &self,
        p: PendingReq,
        status: Option<u16>,
        resp_headers: Option<String>,
        resp_body: Option<Vec<u8>>,
        resp_size: usize,
    ) {
        let duration_ms = p.start.elapsed().as_millis() as i64;
        let content_type = resp_headers
            .as_deref()
            .and_then(|h| serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(h).ok())
            .and_then(|m| {
                m.get("content-type")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            });
        let req_body_stored = truncate(p.req_body, MAX_STORED_BODY);
        let resp_body_stored = resp_body.map(|b| truncate(b, MAX_STORED_BODY));

        let Ok(db) = self.db.lock() else { return };
        let res = db.conn.execute(
            "INSERT INTO traffic(project_id, method, scheme, host, port, path, url,
                                 req_headers, req_body, status, resp_headers, resp_body,
                                 content_type, req_size, resp_size, duration_ms)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
            rusqlite::params![
                p.project_id, p.method, p.scheme, p.host, p.port, p.path, p.url,
                p.req_headers, req_body_stored, status, resp_headers, resp_body_stored,
                content_type, p.req_size as i64, resp_size as i64, duration_ms,
            ],
        );
        let id = match res {
            Ok(_) => db.conn.last_insert_rowid(),
            Err(e) => {
                eprintln!("[proxy] 流量写库失败: {e}");
                return;
            }
        };

        // ---- 被动规则：AI 分析前的本地初筛 ----
        let view = TrafficView {
            url: &p.url,
            req_headers: &p.req_headers,
            resp_headers: resp_headers.as_deref(),
            req_body: &req_body_stored,
            resp_body: resp_body_stored.as_deref(),
        };
        let hits = engine::evaluate(&view);
        let rule_tags: Vec<String> = hits.iter().map(|h| h.rule.tag.to_string()).collect();
        if !rule_tags.is_empty() {
            let _ = db.conn.execute(
                "UPDATE traffic SET rule_tags = ?1 WHERE id = ?2",
                rusqlite::params![serde_json::to_string(&rule_tags).unwrap_or_default(), id],
            );
        }
        // 中危及以上 → 生成待验证 Finding
        let created_at = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let mut new_findings: Vec<Finding> = Vec::new();
        for hit in &hits {
            let rule = hit.rule;
            if rule.severity < Severity::Medium {
                continue;
            }
            let reasoning = format!("{}（命中位置：{}）", rule.description, hit.location);
            let exec = db.conn.execute(
                "INSERT INTO findings(project_id, traffic_id, source, title, vuln_type,
                                      owasp, cwe, severity, confidence, reasoning, verify_steps)
                 VALUES(?1,?2,'rule',?3,?4,?5,?6,?7,?8,?9,?10)",
                rusqlite::params![
                    p.project_id, id, rule.name, rule.vuln_type, rule.owasp, rule.cwe,
                    rule.severity.as_str(), rule.confidence as i64, reasoning, rule.verify_hint,
                ],
            );
            if let Ok(_) = exec {
                new_findings.push(Finding {
                    id: db.conn.last_insert_rowid(),
                    project_id: p.project_id,
                    traffic_id: Some(id),
                    source: "rule".into(),
                    title: rule.name.into(),
                    vuln_type: rule.vuln_type.into(),
                    owasp: rule.owasp.into(),
                    cwe: rule.cwe.into(),
                    severity: rule.severity.as_str().into(),
                    confidence: rule.confidence as i64,
                    reasoning,
                    verify_steps: rule.verify_hint.into(),
                    status: "pending".into(),
                    created_at: created_at.clone(),
                });
            }
        }
        drop(db);

        let summary = TrafficSummary {
            id,
            project_id: p.project_id,
            method: p.method,
            scheme: p.scheme,
            host: p.host,
            port: p.port,
            path: p.path,
            url: p.url,
            status,
            content_type,
            req_size: p.req_size as i64,
            resp_size: resp_size as i64,
            duration_ms,
            rule_tags,
            created_at,
        };
        // 通知前端列表实时追加
        self.sink.on_flow(&summary);
        for f in &new_findings {
            self.sink.on_finding(f);
        }
    }
}

impl HttpHandler for TrafficHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        let (parts, body) = req.into_parts();
        // 必须收完整 body 才能既记录又原样转发
        let body_bytes = match body.collect().await {
            Ok(c) => c.to_bytes(),
            Err(e) => {
                eprintln!("[proxy] 请求体读取失败: {e}");
                Bytes::new()
            }
        };

        let uri = &parts.uri;
        let host = uri.host().unwrap_or_default().to_string();
        let scheme = uri.scheme_str().unwrap_or("http").to_string();
        let port = uri
            .port_u16()
            .unwrap_or(if scheme == "https" { 443 } else { 80 });

        // Scope 外：静默转发，不记录（白名单红线）
        let Some(project_id) = self.in_scope(&host) else {
            return Request::from_parts(parts, Body::from(body_bytes)).into();
        };

        let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        self.pending = Some(PendingReq {
            project_id,
            method: parts.method.to_string(),
            scheme,
            host,
            port,
            path: path.to_string(),
            url: uri.to_string(),
            req_headers: headers_to_json(&parts.headers),
            req_size: body_bytes.len(),
            req_body: body_bytes.to_vec(),
            start: Instant::now(),
        });

        Request::from_parts(parts, Body::from(body_bytes)).into()
    }

    async fn handle_response(
        &mut self,
        _ctx: &HttpContext,
        res: Response<Body>,
    ) -> Response<Body> {
        // 没有暂存 = Scope 外的流量，直接透传
        let Some(p) = self.pending.take() else {
            return res;
        };

        let status = res.status().as_u16();
        let resp_headers = headers_to_json(res.headers());
        let (parts, body) = res.into_parts();
        let body_bytes = match body.collect().await {
            Ok(c) => c.to_bytes(),
            Err(e) => {
                eprintln!("[proxy] 响应体读取失败: {e}");
                Bytes::new()
            }
        };

        self.store_and_emit(
            p,
            Some(status),
            Some(resp_headers),
            Some(body_bytes.to_vec()),
            body_bytes.len(),
        );

        Response::from_parts(parts, Body::from(body_bytes))
    }

    async fn handle_error(
        &mut self,
        _ctx: &HttpContext,
        err: hudsucker::hyper_util::client::legacy::Error,
    ) -> Response<Body> {
        // 上游连接/请求失败：请求已发出但没拿到响应，仍然落库（status 为空）
        if let Some(p) = self.pending.take() {
            eprintln!("[proxy] 上游请求失败: {err}");
            self.store_and_emit(p, None, None, None, 0);
        }
        Response::builder()
            .status(hudsucker::hyper::StatusCode::BAD_GATEWAY)
            .body(Body::empty())
            .expect("build 502 response")
    }

    async fn should_intercept_connect(
        &mut self,
        _ctx: &HttpContext,
        req: &Request<Body>,
    ) -> bool {
        // CONNECT 的 URI 是 authority 形式（host:port）
        let host = req.uri().host().unwrap_or_default();
        self.in_scope(host).is_some()
    }
}

/// host 是否命中 Scope。规则：精确匹配，或 `*.example.com` 通配（同时覆盖 apex）。
/// 模式先归一化：允许用户粘贴完整 URL（`https://a.b/path`）、带端口、大小写混杂。
pub fn host_matches_scope(scope: &[String], host: &str) -> bool {
    let host = host.trim_end_matches('.').to_lowercase();
    scope.iter().any(|raw| {
        let pat = normalize_scope_pattern(raw);
        if pat.is_empty() {
            return false;
        }
        if let Some(suffix) = pat.strip_prefix("*.") {
            host == suffix || host.ends_with(&format!(".{suffix}"))
        } else {
            host == pat
        }
    })
}

/// 把用户输入归一化成纯 host 模式：
/// 去空白/大小写 → 去 scheme（`://` 前缀）→ 去路径 → 去端口 → 去结尾点号
fn normalize_scope_pattern(raw: &str) -> String {
    let mut s = raw.trim().to_lowercase();
    if let Some(idx) = s.find("://") {
        s = s[idx + 3..].to_string();
    }
    if let Some(idx) = s.find('/') {
        s.truncate(idx);
    }
    // 通配前缀后再谈端口：*.example.com 无冒号，example.com:8443 去掉 :8443
    if let Some(idx) = s.rfind(':') {
        // IPv6 不支持（方括号形式 [::1]），原样保留
        if !s.contains(']') {
            s.truncate(idx);
        }
    }
    s.trim_end_matches('.').to_string()
}

/// HeaderMap → JSON 对象字符串（同名头逗号合并，与 schema 注释一致）
fn headers_to_json(headers: &hudsucker::hyper::HeaderMap) -> String {
    let mut map = serde_json::Map::new();
    for (name, value) in headers.iter() {
        let key = name.as_str().to_string();
        let val = String::from_utf8_lossy(value.as_bytes()).into_owned();
        map.entry(key)
            .and_modify(|e: &mut serde_json::Value| {
                if let Some(s) = e.as_str() {
                    *e = serde_json::Value::String(format!("{s}, {val}"));
                }
            })
            .or_insert(serde_json::Value::String(val));
    }
    serde_json::Value::Object(map).to_string()
}

fn truncate(data: Vec<u8>, max: usize) -> Vec<u8> {
    if data.len() > max {
        data[..max].to_vec()
    } else {
        data
    }
}

#[cfg(test)]
mod tests {
    use super::host_matches_scope;

    #[test]
    fn scope_matching() {
        let scope = vec![
            "example.com".to_string(),
            "*.test.cn".to_string(),
            "192.168.1.1".to_string(),
        ];
        assert!(host_matches_scope(&scope, "example.com"));
        assert!(!host_matches_scope(&scope, "www.example.com"));
        assert!(host_matches_scope(&scope, "api.test.cn"));
        assert!(host_matches_scope(&scope, "test.cn"));
        assert!(host_matches_scope(&scope, "192.168.1.1"));
        assert!(!host_matches_scope(&scope, "evil.com"));
        assert!(!host_matches_scope(&[], "example.com"));
    }

    #[test]
    fn scope_matching_tolerates_user_input() {
        // 用户粘贴 URL / 带端口 / 大小写混杂都应命中
        let scope = vec![
            "https://opencode.ai".to_string(),
            "http://Sub.Example.com:8443/login".to_string(),
            "*.foo.bar/".to_string(),
            " HTTPS://a.b/c ".to_string(),
        ];
        assert!(host_matches_scope(&scope, "opencode.ai"));
        assert!(host_matches_scope(&scope, "sub.example.com"));
        assert!(host_matches_scope(&scope, "x.foo.bar"));
        assert!(host_matches_scope(&scope, "foo.bar"));
        assert!(host_matches_scope(&scope, "a.b"));
    }
}
