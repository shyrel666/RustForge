//! 流量拦截器：hudsucker HttpHandler 实现。
//! 设计红线：只有命中当前项目 Scope 白名单的 host 才会被解密和记录，
//! 其余流量 CONNECT 阶段直接盲转发（should_intercept_connect 返回 false）。
//!
//! 生命周期说明（已对照 hudsucker 0.25 源码 internal.rs 确认）：
//! 每个请求都会 clone 一次 handler，同一请求的 handle_request/handle_response
//! 作用于同一个 clone，因此可以用 self.pending 暂存请求侧数据。

use crate::authorization::{load_current_project_policy, AuthorizationError};
use crate::knowledge;
use crate::proxy::body_capture::{
    tee_body, tee_body_with_callback, BodyMetadata, CaptureHandle, CapturedBody,
};
use crate::rules::engine::{self, Severity, TrafficView};
use crate::secrets::redact_sensitive;
use crate::storage::db::Pool;
use crate::storage::models::{Finding, TrafficSummary};
use hudsucker::hyper::{Request, Response};
use hudsucker::{Body, HttpContext, HttpHandler, RequestOrResponse};
use std::sync::Arc;
use std::time::Instant;
use tauri::{AppHandle, Emitter};

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
    req_body_metadata: BodyMetadata,
    req_capture: CaptureHandle,
    start: Instant,
}

#[derive(Clone)]
pub struct TrafficHandler {
    db: Pool,
    sink: Arc<dyn FlowSink>,
    pending: Option<PendingReq>,
}

impl TrafficHandler {
    pub fn new(db: Pool, sink: Arc<dyn FlowSink>) -> Self {
        Self {
            db,
            sink,
            pending: None,
        }
    }

    /// 当前项目 + Scope。没有打开的项目、Scope 为空或配置损坏时严格失败关闭。
    fn authorize_host(&self, host: &str) -> Result<i64, AuthorizationError> {
        let db = self.db.get().map_err(AuthorizationError::storage)?;
        let (project_id, policy) = load_current_project_policy(&db)?;
        policy.authorize_host(host)?;
        Ok(project_id)
    }

    /// 合成完整记录写库并推送事件；随后跑被动规则：打标 + 中危以上建 Finding
    fn store_and_emit(
        &self,
        p: PendingReq,
        status: Option<u16>,
        resp_headers: Option<String>,
        content_type: Option<String>,
        resp_body: Option<CapturedBody>,
    ) {
        let duration_ms = p.start.elapsed().as_millis() as i64;
        let req_capture = p.req_capture.finish(&p.req_body_metadata);
        let response_received = resp_body.is_some();
        let resp_capture = resp_body.unwrap_or_else(CapturedBody::not_received);
        let req_body_stored = req_capture.bytes;
        let resp_body_stored = response_received.then_some(resp_capture.bytes);

        let Ok(db) = self.db.get() else { return };
        // 流量 + 打标 + 建 Finding 放进一个事务，避免中途失败留下半截数据
        let Ok(tx) = db.unchecked_transaction() else {
            eprintln!("[proxy] 开启事务失败，流量丢弃");
            return;
        };
        let res = tx.execute(
            "INSERT INTO traffic(project_id, method, scheme, host, port, path, url,
                                 req_headers, req_body, status, resp_headers, resp_body,
                                 content_type, req_wire_size, resp_wire_size,
                                 req_captured_size, resp_captured_size,
                                 req_truncated, resp_truncated,
                                 req_decode_status, resp_decode_status, duration_ms)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,
                    ?17,?18,?19,?20,?21,?22)",
            rusqlite::params![
                p.project_id,
                p.method,
                p.scheme,
                p.host,
                p.port,
                p.path,
                p.url,
                p.req_headers,
                req_body_stored,
                status,
                resp_headers,
                resp_body_stored,
                content_type,
                req_capture.wire_size,
                resp_capture.wire_size,
                req_capture.captured_size,
                resp_capture.captured_size,
                req_capture.truncated,
                resp_capture.truncated,
                req_capture.decode_status.as_str(),
                resp_capture.decode_status.as_str(),
                duration_ms,
            ],
        );
        let id = match res {
            Ok(_) => tx.last_insert_rowid(),
            Err(e) => {
                eprintln!(
                    "[proxy] 流量写库失败: {}",
                    redact_sensitive(&e.to_string(), &[])
                );
                return;
            }
        };

        // ---- 被动规则：AI 分析前的本地初筛 ----
        let view = TrafficView {
            method: &p.method,
            url: &p.url,
            req_headers: &p.req_headers,
            resp_headers: resp_headers.as_deref(),
            req_body: &req_body_stored,
            resp_body: resp_body_stored.as_deref(),
            status,
            content_type: content_type.as_deref(),
            req_truncated: req_capture.truncated,
            resp_truncated: resp_capture.truncated,
            req_decode_status: req_capture.decode_status.as_str(),
            resp_decode_status: resp_capture.decode_status.as_str(),
        };
        let evaluation = engine::evaluate(&view);
        for diagnostic in &evaluation.diagnostics {
            eprintln!(
                "[rules] {}: {}",
                diagnostic.code,
                redact_sensitive(&diagnostic.message, &[])
            );
        }
        let hits = evaluation.hits;
        let rule_tags: Vec<String> = hits.iter().map(|h| h.rule.tag.to_string()).collect();
        if !rule_tags.is_empty() {
            let _ = tx.execute(
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
            let standard_references = match knowledge::validate_references(&rule.references) {
                Ok(references) => references,
                Err(error) => {
                    eprintln!(
                        "[proxy] 内置规则 `{}` 的标准引用无效，已跳过 Finding: {}",
                        rule.rule_id,
                        redact_sensitive(&error, &[])
                    );
                    continue;
                }
            };
            let standard_references_json =
                serde_json::to_string(&standard_references).unwrap_or_else(|_| "[]".to_string());
            let exec = tx.execute(
                "INSERT INTO findings(project_id, traffic_id, source, title, vuln_type,
                                      standard_references, severity, confidence, reasoning, verify_steps)
                 VALUES(?1,?2,'rule',?3,?4,?5,?6,?7,?8,?9)",
                rusqlite::params![
                    p.project_id,
                    id,
                    &rule.name,
                    &rule.vuln_type,
                    standard_references_json,
                    rule.severity.as_str(),
                    hit.confidence as i64,
                    &reasoning,
                    &rule.verify_hint,
                ],
            );
            if exec.is_ok() {
                new_findings.push(Finding {
                    id: tx.last_insert_rowid(),
                    project_id: p.project_id,
                    traffic_id: Some(id),
                    source: "rule".into(),
                    title: rule.name.clone(),
                    vuln_type: rule.vuln_type.clone(),
                    standard_references,
                    severity: rule.severity.as_str().into(),
                    confidence: hit.confidence as i64,
                    reasoning,
                    verify_steps: rule.verify_hint.clone(),
                    status: "pending".into(),
                    created_at: created_at.clone(),
                });
            }
        }
        if let Err(e) = tx.commit() {
            eprintln!(
                "[proxy] 事务提交失败: {}",
                redact_sensitive(&e.to_string(), &[])
            );
            return;
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
            req_wire_size: req_capture.wire_size,
            resp_wire_size: resp_capture.wire_size,
            req_captured_size: req_capture.captured_size,
            resp_captured_size: resp_capture.captured_size,
            req_truncated: req_capture.truncated,
            resp_truncated: resp_capture.truncated,
            req_decode_status: req_capture.decode_status.to_string(),
            resp_decode_status: resp_capture.decode_status.to_string(),
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

        let uri = &parts.uri;
        let host = uri.host().unwrap_or_default().to_string();
        let scheme = uri.scheme_str().unwrap_or("http").to_string();
        let port = uri
            .port_u16()
            .unwrap_or(if scheme == "https" { 443 } else { 80 });

        // Scope 外：静默转发，不记录也不缓冲 body（原始流直接透传，白名单红线）
        let Ok(project_id) = self.authorize_host(&host) else {
            return Request::from_parts(parts, body).into();
        };

        let path = uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/")
            .to_string();
        let url = uri.to_string();
        let method = parts.method.to_string();
        let req_headers = headers_to_json(&parts.headers);
        let req_body_metadata = BodyMetadata::from_headers(&parts.headers);
        let (body, req_capture) = tee_body(body);
        self.pending = Some(PendingReq {
            project_id,
            method,
            scheme,
            host,
            port,
            path,
            url,
            req_headers,
            req_body_metadata,
            req_capture,
            start: Instant::now(),
        });

        Request::from_parts(parts, body).into()
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        // 没有暂存 = Scope 外的流量，直接透传
        let Some(p) = self.pending.take() else {
            return res;
        };

        let status = res.status().as_u16();
        let resp_headers = headers_to_json(res.headers());
        let resp_body_metadata = BodyMetadata::from_headers(res.headers());
        let content_type = resp_body_metadata.content_type().map(str::to_owned);
        let (parts, body) = res.into_parts();
        let handler = self.clone();
        let (body, _capture) = tee_body_with_callback(body, move |capture| {
            let captured = capture.finish(&resp_body_metadata);
            handler.store_and_emit(
                p,
                Some(status),
                Some(resp_headers),
                content_type,
                Some(captured),
            );
        });

        Response::from_parts(parts, body)
    }

    async fn handle_error(
        &mut self,
        _ctx: &HttpContext,
        err: hudsucker::hyper_util::client::legacy::Error,
    ) -> Response<Body> {
        // 上游连接/请求失败：请求已发出但没拿到响应，仍然落库（status 为空）
        if let Some(p) = self.pending.take() {
            eprintln!(
                "[proxy] 上游请求失败: {}",
                redact_sensitive(&err.to_string(), &[])
            );
            self.store_and_emit(p, None, None, None, None);
        }
        Response::builder()
            .status(hudsucker::hyper::StatusCode::BAD_GATEWAY)
            .body(Body::empty())
            .expect("build 502 response")
    }

    async fn should_intercept_connect(&mut self, _ctx: &HttpContext, req: &Request<Body>) -> bool {
        // CONNECT 的 URI 是 authority 形式（host:port）
        let host = req.uri().host().unwrap_or_default();
        self.authorize_host(host).is_ok()
    }
}

/// HeaderMap → JSON object. A repeated name becomes an array whose item order
/// matches HeaderMap iteration, so Set-Cookie boundaries are never collapsed.
fn headers_to_map(
    headers: &hudsucker::hyper::HeaderMap,
) -> serde_json::Map<String, serde_json::Value> {
    let mut map = serde_json::Map::new();
    for (name, value) in headers.iter() {
        let key = name.as_str().to_string();
        let val = String::from_utf8_lossy(value.as_bytes()).into_owned();
        map.entry(key)
            .and_modify(|e: &mut serde_json::Value| {
                if let serde_json::Value::Array(values) = e {
                    values.push(serde_json::Value::String(val.clone()));
                } else {
                    let first = std::mem::take(e);
                    *e = serde_json::Value::Array(vec![
                        first,
                        serde_json::Value::String(val.clone()),
                    ]);
                }
            })
            .or_insert(serde_json::Value::String(val));
    }
    map
}

fn headers_to_json(headers: &hudsucker::hyper::HeaderMap) -> String {
    serde_json::Value::Object(headers_to_map(headers)).to_string()
}

#[cfg(test)]
mod tests {
    use super::headers_to_json;
    use hudsucker::hyper::header::{HeaderValue, SET_COOKIE};
    use hudsucker::hyper::HeaderMap;

    #[test]
    fn repeated_set_cookie_values_remain_distinct() {
        let mut headers = HeaderMap::new();
        headers.append(SET_COOKIE, HeaderValue::from_static("a=1; Path=/"));
        headers.append(
            SET_COOKIE,
            HeaderValue::from_static("b=2; Expires=Wed, 21 Oct 2030 07:28:00 GMT"),
        );

        let json: serde_json::Value = serde_json::from_str(&headers_to_json(&headers)).unwrap();
        assert_eq!(
            json["set-cookie"],
            serde_json::json!(["a=1; Path=/", "b=2; Expires=Wed, 21 Oct 2030 07:28:00 GMT"])
        );
    }
}
