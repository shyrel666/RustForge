//! 暴露给前端的全部 Tauri commands

use crate::ai::client::{LlmClient, OpenAiClient};
use crate::ai::{analyzer, digest, planner, prompts};
use crate::knowledge;
use crate::proxy::ProxyStatus;
use crate::proxy::ca;
use crate::report;
use crate::storage::models::{AnalysisResult, Finding, Project, TrafficDetail, TrafficSummary};
use crate::tree::model::TaskNode;
use crate::tree::state as tree_state;
use crate::AppState;
use std::collections::HashMap;
use tauri::{AppHandle, Emitter, Manager, State};

type CmdResult<T> = Result<T, String>;

/// 模块内读取单个设置（get_setting 命令的内部复用版）
fn read_setting(conn: &rusqlite::Connection, key: &str) -> Option<String> {
    conn.query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| r.get(0))
        .ok()
}

/// 累加一次 LLM 调用的 token 用量到 settings（本机累计，供成本提示）
fn record_usage(conn: &rusqlite::Connection, usage: &crate::ai::client::Usage) {
    let bump = |key: &str, delta: i64| {
        let _ = conn.execute(
            "INSERT INTO settings(key, value) VALUES(?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + ?2",
            rusqlite::params![key, delta],
        );
    };
    bump("usage_calls", 1);
    bump("usage_prompt_tokens", usage.prompt_tokens);
    bump("usage_completion_tokens", usage.completion_tokens);
    bump("usage_total_tokens", usage.total_tokens);
}

/// 当前生效的 AI 供应商（CC-switch 风格：多供应商 + 一个活动项）。
/// 返回 (base_url, api_key, model)。优先从 ai_providers/ai_current 解析活动供应商；
/// 若尚未配置多供应商（旧版本），回退到旧的单条 base_url/api_key/model 设置。
fn active_ai(conn: &rusqlite::Connection) -> Option<(String, String, String)> {
    if let Some(json) = read_setting(conn, "ai_providers") {
        if let Ok(list) = serde_json::from_str::<Vec<serde_json::Value>>(&json) {
            if !list.is_empty() {
                let current = read_setting(conn, "ai_current").unwrap_or_default();
                let p = list
                    .iter()
                    .find(|p| p["id"].as_str() == Some(current.as_str()))
                    .unwrap_or(&list[0]);
                let base_url = p["base_url"].as_str().unwrap_or_default().trim().to_string();
                let api_key = p["api_key"].as_str().unwrap_or_default().trim().to_string();
                let model = p["model"].as_str().unwrap_or_default().trim().to_string();
                return Some((base_url, api_key, model));
            }
        }
    }
    // 回退：旧版单供应商设置
    let base_url = read_setting(conn, "base_url")?;
    let api_key = read_setting(conn, "api_key")?;
    let model = read_setting(conn, "model").unwrap_or_else(|| "deepseek-chat".into());
    Some((base_url, api_key, model))
}

/// 归一化活动供应商三元组：空 base_url/model 用内置默认兜底。
fn resolved_ai(conn: &rusqlite::Connection) -> CmdResult<(String, String, String)> {
    let (base_url, api_key, model) =
        active_ai(conn).ok_or("请先在设置页添加并选择一个 AI 供应商")?;
    if api_key.trim().is_empty() {
        return Err("当前 AI 供应商未配置 API Key，请在设置页填写".into());
    }
    let base_url = if base_url.trim().is_empty() {
        "https://api.deepseek.com".to_string()
    } else {
        base_url
    };
    let model = if model.trim().is_empty() {
        "deepseek-chat".to_string()
    } else {
        model
    };
    Ok((base_url, api_key, model))
}

/// 红线检查 + 构建 LLM 客户端（ai_enabled=false / 无 Key 直接拒绝）
fn llm_client(conn: &rusqlite::Connection) -> CmdResult<OpenAiClient> {
    if read_setting(conn, "ai_enabled").as_deref() == Some("false") {
        return Err("AI 功能已在设置中全局禁用（隐私开关）".into());
    }
    let (base_url, api_key, model) = resolved_ai(conn)?;
    OpenAiClient::new(&base_url, &api_key, &model)
}

/// 调 LLM 并解析 JSON；解析失败追加提醒重试一次。返回 (解析结果, 累计 token 用量)
async fn chat_json<T>(
    client: &impl LlmClient,
    system: &str,
    prompt: &str,
    parse: impl Fn(&str) -> Result<T, String>,
) -> Result<(T, crate::ai::client::Usage), String> {
    let mut usage = crate::ai::client::Usage::default();
    let first = client.chat(system, prompt).await?;
    usage.add(&first.usage);
    match parse(&first.content) {
        Ok(v) => Ok((v, usage)),
        Err(e1) => {
            eprintln!("[ai] 首次解析失败，重试: {e1}");
            let retry =
                format!("{prompt}\n\n【系统提醒】上次输出不是合法 JSON。这次只输出 JSON 本身，不要用 Markdown 围栏。");
            let second = client.chat(system, &retry).await?;
            usage.add(&second.usage);
            let v = parse(&second.content)
                .map_err(|e2| format!("AI 输出两次都不是合法 JSON，放弃: {e2}"))?;
            Ok((v, usage))
        }
    }
}

// ---------- 设置 ----------

#[tauri::command]
pub fn get_setting(state: State<AppState>, key: String) -> CmdResult<Option<String>> {
    use rusqlite::OptionalExtension;
    let db = state.db.get().map_err(|e| e.to_string())?;
    // 只有"无此行"才返回 None；真实的库/IO 错误必须透传，避免静默掩盖故障
    db
        .query_row(
            "SELECT value FROM settings WHERE key = ?1",
            [&key],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn set_setting(state: State<AppState>, key: String, value: String) -> CmdResult<()> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    db
        .execute(
            "INSERT INTO settings(key, value) VALUES(?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [&key, &value],
        )
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub fn get_all_settings(state: State<AppState>) -> CmdResult<HashMap<String, String>> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    let mut stmt = db
        .prepare("SELECT key, value FROM settings")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(|e| e.to_string())?;
    let mut map = HashMap::new();
    for row in rows {
        let (k, v): (String, String) = row.map_err(|e| e.to_string())?;
        map.insert(k, v);
    }
    Ok(map)
}

/// 从供应商的 OpenAI 兼容 /models 端点拉取可用模型列表（CC-switch 风格「获取模型」）。
/// GET {base_url}/models，Bearer 鉴权；失败时透传服务端错误片段。
#[tauri::command]
pub async fn fetch_models(base_url: String, api_key: String) -> CmdResult<Vec<String>> {
    let base = base_url.trim().trim_end_matches('/');
    if base.is_empty() {
        return Err("请先填写 Base URL".into());
    }
    if api_key.trim().is_empty() {
        return Err("请先填写 API Key".into());
    }
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = http
        .get(format!("{base}/models"))
        .bearer_auth(api_key.trim())
        .send()
        .await
        .map_err(|e| format!("请求失败: {e}"))?;
    let status = resp.status();
    let text = resp.text().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        let snippet: String = text.chars().take(300).collect();
        return Err(format!("获取模型失败 {status}: {snippet}"));
    }
    let json: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("响应非 JSON: {e}"))?;
    // OpenAI 兼容：{ "data": [ { "id": "..." }, ... ] }
    let mut ids: Vec<String> = json["data"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|m| m["id"].as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    ids.sort();
    ids.dedup();
    if ids.is_empty() {
        return Err("该端点未返回模型列表（可能不支持 /models）".into());
    }
    Ok(ids)
}

// ---------- 项目 ----------

fn row_to_project(row: &rusqlite::Row) -> rusqlite::Result<Project> {
    let scope_json: String = row.get(3)?;
    Ok(Project {
        id: row.get(0)?,
        name: row.get(1)?,
        target_host: row.get(2)?,
        scope: serde_json::from_str(&scope_json).unwrap_or_default(),
        created_at: row.get(4)?,
    })
}

#[tauri::command]
pub fn list_projects(state: State<AppState>) -> CmdResult<Vec<Project>> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    let mut stmt = db
        .prepare("SELECT id, name, target_host, scope, created_at FROM projects ORDER BY id DESC")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], row_to_project)
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

#[tauri::command]
pub fn create_project(
    state: State<AppState>,
    name: String,
    target_host: String,
    scope: Vec<String>,
) -> CmdResult<i64> {
    if name.trim().is_empty() {
        return Err("项目名称不能为空".into());
    }
    let db = state.db.get().map_err(|e| e.to_string())?;
    let scope_json = serde_json::to_string(&scope).map_err(|e| e.to_string())?;
    db
        .execute(
            "INSERT INTO projects(name, target_host, scope) VALUES(?1, ?2, ?3)",
            rusqlite::params![name.trim(), target_host.trim(), scope_json],
        )
        .map_err(|e| e.to_string())?;
    Ok(db.last_insert_rowid())
}

#[tauri::command]
pub fn delete_project(state: State<AppState>, id: i64) -> CmdResult<()> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    db
        .execute("DELETE FROM projects WHERE id = ?1", [id])
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// 当前打开的项目 id 存在 settings 里，重启后恢复
#[tauri::command]
pub fn get_current_project(state: State<AppState>) -> CmdResult<Option<Project>> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    let id: i64 = match db
        .query_row(
            "SELECT value FROM settings WHERE key = 'current_project_id'",
            [],
            |row| row.get::<_, String>(0),
        )
        .ok()
        .and_then(|v| v.parse().ok())
    {
        Some(id) => id,
        None => return Ok(None),
    };
    db
        .query_row(
            "SELECT id, name, target_host, scope, created_at FROM projects WHERE id = ?1",
            [id],
            row_to_project,
        )
        .map(Some)
        .or(Ok(None))
}

#[tauri::command]
pub fn set_current_project(state: State<AppState>, id: i64) -> CmdResult<()> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    db
        .execute(
            "INSERT INTO settings(key, value) VALUES('current_project_id', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [id.to_string()],
        )
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// 更新项目 Scope（拦截白名单）
#[tauri::command]
pub fn update_project_scope(
    state: State<AppState>,
    id: i64,
    scope: Vec<String>,
) -> CmdResult<()> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    let scope_json = serde_json::to_string(&scope).map_err(|e| e.to_string())?;
    db
        .execute(
            "UPDATE projects SET scope = ?1 WHERE id = ?2",
            rusqlite::params![scope_json, id],
        )
        .map_err(|e| e.to_string())?;
    Ok(())
}

// ---------- 代理控制 ----------

#[tauri::command]
pub async fn start_proxy(
    app: AppHandle,
    state: State<'_, AppState>,
    port: u16,
) -> CmdResult<ProxyStatus> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    state
        .proxy
        .start(app, state.db.clone(), dir, port)
        .await
}

#[tauri::command]
pub fn stop_proxy(app: AppHandle, state: State<AppState>) -> CmdResult<ProxyStatus> {
    state.proxy.stop(&app)
}

#[tauri::command]
pub fn proxy_status(state: State<AppState>) -> CmdResult<ProxyStatus> {
    Ok(state.proxy.status())
}

// ---------- CA 证书 ----------

#[derive(serde::Serialize)]
pub struct CaInfo {
    /// 证书文件路径（给用户去手动安装用）
    cert_path: String,
    /// SHA-256 指纹，人工核对用
    fingerprint: String,
    /// 当前用户是否已信任（仅 Windows 检测）
    trusted: bool,
}

#[tauri::command]
pub fn get_ca_info(app: AppHandle) -> CmdResult<CaInfo> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let material = ca::ensure_ca(&dir)?;
    Ok(CaInfo {
        cert_path: material.cert_path.to_string_lossy().into_owned(),
        fingerprint: ca::fingerprint_sha256(&material.cert_pem)?,
        trusted: ca::is_trusted(),
    })
}

/// 导出 CA 证书到下载目录，返回目标路径
#[tauri::command]
pub fn export_ca_cert(app: AppHandle) -> CmdResult<String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let material = ca::ensure_ca(&dir)?;
    let dest_dir = app
        .path()
        .download_dir()
        .unwrap_or_else(|_| dir.clone());
    let dest = dest_dir.join("RustForge-RootCA.cer");
    ca::export_cert(&material, &dest)?;
    Ok(dest.to_string_lossy().into_owned())
}

/// 一键安装到当前用户根证书 store（Windows 会弹安全警告，由用户确认）
#[tauri::command]
pub fn install_ca_cert(app: AppHandle) -> CmdResult<String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let material = ca::ensure_ca(&dir)?;
    ca::install_trusted(&material)
}

/// 在文件管理器中定位 CA 证书（手动安装用）
#[tauri::command]
pub fn reveal_ca_cert(app: AppHandle) -> CmdResult<()> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let material = ca::ensure_ca(&dir)?;
    #[cfg(target_os = "windows")]
    std::process::Command::new("explorer")
        .arg(format!("/select,{}", material.cert_path.to_string_lossy()))
        .spawn()
        .map_err(|e| e.to_string())?;
    #[cfg(target_os = "macos")]
    std::process::Command::new("open")
        .args(["-R", &material.cert_path.to_string_lossy().into_owned()])
        .spawn()
        .map_err(|e| e.to_string())?;
    Ok(())
}

// ---------- 运行环境（关于页诊断） ----------

#[derive(serde::Serialize)]
pub struct RuntimeInfo {
    pub os: String,
    pub arch: String,
    pub app_data_dir: String,
}

#[tauri::command]
pub fn get_runtime_info(app: AppHandle) -> CmdResult<RuntimeInfo> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    Ok(RuntimeInfo {
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        app_data_dir: dir.to_string_lossy().into_owned(),
    })
}

/// 在文件管理器中打开应用数据目录（证书 / 本地库所在处）
#[tauri::command]
pub fn reveal_app_data_dir(app: AppHandle) -> CmdResult<()> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    #[cfg(target_os = "windows")]
    std::process::Command::new("explorer")
        .arg(dir.as_os_str())
        .spawn()
        .map_err(|e| e.to_string())?;
    #[cfg(target_os = "macos")]
    std::process::Command::new("open")
        .arg(&dir)
        .spawn()
        .map_err(|e| e.to_string())?;
    #[cfg(all(unix, not(target_os = "macos")))]
    std::process::Command::new("xdg-open")
        .arg(&dir)
        .spawn()
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// 用系统默认浏览器打开外链（仅允许 http/https）
#[tauri::command]
pub fn open_url(url: String) -> CmdResult<()> {
    let url = url.trim();
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("仅允许打开 http/https 链接".into());
    }
    // 拒绝控制字符/空白/引号，避免参数被截断或注入
    if url.chars().any(|c| c.is_control() || c.is_whitespace() || c == '"') {
        return Err("链接包含非法字符".into());
    }
    #[cfg(target_os = "windows")]
    {
        // 用 explorer 直接打开（CreateProcess，不经 cmd），
        // 避免 URL 里的 & | ^ 等被命令解释器当作元字符执行
        std::process::Command::new("explorer")
            .arg(url)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(url)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::process::Command::new("xdg-open")
            .arg(url)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

// ---------- 流量查询 ----------

fn row_to_summary(row: &rusqlite::Row) -> rusqlite::Result<TrafficSummary> {
    let tags_json: String = row.get(14)?;
    Ok(TrafficSummary {
        id: row.get(0)?,
        project_id: row.get(1)?,
        method: row.get(2)?,
        scheme: row.get(3)?,
        host: row.get(4)?,
        port: row.get::<_, i64>(5)? as u16,
        path: row.get(6)?,
        url: row.get(7)?,
        status: row.get::<_, Option<i64>>(8)?.map(|s| s as u16),
        content_type: row.get(9)?,
        req_size: row.get(10)?,
        resp_size: row.get(11)?,
        duration_ms: row.get(12)?,
        created_at: row.get(13)?,
        rule_tags: serde_json::from_str(&tags_json).unwrap_or_default(),
    })
}

const SUMMARY_COLS: &str =
    "id, project_id, method, scheme, host, port, path, url, status, content_type,
     req_size, resp_size, duration_ms, created_at, rule_tags";

#[tauri::command]
pub fn list_traffic(
    state: State<AppState>,
    project_id: i64,
    method: Option<String>,
    status_class: Option<String>,
    search: Option<String>,
    limit: u32,
    offset: u32,
) -> CmdResult<Vec<TrafficSummary>> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    let sql = format!(
        "SELECT {SUMMARY_COLS} FROM traffic
         WHERE project_id = ?1
           AND (?2 IS NULL OR method = ?2)
           AND (?3 IS NULL OR status / 100 = CAST(?3 AS INTEGER))
           AND (?4 IS NULL OR host LIKE '%' || ?4 || '%' OR path LIKE '%' || ?4 || '%')
         ORDER BY id DESC LIMIT ?5 OFFSET ?6"
    );
    let mut stmt = db.prepare(&sql).map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(
            rusqlite::params![
                project_id,
                method.filter(|m| !m.is_empty()),
                status_class.filter(|s| !s.is_empty()),
                search.filter(|s| !s.is_empty()),
                limit,
                offset
            ],
            row_to_summary,
        )
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

/// body 二进制 → （文本, base64) 二选一
fn body_fields(body: &[u8]) -> (Option<String>, Option<String>) {
    use base64::Engine;
    match std::str::from_utf8(body) {
        Ok(s) => (Some(s.to_string()), None),
        Err(_) => (
            None,
            Some(base64::engine::general_purpose::STANDARD.encode(body)),
        ),
    }
}

/// 共享加载逻辑：get_traffic_detail 命令和 AI 分析都用
fn load_detail(conn: &rusqlite::Connection, id: i64) -> CmdResult<TrafficDetail> {
    let row = conn
        .query_row(
            &format!(
                "SELECT {SUMMARY_COLS}, req_headers, req_body, resp_headers, resp_body
                 FROM traffic WHERE id = ?1"
            ),
            [id],
            |row| {
                Ok((
                    row_to_summary(row)?,
                    row.get::<_, String>(15)?,
                    row.get::<_, Option<Vec<u8>>>(16)?,
                    row.get::<_, Option<String>>(17)?,
                    row.get::<_, Option<Vec<u8>>>(18)?,
                ))
            },
        )
        .map_err(|e| format!("流量记录 #{id} 不存在: {e}"))?;

    let (summary, req_headers, req_body, resp_headers, resp_body) = row;
    let (req_body_text, req_body_base64) = body_fields(&req_body.unwrap_or_default());
    let (resp_body_text, resp_body_base64) = body_fields(&resp_body.unwrap_or_default());
    Ok(TrafficDetail {
        summary,
        req_headers,
        req_body_text,
        req_body_base64,
        resp_headers,
        resp_body_text,
        resp_body_base64,
    })
}

#[tauri::command]
pub fn get_traffic_detail(state: State<AppState>, id: i64) -> CmdResult<TrafficDetail> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    load_detail(&db, id)
}

#[tauri::command]
pub fn clear_traffic(state: State<AppState>, project_id: i64) -> CmdResult<()> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    db
        .execute("DELETE FROM traffic WHERE project_id = ?1", [project_id])
        .map_err(|e| e.to_string())?;
    Ok(())
}

// ---------- AI 分析 ----------

/// 对一条流量做 AI 分析：结构化结果落 analyses 缓存表，
/// 每个漏洞假设生成 source='ai' 的待验证 Finding。红线：
/// ai_enabled=false 时直接拒绝；API Key 未配置时报清晰错误。
#[tauri::command]
pub async fn analyze_traffic(
    app: AppHandle,
    state: State<'_, AppState>,
    traffic_id: i64,
) -> CmdResult<AnalysisResult> {
    // 1) 读设置 + 流量（短锁）
    let (detail, template, model, base_url, api_key, project_id) = {
        let db = state.db.get().map_err(|e| e.to_string())?;
        if read_setting(&db, "ai_enabled").as_deref() == Some("false") {
            return Err("AI 功能已在设置中全局禁用（隐私开关）".into());
        }
        let (base_url, api_key, model) = resolved_ai(&db)?;
        let template = read_setting(&db, prompts::ANALYZE_TEMPLATE_KEY)
            .filter(|t| !t.trim().is_empty())
            .unwrap_or_else(|| prompts::DEFAULT_ANALYZE_TEMPLATE.to_string());
        let detail = load_detail(&db, traffic_id)?;
        let project_id = detail.summary.project_id;
        (detail, template, model, base_url, api_key, project_id)
    };

    // 2) 调 LLM（可能几十秒，不持锁）
    let client = OpenAiClient::new(&base_url, &api_key, &model)?;
    let (result, usage) = analyzer::analyze(&client, &template, &detail).await?;

    // 3) 落库：分析缓存 + 每个假设一条待验证 Finding
    let created_at = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let mut new_findings: Vec<Finding> = Vec::new();
    {
        let db = state.db.get().map_err(|e| e.to_string())?;
        // 整组落库放进事务，保证原子；同时清掉本流量此前"待验证"的 AI 结果与
        // 分析缓存，避免"重新分析"反复堆积重复 Finding（已确认/已排除的保留）
        let tx = db.unchecked_transaction().map_err(|e| e.to_string())?;
        tx.execute(
            "DELETE FROM findings WHERE traffic_id = ?1 AND source = 'ai' AND status = 'pending'",
            [traffic_id],
        )
        .map_err(|e| e.to_string())?;
        tx.execute("DELETE FROM analyses WHERE traffic_id = ?1", [traffic_id])
            .map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO analyses(project_id, traffic_id, purpose, suspicious_params, summary, raw_json, model)
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
            rusqlite::params![
                project_id,
                traffic_id,
                result.purpose,
                serde_json::to_string(&result.suspicious_params).unwrap_or_default(),
                result.summary,
                serde_json::to_string(&result).unwrap_or_default(),
                model,
            ],
        )
        .map_err(|e| e.to_string())?;

        for h in &result.hypotheses {
            let reasoning = if h.param.trim().is_empty() {
                h.reasoning.clone()
            } else {
                format!("【可疑参数】{}\n{}", h.param, h.reasoning)
            };
            tx.execute(
                "INSERT INTO findings(project_id, traffic_id, source, title, vuln_type,
                                      owasp, cwe, severity, confidence, reasoning, verify_steps)
                 VALUES(?1,?2,'ai',?3,?4,?5,?6,?7,?8,?9,?10)",
                rusqlite::params![
                    project_id, traffic_id, h.vuln_type, h.vuln_type, h.owasp, h.cwe,
                    h.severity, h.confidence as i64, reasoning, h.verify_steps,
                ],
            )
            .map_err(|e| e.to_string())?;
            new_findings.push(Finding {
                id: tx.last_insert_rowid(),
                project_id,
                traffic_id: Some(traffic_id),
                source: "ai".into(),
                title: h.vuln_type.clone(),
                vuln_type: h.vuln_type.clone(),
                owasp: h.owasp.clone(),
                cwe: h.cwe.clone(),
                severity: h.severity.clone(),
                confidence: h.confidence as i64,
                reasoning,
                verify_steps: h.verify_steps.clone(),
                status: "pending".into(),
                created_at: created_at.clone(),
            });
        }
        record_usage(&tx, &usage);
        tx.commit().map_err(|e| e.to_string())?;
    }
    for f in &new_findings {
        let _ = app.emit("finding:new", f);
    }
    Ok(result)
}

/// 读取某条流量最近一次 AI 分析缓存（避免重复烧 token）
#[tauri::command]
pub fn get_analysis(state: State<AppState>, traffic_id: i64) -> CmdResult<Option<AnalysisResult>> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    let raw: Option<String> = db
        .query_row(
            "SELECT raw_json FROM analyses WHERE traffic_id = ?1 ORDER BY id DESC LIMIT 1",
            [traffic_id],
            |row| row.get(0),
        )
        .ok();
    match raw {
        Some(j) => serde_json::from_str(&j)
            .map(Some)
            .map_err(|e| format!("分析缓存损坏: {e}")),
        None => Ok(None),
    }
}

// ---------- Findings ----------

#[tauri::command]
pub fn list_findings(
    state: State<AppState>,
    project_id: i64,
    status: Option<String>,
    severity: Option<String>,
    source: Option<String>,
) -> CmdResult<Vec<Finding>> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    let mut stmt = db
        .prepare(
            "SELECT id, project_id, traffic_id, source, title, vuln_type, owasp, cwe,
                    severity, confidence, reasoning, verify_steps, status, created_at
             FROM findings
             WHERE project_id = ?1
               AND (?2 IS NULL OR status = ?2)
               AND (?3 IS NULL OR severity = ?3)
               AND (?4 IS NULL OR source = ?4)
             ORDER BY id DESC LIMIT 500",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(
            rusqlite::params![
                project_id,
                status.filter(|s| !s.is_empty()),
                severity.filter(|s| !s.is_empty()),
                source.filter(|s| !s.is_empty()),
            ],
            |row| {
                Ok(Finding {
                    id: row.get(0)?,
                    project_id: row.get(1)?,
                    traffic_id: row.get(2)?,
                    source: row.get(3)?,
                    title: row.get(4)?,
                    vuln_type: row.get(5)?,
                    owasp: row.get(6)?,
                    cwe: row.get(7)?,
                    severity: row.get(8)?,
                    confidence: row.get(9)?,
                    reasoning: row.get(10)?,
                    verify_steps: row.get(11)?,
                    status: row.get(12)?,
                    created_at: row.get(13)?,
                })
            },
        )
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

/// 状态流转：pending（待验证）→ confirmed / rejected（人工结论）
#[tauri::command]
pub fn update_finding_status(
    state: State<AppState>,
    id: i64,
    status: String,
) -> CmdResult<()> {
    if !["pending", "confirmed", "rejected"].contains(&status.as_str()) {
        return Err(format!("非法状态: {status}"));
    }
    let db = state.db.get().map_err(|e| e.to_string())?;
    db
        .execute(
            "UPDATE findings SET status = ?1 WHERE id = ?2",
            rusqlite::params![status, id],
        )
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub fn delete_finding(state: State<AppState>, id: i64) -> CmdResult<()> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    db
        .execute("DELETE FROM findings WHERE id = ?1", [id])
        .map_err(|e| e.to_string())?;
    Ok(())
}

// ---------- 提示词模板 ----------

/// 取模板：settings 有自定义就用，否则返回内置默认
#[tauri::command]
pub fn get_prompt_template(state: State<AppState>) -> CmdResult<String> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    Ok(
        read_setting(&db, prompts::ANALYZE_TEMPLATE_KEY)
            .filter(|t| !t.trim().is_empty())
            .unwrap_or_else(|| prompts::DEFAULT_ANALYZE_TEMPLATE.to_string()),
    )
}

#[tauri::command]
pub fn set_prompt_template(state: State<AppState>, content: String) -> CmdResult<()> {
    if content.trim().is_empty() {
        return Err("模板不能为空".into());
    }
    let db = state.db.get().map_err(|e| e.to_string())?;
    db
        .execute(
            "INSERT INTO settings(key, value) VALUES(?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            rusqlite::params![prompts::ANALYZE_TEMPLATE_KEY, content],
        )
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// 恢复内置默认模板
#[tauri::command]
pub fn reset_prompt_template(state: State<AppState>) -> CmdResult<()> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    db
        .execute(
            "DELETE FROM settings WHERE key = ?1",
            [prompts::ANALYZE_TEMPLATE_KEY],
        )
        .map_err(|e| e.to_string())?;
    Ok(())
}

// ---------- 渗透任务树 ----------

fn row_to_task_node(conn: &rusqlite::Connection, row: &rusqlite::Row) -> rusqlite::Result<TaskNode> {
    let id: i64 = row.get(0)?;
    let finding_ids: Vec<i64> = {
        let mut stmt = conn.prepare(
            "SELECT finding_id FROM task_findings WHERE task_id = ?1 ORDER BY finding_id",
        )?;
        let rows = stmt.query_map([id], |r| r.get(0))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        out
    };
    Ok(TaskNode {
        id,
        project_id: row.get(1)?,
        parent_id: row.get(2)?,
        title: row.get(3)?,
        description: row.get(4)?,
        why: row.get(5)?,
        how_to: row.get(6)?,
        verify_criteria: row.get(7)?,
        status: row.get(8)?,
        sort_order: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
        finding_ids,
    })
}

const TASK_COLS: &str =
    "id, project_id, parent_id, title, description, why, how_to, verify_criteria,
     status, sort_order, created_at, updated_at";

fn load_task_nodes(conn: &rusqlite::Connection, project_id: i64) -> CmdResult<Vec<TaskNode>> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {TASK_COLS} FROM task_nodes WHERE project_id = ?1 ORDER BY id"
        ))
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    let mut rows = stmt.query([project_id]).map_err(|e| e.to_string())?;
    while let Some(row) = rows.next().map_err(|e| e.to_string())? {
        out.push(row_to_task_node(conn, row).map_err(|e| e.to_string())?);
    }
    Ok(out)
}

fn load_task_node(conn: &rusqlite::Connection, id: i64) -> CmdResult<TaskNode> {
    conn.query_row(
        &format!("SELECT {TASK_COLS} FROM task_nodes WHERE id = ?1"),
        [id],
        |row| row_to_task_node(conn, row),
    )
    .map_err(|e| format!("任务节点 #{id} 不存在: {e}"))
}

#[tauri::command]
pub fn get_task_tree(state: State<AppState>, project_id: i64) -> CmdResult<Vec<TaskNode>> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    load_task_nodes(&db, project_id)
}

/// AI 生成整棵树（replace=true 时先清空现有树）。持锁取数 → 放锁调 LLM → 持锁落库。
#[tauri::command]
pub async fn generate_task_tree(
    state: State<'_, AppState>,
    project_id: i64,
    replace: bool,
) -> CmdResult<usize> {
    let (client, digest_text, target, valid_ids) = {
        let db = state.db.get().map_err(|e| e.to_string())?;
        let existing: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM task_nodes WHERE project_id = ?1",
                [project_id],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if existing > 0 && !replace {
            return Err("任务树已存在。如需重建请点「重新生成」（会清空现有树）".into());
        }
        let client = llm_client(&db)?;
        let digest_text = digest::build_digest(&db, project_id)?;
        let target: String = db
            .query_row(
                "SELECT target_host FROM projects WHERE id = ?1",
                [project_id],
                |r| r.get(0),
            )
            .unwrap_or_default();
        let valid_ids = planner::valid_finding_ids(&db, project_id)?;
        (client, digest_text, target, valid_ids)
    };

    let prompt = planner::plan_prompt(&digest_text, &target);
    let (tree, usage) = chat_json(&client, planner::SYSTEM_PROMPT, &prompt, |raw| {
        planner::parse_plan(raw, &valid_ids)
    })
    .await?;

    let db = state.db.get().map_err(|e| e.to_string())?;
    let n = planner::insert_tree(&db, project_id, &tree, replace)?;
    record_usage(&db, &usage);
    Ok(n)
}

/// AI 展开节点为子任务
#[tauri::command]
pub async fn expand_task_node(state: State<'_, AppState>, node_id: i64) -> CmdResult<usize> {
    let (client, node, digest_text, valid_ids) = {
        let db = state.db.get().map_err(|e| e.to_string())?;
        let node = load_task_node(&db, node_id)?;
        let client = llm_client(&db)?;
        let digest_text = digest::build_digest(&db, node.project_id)?;
        let valid_ids = planner::valid_finding_ids(&db, node.project_id)?;
        (client, node, digest_text, valid_ids)
    };

    let prompt = planner::expand_prompt(&node, &digest_text);
    let (children, usage) = chat_json(&client, planner::SYSTEM_PROMPT, &prompt, |raw| {
        planner::parse_expand(raw, &valid_ids)
    })
    .await?;

    let db = state.db.get().map_err(|e| e.to_string())?;
    // 节点可能在等待期间被删，重新加载确认存在
    let node = load_task_node(&db, node_id)?;
    let n = planner::insert_children(&db, &node, &children)?;
    record_usage(&db, &usage);
    Ok(n)
}

/// AI 换个思路（重写节点四要素，状态重置 todo）
#[tauri::command]
pub async fn alternative_task_node(state: State<'_, AppState>, node_id: i64) -> CmdResult<()> {
    let (client, node, digest_text) = {
        let db = state.db.get().map_err(|e| e.to_string())?;
        let node = load_task_node(&db, node_id)?;
        let client = llm_client(&db)?;
        let digest_text = digest::build_digest(&db, node.project_id)?;
        (client, node, digest_text)
    };

    let prompt = planner::alternative_prompt(&node, &digest_text);
    let (alt, usage) = chat_json(&client, planner::SYSTEM_PROMPT, &prompt, |raw| {
        planner::parse_alternative(raw)
    })
    .await?;

    let db = state.db.get().map_err(|e| e.to_string())?;
    planner::apply_alternative(&db, node_id, &alt)?;
    record_usage(&db, &usage);
    Ok(())
}

/// "下一步"：进行中优先，否则第一个可执行的 todo 叶子
#[tauri::command]
pub fn next_task(state: State<AppState>, project_id: i64) -> CmdResult<Option<TaskNode>> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    let nodes = load_task_nodes(&db, project_id)?;
    let id = tree_state::next_actionable(&nodes);
    Ok(id.and_then(|nid| nodes.into_iter().find(|n| n.id == nid)))
}

/// 手动标记状态（状态机白名单校验）
#[tauri::command]
pub fn update_task_status(state: State<AppState>, node_id: i64, status: String) -> CmdResult<()> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    let node = load_task_node(&db, node_id)?;
    if !tree_state::can_transition(&node.status, &status) {
        return Err(format!("不允许从「{}」变为「{}」", node.status, status));
    }
    db
        .execute(
            "UPDATE task_nodes SET status = ?1, updated_at = datetime('now','localtime') WHERE id = ?2",
            rusqlite::params![status, node_id],
        )
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// 手动添加节点
#[tauri::command]
pub fn create_task_node(
    state: State<AppState>,
    project_id: i64,
    parent_id: Option<i64>,
    title: String,
    description: String,
    why: String,
    how_to: String,
    verify_criteria: String,
) -> CmdResult<i64> {
    if title.trim().is_empty() {
        return Err("标题不能为空".into());
    }
    let db = state.db.get().map_err(|e| e.to_string())?;
    if let Some(pid) = parent_id {
        let parent = load_task_node(&db, pid)?;
        if parent.project_id != project_id {
            return Err("父节点不属于当前项目".into());
        }
    }
    let next_sort: i64 = db
        .query_row(
            "SELECT COALESCE(MAX(sort_order) + 1, 0) FROM task_nodes
             WHERE project_id = ?1 AND parent_id IS ?2",
            rusqlite::params![project_id, parent_id],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    db
        .execute(
            "INSERT INTO task_nodes(project_id, parent_id, title, description, why, how_to,
                                    verify_criteria, status, sort_order)
             VALUES(?1,?2,?3,?4,?5,?6,?7,'todo',?8)",
            rusqlite::params![
                project_id, parent_id, title.trim(), description, why, how_to,
                verify_criteria, next_sort,
            ],
        )
        .map_err(|e| e.to_string())?;
    Ok(db.last_insert_rowid())
}

/// 删除节点（子节点与关联随 FK 级联删除）
#[tauri::command]
pub fn delete_task_node(state: State<AppState>, node_id: i64) -> CmdResult<()> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    db
        .execute("DELETE FROM task_nodes WHERE id = ?1", [node_id])
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// 节点关联的 Finding 列表
#[tauri::command]
pub fn get_task_findings(state: State<AppState>, node_id: i64) -> CmdResult<Vec<Finding>> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    let mut stmt = db
        .prepare(
            "SELECT f.id, f.project_id, f.traffic_id, f.source, f.title, f.vuln_type,
                    f.owasp, f.cwe, f.severity, f.confidence, f.reasoning, f.verify_steps,
                    f.status, f.created_at
             FROM findings f JOIN task_findings tf ON tf.finding_id = f.id
             WHERE tf.task_id = ?1 ORDER BY f.id",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([node_id], |row| {
            Ok(Finding {
                id: row.get(0)?,
                project_id: row.get(1)?,
                traffic_id: row.get(2)?,
                source: row.get(3)?,
                title: row.get(4)?,
                vuln_type: row.get(5)?,
                owasp: row.get(6)?,
                cwe: row.get(7)?,
                severity: row.get(8)?,
                confidence: row.get(9)?,
                reasoning: row.get(10)?,
                verify_steps: row.get(11)?,
                status: row.get(12)?,
                created_at: row.get(13)?,
            })
        })
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

// ---------- 知识库（OWASP/CWE 卡片） ----------

#[tauri::command]
pub fn get_knowledge_cards(owasp: String, cwe: String) -> CmdResult<Vec<knowledge::KnowledgeCard>> {
    Ok(knowledge::lookup(&owasp, &cwe))
}

// ---------- Repeater（手动改包重发） ----------

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ReplayHeader {
    pub name: String,
    pub value: String,
}

#[derive(serde::Serialize)]
pub struct ReplayResponse {
    pub status: u16,
    pub status_text: String,
    pub headers: Vec<ReplayHeader>,
    pub body_text: Option<String>,
    pub body_base64: Option<String>,
    pub resp_size: i64,
    pub duration_ms: i64,
}

/// 手动重发一个请求——人在回路的「验证」动作，由用户主动触发、可自由改包。
/// pentest 工具惯例：忽略证书错误、不自动跟随重定向（便于观察 3xx/鉴权行为）。
#[tauri::command]
pub async fn replay_request(
    method: String,
    url: String,
    headers: Vec<ReplayHeader>,
    body: Option<String>,
) -> CmdResult<ReplayResponse> {
    use base64::Engine;
    use std::time::{Duration, Instant};

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("HTTP 客户端初始化失败: {e}"))?;

    let m = reqwest::Method::from_bytes(method.trim().to_uppercase().as_bytes())
        .map_err(|_| format!("非法的 HTTP 方法: {method}"))?;
    let mut req = client.request(m, url.trim());
    for h in &headers {
        let name = h.name.trim();
        // content-length / host 交给 reqwest 依据实际 body/url 计算，避免冲突
        if name.is_empty()
            || name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("host")
        {
            continue;
        }
        req = req.header(name, &h.value);
    }
    if let Some(b) = body.filter(|b| !b.is_empty()) {
        req = req.body(b);
    }

    let start = Instant::now();
    let resp = req.send().await.map_err(|e| format!("请求失败: {e}"))?;
    let duration_ms = start.elapsed().as_millis() as i64;

    let status = resp.status();
    let out_headers: Vec<ReplayHeader> = resp
        .headers()
        .iter()
        .map(|(k, v)| ReplayHeader {
            name: k.to_string(),
            value: v.to_str().unwrap_or("<非文本值>").to_string(),
        })
        .collect();
    let bytes = resp.bytes().await.map_err(|e| format!("读取响应体失败: {e}"))?;
    let resp_size = bytes.len() as i64;
    let (body_text, body_base64) = match std::str::from_utf8(&bytes) {
        Ok(s) => (Some(s.to_string()), None),
        Err(_) => (
            None,
            Some(base64::engine::general_purpose::STANDARD.encode(&bytes)),
        ),
    };

    Ok(ReplayResponse {
        status: status.as_u16(),
        status_text: status.canonical_reason().unwrap_or("").to_string(),
        headers: out_headers,
        body_text,
        body_base64,
        resp_size,
        duration_ms,
    })
}

// ---------- 学习报告 ----------

/// 生成 Markdown 报告文本（供前端预览）
#[tauri::command]
pub fn build_report(state: State<AppState>, project_id: i64) -> CmdResult<String> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    report::build_markdown(&db, project_id)
}

/// 导出报告到下载目录，返回保存路径
#[tauri::command]
pub fn export_report(app: AppHandle, state: State<AppState>, project_id: i64) -> CmdResult<String> {
    let md = {
        let db = state.db.get().map_err(|e| e.to_string())?;
        report::build_markdown(&db, project_id)?
    };
    let dest_dir = app
        .path()
        .download_dir()
        .unwrap_or_else(|_| std::env::temp_dir());
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let dest = dest_dir.join(format!("RustForge-Report-{stamp}.md"));
    std::fs::write(&dest, md).map_err(|e| format!("写入报告失败: {e}"))?;
    Ok(dest.to_string_lossy().into_owned())
}

// ---------- 流量计数（分页/加载更多用） ----------

/// 按当前筛选条件统计总条数（与 list_traffic 的 WHERE 保持一致）
#[tauri::command]
pub fn count_traffic(
    state: State<AppState>,
    project_id: i64,
    method: Option<String>,
    status_class: Option<String>,
    search: Option<String>,
) -> CmdResult<i64> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    db
        .query_row(
            "SELECT COUNT(*) FROM traffic
             WHERE project_id = ?1
               AND (?2 IS NULL OR method = ?2)
               AND (?3 IS NULL OR status / 100 = CAST(?3 AS INTEGER))
               AND (?4 IS NULL OR host LIKE '%' || ?4 || '%' OR path LIKE '%' || ?4 || '%')",
            rusqlite::params![
                project_id,
                method.filter(|m| !m.is_empty()),
                status_class.filter(|s| !s.is_empty()),
                search.filter(|s| !s.is_empty()),
            ],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())
}

// ---------- Token 用量统计 ----------

#[derive(serde::Serialize)]
pub struct TokenUsage {
    pub calls: i64,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub total_tokens: i64,
}

/// 读本机累计用量（record_usage 写入的 settings 键）
#[tauri::command]
pub fn get_token_usage(state: State<AppState>) -> CmdResult<TokenUsage> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    let read = |key: &str| -> i64 {
        db
            .query_row(
                "SELECT CAST(value AS INTEGER) FROM settings WHERE key = ?1",
                [key],
                |r| r.get(0),
            )
            .unwrap_or(0)
    };
    Ok(TokenUsage {
        calls: read("usage_calls"),
        prompt_tokens: read("usage_prompt_tokens"),
        completion_tokens: read("usage_completion_tokens"),
        total_tokens: read("usage_total_tokens"),
    })
}

#[tauri::command]
pub fn reset_token_usage(state: State<AppState>) -> CmdResult<()> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    db
        .execute(
            "DELETE FROM settings WHERE key IN
             ('usage_calls','usage_prompt_tokens','usage_completion_tokens','usage_total_tokens')",
            [],
        )
        .map_err(|e| e.to_string())?;
    Ok(())
}
