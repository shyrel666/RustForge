//! 暴露给前端的全部 Tauri commands

use crate::ai::client::{LlmClient, OpenAiClient};
use crate::ai::context::{self, AiContextPreview, AiDataPolicy};
use crate::ai::redaction::{redact_fallback_text, RedactionManifest};
use crate::ai::validation::ValidationReport;
use crate::ai::{analyzer, digest, planner, prompts};
use crate::authorization::{
    load_project_policy, normalize_scope_entries, AuthorizationError, ScopeDecision,
};
use crate::evidence::{self, Evidence, EvidenceSourceType, FindingEvent};
use crate::knowledge;
use crate::knowledge::StandardReference;
use crate::proxy::ca;
use crate::proxy::ProxyStatus;
use crate::replay::{
    self, ReplayRequestInput, ReplayRun, ReplayRunDiff, ReplayRunPage, ReplaySession, TlsPolicy,
};
use crate::report;
use crate::secrets::{
    is_sensitive_setting_key, json_contains_sensitive_field, provider_api_key_id, redact_sensitive,
    SecretStore, SecretString,
};
use crate::storage::models::{
    AnalysisResult, Finding, FindingRuleHit, FindingTrafficRef, Project, TrafficDetail,
    TrafficSummary,
};
use crate::tree::model::{
    CreateTaskNodeInput, TaskNode, TaskPlanApplyResult, TaskPlanEvent, TaskPlanProposal, TestPlan,
    UpdateTaskNodeInput,
};
use crate::tree::service as tree_service;
use crate::tree::state as tree_state;
use crate::AppState;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use zeroize::Zeroizing;

type CmdResult<T> = Result<T, String>;
const AI_DATA_POLICY_SETTING: &str = "ai_data_policy";

/// 模块内读取单个设置（get_setting 命令的内部复用版）
fn read_setting(conn: &rusqlite::Connection, key: &str) -> Option<String> {
    conn.query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| {
        r.get(0)
    })
    .ok()
}

fn read_ai_data_policy(conn: &rusqlite::Connection) -> CmdResult<AiDataPolicy> {
    let policy = match read_setting(conn, AI_DATA_POLICY_SETTING) {
        Some(json) => {
            serde_json::from_str(&json).map_err(|error| format!("AI 数据策略损坏: {error}"))?
        }
        None => AiDataPolicy::default(),
    };
    policy.validate()?;
    Ok(policy)
}

fn load_prompt_version(
    conn: &rusqlite::Connection,
    id: i64,
    active: bool,
) -> CmdResult<prompts::PromptTemplateView> {
    conn.query_row(
        "SELECT id, prompt_id, version, content, based_on_id, operation, created_at
         FROM prompt_versions WHERE id = ?1 AND prompt_id = ?2",
        rusqlite::params![id, prompts::ANALYZE_PROMPT_ID],
        |row| {
            Ok(prompts::PromptTemplateView {
                id: Some(row.get(0)?),
                prompt_id: row.get(1)?,
                version: row.get(2)?,
                source: "custom".to_string(),
                content: row.get(3)?,
                based_on_id: row.get(4)?,
                operation: row.get(5)?,
                created_at: Some(row.get(6)?),
                active,
            })
        },
    )
    .map_err(|error| format!("提示词版本 #{id} 不存在或已损坏: {error}"))
}

fn active_prompt(conn: &rusqlite::Connection) -> CmdResult<prompts::PromptTemplateView> {
    let Some(value) = read_setting(conn, prompts::ACTIVE_ANALYZE_PROMPT_SETTING) else {
        return Ok(prompts::PromptTemplateView::builtin(true));
    };
    let id = value
        .parse::<i64>()
        .map_err(|_| "活动提示词版本 id 损坏，请恢复默认提示词".to_string())?;
    load_prompt_version(conn, id, true)
}

fn create_prompt_version(
    conn: &rusqlite::Connection,
    content: String,
    based_on_id: Option<i64>,
    operation: &str,
) -> CmdResult<prompts::PromptTemplateView> {
    prompts::validate_template(&content)?;
    if !matches!(operation, "save" | "copy" | "rollback") {
        return Err("非法提示词版本操作".to_string());
    }
    let tx = conn
        .unchecked_transaction()
        .map_err(|error| error.to_string())?;
    let latest: i64 = tx
        .query_row(
            "SELECT COALESCE(MAX(version), ?2) FROM prompt_versions WHERE prompt_id = ?1",
            rusqlite::params![
                prompts::ANALYZE_PROMPT_ID,
                prompts::DEFAULT_ANALYZE_PROMPT_VERSION
            ],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    let version = latest + 1;
    tx.execute(
        "INSERT INTO prompt_versions(prompt_id, version, content, based_on_id, operation)
         VALUES(?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            prompts::ANALYZE_PROMPT_ID,
            version,
            content,
            based_on_id,
            operation
        ],
    )
    .map_err(|error| error.to_string())?;
    let id = tx.last_insert_rowid();
    tx.execute(
        "INSERT INTO settings(key, value) VALUES(?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        rusqlite::params![prompts::ACTIVE_ANALYZE_PROMPT_SETTING, id.to_string()],
    )
    .map_err(|error| error.to_string())?;
    tx.commit().map_err(|error| error.to_string())?;
    load_prompt_version(conn, id, true)
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AiProviderMetadata {
    id: String,
    name: String,
    base_url: String,
    model: String,
    note: String,
    supports_json_schema: bool,
}

/// 通用设置写接口只接受非敏感元数据；`has_api_key` 也是只读状态。
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AiProviderWrite {
    id: String,
    name: String,
    base_url: String,
    model: String,
    note: String,
    supports_json_schema: bool,
}

#[derive(Debug, serde::Serialize)]
struct AiProviderView {
    id: String,
    name: String,
    base_url: String,
    model: String,
    note: String,
    has_api_key: bool,
    supports_json_schema: bool,
}

#[derive(Debug, serde::Serialize)]
pub struct ApiKeyStatus {
    provider_id: String,
    has_api_key: bool,
}

fn parse_stored_providers(value: Option<String>) -> CmdResult<Vec<AiProviderMetadata>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let mut providers: Vec<AiProviderMetadata> = serde_json::from_str(&value)
        .map_err(|_| "AI 供应商配置损坏，请重建开发数据库后重新配置".to_string())?;
    for provider in &mut providers {
        provider.base_url = normalize_provider_base_url(&provider.base_url)?;
    }
    validate_provider_metadata(&providers)?;
    Ok(providers)
}

fn normalize_provider_base_url(value: &str) -> CmdResult<String> {
    let normalized = value.trim().trim_end_matches('/').to_string();
    let parsed =
        url::Url::parse(&normalized).map_err(|_| "AI 供应商 Base URL 格式无效".to_string())?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err("AI 供应商 Base URL 必须是含主机名的 HTTP(S) URL".into());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("AI 供应商 Base URL 不得包含用户名或密码".into());
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("AI 供应商 Base URL 不得包含查询参数或 fragment".into());
    }
    Ok(normalized)
}

fn validate_provider_metadata(providers: &[AiProviderMetadata]) -> CmdResult<()> {
    let mut ids = HashSet::new();
    for provider in providers {
        provider_api_key_id(&provider.id).map_err(|error| error.to_string())?;
        if !ids.insert(provider.id.as_str()) {
            return Err("AI 供应商 id 重复".into());
        }
        normalize_provider_base_url(&provider.base_url)?;
    }
    Ok(())
}

fn normalize_provider_write(value: &str) -> CmdResult<(String, Vec<AiProviderMetadata>)> {
    if json_contains_sensitive_field(value) {
        return Err("[SENSITIVE_SETTING] AI 供应商配置不得包含 API Key 或鉴权信息".into());
    }
    let writes: Vec<AiProviderWrite> =
        serde_json::from_str(value).map_err(|_| "AI 供应商配置格式无效".to_string())?;
    let providers: Vec<AiProviderMetadata> = writes
        .into_iter()
        .map(|provider| {
            Ok(AiProviderMetadata {
                id: provider.id,
                name: provider.name,
                base_url: normalize_provider_base_url(&provider.base_url)?,
                model: provider.model,
                note: provider.note,
                supports_json_schema: provider.supports_json_schema,
            })
        })
        .collect::<CmdResult<_>>()?;
    validate_provider_metadata(&providers)?;
    let normalized = serde_json::to_string(&providers).map_err(|error| error.to_string())?;
    Ok((normalized, providers))
}

fn stored_providers(conn: &rusqlite::Connection) -> CmdResult<Vec<AiProviderMetadata>> {
    parse_stored_providers(read_setting(conn, "ai_providers"))
}

fn provider_views(
    providers: Vec<AiProviderMetadata>,
    secrets: &dyn SecretStore,
) -> CmdResult<String> {
    let mut views = Vec::with_capacity(providers.len());
    for provider in providers {
        let secret_id = provider_api_key_id(&provider.id).map_err(|error| error.to_string())?;
        let has_api_key = secrets
            .get(&secret_id)
            .map_err(|error| error.to_string())?
            .is_some_and(|secret| !secret.expose().trim().is_empty());
        views.push(AiProviderView {
            id: provider.id,
            name: provider.name,
            base_url: provider.base_url,
            model: provider.model,
            note: provider.note,
            has_api_key,
            supports_json_schema: provider.supports_json_schema,
        });
    }
    serde_json::to_string(&views).map_err(|error| error.to_string())
}

fn ensure_provider_exists(conn: &rusqlite::Connection, provider_id: &str) -> CmdResult<()> {
    if stored_providers(conn)?
        .iter()
        .any(|provider| provider.id == provider_id)
    {
        Ok(())
    } else {
        Err("AI 供应商不存在，请先保存供应商配置".into())
    }
}

/// 当前生效的 AI 供应商，仅返回非敏感元数据。
fn active_ai(conn: &rusqlite::Connection) -> CmdResult<Option<(String, String, String, bool)>> {
    let list = stored_providers(conn)?;
    if list.is_empty() {
        return Ok(None);
    }
    let current = read_setting(conn, "ai_current").unwrap_or_default();
    let provider = list
        .iter()
        .find(|provider| provider.id == current)
        .unwrap_or(&list[0]);
    Ok(Some((
        provider.id.clone(),
        normalize_provider_base_url(&provider.base_url)?,
        provider.model.trim().to_string(),
        provider.supports_json_schema,
    )))
}

#[derive(Debug)]
struct ResolvedAi {
    provider_id: String,
    base_url: String,
    api_key: SecretString,
    model: String,
    supports_json_schema: bool,
}

/// 归一化活动供应商并从系统凭据库读取 Key。
fn resolved_ai(conn: &rusqlite::Connection, secrets: &dyn SecretStore) -> CmdResult<ResolvedAi> {
    if read_setting(conn, "ai_enabled").as_deref() == Some("false") {
        return Err("AI 功能已在设置中全局禁用（隐私开关）".into());
    }
    let (provider_id, base_url, model, supports_json_schema) =
        active_ai(conn)?.ok_or("请先在设置页添加并选择一个 AI 供应商")?;
    let secret_id = provider_api_key_id(&provider_id).map_err(|error| error.to_string())?;
    let api_key = secrets
        .get(&secret_id)
        .map_err(|error| error.to_string())?
        .ok_or("当前 AI 供应商未配置 API Key，请在设置页填写")?;
    if api_key.expose().trim().is_empty() {
        return Err("当前 AI 供应商未配置 API Key，请在设置页填写".into());
    }
    let model = if model.trim().is_empty() {
        "deepseek-chat".to_string()
    } else {
        model
    };
    Ok(ResolvedAi {
        provider_id,
        base_url,
        api_key,
        model,
        supports_json_schema,
    })
}

#[derive(Debug)]
struct JsonAudit {
    usage: crate::ai::client::Usage,
    validation: ValidationReport,
    raw_output_hash: String,
}

#[derive(Debug)]
struct ChatJsonAttempt<T> {
    result: Option<T>,
    audit: JsonAudit,
}

fn sha256_text(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn valid_json_report(attempts: usize, warnings: Vec<String>) -> ValidationReport {
    ValidationReport {
        status: "valid".to_string(),
        errors: Vec::new(),
        warnings,
        attempts,
        hypotheses_total: 0,
        grounded_hypotheses: 0,
        ungrounded_hypotheses: 0,
    }
}

/// 调 LLM 并解析 JSON；解析失败追加提醒重试一次。模型产生过的响应即使
/// 最终无效也作为审计结果返回，由调用方写入 analysis_runs。
async fn chat_json<T>(
    client: &impl LlmClient,
    system: &str,
    prompt: &str,
    parse: impl Fn(&str) -> Result<T, String>,
) -> Result<ChatJsonAttempt<T>, String> {
    let mut usage = crate::ai::client::Usage::default();
    let first = client.chat(system, prompt, None).await?;
    usage.add(&first.usage);
    match parse(&first.content) {
        Ok(value) => Ok(ChatJsonAttempt {
            result: Some(value),
            audit: JsonAudit {
                usage,
                validation: valid_json_report(1, Vec::new()),
                raw_output_hash: sha256_text(&first.content),
            },
        }),
        Err(e1) => {
            eprintln!("[ai] 首次解析失败，重试: {}", redact_sensitive(&e1, &[]));
            let retry = format!("{prompt}\n\n{}", planner::RETRY_SUFFIX);
            let second = match client.chat(system, &retry, None).await {
                Ok(response) => response,
                Err(error) => {
                    let mut validation = ValidationReport::invalid(e1);
                    validation.warnings.push(format!(
                        "JSON 校验重试调用失败：{}",
                        redact_sensitive(&error, &[])
                    ));
                    return Ok(ChatJsonAttempt {
                        result: None,
                        audit: JsonAudit {
                            usage,
                            validation,
                            raw_output_hash: sha256_text(&first.content),
                        },
                    });
                }
            };
            usage.add(&second.usage);
            match parse(&second.content) {
                Ok(value) => Ok(ChatJsonAttempt {
                    result: Some(value),
                    audit: JsonAudit {
                        usage,
                        validation: valid_json_report(
                            2,
                            vec![format!(
                                "首次模型响应未通过 JSON 校验：{}",
                                redact_sensitive(&e1, &[])
                            )],
                        ),
                        raw_output_hash: sha256_text(&second.content),
                    },
                }),
                Err(e2) => {
                    let mut validation = ValidationReport::invalid(e2);
                    validation.attempts = 2;
                    validation.warnings.push(format!(
                        "首次模型响应也无效：{}",
                        redact_sensitive(&e1, &[])
                    ));
                    Ok(ChatJsonAttempt {
                        result: None,
                        audit: JsonAudit {
                            usage,
                            validation,
                            raw_output_hash: sha256_text(&second.content),
                        },
                    })
                }
            }
        }
    }
}

// ---------- 设置 ----------

#[tauri::command]
pub fn get_setting(state: State<AppState>, key: String) -> CmdResult<Option<String>> {
    use rusqlite::OptionalExtension;
    if is_sensitive_setting_key(&key) {
        return Err("[SENSITIVE_SETTING] 通用设置接口不允许读取秘密".into());
    }
    let db = state.db.get().map_err(|e| e.to_string())?;
    // 只有"无此行"才返回 None；真实的库/IO 错误必须透传，避免静默掩盖故障
    let value: Option<String> = db
        .query_row("SELECT value FROM settings WHERE key = ?1", [&key], |row| {
            row.get(0)
        })
        .optional()
        .map_err(|e| e.to_string())?;
    if key == "ai_providers" {
        return value
            .map(|value| {
                let providers = parse_stored_providers(Some(value))?;
                provider_views(providers, state.secrets.as_ref())
            })
            .transpose();
    }
    Ok(value)
}

fn set_provider_metadata(
    conn: &rusqlite::Connection,
    secrets: &dyn SecretStore,
    value: &str,
) -> CmdResult<()> {
    let old = stored_providers(conn)?;
    let old_json = serde_json::to_string(&old).map_err(|error| error.to_string())?;
    let (normalized, new) = normalize_provider_write(value)?;
    let new_ids: HashSet<&str> = new.iter().map(|provider| provider.id.as_str()).collect();
    let mut removed_credentials = Vec::new();
    for removed in old
        .iter()
        .filter(|provider| !new_ids.contains(provider.id.as_str()))
    {
        let secret_id = provider_api_key_id(&removed.id).map_err(|error| error.to_string())?;
        let credential = secrets.get(&secret_id).map_err(|error| error.to_string())?;
        removed_credentials.push((secret_id, credential));
    }

    // SQLite is the source of truth for which credentials are live. Never
    // delete an externally stored credential before this write succeeds.
    conn.execute(
        "INSERT INTO settings(key, value) VALUES('ai_providers', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [&normalized],
    )
    .map_err(|error| error.to_string())?;

    for (secret_id, _) in &removed_credentials {
        if let Err(delete_error) = secrets.delete(secret_id) {
            let mut recovery_errors = Vec::new();
            for (restore_id, credential) in &removed_credentials {
                if let Some(credential) = credential {
                    if let Err(error) = secrets.set(restore_id, credential.expose()) {
                        recovery_errors.push(format!("恢复系统凭据 {restore_id} 失败: {error}"));
                    }
                }
            }
            if let Err(error) = conn.execute(
                "INSERT INTO settings(key, value) VALUES('ai_providers', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [&old_json],
            ) {
                recovery_errors.push(format!("恢复 Provider 元数据失败: {error}"));
            }
            let recovery = if recovery_errors.is_empty() {
                "已恢复原 Provider 配置和凭据".to_string()
            } else {
                recovery_errors.join("；")
            };
            return Err(format!(
                "删除 Provider 系统凭据失败: {delete_error}；{recovery}"
            ));
        }
    }
    Ok(())
}

#[tauri::command]
pub fn set_setting(state: State<AppState>, key: String, value: String) -> CmdResult<()> {
    if is_sensitive_setting_key(&key) {
        return Err("[SENSITIVE_SETTING] 请使用专用 API Key 命令".into());
    }
    let db = state.db.get().map_err(|e| e.to_string())?;
    if key == "ai_providers" {
        return set_provider_metadata(&db, state.secrets.as_ref(), &value);
    }
    let value = match key.as_str() {
        "ai_enabled" | "consent_accepted" if matches!(value.as_str(), "true" | "false") => value,
        "proxy_port" => {
            let port: u16 = value.parse().map_err(|_| "代理端口无效")?;
            if port < 1024 {
                return Err("代理端口必须在 1024 到 65535 之间".into());
            }
            port.to_string()
        }
        "theme" if matches!(value.as_str(), "light" | "dark" | "system") => value,
        "ai_current" => {
            if !value.is_empty() {
                provider_api_key_id(&value).map_err(|error| error.to_string())?;
                ensure_provider_exists(&db, &value)?;
            }
            value
        }
        "ai_enabled" | "consent_accepted" => return Err("布尔设置值无效".into()),
        "theme" => return Err("主题设置值无效".into()),
        _ => return Err("[SETTING_NOT_WRITABLE] 通用设置接口只允许写入已声明的非敏感设置".into()),
    };
    db.execute(
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
        if is_sensitive_setting_key(&k) {
            continue;
        }
        if k == "ai_providers" {
            let providers = parse_stored_providers(Some(v))?;
            map.insert(k, provider_views(providers, state.secrets.as_ref())?);
        } else {
            map.insert(k, v);
        }
    }
    Ok(map)
}

#[tauri::command]
pub fn get_ai_data_policy(state: State<AppState>) -> CmdResult<AiDataPolicy> {
    let db = state.db.get().map_err(|error| error.to_string())?;
    read_ai_data_policy(&db)
}

#[tauri::command]
pub fn set_ai_data_policy(state: State<AppState>, policy: AiDataPolicy) -> CmdResult<AiDataPolicy> {
    policy.validate()?;
    let json = serde_json::to_string(&policy).map_err(|error| error.to_string())?;
    let db = state.db.get().map_err(|error| error.to_string())?;
    db.execute(
        "INSERT INTO settings(key, value) VALUES(?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        rusqlite::params![AI_DATA_POLICY_SETTING, json],
    )
    .map_err(|error| error.to_string())?;
    Ok(policy)
}

#[tauri::command]
pub fn set_provider_api_key(
    state: State<AppState>,
    provider_id: String,
    api_key: String,
) -> CmdResult<ApiKeyStatus> {
    let provider_id = provider_id.trim().to_string();
    let api_key = Zeroizing::new(api_key);
    let api_key = api_key.trim();
    if api_key.is_empty() {
        return Err("API Key 不能为空".into());
    }
    if api_key.len() > 16 * 1024 {
        return Err("API Key 长度超出限制".into());
    }
    let secret_id = provider_api_key_id(&provider_id).map_err(|error| error.to_string())?;
    {
        let db = state.db.get().map_err(|error| error.to_string())?;
        ensure_provider_exists(&db, &provider_id)?;
    }
    state
        .secrets
        .set(&secret_id, api_key)
        .map_err(|error| error.to_string())?;
    Ok(ApiKeyStatus {
        provider_id,
        has_api_key: true,
    })
}

#[tauri::command]
pub fn delete_provider_api_key(
    state: State<AppState>,
    provider_id: String,
) -> CmdResult<ApiKeyStatus> {
    let provider_id = provider_id.trim().to_string();
    let secret_id = provider_api_key_id(&provider_id).map_err(|error| error.to_string())?;
    state
        .secrets
        .delete(&secret_id)
        .map_err(|error| error.to_string())?;
    Ok(ApiKeyStatus {
        provider_id,
        has_api_key: false,
    })
}

/// 从供应商的 OpenAI 兼容 /models 端点拉取可用模型列表。
/// Key 仅由后端根据 provider_id 从系统凭据库读取。
#[tauri::command]
pub async fn fetch_models(
    state: State<'_, AppState>,
    provider_id: String,
) -> CmdResult<Vec<String>> {
    let provider_id = provider_id.trim().to_string();
    let base = {
        let db = state.db.get().map_err(|error| error.to_string())?;
        stored_providers(&db)?
            .into_iter()
            .find(|provider| provider.id == provider_id)
            .map(|provider| provider.base_url)
            .ok_or("AI 供应商不存在，请先保存供应商配置")?
    };
    let secret_id = provider_api_key_id(&provider_id).map_err(|error| error.to_string())?;
    let api_key = state
        .secrets
        .get(&secret_id)
        .map_err(|error| error.to_string())?
        .ok_or("当前 AI 供应商未配置 API Key，请先保存 Key")?;
    if api_key.expose().trim().is_empty() {
        return Err("当前 AI 供应商未配置 API Key，请先保存 Key".into());
    }
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = http
        .get(format!("{base}/models"))
        .bearer_auth(api_key.expose())
        .send()
        .await
        .map_err(|error| redact_sensitive(&format!("请求失败: {error}"), &[api_key.expose()]))?;
    let status = resp.status();
    let text = Zeroizing::new(
        resp.text()
            .await
            .map_err(|error| redact_sensitive(&error.to_string(), &[api_key.expose()]))?,
    );
    if !status.is_success() {
        let snippet: String = text.chars().take(300).collect();
        return Err(redact_sensitive(
            &format!("获取模型失败 {status}: {snippet}"),
            &[api_key.expose()],
        ));
    }
    let json: serde_json::Value =
        serde_json::from_str(&text).map_err(|error| format!("响应非 JSON: {error}"))?;
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

#[cfg(test)]
mod settings_security_tests {
    use super::*;
    use crate::secrets::{MemorySecretStore, SecretStoreError};
    use std::sync::Mutex;

    #[derive(Default)]
    struct FailingDeleteStore {
        value: Mutex<Option<String>>,
    }

    impl SecretStore for FailingDeleteStore {
        fn get(&self, _secret_id: &str) -> Result<Option<SecretString>, SecretStoreError> {
            Ok(self
                .value
                .lock()
                .unwrap()
                .as_ref()
                .map(|value| SecretString::new(value.clone())))
        }

        fn set(&self, _secret_id: &str, secret: &str) -> Result<(), SecretStoreError> {
            *self.value.lock().unwrap() = Some(secret.to_string());
            Ok(())
        }

        fn delete(&self, _secret_id: &str) -> Result<(), SecretStoreError> {
            Err(SecretStoreError::OperationFailed)
        }
    }

    fn settings_connection() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
             INSERT INTO settings(key, value) VALUES
             ('ai_current', 'provider_01'),
             ('ai_providers',
              '[{\"id\":\"provider_01\",\"name\":\"Demo\",\"base_url\":\"https://example.test/v1\",\"model\":\"demo\",\"note\":\"\",\"supports_json_schema\":true}]');",
        )
        .unwrap();
        conn
    }

    #[test]
    fn provider_settings_reject_plaintext_keys_and_strip_status_fields() {
        let plaintext = r#"[{"id":"p1","name":"Demo","base_url":"https://example.test","api_key":"must-not-store","model":"m","note":"","supports_json_schema":false}]"#;
        let error = normalize_provider_write(plaintext).unwrap_err();
        assert!(error.contains("SENSITIVE_SETTING"));
        assert!(!error.contains("must-not-store"));

        let with_status = r#"[{"id":"p1","name":"Demo","base_url":"https://example.test","model":"m","note":"","supports_json_schema":false,"has_api_key":true}]"#;
        // get_all_settings 的布尔状态不是秘密，但通用写接口要求前端显式只写元数据。
        assert!(normalize_provider_write(with_status).is_err());

        let metadata = r#"[{"id":"p1","name":"Demo","base_url":"https://example.test","model":"m","note":"","supports_json_schema":false}]"#;
        let (normalized, providers) = normalize_provider_write(metadata).unwrap();
        assert_eq!(providers.len(), 1);
        assert!(!normalized.contains("api_key"));
        assert!(!normalized.contains("has_api_key"));
    }

    #[test]
    fn provider_base_url_is_normalized_and_rejects_ambiguous_destinations() {
        let metadata = r#"[{"id":"p1","name":"Demo","base_url":" https://example.test/v1/ ","model":"m","note":"","supports_json_schema":false}]"#;
        let (_, providers) = normalize_provider_write(metadata).unwrap();
        assert_eq!(providers[0].base_url, "https://example.test/v1");

        for base_url in [
            "file:///tmp/model",
            "https://user:password@example.test/v1",
            "https://example.test/v1?target=other",
            "https://example.test/v1#fragment",
        ] {
            assert!(
                normalize_provider_base_url(base_url).is_err(),
                "{base_url} should be rejected"
            );
        }
    }

    #[test]
    fn provider_views_only_expose_boolean_status() {
        let conn = settings_connection();
        let store = MemorySecretStore::default();
        let secret_id = provider_api_key_id("provider_01").unwrap();
        store.set(&secret_id, "sk-never-return-this").unwrap();

        let json = provider_views(stored_providers(&conn).unwrap(), &store).unwrap();
        assert!(json.contains(r#""has_api_key":true"#));
        assert!(!json.contains("sk-never-return-this"));
        assert!(!json.contains(r#""api_key""#));

        store.delete(&secret_id).unwrap();
        let json = provider_views(stored_providers(&conn).unwrap(), &store).unwrap();
        assert!(json.contains(r#""has_api_key":false"#));
        assert!(!json.contains("sk-never-return-this"));
    }

    #[test]
    fn resolved_ai_reads_and_deletes_only_through_secret_store() {
        let conn = settings_connection();
        let store = MemorySecretStore::default();
        let secret_id = provider_api_key_id("provider_01").unwrap();
        store.set(&secret_id, "sk-backend-only").unwrap();

        let resolved = resolved_ai(&conn, &store).unwrap();
        assert_eq!(resolved.base_url, "https://example.test/v1");
        assert_eq!(resolved.model, "demo");
        assert_eq!(resolved.api_key.expose(), "sk-backend-only");
        assert!(resolved.supports_json_schema);
        drop(resolved);

        store.delete(&secret_id).unwrap();
        let error = resolved_ai(&conn, &store).unwrap_err();
        assert!(error.contains("未配置 API Key"));
        assert!(!error.contains("sk-backend-only"));
    }

    #[test]
    fn provider_metadata_write_failure_never_deletes_live_credentials() {
        let conn = settings_connection();
        let store = MemorySecretStore::default();
        let secret_id = provider_api_key_id("provider_01").unwrap();
        store.set(&secret_id, "sk-still-live").unwrap();
        conn.execute_batch(
            "CREATE TRIGGER reject_provider_update
             BEFORE UPDATE OF value ON settings
             WHEN OLD.key = 'ai_providers'
             BEGIN
               SELECT RAISE(ABORT, 'simulated write failure');
             END;",
        )
        .unwrap();

        assert!(set_provider_metadata(&conn, &store, "[]").is_err());
        assert_eq!(
            store.get(&secret_id).unwrap().unwrap().expose(),
            "sk-still-live"
        );
        assert_eq!(stored_providers(&conn).unwrap().len(), 1);
    }

    #[test]
    fn credential_delete_failure_restores_original_provider_state() {
        let conn = settings_connection();
        let store = FailingDeleteStore::default();
        let secret_id = provider_api_key_id("provider_01").unwrap();
        store.set(&secret_id, "sk-restored").unwrap();

        let error = set_provider_metadata(&conn, &store, "[]").unwrap_err();

        assert!(error.contains("已恢复原 Provider 配置和凭据"));
        assert_eq!(stored_providers(&conn).unwrap().len(), 1);
        assert_eq!(
            store.get(&secret_id).unwrap().unwrap().expose(),
            "sk-restored"
        );
    }

    #[test]
    fn prompt_versions_are_immutable_and_rollback_creates_a_new_head() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::storage::migrations::migrate(&mut conn).unwrap();
        let builtin = active_prompt(&conn).unwrap();
        assert_eq!(builtin.source, "builtin");

        let first_content = prompts::DEFAULT_ANALYZE_TEMPLATE.replace("资深", "严谨");
        let first = create_prompt_version(&conn, first_content.clone(), None, "save").unwrap();
        assert_eq!(first.version, prompts::DEFAULT_ANALYZE_PROMPT_VERSION + 1);
        let rollback =
            create_prompt_version(&conn, builtin.content.clone(), first.id, "rollback").unwrap();
        assert!(rollback.version > first.version);
        assert_eq!(active_prompt(&conn).unwrap().id, rollback.id);

        let stored_first = load_prompt_version(&conn, first.id.unwrap(), false).unwrap();
        assert_eq!(stored_first.content, first_content);
        assert_eq!(stored_first.operation, "save");
        assert_eq!(rollback.operation, "rollback");
        assert!(conn
            .execute(
                "UPDATE prompt_versions SET content = 'tampered' WHERE id = ?1",
                [first.id.unwrap()]
            )
            .is_err());
        assert!(conn
            .execute(
                "DELETE FROM prompt_versions WHERE id = ?1",
                [first.id.unwrap()]
            )
            .is_err());
    }
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
    let scope = normalize_scope_entries(&scope).map_err(|error| error.to_string())?;
    let db = state.db.get().map_err(|e| e.to_string())?;
    let scope_json = serde_json::to_string(&scope).map_err(|e| e.to_string())?;
    db.execute(
        "INSERT INTO projects(name, target_host, scope) VALUES(?1, ?2, ?3)",
        rusqlite::params![name.trim(), target_host.trim(), scope_json],
    )
    .map_err(|e| e.to_string())?;
    Ok(db.last_insert_rowid())
}

#[tauri::command]
pub fn delete_project(state: State<AppState>, id: i64) -> CmdResult<()> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    replay::service::recover_interrupted_attempts(&db)?;
    db.execute("DELETE FROM projects WHERE id = ?1", [id])
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
    db.query_row(
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
    let exists: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM projects WHERE id = ?1)",
            [id],
            |row| row.get(0),
        )
        .map_err(|e| e.to_string())?;
    if !exists {
        return Err(AuthorizationError::ProjectNotFound.to_string());
    }
    db.execute(
        "INSERT INTO settings(key, value) VALUES('current_project_id', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [id.to_string()],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// 更新项目 Scope（拦截白名单）
#[tauri::command]
pub fn update_project_scope(state: State<AppState>, id: i64, scope: Vec<String>) -> CmdResult<()> {
    let scope = normalize_scope_entries(&scope).map_err(|error| error.to_string())?;
    let db = state.db.get().map_err(|e| e.to_string())?;
    let scope_json = serde_json::to_string(&scope).map_err(|e| e.to_string())?;
    let changed = db
        .execute(
            "UPDATE projects SET scope = ?1 WHERE id = ?2",
            rusqlite::params![scope_json, id],
        )
        .map_err(|e| e.to_string())?;
    if changed == 0 {
        return Err(AuthorizationError::ProjectNotFound.to_string());
    }
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
    state.proxy.start(app, state.db.clone(), dir, port).await
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
    let dest_dir = app.path().download_dir().unwrap_or_else(|_| dir.clone());
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
    if url
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || c == '"')
    {
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
    let tags_json: String = row.get(20)?;
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
        req_wire_size: row.get(10)?,
        resp_wire_size: row.get(11)?,
        req_captured_size: row.get(12)?,
        resp_captured_size: row.get(13)?,
        req_truncated: row.get(14)?,
        resp_truncated: row.get(15)?,
        req_decode_status: row.get(16)?,
        resp_decode_status: row.get(17)?,
        duration_ms: row.get(18)?,
        created_at: row.get(19)?,
        rule_tags: serde_json::from_str(&tags_json).unwrap_or_default(),
    })
}

const SUMMARY_COLS: &str =
    "id, project_id, method, scheme, host, port, path, url, status, content_type,
     req_wire_size, resp_wire_size, req_captured_size, resp_captured_size,
     req_truncated, resp_truncated, req_decode_status, resp_decode_status,
     duration_ms, created_at, rule_tags";

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

/// Body representation follows the capture classifier instead of guessing that
/// every valid UTF-8 byte sequence is text.
fn body_fields(body: Option<&[u8]>, decode_status: &str) -> (Option<String>, Option<String>) {
    use base64::Engine;
    let Some(body) = body else {
        return (None, None);
    };
    let classified_as_text = matches!(decode_status, "empty" | "identity_text" | "decoded_text");
    if classified_as_text {
        if let Ok(text) = std::str::from_utf8(body) {
            return (Some(text.to_string()), None);
        }
    }
    (
        None,
        Some(base64::engine::general_purpose::STANDARD.encode(body)),
    )
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
                    row.get::<_, String>(21)?,
                    row.get::<_, Option<Vec<u8>>>(22)?,
                    row.get::<_, Option<String>>(23)?,
                    row.get::<_, Option<Vec<u8>>>(24)?,
                ))
            },
        )
        .map_err(|e| format!("流量记录 #{id} 不存在: {e}"))?;

    let (summary, req_headers, req_body, resp_headers, resp_body) = row;
    let (req_body_text, req_body_base64) =
        body_fields(req_body.as_deref(), &summary.req_decode_status);
    let (resp_body_text, resp_body_base64) =
        body_fields(resp_body.as_deref(), &summary.resp_decode_status);
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
    db.execute("DELETE FROM traffic WHERE project_id = ?1", [project_id])
        .map_err(|e| e.to_string())?;
    Ok(())
}

// ---------- AI 分析 ----------

#[derive(Debug, serde::Serialize)]
pub struct AnalysisRunView {
    pub id: i64,
    pub project_id: i64,
    pub traffic_id: Option<i64>,
    pub provider_id: String,
    pub provider_base_url: String,
    pub model: String,
    pub prompt_id: String,
    pub prompt_version: i64,
    pub input_hash: String,
    pub policy: AiDataPolicy,
    pub manifest: crate::ai::redaction::RedactionManifest,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub total_tokens: i64,
    pub schema_applied: bool,
    pub validation: crate::ai::validation::ValidationReport,
    pub raw_output_hash: String,
    pub created_at: String,
}

/// 生成最终发送内容。此命令不读取 API Key，也不调用网络。
#[tauri::command]
pub fn preview_ai_context(
    state: State<AppState>,
    traffic_id: i64,
    policy: Option<AiDataPolicy>,
) -> CmdResult<AiContextPreview> {
    let db = state.db.get().map_err(|error| error.to_string())?;
    if read_setting(&db, "ai_enabled").as_deref() == Some("false") {
        return Err("AI 功能已在设置中全局禁用（隐私开关）".to_string());
    }
    let (provider_id, base_url, model, supports_json_schema) =
        active_ai(&db)?.ok_or("请先在设置页添加并选择一个 AI 供应商")?;
    let model = if model.trim().is_empty() {
        "deepseek-chat".to_string()
    } else {
        model
    };
    let detail = load_detail(&db, traffic_id)?;
    let template = active_prompt(&db)?;
    let policy = policy.unwrap_or(read_ai_data_policy(&db)?);
    context::build_preview(
        &detail,
        &template,
        &provider_id,
        &base_url,
        &model,
        supports_json_schema,
        policy,
    )
}

/// 对一条流量做 AI 分析。后端重新构建上下文并核对预览哈希；模型响应无论
/// 是否通过校验都会留下 analysis_runs，只有通过校验才创建 Finding。
fn delete_replaceable_ai_findings(
    conn: &rusqlite::Connection,
    traffic_id: i64,
) -> CmdResult<usize> {
    conn.execute(
        "DELETE FROM findings
         WHERE traffic_id = ?1 AND source = 'ai' AND status = 'pending'
           AND analyst_notes = ''
           AND NOT EXISTS(
               SELECT 1 FROM finding_evidence fe WHERE fe.finding_id = findings.id
           )
           AND NOT EXISTS(
               SELECT 1 FROM finding_events event
               WHERE event.finding_id = findings.id AND event.event_type <> 'created'
           )
           AND NOT EXISTS(
               SELECT 1 FROM task_findings tf WHERE tf.finding_id = findings.id
           )",
        [traffic_id],
    )
    .map_err(|error| error.to_string())
}

#[cfg(test)]
mod ai_finding_replacement_tests {
    use super::*;

    fn fixture() -> (rusqlite::Connection, i64, i64, i64) {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::storage::migrations::migrate(&mut conn).unwrap();
        conn.execute(
            "INSERT INTO projects(name, target_host) VALUES('p', 'example.test')",
            [],
        )
        .unwrap();
        let project_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO traffic(project_id, method, host, url)
             VALUES(?1, 'GET', 'example.test', 'https://example.test/')",
            [project_id],
        )
        .unwrap();
        let traffic_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO analysis_runs(
                 project_id, traffic_id, provider_id, provider_base_url, model, prompt_id,
                 prompt_version, input_hash, policy_json, manifest_json,
                 validation_status, validation_json, raw_output_hash
             ) VALUES(
                 ?1,?2,'provider','https://provider.test/v1','model','analyze',1,
                 ?3,'{}','{}','valid','{}',?4
             )",
            rusqlite::params![project_id, traffic_id, "a".repeat(64), "b".repeat(64)],
        )
        .unwrap();
        let run_id = conn.last_insert_rowid();
        (conn, project_id, traffic_id, run_id)
    }

    fn insert_ai_finding(
        conn: &rusqlite::Connection,
        project_id: i64,
        traffic_id: i64,
        run_id: i64,
        title: &str,
    ) -> i64 {
        conn.execute(
            "INSERT INTO findings(
                 project_id, traffic_id, analysis_run_id, source, title, severity
             ) VALUES(?1,?2,?3,'ai',?4,'medium')",
            rusqlite::params![project_id, traffic_id, run_id, title],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    fn finding_exists(conn: &rusqlite::Connection, finding_id: i64) -> bool {
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM findings WHERE id = ?1)",
            [finding_id],
            |row| row.get(0),
        )
        .unwrap()
    }

    #[test]
    fn reanalysis_removes_only_completely_untouched_pending_hypotheses() {
        let (mut conn, project_id, traffic_id, run_id) = fixture();
        let untouched =
            insert_ai_finding(&conn, project_id, traffic_id, run_id, "untouched pending");
        let reviewed =
            insert_ai_finding(&conn, project_id, traffic_id, run_id, "severity reviewed");
        let status_reviewed =
            insert_ai_finding(&conn, project_id, traffic_id, run_id, "status reviewed");
        let linked_to_task =
            insert_ai_finding(&conn, project_id, traffic_id, run_id, "linked to task");
        let linked_to_evidence =
            insert_ai_finding(&conn, project_id, traffic_id, run_id, "linked to evidence");

        crate::evidence::service::update_finding_review(
            &mut conn,
            reviewed,
            "high",
            "",
            Some("analyst raised severity"),
            "analyst",
        )
        .unwrap();
        crate::evidence::service::update_finding_status(
            &mut conn,
            status_reviewed,
            "rejected",
            Some("not reproducible"),
            "analyst",
        )
        .unwrap();
        crate::evidence::service::update_finding_status(
            &mut conn,
            status_reviewed,
            "pending",
            Some("reopened"),
            "analyst",
        )
        .unwrap();

        conn.execute(
            "INSERT INTO task_nodes(project_id, title) VALUES(?1, 'verify')",
            [project_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO task_findings(task_id, finding_id) VALUES(?1, ?2)",
            rusqlite::params![conn.last_insert_rowid(), linked_to_task],
        )
        .unwrap();
        crate::evidence::service::create_finding_evidence(
            &mut conn,
            linked_to_evidence,
            EvidenceSourceType::Traffic,
            traffic_id,
            "captured response",
            "analyst",
        )
        .unwrap();

        assert_eq!(
            delete_replaceable_ai_findings(&conn, traffic_id).unwrap(),
            1
        );
        assert!(!finding_exists(&conn, untouched));
        for preserved in [
            reviewed,
            status_reviewed,
            linked_to_task,
            linked_to_evidence,
        ] {
            assert!(
                finding_exists(&conn, preserved),
                "reviewed Finding #{preserved} must survive re-analysis"
            );
        }
        let status_event_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM finding_events WHERE finding_id = ?1",
                [status_reviewed],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status_event_count, 3);
    }
}

#[tauri::command]
pub async fn analyze_traffic(
    app: AppHandle,
    state: State<'_, AppState>,
    traffic_id: i64,
    policy: AiDataPolicy,
    expected_input_hash: String,
) -> CmdResult<AnalysisResult> {
    let (preview, resolved, project_id) = {
        let db = state.db.get().map_err(|e| e.to_string())?;
        if read_setting(&db, "ai_enabled").as_deref() == Some("false") {
            return Err("AI 功能已在设置中全局禁用（隐私开关）".into());
        }
        let resolved = resolved_ai(&db, state.secrets.as_ref())?;
        let template = active_prompt(&db)?;
        let detail = load_detail(&db, traffic_id)?;
        let project_id = detail.summary.project_id;
        let preview = context::build_preview(
            &detail,
            &template,
            &resolved.provider_id,
            &resolved.base_url,
            &resolved.model,
            resolved.supports_json_schema,
            policy,
        )?;
        if preview.input_hash != expected_input_hash {
            return Err(
                "AI 发送预览已过期：流量、供应商、提示词或策略发生变化，请重新预览".to_string(),
            );
        }
        (preview, resolved, project_id)
    };

    let client = OpenAiClient::new(&resolved.base_url, resolved.api_key, &resolved.model)?;
    let attempt = analyzer::analyze(&client, &preview).await?;

    let mut new_findings: Vec<Finding> = Vec::new();
    let mut result = attempt.result;
    let validation_error = attempt.validation.errors.join("；");
    let policy_json = serde_json::to_string(&preview.policy).map_err(|e| e.to_string())?;
    let manifest_json = serde_json::to_string(&preview.manifest).map_err(|e| e.to_string())?;
    let validation_json = serde_json::to_string(&attempt.validation).map_err(|e| e.to_string())?;
    let run_id;
    {
        let db = state.db.get().map_err(|e| e.to_string())?;
        let tx = db.unchecked_transaction().map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO analysis_runs(
                project_id, traffic_id, provider_id, provider_base_url, model, prompt_id,
                prompt_version, input_hash, policy_json, manifest_json, prompt_tokens,
                completion_tokens, total_tokens, schema_applied, validation_status,
                validation_json, raw_output_hash
             ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
            rusqlite::params![
                project_id,
                traffic_id,
                preview.provider_id,
                preview.provider_base_url,
                preview.model,
                preview.prompt_id,
                preview.prompt_version,
                preview.input_hash,
                policy_json,
                manifest_json,
                attempt.usage.prompt_tokens.max(0),
                attempt.usage.completion_tokens.max(0),
                attempt.usage.total_tokens.max(0),
                i64::from(attempt.schema_applied),
                attempt.validation.status,
                validation_json,
                attempt.raw_output_hash,
            ],
        )
        .map_err(|e| e.to_string())?;
        run_id = tx.last_insert_rowid();

        if let Some(result) = result.as_mut() {
            result.analysis_run_id = Some(run_id);
            // A valid replacement removes only untouched pending hypotheses. Any Finding
            // with Evidence, analyst edits, status history, or task links has entered the
            // review workflow and is preserved, as are immutable analysis_runs.
            delete_replaceable_ai_findings(&tx, traffic_id)?;
            tx.execute("DELETE FROM analyses WHERE traffic_id = ?1", [traffic_id])
                .map_err(|e| e.to_string())?;
            tx.execute(
                "INSERT INTO analyses(project_id, traffic_id, analysis_run_id, purpose,
                                       suspicious_params, summary, raw_json, model)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                rusqlite::params![
                    project_id,
                    traffic_id,
                    run_id,
                    result.purpose,
                    serde_json::to_string(&result.suspicious_params).unwrap_or_default(),
                    result.summary,
                    serde_json::to_string(&result).unwrap_or_default(),
                    resolved.model,
                ],
            )
            .map_err(|e| e.to_string())?;

            for hypothesis in &result.hypotheses {
                let reasoning = format!(
                    "{}{}\n【证据引用】{}\n【Grounding】{}",
                    if hypothesis.param.trim().is_empty() {
                        String::new()
                    } else {
                        format!("【可疑参数】{}\n", hypothesis.param)
                    },
                    hypothesis.reasoning,
                    if hypothesis.evidence_refs.is_empty() {
                        "无".to_string()
                    } else {
                        hypothesis.evidence_refs.join("、")
                    },
                    hypothesis.grounding_status,
                );
                let standard_references_json =
                    knowledge::references_to_json(&hypothesis.standard_references)?;
                tx.execute(
                    "INSERT INTO findings(project_id, traffic_id, analysis_run_id, source,
                                          title, vuln_type, standard_references, severity, confidence,
                                          reasoning, verify_steps)
                     VALUES(?1,?2,?3,'ai',?4,?5,?6,?7,?8,?9,?10)",
                    rusqlite::params![
                        project_id,
                        traffic_id,
                        run_id,
                        hypothesis.vuln_type,
                        hypothesis.vuln_type,
                        standard_references_json,
                        hypothesis.severity,
                        hypothesis.confidence as i64,
                        reasoning,
                        hypothesis.verify_steps,
                    ],
                )
                .map_err(|e| e.to_string())?;
                let finding_id = tx.last_insert_rowid();
                tx.execute(
                    "INSERT INTO finding_traffic(finding_id, traffic_id) VALUES(?1,?2)",
                    rusqlite::params![finding_id, traffic_id],
                )
                .map_err(|e| e.to_string())?;
                new_findings.push(evidence::service::load_finding(&tx, finding_id)?);
            }
        }
        record_usage(&tx, &attempt.usage);
        tx.commit().map_err(|e| e.to_string())?;
    }

    let Some(result) = result else {
        return Err(format!(
            "AI 输出未通过后端结构化校验，未创建 Finding。审计运行 #{run_id}：{validation_error}"
        ));
    };
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

#[tauri::command]
pub fn get_analysis_run(state: State<AppState>, run_id: i64) -> CmdResult<AnalysisRunView> {
    let db = state.db.get().map_err(|error| error.to_string())?;
    let row = db
        .query_row(
            "SELECT id, project_id, traffic_id, provider_id, provider_base_url, model,
                    prompt_id, prompt_version, input_hash, policy_json, manifest_json,
                    prompt_tokens, completion_tokens, total_tokens, schema_applied,
                    validation_json, raw_output_hash, created_at
             FROM analysis_runs WHERE id = ?1",
            [run_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, i64>(13)?,
                    row.get::<_, bool>(14)?,
                    row.get::<_, String>(15)?,
                    row.get::<_, String>(16)?,
                    row.get::<_, String>(17)?,
                ))
            },
        )
        .map_err(|error| format!("分析运行 #{run_id} 不存在: {error}"))?;
    Ok(AnalysisRunView {
        id: row.0,
        project_id: row.1,
        traffic_id: row.2,
        provider_id: row.3,
        provider_base_url: row.4,
        model: row.5,
        prompt_id: row.6,
        prompt_version: row.7,
        input_hash: row.8,
        policy: serde_json::from_str(&row.9)
            .map_err(|error| format!("分析运行策略损坏: {error}"))?,
        manifest: serde_json::from_str(&row.10)
            .map_err(|error| format!("分析运行 manifest 损坏: {error}"))?,
        prompt_tokens: row.11,
        completion_tokens: row.12,
        total_tokens: row.13,
        schema_applied: row.14,
        validation: serde_json::from_str(&row.15)
            .map_err(|error| format!("分析运行校验记录损坏: {error}"))?,
        raw_output_hash: row.16,
        created_at: row.17,
    })
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
        .prepare(&format!(
            "SELECT {} FROM findings
             WHERE project_id = ?1
               AND (?2 IS NULL OR status = ?2)
               AND (?3 IS NULL OR severity = ?3)
               AND (?4 IS NULL OR source = ?4)
             ORDER BY id DESC LIMIT 500",
            Finding::COLUMNS
        ))
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(
            rusqlite::params![
                project_id,
                status.filter(|s| !s.is_empty()),
                severity.filter(|s| !s.is_empty()),
                source.filter(|s| !s.is_empty()),
            ],
            Finding::from_row,
        )
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

/// 同一指纹命中过的全部流量。重复命中不会新建 Finding，只在这里累积。
#[tauri::command]
pub fn list_finding_traffic(state: State<AppState>, id: i64) -> CmdResult<Vec<FindingTrafficRef>> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    let mut stmt = db
        .prepare(
            "SELECT t.id, t.method, t.url, t.status, ft.first_seen_at
             FROM finding_traffic ft JOIN traffic t ON t.id = ft.traffic_id
             WHERE ft.finding_id = ?1
             ORDER BY t.id DESC LIMIT 200",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([id], |row| {
            Ok(FindingTrafficRef {
                traffic_id: row.get(0)?,
                method: row.get(1)?,
                url: row.get(2)?,
                status: row.get(3)?,
                first_seen_at: row.get(4)?,
            })
        })
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

/// 同一 Finding 的逐次规则命中快照，包括补丁版本和当时的脱敏证据。
#[tauri::command]
pub fn list_finding_rule_hits(state: State<AppState>, id: i64) -> CmdResult<Vec<FindingRuleHit>> {
    let db = state.db.get().map_err(|error| error.to_string())?;
    let mut stmt = db
        .prepare(
            "SELECT id, finding_id, evaluation_id, traffic_id, pack_id, pack_version,
                    rule_id, rule_version, field_path, evidence, confidence,
                    incomplete_evidence, hit_fingerprint, created_at
             FROM finding_rule_hits
             WHERE finding_id = ?1
             ORDER BY id DESC
             LIMIT 200",
        )
        .map_err(|error| error.to_string())?;
    let rows = stmt
        .query_map([id], |row| {
            Ok(FindingRuleHit {
                id: row.get(0)?,
                finding_id: row.get(1)?,
                evaluation_id: row.get(2)?,
                traffic_id: row.get(3)?,
                pack_id: row.get(4)?,
                pack_version: row.get(5)?,
                rule_id: row.get(6)?,
                rule_version: row.get(7)?,
                field_path: row.get(8)?,
                evidence: row.get(9)?,
                confidence: row.get(10)?,
                incomplete_evidence: row.get(11)?,
                hit_fingerprint: row.get(12)?,
                created_at: row.get(13)?,
            })
        })
        .map_err(|error| error.to_string())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn list_finding_evidence(state: State<AppState>, id: i64) -> CmdResult<Vec<Evidence>> {
    let db = state.db.get().map_err(|error| error.to_string())?;
    evidence::service::list_finding_evidence(&db, id)
}

#[tauri::command]
pub fn list_finding_events(state: State<AppState>, id: i64) -> CmdResult<Vec<FindingEvent>> {
    let db = state.db.get().map_err(|error| error.to_string())?;
    evidence::service::list_finding_events(&db, id)
}

#[tauri::command]
pub fn create_finding_evidence(
    app: AppHandle,
    state: State<AppState>,
    finding_id: i64,
    source_type: String,
    source_id: i64,
    observation: String,
) -> CmdResult<Evidence> {
    let source_type = EvidenceSourceType::parse(&source_type)?;
    let mut db = state.db.get().map_err(|error| error.to_string())?;
    let item = evidence::service::create_finding_evidence(
        &mut db,
        finding_id,
        source_type,
        source_id,
        &observation,
        "analyst:local",
    )?;
    let finding = evidence::service::load_finding(&db, finding_id)?;
    let _ = app.emit("finding:updated", &finding);
    Ok(item)
}

#[tauri::command]
pub fn create_task_evidence(
    state: State<AppState>,
    task_id: i64,
    source_type: String,
    source_id: i64,
    observation: String,
) -> CmdResult<i64> {
    let source_type = EvidenceSourceType::parse(&source_type)?;
    let mut db = state.db.get().map_err(|error| error.to_string())?;
    evidence::service::create_task_evidence(
        &mut db,
        task_id,
        source_type,
        source_id,
        &observation,
        "analyst:local",
    )
}

#[tauri::command]
pub fn set_finding_evidence_accepted(
    app: AppHandle,
    state: State<AppState>,
    finding_id: i64,
    evidence_id: i64,
    accepted: bool,
    reason: String,
) -> CmdResult<Evidence> {
    let mut db = state.db.get().map_err(|error| error.to_string())?;
    let item = evidence::service::set_finding_evidence_accepted(
        &mut db,
        finding_id,
        evidence_id,
        accepted,
        &reason,
        "analyst:local",
    )?;
    let finding = evidence::service::load_finding(&db, finding_id)?;
    let _ = app.emit("finding:updated", &finding);
    Ok(item)
}

/// 规则运行状况：坏包禁用原因、求值超时次数、队列丢弃数。
#[tauri::command]
pub fn get_rule_diagnostics(
    state: State<AppState>,
    project_id: i64,
) -> CmdResult<crate::rules::worker::RuleDiagnostics> {
    let db = state.db.get().map_err(|error| error.to_string())?;
    let exists: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM projects WHERE id = ?1)",
            [project_id],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if !exists {
        return Err(format!("项目 #{project_id} 不存在"));
    }
    let mut diagnostics = crate::rules::worker::diagnostics();
    diagnostics.recent_evaluations = crate::rules::worker::recent_evaluations(&db, project_id, 20)?;
    Ok(diagnostics)
}

/// 人工状态流转。confirmed 必须有人工接受的 Evidence，rejected 必须给出原因；
/// Finding 更新与不可变事件在同一事务中提交。
#[tauri::command]
pub fn update_finding_status(
    app: AppHandle,
    state: State<AppState>,
    id: i64,
    status: String,
    reason: Option<String>,
) -> CmdResult<Finding> {
    let mut db = state.db.get().map_err(|error| error.to_string())?;
    let finding = evidence::service::update_finding_status(
        &mut db,
        id,
        &status,
        reason.as_deref(),
        "analyst:local",
    )?;
    let _ = app.emit("finding:updated", &finding);
    Ok(finding)
}

#[tauri::command]
pub fn update_finding_review(
    app: AppHandle,
    state: State<AppState>,
    id: i64,
    severity: String,
    analyst_notes: String,
    reason: Option<String>,
) -> CmdResult<Finding> {
    let mut db = state.db.get().map_err(|error| error.to_string())?;
    let finding = evidence::service::update_finding_review(
        &mut db,
        id,
        &severity,
        &analyst_notes,
        reason.as_deref(),
        "analyst:local",
    )?;
    let _ = app.emit("finding:updated", &finding);
    Ok(finding)
}

#[tauri::command]
pub fn delete_finding(state: State<AppState>, id: i64) -> CmdResult<()> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    db.execute("DELETE FROM findings WHERE id = ?1", [id])
        .map_err(|e| e.to_string())?;
    Ok(())
}

// ---------- 提示词模板 ----------

#[tauri::command]
pub fn get_prompt_template(state: State<AppState>) -> CmdResult<prompts::PromptTemplateView> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    active_prompt(&db)
}

#[tauri::command]
pub fn list_prompt_versions(state: State<AppState>) -> CmdResult<Vec<prompts::PromptTemplateView>> {
    let db = state.db.get().map_err(|error| error.to_string())?;
    let active_id = read_setting(&db, prompts::ACTIVE_ANALYZE_PROMPT_SETTING)
        .map(|value| {
            value
                .parse::<i64>()
                .map_err(|_| "活动提示词版本 id 损坏".to_string())
        })
        .transpose()?;
    let mut output = vec![prompts::PromptTemplateView::builtin(active_id.is_none())];
    let mut statement = db
        .prepare("SELECT id FROM prompt_versions WHERE prompt_id = ?1 ORDER BY version DESC")
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([prompts::ANALYZE_PROMPT_ID], |row| row.get::<_, i64>(0))
        .map_err(|error| error.to_string())?;
    for row in rows {
        let id = row.map_err(|error| error.to_string())?;
        output.push(load_prompt_version(&db, id, active_id == Some(id))?);
    }
    Ok(output)
}

#[tauri::command]
pub fn set_prompt_template(
    state: State<AppState>,
    content: String,
) -> CmdResult<prompts::PromptTemplateView> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    let based_on_id = active_prompt(&db)?.id;
    create_prompt_version(&db, content, based_on_id, "save")
}

#[tauri::command]
pub fn copy_prompt_template(
    state: State<AppState>,
    source_id: Option<i64>,
) -> CmdResult<prompts::PromptTemplateView> {
    let db = state.db.get().map_err(|error| error.to_string())?;
    let source = match source_id {
        Some(id) => load_prompt_version(&db, id, false)?,
        None => prompts::PromptTemplateView::builtin(false),
    };
    create_prompt_version(&db, source.content, source.id, "copy")
}

#[tauri::command]
pub fn rollback_prompt_template(
    state: State<AppState>,
    source_id: Option<i64>,
) -> CmdResult<prompts::PromptTemplateView> {
    let db = state.db.get().map_err(|error| error.to_string())?;
    let source = match source_id {
        Some(id) => load_prompt_version(&db, id, false)?,
        None => prompts::PromptTemplateView::builtin(false),
    };
    create_prompt_version(&db, source.content, source.id, "rollback")
}

/// 恢复内置默认模板
#[tauri::command]
pub fn reset_prompt_template(state: State<AppState>) -> CmdResult<prompts::PromptTemplateView> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    db.execute(
        "DELETE FROM settings WHERE key = ?1",
        [prompts::ACTIVE_ANALYZE_PROMPT_SETTING],
    )
    .map_err(|e| e.to_string())?;
    Ok(prompts::PromptTemplateView::builtin(true))
}

// ---------- 版本化测试计划 ----------

#[tauri::command]
pub fn get_task_tree(state: State<AppState>, project_id: i64) -> CmdResult<Vec<TaskNode>> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    tree_service::load_nodes(&db, project_id, false)
}

#[tauri::command]
pub fn get_test_plan(state: State<AppState>, project_id: i64) -> CmdResult<TestPlan> {
    let db = state.db.get().map_err(|error| error.to_string())?;
    tree_service::get_plan(&db, project_id)
}

#[tauri::command]
pub fn list_task_plan_events(
    state: State<AppState>,
    project_id: i64,
) -> CmdResult<Vec<TaskPlanEvent>> {
    let db = state.db.get().map_err(|error| error.to_string())?;
    tree_service::list_events(&db, project_id)
}

const MAX_TASK_AI_INPUT_BYTES: usize = 32 * 1024;
const MAX_TASK_AI_FIELD_BYTES: usize = 4 * 1024;
const MAX_TASK_AI_DIGEST_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TaskAiOperation {
    Generate,
    Expand,
    Alternative,
}

impl TaskAiOperation {
    fn parse(value: &str) -> CmdResult<Self> {
        match value {
            "generate" => Ok(Self::Generate),
            "expand" => Ok(Self::Expand),
            "alternative" => Ok(Self::Alternative),
            _ => Err("不支持的任务规划 AI 操作".to_string()),
        }
    }

    fn prompt_id(self) -> &'static str {
        match self {
            Self::Generate => planner::PLAN_PROMPT_ID,
            Self::Expand => planner::EXPAND_PROMPT_ID,
            Self::Alternative => planner::ALTERNATIVE_PROMPT_ID,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Generate => "generate",
            Self::Expand => "expand",
            Self::Alternative => "alternative",
        }
    }
}

struct PreparedTaskAi {
    preview: AiContextPreview,
    project_id: i64,
    node_id: Option<i64>,
    base_revision: i64,
    valid_finding_ids: Vec<i64>,
}

#[derive(Debug, serde::Serialize)]
pub struct TaskAiExecution {
    pub analysis_run_id: i64,
    pub proposal: TaskPlanProposal,
}

fn truncate_task_ai_value(
    value: String,
    location: &str,
    max_bytes: usize,
    manifest: &mut RedactionManifest,
) -> String {
    if value.len() <= max_bytes {
        return value;
    }
    let marker = "\n[OMITTED:task_ai_field_limit]";
    let mut end = max_bytes.saturating_sub(marker.len()).min(value.len());
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    manifest.omit(
        location,
        format!("任务规划输入超过 {max_bytes} 字节，已在发送前截断"),
    );
    format!("{}{marker}", &value[..end])
}

fn redact_task_ai_value(value: &str, location: &str, manifest: &mut RedactionManifest) -> String {
    let redacted = redact_fallback_text(value, location, true, manifest);
    truncate_task_ai_value(redacted, location, MAX_TASK_AI_FIELD_BYTES, manifest)
}

fn redact_task_node(node: &TaskNode, manifest: &mut RedactionManifest) -> TaskNode {
    let mut safe = node.clone();
    safe.title = redact_task_ai_value(&node.title, "planner.task.title", manifest);
    safe.description =
        redact_task_ai_value(&node.description, "planner.task.description", manifest);
    safe.why = redact_task_ai_value(&node.why, "planner.task.why", manifest);
    safe.how_to = redact_task_ai_value(&node.how_to, "planner.task.how_to", manifest);
    safe.verify_criteria = redact_task_ai_value(
        &node.verify_criteria,
        "planner.task.verify_criteria",
        manifest,
    );
    safe
}

#[allow(clippy::too_many_arguments)]
fn prepare_task_ai(
    conn: &rusqlite::Connection,
    operation: TaskAiOperation,
    project_id: Option<i64>,
    node_id: Option<i64>,
    provider_id: &str,
    provider_base_url: &str,
    model: &str,
) -> CmdResult<PreparedTaskAi> {
    let mut manifest = RedactionManifest::default();
    let (project_id, node_id, prompt, valid_finding_ids) = match operation {
        TaskAiOperation::Generate => {
            let project_id = project_id.ok_or("生成测试计划需要项目 id")?;
            let target: String = conn
                .query_row(
                    "SELECT target_host FROM projects WHERE id = ?1",
                    [project_id],
                    |row| row.get(0),
                )
                .map_err(|_| "项目不存在".to_string())?;
            let target = redact_task_ai_value(&target, "planner.target", &mut manifest);
            let digest = digest::build_redacted_digest(conn, project_id, &mut manifest)?;
            let digest = truncate_task_ai_value(
                digest,
                "planner.digest",
                MAX_TASK_AI_DIGEST_BYTES,
                &mut manifest,
            );
            let valid_ids = planner::valid_finding_ids(conn, project_id)?;
            (
                project_id,
                None,
                planner::plan_prompt(&digest, &target),
                valid_ids,
            )
        }
        TaskAiOperation::Expand | TaskAiOperation::Alternative => {
            let node_id = node_id.ok_or("任务节点 AI 操作需要节点 id")?;
            let node = tree_service::load_node(conn, node_id)?;
            if project_id.is_some_and(|project_id| project_id != node.project_id) {
                return Err("任务节点不属于指定项目".to_string());
            }
            let digest = digest::build_redacted_digest(conn, node.project_id, &mut manifest)?;
            let digest = truncate_task_ai_value(
                digest,
                "planner.digest",
                MAX_TASK_AI_DIGEST_BYTES,
                &mut manifest,
            );
            let safe_node = redact_task_node(&node, &mut manifest);
            let prompt = match operation {
                TaskAiOperation::Expand => planner::expand_prompt(&safe_node, &digest),
                TaskAiOperation::Alternative => planner::alternative_prompt(&safe_node, &digest),
                TaskAiOperation::Generate => unreachable!(),
            };
            let valid_ids = planner::valid_finding_ids(conn, node.project_id)?;
            (node.project_id, Some(node_id), prompt, valid_ids)
        }
    };
    let base_revision = tree_service::get_plan(conn, project_id)?.revision;
    let base_revision_text = base_revision.to_string();
    let retry_user_prompt = format!("{prompt}\n\n{}", planner::RETRY_SUFFIX);
    manifest.total_input_bytes = planner::SYSTEM_PROMPT.len() + retry_user_prompt.len();
    if manifest.total_input_bytes > MAX_TASK_AI_INPUT_BYTES {
        return Err(format!(
            "任务规划上下文超过 {} 字节，请缩短节点内容或流量摘要",
            MAX_TASK_AI_INPUT_BYTES
        ));
    }
    let policy = AiDataPolicy::default();
    let policy_json = serde_json::to_string(&policy).map_err(|error| error.to_string())?;
    let prompt_version = planner::PROMPT_VERSION.to_string();
    let input_hash = context::input_hash(&[
        provider_id.as_bytes(),
        provider_base_url.as_bytes(),
        model.as_bytes(),
        operation.prompt_id().as_bytes(),
        prompt_version.as_bytes(),
        base_revision_text.as_bytes(),
        policy_json.as_bytes(),
        planner::SYSTEM_PROMPT.as_bytes(),
        prompt.as_bytes(),
        retry_user_prompt.as_bytes(),
        b"",
    ]);
    Ok(PreparedTaskAi {
        preview: AiContextPreview {
            traffic_id: 0,
            provider_id: provider_id.to_string(),
            provider_base_url: provider_base_url.to_string(),
            model: model.to_string(),
            prompt_id: operation.prompt_id().to_string(),
            prompt_version: planner::PROMPT_VERSION,
            prompt_source: "builtin".to_string(),
            system_prompt: planner::SYSTEM_PROMPT.to_string(),
            user_prompt: prompt,
            retry_user_prompt,
            response_schema: None,
            input_hash,
            policy,
            manifest,
            evidence_refs: Vec::new(),
            is_relaxed: false,
        },
        project_id,
        node_id,
        base_revision,
        valid_finding_ids,
    })
}

#[allow(clippy::too_many_arguments)]
fn create_task_ai_proposal(
    conn: &mut rusqlite::Connection,
    prepared: &PreparedTaskAi,
    operation: TaskAiOperation,
    proposed: crate::tree::model::PlannedTree,
    analysis_run_id: i64,
    provider_id: &str,
    provider_base_url: &str,
    model: &str,
) -> CmdResult<TaskPlanProposal> {
    tree_service::create_proposal_checked(
        conn,
        prepared.project_id,
        prepared.base_revision,
        operation.as_str(),
        prepared.node_id,
        proposed,
        Some(analysis_run_id),
        |transaction| {
            let current = prepare_task_ai(
                transaction,
                operation,
                Some(prepared.project_id),
                prepared.node_id,
                provider_id,
                provider_base_url,
                model,
            )?;
            if current.base_revision != prepared.base_revision
                || current.preview.input_hash != prepared.preview.input_hash
            {
                return Err(
                    "AI 测试计划上下文已变化；本次模型运行已保留审计，但 proposal 未创建，请重新预览"
                        .to_string(),
                );
            }
            Ok(())
        },
    )
}

fn persist_task_ai_run(
    conn: &rusqlite::Connection,
    prepared: &PreparedTaskAi,
    audit: &JsonAudit,
) -> CmdResult<i64> {
    let preview = &prepared.preview;
    let policy_json = serde_json::to_string(&preview.policy).map_err(|error| error.to_string())?;
    let manifest_json =
        serde_json::to_string(&preview.manifest).map_err(|error| error.to_string())?;
    let validation_json =
        serde_json::to_string(&audit.validation).map_err(|error| error.to_string())?;
    conn.execute(
        "INSERT INTO analysis_runs(
            project_id, traffic_id, provider_id, provider_base_url, model, prompt_id,
            prompt_version, input_hash, policy_json, manifest_json, prompt_tokens,
            completion_tokens, total_tokens, schema_applied, validation_status,
            validation_json, raw_output_hash
         ) VALUES(?1,NULL,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,0,?13,?14,?15)",
        rusqlite::params![
            prepared.project_id,
            preview.provider_id,
            preview.provider_base_url,
            preview.model,
            preview.prompt_id,
            preview.prompt_version,
            preview.input_hash,
            policy_json,
            manifest_json,
            audit.usage.prompt_tokens.max(0),
            audit.usage.completion_tokens.max(0),
            audit.usage.total_tokens.max(0),
            audit.validation.status,
            validation_json,
            audit.raw_output_hash,
        ],
    )
    .map_err(|error| error.to_string())?;
    let run_id = conn.last_insert_rowid();
    record_usage(conn, &audit.usage);
    Ok(run_id)
}

fn task_ai_validation_error(run_id: i64, validation: &ValidationReport) -> String {
    format!(
        "AI 输出两次都未通过测试计划 JSON 校验，未创建 proposal。审计运行 #{run_id}：{}",
        validation.errors.join("；")
    )
}

/// 生成任务规划调用的最终发送内容，不读取 API Key，也不调用网络。
#[tauri::command]
pub fn preview_task_ai(
    state: State<AppState>,
    operation: String,
    project_id: Option<i64>,
    node_id: Option<i64>,
) -> CmdResult<AiContextPreview> {
    let db = state.db.get().map_err(|error| error.to_string())?;
    if read_setting(&db, "ai_enabled").as_deref() == Some("false") {
        return Err("AI 功能已在设置中全局禁用（隐私开关）".to_string());
    }
    let (provider_id, provider_base_url, model, _) =
        active_ai(&db)?.ok_or("请先在设置页添加并选择一个 AI 供应商")?;
    let model = if model.trim().is_empty() {
        "deepseek-chat".to_string()
    } else {
        model
    };
    Ok(prepare_task_ai(
        &db,
        TaskAiOperation::parse(&operation)?,
        project_id,
        node_id,
        &provider_id,
        &provider_base_url,
        &model,
    )?
    .preview)
}

/// AI 生成测试计划 proposal。该命令只持久化 proposal 与 diff，不直接修改节点。
#[tauri::command]
pub async fn generate_task_tree(
    state: State<'_, AppState>,
    project_id: i64,
    expected_input_hash: String,
) -> CmdResult<TaskAiExecution> {
    let (prepared, resolved) = {
        let db = state.db.get().map_err(|error| error.to_string())?;
        let resolved = resolved_ai(&db, state.secrets.as_ref())?;
        let prepared = prepare_task_ai(
            &db,
            TaskAiOperation::Generate,
            Some(project_id),
            None,
            &resolved.provider_id,
            &resolved.base_url,
            &resolved.model,
        )?;
        if prepared.preview.input_hash != expected_input_hash {
            return Err("AI 发送预览已过期，请重新预览任务规划内容".to_string());
        }
        (prepared, resolved)
    };
    let provider_id = resolved.provider_id.clone();
    let provider_base_url = resolved.base_url.clone();
    let model = resolved.model.clone();
    let client = OpenAiClient::new(&resolved.base_url, resolved.api_key, &resolved.model)?;
    let valid_ids = prepared.valid_finding_ids.clone();
    let attempt = chat_json(
        &client,
        &prepared.preview.system_prompt,
        &prepared.preview.user_prompt,
        |raw| planner::parse_plan(raw, &valid_ids),
    )
    .await?;

    let mut db = state.db.get().map_err(|error| error.to_string())?;
    let run_id = persist_task_ai_run(&db, &prepared, &attempt.audit)?;
    let Some(tree) = attempt.result else {
        return Err(task_ai_validation_error(run_id, &attempt.audit.validation));
    };
    let proposal = create_task_ai_proposal(
        &mut db,
        &prepared,
        TaskAiOperation::Generate,
        tree,
        run_id,
        &provider_id,
        &provider_base_url,
        &model,
    )?;
    Ok(TaskAiExecution {
        analysis_run_id: run_id,
        proposal,
    })
}

/// AI 展开节点也先形成完整计划 proposal，等待用户查看 diff 后确认。
#[tauri::command]
pub async fn expand_task_node(
    state: State<'_, AppState>,
    node_id: i64,
    expected_input_hash: String,
) -> CmdResult<TaskAiExecution> {
    let (prepared, resolved) = {
        let db = state.db.get().map_err(|error| error.to_string())?;
        let resolved = resolved_ai(&db, state.secrets.as_ref())?;
        let prepared = prepare_task_ai(
            &db,
            TaskAiOperation::Expand,
            None,
            Some(node_id),
            &resolved.provider_id,
            &resolved.base_url,
            &resolved.model,
        )?;
        if prepared.preview.input_hash != expected_input_hash {
            return Err("AI 发送预览已过期，请重新预览任务规划内容".to_string());
        }
        (prepared, resolved)
    };
    let provider_id = resolved.provider_id.clone();
    let provider_base_url = resolved.base_url.clone();
    let model = resolved.model.clone();
    let client = OpenAiClient::new(&resolved.base_url, resolved.api_key, &resolved.model)?;
    let valid_ids = prepared.valid_finding_ids.clone();
    let attempt = chat_json(
        &client,
        &prepared.preview.system_prompt,
        &prepared.preview.user_prompt,
        |raw| planner::parse_expand(raw, &valid_ids),
    )
    .await?;

    let mut db = state.db.get().map_err(|error| error.to_string())?;
    let run_id = persist_task_ai_run(&db, &prepared, &attempt.audit)?;
    let Some(children) = attempt.result else {
        return Err(task_ai_validation_error(run_id, &attempt.audit.validation));
    };
    let target_id = prepared.node_id.unwrap_or(node_id);
    let proposed = tree_service::plan_with_expansion(&db, target_id, children)?;
    let proposal = create_task_ai_proposal(
        &mut db,
        &prepared,
        TaskAiOperation::Expand,
        proposed,
        run_id,
        &provider_id,
        &provider_base_url,
        &model,
    )?;
    Ok(TaskAiExecution {
        analysis_run_id: run_id,
        proposal,
    })
}

/// AI “换个思路”只提出字段差异；人工进度、锁定字段与 Evidence 仍由合并层保护。
#[tauri::command]
pub async fn alternative_task_node(
    state: State<'_, AppState>,
    node_id: i64,
    expected_input_hash: String,
) -> CmdResult<TaskAiExecution> {
    let (prepared, resolved) = {
        let db = state.db.get().map_err(|error| error.to_string())?;
        let resolved = resolved_ai(&db, state.secrets.as_ref())?;
        let prepared = prepare_task_ai(
            &db,
            TaskAiOperation::Alternative,
            None,
            Some(node_id),
            &resolved.provider_id,
            &resolved.base_url,
            &resolved.model,
        )?;
        if prepared.preview.input_hash != expected_input_hash {
            return Err("AI 发送预览已过期，请重新预览任务规划内容".to_string());
        }
        (prepared, resolved)
    };
    let provider_id = resolved.provider_id.clone();
    let provider_base_url = resolved.base_url.clone();
    let model = resolved.model.clone();
    let client = OpenAiClient::new(&resolved.base_url, resolved.api_key, &resolved.model)?;
    let attempt = chat_json(
        &client,
        &prepared.preview.system_prompt,
        &prepared.preview.user_prompt,
        planner::parse_alternative,
    )
    .await?;

    let mut db = state.db.get().map_err(|error| error.to_string())?;
    let run_id = persist_task_ai_run(&db, &prepared, &attempt.audit)?;
    let Some(alternative) = attempt.result else {
        return Err(task_ai_validation_error(run_id, &attempt.audit.validation));
    };
    let target_id = prepared.node_id.unwrap_or(node_id);
    let proposed = tree_service::plan_with_alternative(&db, target_id, &alternative)?;
    let proposal = create_task_ai_proposal(
        &mut db,
        &prepared,
        TaskAiOperation::Alternative,
        proposed,
        run_id,
        &provider_id,
        &provider_base_url,
        &model,
    )?;
    Ok(TaskAiExecution {
        analysis_run_id: run_id,
        proposal,
    })
}

#[cfg(test)]
mod task_ai_firewall_tests {
    use super::*;

    fn task_connection() -> rusqlite::Connection {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::storage::migrations::migrate(&mut conn).unwrap();
        conn.execute(
            "INSERT INTO projects(name, target_host) VALUES('p', 'example.test')",
            [],
        )
        .unwrap();
        let project_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO traffic(project_id, method, host, path, url)
             VALUES(?1, 'GET', 'example.test',
                    '/reset?token=must-not-leave-local',
                    'https://example.test/reset?token=must-not-leave-local')",
            [project_id],
        )
        .unwrap();
        conn
    }

    #[test]
    fn planner_preview_redacts_queries_binds_input_and_persists_a_run() {
        let mut conn = task_connection();
        let project_id: i64 = conn
            .query_row("SELECT id FROM projects LIMIT 1", [], |row| row.get(0))
            .unwrap();
        let prepared = prepare_task_ai(
            &conn,
            TaskAiOperation::Generate,
            Some(project_id),
            None,
            "provider",
            "https://provider.test/v1",
            "model",
        )
        .unwrap();

        assert!(!prepared
            .preview
            .user_prompt
            .contains("must-not-leave-local"));
        assert!(prepared.preview.user_prompt.contains("REDACTED"));
        assert!(prepared.preview.user_prompt.contains("UNTRUSTED_HTTP_DATA"));
        assert_eq!(prepared.preview.input_hash.len(), 64);

        let audit = JsonAudit {
            usage: crate::ai::client::Usage {
                prompt_tokens: 2,
                completion_tokens: 3,
                total_tokens: 5,
            },
            validation: valid_json_report(1, Vec::new()),
            raw_output_hash: "a".repeat(64),
        };
        let run_id = persist_task_ai_run(&conn, &prepared, &audit).unwrap();
        let stored: (Option<i64>, String, String) = conn
            .query_row(
                "SELECT traffic_id, prompt_id, input_hash
                 FROM analysis_runs WHERE id = ?1",
                [run_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(stored.0, None);
        assert_eq!(stored.1, planner::PLAN_PROMPT_ID);
        assert_eq!(stored.2, prepared.preview.input_hash);

        conn.execute(
            "UPDATE traffic SET path = '/changed?password=new-secret' WHERE project_id = ?1",
            [project_id],
        )
        .unwrap();
        let changed = prepare_task_ai(
            &conn,
            TaskAiOperation::Generate,
            Some(project_id),
            None,
            "provider",
            "https://provider.test/v1",
            "model",
        )
        .unwrap();
        assert_ne!(changed.preview.input_hash, prepared.preview.input_hash);
        assert!(!changed.preview.user_prompt.contains("new-secret"));

        let error = create_task_ai_proposal(
            &mut conn,
            &prepared,
            TaskAiOperation::Generate,
            crate::tree::model::PlannedTree { phases: vec![] },
            run_id,
            "provider",
            "https://provider.test/v1",
            "model",
        )
        .unwrap_err();
        assert!(error.contains("上下文已变化"));
        let proposal_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM task_plan_proposals", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(proposal_count, 0);
    }
}

#[tauri::command]
pub fn apply_task_plan_proposal(
    state: State<AppState>,
    project_id: i64,
    proposal_id: i64,
) -> CmdResult<TaskPlanApplyResult> {
    let mut db = state.db.get().map_err(|error| error.to_string())?;
    tree_service::apply_proposal(&mut db, project_id, proposal_id, "analyst")
}

#[tauri::command]
pub fn reject_task_plan_proposal(state: State<AppState>, proposal_id: i64) -> CmdResult<()> {
    let db = state.db.get().map_err(|error| error.to_string())?;
    tree_service::reject_proposal(&db, proposal_id)
}

/// “下一步”使用显式 prerequisite 与稳定风险/优先级排序。
#[tauri::command]
pub fn next_task(state: State<AppState>, project_id: i64) -> CmdResult<Option<TaskNode>> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    let nodes = tree_service::load_nodes(&db, project_id, false)?;
    let id = tree_state::next_actionable(&nodes);
    Ok(id.and_then(|nid| nodes.into_iter().find(|n| n.id == nid)))
}

/// 手工状态永远通过专用事务写入，并记录原因与不可变事件。
#[tauri::command]
pub fn update_task_status(
    state: State<AppState>,
    node_id: i64,
    status: String,
    reason: Option<String>,
) -> CmdResult<TaskNode> {
    let mut db = state.db.get().map_err(|error| error.to_string())?;
    tree_service::update_status(&mut db, node_id, &status, reason.as_deref(), "analyst")
}

/// 人工创建的字段默认全部锁定，后续 proposal 只会把它列为 preserved。
#[tauri::command]
pub fn create_task_node(state: State<AppState>, input: CreateTaskNodeInput) -> CmdResult<i64> {
    let mut db = state.db.get().map_err(|error| error.to_string())?;
    tree_service::create_manual_node(&mut db, &input, "analyst")
}

#[tauri::command]
pub fn update_task_node(state: State<AppState>, input: UpdateTaskNodeInput) -> CmdResult<TaskNode> {
    let mut db = state.db.get().map_err(|error| error.to_string())?;
    tree_service::update_manual_fields(&mut db, &input, "analyst")
}

/// 保留旧 IPC 名称，但语义已改为可审计归档，不再物理删除节点或 Evidence 关系。
#[tauri::command]
pub fn delete_task_node(state: State<AppState>, node_id: i64) -> CmdResult<()> {
    let mut db = state.db.get().map_err(|error| error.to_string())?;
    tree_service::archive_node(&mut db, node_id, "analyst")
}

/// 节点关联的 Finding 列表
#[tauri::command]
pub fn get_task_findings(state: State<AppState>, node_id: i64) -> CmdResult<Vec<Finding>> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    let mut stmt = db
        .prepare(&format!(
            "SELECT {} FROM findings f JOIN task_findings tf ON tf.finding_id = f.id
             WHERE tf.task_id = ?1 ORDER BY f.id",
            Finding::COLUMNS
        ))
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([node_id], Finding::from_row)
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

// ---------- 版本化安全标准知识卡 ----------

/// 逐条解析：命中的返回知识卡，未收录/非法的返回明确状态，不因为其中一条
/// 无法解析就让整块知识区变成报错。
#[tauri::command]
pub fn get_knowledge_cards(
    references: Vec<StandardReference>,
) -> CmdResult<knowledge::KnowledgeLookup> {
    knowledge::resolve(&references)
}

// ---------- Repeater（手动改包重发） ----------

/// Repeater 编辑器的无网络预检。它与真正发送请求调用完全相同的 ScopePolicy；
/// `replay_request` 仍会再次校验，不能把预检结果当作授权令牌。
#[tauri::command]
pub fn authorize_replay_target(
    state: State<AppState>,
    project_id: Option<i64>,
    url: String,
) -> CmdResult<ScopeDecision> {
    let project_id = project_id.ok_or_else(|| AuthorizationError::NoActiveProject.to_string())?;
    let db = state
        .db
        .get()
        .map_err(|error| AuthorizationError::storage(error).to_string())?;
    let policy = load_project_policy(&db, project_id).map_err(|error| error.to_string())?;
    policy
        .authorize_url(&url)
        .map(|authorized| authorized.decision)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn list_replay_sessions(
    state: State<AppState>,
    project_id: i64,
) -> CmdResult<Vec<ReplaySession>> {
    let db = state.db.get().map_err(|error| error.to_string())?;
    replay::service::list_sessions(&db, project_id)
}

#[tauri::command]
pub fn create_replay_session(
    state: State<AppState>,
    project_id: i64,
    title: String,
    source_traffic_id: Option<i64>,
    tls_policy: String,
) -> CmdResult<ReplaySession> {
    let tls_policy = TlsPolicy::parse(&tls_policy)?;
    let mut db = state.db.get().map_err(|error| error.to_string())?;
    replay::service::create_session(&mut db, project_id, &title, source_traffic_id, tls_policy)
}

#[tauri::command]
pub fn update_replay_session(
    state: State<AppState>,
    session_id: i64,
    title: String,
    tls_policy: String,
) -> CmdResult<ReplaySession> {
    let tls_policy = TlsPolicy::parse(&tls_policy)?;
    let db = state.db.get().map_err(|error| error.to_string())?;
    replay::service::update_session(&db, session_id, &title, tls_policy)
}

#[tauri::command]
pub fn select_replay_session(state: State<AppState>, session_id: i64) -> CmdResult<ReplaySession> {
    let mut db = state.db.get().map_err(|error| error.to_string())?;
    replay::service::select_session(&mut db, session_id)
}

#[tauri::command]
pub fn delete_replay_session(state: State<AppState>, session_id: i64) -> CmdResult<()> {
    let mut db = state.db.get().map_err(|error| error.to_string())?;
    replay::service::delete_session(&mut db, session_id)
}

#[tauri::command]
pub fn list_replay_runs(
    state: State<AppState>,
    session_id: i64,
    before_id: Option<i64>,
    limit: Option<i64>,
) -> CmdResult<ReplayRunPage> {
    let db = state.db.get().map_err(|error| error.to_string())?;
    replay::service::list_runs(&db, session_id, before_id, limit)
}

#[tauri::command]
pub fn get_replay_run(
    state: State<AppState>,
    project_id: i64,
    run_id: i64,
) -> CmdResult<ReplayRun> {
    let db = state.db.get().map_err(|error| error.to_string())?;
    replay::service::load_run_for_project(&db, project_id, run_id)
}

#[tauri::command]
pub fn compare_replay_runs(
    state: State<AppState>,
    project_id: i64,
    left_run_id: i64,
    right_run_id: i64,
) -> CmdResult<ReplayRunDiff> {
    let db = state.db.get().map_err(|error| error.to_string())?;
    replay::service::compare_runs(&db, project_id, left_run_id, right_run_id)
}

/// 手动重发一个请求。唯一主动触发点仍是用户点击；service 在任何 HTTP
/// client/socket 创建前重新执行 ScopePolicy，并把成功、失败或拒绝都追加为 run。
#[tauri::command]
pub async fn replay_request(
    state: State<'_, AppState>,
    project_id: i64,
    session_id: i64,
    request: ReplayRequestInput,
) -> CmdResult<ReplayRun> {
    replay::service::execute_request(state.db.clone(), project_id, session_id, request).await
}

// ---------- 证据化报告 ----------

/// 生成默认脱敏的 Markdown 报告文本（供前端预览）。
#[tauri::command]
pub fn build_report(state: State<AppState>, project_id: i64) -> CmdResult<String> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    report::build_markdown(&db, project_id)
}

#[derive(Debug, serde::Serialize)]
pub struct ReportExportResult {
    pub markdown_path: String,
    pub json_path: String,
    pub contains_sensitive_evidence: bool,
}

/// 同时导出主 Markdown 和机器可读 JSON 备份。
///
/// 默认只使用 Evidence 的不可变脱敏快照。原始来源内容不会成为持久设置；
/// 每次敏感导出都必须在后端弹出的原生确认框中单独确认；renderer 不持有、
/// 不签发、也不能复用任何确认令牌。
#[tauri::command]
pub async fn export_report(
    app: AppHandle,
    state: State<'_, AppState>,
    project_id: i64,
    include_sensitive_evidence: bool,
) -> CmdResult<ReportExportResult> {
    let options = if include_sensitive_evidence {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        app.dialog()
            .message(
                "本次导出会附加当前仍可读取的原始请求/响应片段，可能包含 Cookie、\
                 Authorization、API Key 或业务数据。确认仅对本次导出调用有效。",
            )
            .title("导出原始敏感 Evidence")
            .kind(MessageDialogKind::Warning)
            .buttons(MessageDialogButtons::OkCancelCustom(
                "仅本次包含原始内容".to_string(),
                "取消".to_string(),
            ))
            .show(move |confirmed| {
                let _ = sender.send(confirmed);
            });
        if !receiver
            .await
            .map_err(|_| "敏感导出确认框意外关闭".to_string())?
        {
            return Err("已取消敏感 Evidence 导出".to_string());
        }
        report::ReportOptions::confirmed_sensitive()
    } else {
        report::ReportOptions::redacted()
    };
    let bundle = {
        let db = state.db.get().map_err(|e| e.to_string())?;
        report::build_bundle(&db, project_id, options)?
    };
    let dest_dir = app
        .path()
        .download_dir()
        .unwrap_or_else(|_| std::env::temp_dir());
    let safe_project = report::safe_file_component(&bundle.project_name, project_id);
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S-%3f");
    let sensitivity_marker = if bundle.contains_sensitive_evidence {
        "-SENSITIVE"
    } else {
        ""
    };
    let basename =
        format!("RustForge-Report-{safe_project}-{project_id}{sensitivity_marker}-{stamp}");
    let (markdown_path, json_path) =
        write_report_pair(&dest_dir, &basename, &bundle.markdown, &bundle.json)?;
    Ok(ReportExportResult {
        markdown_path: markdown_path.to_string_lossy().into_owned(),
        json_path: json_path.to_string_lossy().into_owned(),
        contains_sensitive_evidence: bundle.contains_sensitive_evidence,
    })
}

fn write_report_pair(
    directory: &std::path::Path,
    basename: &str,
    markdown: &str,
    json: &str,
) -> Result<(std::path::PathBuf, std::path::PathBuf), String> {
    use std::io::Write;

    std::fs::create_dir_all(directory).map_err(|error| format!("创建报告导出目录失败: {error}"))?;
    for attempt in 0..100 {
        let suffix = if attempt == 0 {
            String::new()
        } else {
            format!("-{attempt}")
        };
        let markdown_path = directory.join(format!("{basename}{suffix}.md"));
        let json_path = directory.join(format!("{basename}{suffix}.json"));
        let mut markdown_file = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&markdown_path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("创建 Markdown 报告失败: {error}")),
        };
        let mut json_file = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&json_path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                drop(markdown_file);
                let _ = std::fs::remove_file(&markdown_path);
                continue;
            }
            Err(error) => {
                drop(markdown_file);
                let _ = std::fs::remove_file(&markdown_path);
                return Err(format!("创建 JSON 报告失败: {error}"));
            }
        };
        if let Err(error) = markdown_file
            .write_all(markdown.as_bytes())
            .and_then(|_| json_file.write_all(json.as_bytes()))
        {
            drop(markdown_file);
            drop(json_file);
            let _ = std::fs::remove_file(&markdown_path);
            let _ = std::fs::remove_file(&json_path);
            return Err(format!("写入报告失败: {error}"));
        }
        return Ok((markdown_path, json_path));
    }
    Err("报告文件名冲突次数过多，请稍后重试".to_string())
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
    db.query_row(
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
        db.query_row(
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
    db.execute(
        "DELETE FROM settings WHERE key IN
             ('usage_calls','usage_prompt_tokens','usage_completion_tokens','usage_total_tokens')",
        [],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// 趋势数据点（按日或按月聚合）
#[derive(serde::Serialize)]
pub struct UsageTrendPoint {
    pub period: String,
    pub calls: i64,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub total_tokens: i64,
}

/// 从 analysis_runs 表按日/月聚合 Token 使用趋势
#[tauri::command]
pub fn get_usage_trend(
    state: State<AppState>,
    granularity: String,
) -> CmdResult<Vec<UsageTrendPoint>> {
    let db = state.db.get().map_err(|e| e.to_string())?;
    let date_format = if granularity == "month" {
        "%Y-%m"
    } else {
        "%Y-%m-%d"
    };
    let sql = format!(
        "SELECT strftime('{}', created_at) AS period, \
                COUNT(*) AS calls, \
                COALESCE(SUM(prompt_tokens), 0) AS prompt_tokens, \
                COALESCE(SUM(completion_tokens), 0) AS completion_tokens, \
                COALESCE(SUM(total_tokens), 0) AS total_tokens \
         FROM analysis_runs \
         GROUP BY period \
         ORDER BY period ASC",
        date_format
    );
    let mut stmt = db.prepare(&sql).map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |row| {
            Ok(UsageTrendPoint {
                period: row.get(0)?,
                calls: row.get(1)?,
                prompt_tokens: row.get(2)?,
                completion_tokens: row.get(3)?,
                total_tokens: row.get(4)?,
            })
        })
        .map_err(|e| e.to_string())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())
}
