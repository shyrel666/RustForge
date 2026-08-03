//! 系统凭据库封装与秘密日志过滤。
//!
//! API Key 只允许通过本模块进入系统凭据库；SQLite、Tauri 返回值和日志都不得
//! 保存或返回完整秘密。

use regex::Regex;
use std::fmt;
use std::sync::OnceLock;
use zeroize::Zeroizing;

const CREDENTIAL_SERVICE: &str = "com.rustforge.app";
const MAX_PROVIDER_ID_LEN: usize = 96;

#[derive(Debug, thiserror::Error)]
pub enum SecretStoreError {
    #[error("供应商标识无效")]
    InvalidProviderId,
    #[error("系统凭据库不可用，请确认当前用户会话的凭据服务已解锁")]
    Unavailable,
    #[error("系统凭据库操作失败")]
    OperationFailed,
    #[error("评估身份凭据标识无效")]
    InvalidAssessmentProfileId,
}

/// 会在释放时清零底层字符串，且 Debug 永远不显示秘密。
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString([REDACTED])")
    }
}

/// 可替换的秘密后端；生产使用系统凭据库，单元测试使用内存实现。
pub trait SecretStore: Send + Sync {
    fn get(&self, secret_id: &str) -> Result<Option<SecretString>, SecretStoreError>;
    fn set(&self, secret_id: &str, secret: &str) -> Result<(), SecretStoreError>;
    fn delete(&self, secret_id: &str) -> Result<(), SecretStoreError>;
}

#[derive(Debug, Default)]
pub struct SystemSecretStore;

impl SystemSecretStore {
    pub fn new() -> Self {
        Self
    }

    fn entry(secret_id: &str) -> Result<keyring::v1::Entry, SecretStoreError> {
        keyring::v1::Entry::new(CREDENTIAL_SERVICE, secret_id).map_err(map_keyring_error)
    }
}

fn map_keyring_error(error: keyring::v1::Error) -> SecretStoreError {
    match error {
        keyring::v1::Error::NoDefaultStore | keyring::v1::Error::NoStorageAccess(_) => {
            SecretStoreError::Unavailable
        }
        _ => SecretStoreError::OperationFailed,
    }
}

impl SecretStore for SystemSecretStore {
    fn get(&self, secret_id: &str) -> Result<Option<SecretString>, SecretStoreError> {
        let entry = Self::entry(secret_id)?;
        match entry.get_password() {
            Ok(secret) => Ok(Some(SecretString::new(secret))),
            Err(keyring::v1::Error::NoEntry) => Ok(None),
            Err(error) => Err(map_keyring_error(error)),
        }
    }

    fn set(&self, secret_id: &str, secret: &str) -> Result<(), SecretStoreError> {
        Self::entry(secret_id)?
            .set_password(secret)
            .map_err(map_keyring_error)
    }

    fn delete(&self, secret_id: &str) -> Result<(), SecretStoreError> {
        let entry = Self::entry(secret_id)?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::v1::Error::NoEntry) => Ok(()),
            Err(error) => Err(map_keyring_error(error)),
        }
    }
}

/// 为供应商 API Key 生成稳定的系统凭据标识。
pub fn provider_api_key_id(provider_id: &str) -> Result<String, SecretStoreError> {
    let provider_id = provider_id.trim();
    if provider_id.is_empty()
        || provider_id.len() > MAX_PROVIDER_ID_LEN
        || !provider_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(SecretStoreError::InvalidProviderId);
    }
    Ok(format!("provider.{provider_id}.api-key"))
}

/// Assessment 身份凭据的稳定系统凭据标识。项目 ID 同时进入标识，避免错误的
/// 跨项目 profile 引用落到同一条系统凭据。
pub fn assessment_auth_profile_secret_id(
    project_id: i64,
    profile_id: i64,
) -> Result<String, SecretStoreError> {
    if project_id <= 0 || profile_id <= 0 {
        return Err(SecretStoreError::InvalidAssessmentProfileId);
    }
    Ok(format!(
        "assessment.project.{project_id}.auth-profile.{profile_id}.header"
    ))
}

/// 通用设置 API 必须拒绝这些键，避免绕过专用秘密命令。
pub fn is_sensitive_setting_key(key: &str) -> bool {
    let normalized: String = key
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    normalized == "authorization"
        || normalized == "proxyauthorization"
        || normalized.ends_with("apikey")
        || normalized.ends_with("password")
        || normalized.ends_with("credential")
        || normalized.ends_with("secret")
        || normalized.ends_with("token")
        || normalized == "cookie"
        || normalized == "setcookie"
}

fn value_contains_sensitive_field(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(map) => map.iter().any(|(key, value)| {
            is_sensitive_setting_key(key) || value_contains_sensitive_field(value)
        }),
        serde_json::Value::Array(values) => values.iter().any(value_contains_sensitive_field),
        _ => false,
    }
}

pub fn json_contains_sensitive_field(json: &str) -> bool {
    serde_json::from_str(json)
        .map(|value| value_contains_sensitive_field(&value))
        .unwrap_or_else(|_| {
            let compact: String = json
                .chars()
                .filter(|ch| ch.is_ascii_alphanumeric())
                .flat_map(char::to_lowercase)
                .collect();
            compact.contains("apikey") || compact.contains("authorization")
        })
}

/// 未发布基线不迁移旧版明文秘密：发现后直接拒绝启动并要求重建开发数据库。
pub fn validate_no_plaintext_settings(conn: &rusqlite::Connection) -> Result<(), String> {
    let mut statement = conn
        .prepare("SELECT key, value FROM settings")
        .map_err(|error| format!("检查设置安全基线失败: {error}"))?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|error| format!("检查设置安全基线失败: {error}"))?;

    for row in rows {
        let (key, value) = row.map_err(|error| format!("检查设置安全基线失败: {error}"))?;
        if is_sensitive_setting_key(&key)
            || (key == "ai_providers" && json_contains_sensitive_field(&value))
        {
            return Err(
                "[PLAINTEXT_SECRET_FOUND] 数据库含旧版明文秘密；当前版本不提供兼容迁移，请删除开发数据库后重新配置"
                    .into(),
            );
        }
    }
    Ok(())
}

fn bearer_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+").expect("valid bearer regex")
    })
}

fn common_api_key_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:sk-[a-z0-9._-]{8,}|AIza[a-z0-9_-]{20,}|AKIA[A-Z0-9]{16}|gh[pousr]_[a-z0-9]{20,})\b",
        )
        .expect("valid common API key regex")
    })
}

fn header_secret_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(
            r"(?i)\b(authorization|proxy-authorization|x-api-key|api[_ -]?key)\b(\s*[:=]\s*)[^\r\n,;]+",
        )
        .expect("valid secret header regex")
    })
}

fn json_secret_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(
            r#"(?i)("(?:authorization|proxy-authorization|x-api-key|api[_-]?key)"\s*:\s*)("[^"]*"|'[^']*'|[^,\s}]+)"#,
        )
        .expect("valid JSON secret regex")
    })
}

fn private_key_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"(?s)-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?-----END [^-\r\n]*PRIVATE KEY-----")
            .expect("valid private key regex")
    })
}

/// 过滤已知秘密、鉴权头、常见 API Key 写法和 PEM 私钥。
pub fn redact_sensitive(text: &str, known_secrets: &[&str]) -> String {
    let mut redacted = text.to_string();
    for secret in known_secrets {
        if !secret.is_empty() {
            redacted = redacted.replace(secret, "[REDACTED]");
        }
    }
    redacted = private_key_pattern()
        .replace_all(&redacted, "[REDACTED PRIVATE KEY]")
        .into_owned();
    redacted = common_api_key_pattern()
        .replace_all(&redacted, "[REDACTED API KEY]")
        .into_owned();
    redacted = bearer_pattern()
        .replace_all(&redacted, "Bearer [REDACTED]")
        .into_owned();
    redacted = json_secret_pattern()
        .replace_all(&redacted, "$1\"[REDACTED]\"")
        .into_owned();
    redacted = header_secret_pattern()
        .replace_all(&redacted, "$1$2[REDACTED]")
        .into_owned();
    redacted
}

#[cfg(test)]
#[derive(Default)]
pub struct MemorySecretStore {
    values: std::sync::Mutex<std::collections::HashMap<String, Zeroizing<String>>>,
}

#[cfg(test)]
impl SecretStore for MemorySecretStore {
    fn get(&self, secret_id: &str) -> Result<Option<SecretString>, SecretStoreError> {
        let values = self.values.lock().expect("memory secret store lock");
        Ok(values
            .get(secret_id)
            .map(|value| SecretString::new(value.to_string())))
    }

    fn set(&self, secret_id: &str, secret: &str) -> Result<(), SecretStoreError> {
        self.values
            .lock()
            .expect("memory secret store lock")
            .insert(secret_id.to_string(), Zeroizing::new(secret.to_string()));
        Ok(())
    }

    fn delete(&self, secret_id: &str) -> Result<(), SecretStoreError> {
        self.values
            .lock()
            .expect("memory secret store lock")
            .remove(secret_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_supports_set_replace_and_idempotent_delete() {
        let store = MemorySecretStore::default();
        store.set("provider.demo.api-key", "first-secret").unwrap();
        assert_eq!(
            store
                .get("provider.demo.api-key")
                .unwrap()
                .unwrap()
                .expose(),
            "first-secret"
        );

        store.set("provider.demo.api-key", "replacement").unwrap();
        assert_eq!(
            store
                .get("provider.demo.api-key")
                .unwrap()
                .unwrap()
                .expose(),
            "replacement"
        );

        store.delete("provider.demo.api-key").unwrap();
        store.delete("provider.demo.api-key").unwrap();
        assert!(store.get("provider.demo.api-key").unwrap().is_none());
    }

    #[test]
    fn provider_ids_are_constrained_before_becoming_credential_ids() {
        assert_eq!(
            provider_api_key_id("provider_01").unwrap(),
            "provider.provider_01.api-key"
        );
        assert!(provider_api_key_id("../escape").is_err());
        assert!(provider_api_key_id("含中文").is_err());
        assert!(provider_api_key_id("").is_err());
    }

    #[test]
    fn generic_settings_recognize_common_secret_key_names() {
        for key in [
            "api_key",
            "openaiApiKey",
            "Authorization",
            "client_secret",
            "access_token",
            "database_password",
            "cookie",
        ] {
            assert!(is_sensitive_setting_key(key), "{key} should be sensitive");
        }
        assert!(!is_sensitive_setting_key("usage_total_tokens"));
        assert!(!is_sensitive_setting_key("consent_accepted"));
    }

    #[test]
    fn secret_debug_and_log_redaction_never_expose_values() {
        let secret = SecretString::new("sk-super-secret".into());
        assert_eq!(format!("{secret:?}"), "SecretString([REDACTED])");

        let input = concat!(
            "Authorization: Bearer sk-super-secret\n",
            "Proxy-Authorization: Basic dW5saXN0ZWQtc2VjcmV0\n",
            "upstream echoed sk-unlisted-secret\n",
            r#"{"api_key":"another-secret"}"#,
            "\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"
        );
        let output = redact_sensitive(input, &[secret.expose()]);
        assert!(!output.contains("sk-super-secret"));
        assert!(!output.contains("dW5saXN0ZWQtc2VjcmV0"));
        assert!(!output.contains("sk-unlisted-secret"));
        assert!(!output.contains("another-secret"));
        assert!(!output.contains("\nabc\n"));
        assert!(output.contains("[REDACTED]"));
    }

    #[test]
    fn plaintext_settings_are_rejected_without_migration() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
             INSERT INTO settings(key, value)
             VALUES('ai_providers', '[{\"id\":\"p1\",\"api_key\":\"secret\"}]');",
        )
        .unwrap();
        let error = validate_no_plaintext_settings(&conn).unwrap_err();
        assert!(error.contains("PLAINTEXT_SECRET_FOUND"));
        assert!(!error.contains("\"secret\""));
    }
}
