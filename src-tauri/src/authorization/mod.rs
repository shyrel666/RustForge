//! 主动/被动网络路径共用的授权边界。
//!
//! 前端提示只能改善体验，真正的 Scope 判定必须在这里完成。代理和 Repeater
//! 都从项目记录构造同一个 [`ScopePolicy`]，避免各自实现一套近似规则。

mod scope;

pub use scope::{
    normalize_scope_entries, AuthorizedUrl, ScopeDecision, ScopeMatchKind, ScopePolicy,
};

use rusqlite::{Connection, OptionalExtension};
use std::fmt;

/// Scope 授权的稳定错误分类。
///
/// `Display` 始终以 `[CODE]` 开头，Tauri 前端可以稳定展示/识别，不必依赖
/// 后面的中文说明。解析错误不会回显完整 URL，避免把 query 中的秘密带入日志。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationError {
    NoActiveProject,
    ProjectNotFound,
    EmptyScope,
    InvalidScope(String),
    InvalidUrl,
    UnsupportedScheme(String),
    UrlUserInfo,
    MissingHost,
    InvalidHost,
    OutOfScope(String),
    Storage(String),
}

impl AuthorizationError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NoActiveProject => "NO_ACTIVE_PROJECT",
            Self::ProjectNotFound => "PROJECT_NOT_FOUND",
            Self::EmptyScope => "EMPTY_SCOPE",
            Self::InvalidScope(_) => "INVALID_SCOPE",
            Self::InvalidUrl => "INVALID_URL",
            Self::UnsupportedScheme(_) => "UNSUPPORTED_SCHEME",
            Self::UrlUserInfo => "URL_USERINFO",
            Self::MissingHost => "MISSING_HOST",
            Self::InvalidHost => "INVALID_HOST",
            Self::OutOfScope(_) => "OUT_OF_SCOPE",
            Self::Storage(_) => "SCOPE_STORAGE",
        }
    }

    pub fn storage(error: impl fmt::Display) -> Self {
        Self::Storage(error.to_string())
    }
}

impl fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] ", self.code())?;
        match self {
            Self::NoActiveProject => write!(f, "请先打开一个项目"),
            Self::ProjectNotFound => write!(f, "指定项目不存在"),
            Self::EmptyScope => write!(f, "项目 Scope 为空，未授权任何目标"),
            Self::InvalidScope(reason) => write!(f, "项目 Scope 配置无效：{reason}"),
            Self::InvalidUrl => write!(f, "请求 URL 无效"),
            Self::UnsupportedScheme(scheme) => {
                write!(f, "不支持的 URL scheme：{scheme}（只允许 http/https）")
            }
            Self::UrlUserInfo => write!(f, "URL 不允许包含 username/password userinfo"),
            Self::MissingHost => write!(f, "URL 缺少目标 host"),
            Self::InvalidHost => write!(f, "目标 host 无效"),
            Self::OutOfScope(host) => {
                write!(f, "目标 {host} 不在当前项目的授权 Scope 内")
            }
            Self::Storage(message) => write!(f, "读取项目授权范围失败：{message}"),
        }
    }
}

impl std::error::Error for AuthorizationError {}

/// 从明确的项目上下文读取并编译 Scope。
pub fn load_project_policy(
    conn: &Connection,
    project_id: i64,
) -> Result<ScopePolicy, AuthorizationError> {
    let scope_json: Option<String> = conn
        .query_row(
            "SELECT scope FROM projects WHERE id = ?1",
            [project_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(AuthorizationError::storage)?;
    let scope_json = scope_json.ok_or(AuthorizationError::ProjectNotFound)?;
    let entries: Vec<String> = serde_json::from_str(&scope_json)
        .map_err(|_| AuthorizationError::InvalidScope("存储格式不是字符串数组".into()))?;
    ScopePolicy::new(&entries)
}

/// 读取代理使用的“当前项目 + Scope”。没有当前项目时严格失败关闭。
pub fn load_current_project_policy(
    conn: &Connection,
) -> Result<(i64, ScopePolicy), AuthorizationError> {
    let raw_id: Option<String> = conn
        .query_row(
            "SELECT value FROM settings WHERE key = 'current_project_id'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(AuthorizationError::storage)?;
    let project_id = raw_id
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or(AuthorizationError::NoActiveProject)?;
    let policy = load_project_policy(conn, project_id)?;
    Ok((project_id, policy))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE projects (
                id INTEGER PRIMARY KEY,
                scope TEXT NOT NULL
             );
             CREATE TABLE settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
             );",
        )
        .unwrap();
        conn
    }

    #[test]
    fn explicit_and_current_project_use_the_same_policy() {
        let conn = test_db();
        conn.execute(
            "INSERT INTO projects(id, scope) VALUES(7, ?1)",
            [r#"["*.Example.COM."]"#],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO settings(key, value) VALUES('current_project_id', '7')",
            [],
        )
        .unwrap();

        let explicit = load_project_policy(&conn, 7).unwrap();
        let (id, current) = load_current_project_policy(&conn).unwrap();
        assert_eq!(id, 7);
        assert_eq!(
            explicit.authorize_host("api.example.com").unwrap(),
            current.authorize_host("api.example.com").unwrap()
        );
    }

    #[test]
    fn missing_context_has_stable_errors() {
        let conn = test_db();
        assert_eq!(
            load_current_project_policy(&conn).unwrap_err().code(),
            "NO_ACTIVE_PROJECT"
        );
        assert_eq!(
            load_project_policy(&conn, 404).unwrap_err().code(),
            "PROJECT_NOT_FOUND"
        );
    }
}
