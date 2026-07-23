use rusqlite::Connection;
use std::path::Path;

/// SQLite 数据库句柄。schema 覆盖全部 Phase 的表结构，
/// Phase 0 只用到 settings / projects，其余表提前建好避免后续迁移。
pub struct Db {
    pub conn: Connection,
}

/// 连接级 PRAGMA：必须逐连接设置。foreign_keys 是连接级开关（级联删除依赖它），
/// busy_timeout 让并发写入排队而非直接 SQLITE_BUSY 报错。WAL 是库级持久设置，
/// 但每连接重复设置无害。
const PRAGMAS: &str = "\
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;
PRAGMA synchronous = NORMAL;
";

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- 一个授权目标 = 一个项目
CREATE TABLE IF NOT EXISTS projects (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    target_host TEXT NOT NULL DEFAULT '',
    scope       TEXT NOT NULL DEFAULT '[]',  -- JSON 数组：拦截的域名/IP 白名单
    created_at  TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);

-- 代理抓取的 HTTP 流量
CREATE TABLE IF NOT EXISTS traffic (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id    INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    method        TEXT NOT NULL,
    scheme        TEXT NOT NULL DEFAULT 'https',
    host          TEXT NOT NULL,
    port          INTEGER NOT NULL DEFAULT 443,
    path          TEXT NOT NULL DEFAULT '/',
    url           TEXT NOT NULL,
    req_headers   TEXT NOT NULL DEFAULT '{}',  -- JSON 对象
    req_body      BLOB,
    status        INTEGER,                      -- 响应状态码，NULL=未收到响应
    resp_headers  TEXT,                         -- JSON 对象
    resp_body     BLOB,
    content_type  TEXT,
    req_size      INTEGER NOT NULL DEFAULT 0,
    resp_size     INTEGER NOT NULL DEFAULT 0,
    duration_ms   INTEGER NOT NULL DEFAULT 0,
    rule_tags     TEXT NOT NULL DEFAULT '[]',   -- 被动规则命中的标签，JSON 数组
    created_at    TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);
CREATE INDEX IF NOT EXISTS idx_traffic_project ON traffic(project_id, id);

-- 漏洞发现（来源：AI 分析 或 被动规则）
CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id   INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    traffic_id   INTEGER REFERENCES traffic(id) ON DELETE SET NULL,
    source       TEXT NOT NULL,                 -- 'ai' | 'rule'
    title        TEXT NOT NULL,
    vuln_type    TEXT NOT NULL DEFAULT '',
    owasp        TEXT NOT NULL DEFAULT '',      -- 如 'A01:2021 Broken Access Control'
    cwe          TEXT NOT NULL DEFAULT '',      -- 如 'CWE-89'
    severity     TEXT NOT NULL DEFAULT 'info',  -- critical/high/medium/low/info
    confidence   INTEGER NOT NULL DEFAULT 0,    -- 0-100
    reasoning    TEXT NOT NULL DEFAULT '',      -- AI 推理过程
    verify_steps TEXT NOT NULL DEFAULT '',      -- 手动验证步骤（Markdown）
    status       TEXT NOT NULL DEFAULT 'pending', -- pending/confirmed/rejected
    created_at   TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);
CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id, id);

-- 渗透任务树节点
CREATE TABLE IF NOT EXISTS task_nodes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    parent_id       INTEGER REFERENCES task_nodes(id) ON DELETE CASCADE,
    title           TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',   -- 做什么
    why             TEXT NOT NULL DEFAULT '',   -- 为什么做这步
    how_to          TEXT NOT NULL DEFAULT '',   -- 怎么做（具体操作）
    verify_criteria TEXT NOT NULL DEFAULT '',   -- 完成判定标准
    status          TEXT NOT NULL DEFAULT 'todo', -- todo/in_progress/done/blocked
    sort_order      INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);
CREATE INDEX IF NOT EXISTS idx_task_nodes_project ON task_nodes(project_id, parent_id);

-- AI 对单条流量的分析结果缓存（避免重复调用烧 token）
CREATE TABLE IF NOT EXISTS analyses (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id        INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    traffic_id        INTEGER NOT NULL REFERENCES traffic(id) ON DELETE CASCADE,
    purpose           TEXT NOT NULL DEFAULT '',
    suspicious_params TEXT NOT NULL DEFAULT '[]', -- JSON 数组
    summary           TEXT NOT NULL DEFAULT '',
    raw_json          TEXT NOT NULL DEFAULT '{}', -- AnalysisResult 完整 JSON
    model             TEXT NOT NULL DEFAULT '',
    created_at        TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);
CREATE INDEX IF NOT EXISTS idx_analyses_traffic ON analyses(traffic_id, id);

-- 任务树节点 ↔ Finding 双向关联
CREATE TABLE IF NOT EXISTS task_findings (
    task_id    INTEGER NOT NULL REFERENCES task_nodes(id) ON DELETE CASCADE,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    PRIMARY KEY (task_id, finding_id)
);
"#;

impl Db {
    pub fn open(path: &Path) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        conn.execute_batch(PRAGMAS)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }
}

/// r2d2 + rusqlite 连接池类型别名，全应用共享一个池。
pub type Pool = r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>;
/// 从池里借出的连接；Deref 到 rusqlite::Connection，可直接当连接用。
pub type PooledConn = r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>;

/// 打开数据库连接池：每条连接经 with_init 启用连接级 PRAGMA（外键/超时/WAL），
/// 并在首条连接上建表。相比单连接 + 全局 Mutex，代理写入与 UI 读取可各持一条
/// 连接并行（WAL 允许 1 写 + N 读），同时彻底规避 Mutex 中毒导致的永久失效。
pub fn open_pool(path: &Path) -> Result<Pool, String> {
    let manager =
        r2d2_sqlite::SqliteConnectionManager::file(path).with_init(|c| c.execute_batch(PRAGMAS));
    let pool = r2d2::Pool::builder()
        .max_size(8)
        .build(manager)
        .map_err(|e| format!("初始化数据库连接池失败: {e}"))?;
    let conn = pool.get().map_err(|e| e.to_string())?;
    conn.execute_batch(SCHEMA).map_err(|e| e.to_string())?;
    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 每条池连接都必须开启 foreign_keys，否则级联删除失效——这里直接验证级联。
    #[test]
    fn pool_enforces_foreign_key_cascade() {
        let dir = std::env::temp_dir().join(format!("rustforge-pool-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pool.db");
        let _ = std::fs::remove_file(&path);

        let pool = open_pool(&path).unwrap();
        let conn = pool.get().unwrap();
        conn.execute("INSERT INTO projects(name) VALUES('p')", []).unwrap();
        let pid = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO traffic(project_id, method, host, url) VALUES(?1,'GET','h','u')",
            [pid],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO findings(project_id, source, title) VALUES(?1,'rule','t')",
            [pid],
        )
        .unwrap();

        conn.execute("DELETE FROM projects WHERE id = ?1", [pid]).unwrap();

        let traffic: i64 = conn
            .query_row("SELECT COUNT(*) FROM traffic", [], |r| r.get(0))
            .unwrap();
        let findings: i64 = conn
            .query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0))
            .unwrap();
        assert_eq!(traffic, 0, "删除项目应级联清空流量（依赖每连接 foreign_keys=ON）");
        assert_eq!(findings, 0, "删除项目应级联清空发现");
    }
}
