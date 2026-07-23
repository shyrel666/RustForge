use rusqlite::Connection;
use std::path::Path;

/// SQLite 数据库句柄。schema 覆盖全部 Phase 的表结构，
/// Phase 0 只用到 settings / projects，其余表提前建好避免后续迁移。
pub struct Db {
    pub conn: Connection,
}

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;  -- 级联删除（项目→流量/发现/任务树）依赖它

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
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }
}
