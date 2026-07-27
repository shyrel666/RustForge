CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- 一个授权目标 = 一个项目
CREATE TABLE IF NOT EXISTS projects (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    target_host TEXT NOT NULL DEFAULT '',
    scope       TEXT NOT NULL DEFAULT '[]',
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
    req_headers   TEXT NOT NULL DEFAULT '{}',
    req_body      BLOB,
    status        INTEGER,
    resp_headers  TEXT,
    resp_body     BLOB,
    content_type  TEXT,
    req_wire_size       INTEGER NOT NULL DEFAULT 0,
    resp_wire_size      INTEGER NOT NULL DEFAULT 0,
    req_captured_size   INTEGER NOT NULL DEFAULT 0,
    resp_captured_size  INTEGER NOT NULL DEFAULT 0,
    req_truncated       INTEGER NOT NULL DEFAULT 0 CHECK(req_truncated IN (0, 1)),
    resp_truncated      INTEGER NOT NULL DEFAULT 0 CHECK(resp_truncated IN (0, 1)),
    req_decode_status   TEXT NOT NULL DEFAULT 'empty'
        CHECK(req_decode_status IN (
            'not_received', 'empty', 'identity_text', 'identity_binary',
            'decoded_text', 'decoded_binary', 'decode_failed',
            'unsupported_encoding', 'encoded_truncated', 'decode_truncated',
            'stream_error', 'stream_incomplete'
        )),
    resp_decode_status  TEXT NOT NULL DEFAULT 'not_received'
        CHECK(resp_decode_status IN (
            'not_received', 'empty', 'identity_text', 'identity_binary',
            'decoded_text', 'decoded_binary', 'decode_failed',
            'unsupported_encoding', 'encoded_truncated', 'decode_truncated',
            'stream_error', 'stream_incomplete'
        )),
    duration_ms   INTEGER NOT NULL DEFAULT 0,
    rule_tags     TEXT NOT NULL DEFAULT '[]',
    created_at    TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);
CREATE INDEX IF NOT EXISTS idx_traffic_project ON traffic(project_id, id);

-- 自定义分析提示词的不可变版本历史；settings 只保存当前激活的版本 id。
CREATE TABLE IF NOT EXISTS prompt_versions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    prompt_id    TEXT NOT NULL,
    version      INTEGER NOT NULL CHECK(version > 0),
    content      TEXT NOT NULL,
    based_on_id  INTEGER REFERENCES prompt_versions(id) ON DELETE SET NULL,
    operation    TEXT NOT NULL CHECK(operation IN ('save', 'copy', 'rollback')),
    created_at   TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    UNIQUE(prompt_id, version)
);
CREATE INDEX IF NOT EXISTS idx_prompt_versions_prompt
    ON prompt_versions(prompt_id, version DESC);

CREATE TRIGGER IF NOT EXISTS trg_prompt_versions_immutable_update
BEFORE UPDATE ON prompt_versions
BEGIN
    SELECT RAISE(ABORT, 'prompt versions are immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_prompt_versions_immutable_delete
BEFORE DELETE ON prompt_versions
BEGIN
    SELECT RAISE(ABORT, 'prompt versions are immutable');
END;

-- 每次模型产生响应都留下审计记录；校验失败的运行也保留，但不会创建 Finding。
CREATE TABLE IF NOT EXISTS analysis_runs (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id         INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    traffic_id         INTEGER REFERENCES traffic(id) ON DELETE SET NULL,
    provider_id        TEXT NOT NULL,
    provider_base_url  TEXT NOT NULL,
    model              TEXT NOT NULL,
    prompt_id          TEXT NOT NULL,
    prompt_version     INTEGER NOT NULL CHECK(prompt_version > 0),
    input_hash         TEXT NOT NULL CHECK(length(input_hash) = 64),
    policy_json        TEXT NOT NULL,
    manifest_json      TEXT NOT NULL,
    prompt_tokens      INTEGER NOT NULL DEFAULT 0 CHECK(prompt_tokens >= 0),
    completion_tokens  INTEGER NOT NULL DEFAULT 0 CHECK(completion_tokens >= 0),
    total_tokens       INTEGER NOT NULL DEFAULT 0 CHECK(total_tokens >= 0),
    schema_applied     INTEGER NOT NULL DEFAULT 0 CHECK(schema_applied IN (0, 1)),
    validation_status  TEXT NOT NULL CHECK(validation_status IN ('valid', 'invalid')),
    validation_json    TEXT NOT NULL,
    raw_output_hash    TEXT NOT NULL CHECK(length(raw_output_hash) = 64),
    created_at         TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);
CREATE INDEX IF NOT EXISTS idx_analysis_runs_traffic
    ON analysis_runs(traffic_id, id DESC);

-- 漏洞发现（来源：AI 分析 或被动规则）
CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id   INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    traffic_id   INTEGER REFERENCES traffic(id) ON DELETE SET NULL,
    analysis_run_id INTEGER REFERENCES analysis_runs(id) ON DELETE SET NULL,
    source       TEXT NOT NULL,
    title        TEXT NOT NULL,
    vuln_type    TEXT NOT NULL DEFAULT '',
    standard_references TEXT NOT NULL DEFAULT '[]'
                 CHECK(json_valid(standard_references) AND json_type(standard_references) = 'array'),
    severity     TEXT NOT NULL DEFAULT 'info',
    confidence   INTEGER NOT NULL DEFAULT 0,
    reasoning    TEXT NOT NULL DEFAULT '',
    verify_steps TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'pending',
    created_at   TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);
CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id, id);

-- Defense in depth: even a future caller cannot turn an invalid model response
-- into an AI Finding or attach a run from another traffic/project.
CREATE TRIGGER IF NOT EXISTS trg_ai_finding_requires_valid_run_insert
BEFORE INSERT ON findings
WHEN NEW.source = 'ai'
BEGIN
    SELECT RAISE(ABORT, 'AI finding requires a matching valid analysis run')
    WHERE NOT EXISTS (
        SELECT 1 FROM analysis_runs AS run
        WHERE run.id = NEW.analysis_run_id
          AND run.validation_status = 'valid'
          AND run.project_id = NEW.project_id
          AND (NEW.traffic_id IS NULL OR run.traffic_id = NEW.traffic_id)
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_ai_finding_requires_valid_run_update
BEFORE UPDATE OF source, analysis_run_id, project_id, traffic_id ON findings
WHEN NEW.source = 'ai'
BEGIN
    SELECT RAISE(ABORT, 'AI finding requires a matching valid analysis run')
    WHERE NOT EXISTS (
        SELECT 1 FROM analysis_runs AS run
        WHERE run.id = NEW.analysis_run_id
          AND run.validation_status = 'valid'
          AND run.project_id = NEW.project_id
          AND (NEW.traffic_id IS NULL OR run.traffic_id = NEW.traffic_id)
    );
END;

-- 渗透任务树节点
CREATE TABLE IF NOT EXISTS task_nodes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    parent_id       INTEGER REFERENCES task_nodes(id) ON DELETE CASCADE,
    title           TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    why             TEXT NOT NULL DEFAULT '',
    how_to          TEXT NOT NULL DEFAULT '',
    verify_criteria TEXT NOT NULL DEFAULT '',
    standard_references TEXT NOT NULL DEFAULT '[]'
                    CHECK(json_valid(standard_references) AND json_type(standard_references) = 'array'),
    status          TEXT NOT NULL DEFAULT 'todo',
    sort_order      INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);
CREATE INDEX IF NOT EXISTS idx_task_nodes_project ON task_nodes(project_id, parent_id);

-- AI 对单条流量的分析结果缓存
CREATE TABLE IF NOT EXISTS analyses (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id        INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    traffic_id        INTEGER NOT NULL REFERENCES traffic(id) ON DELETE CASCADE,
    analysis_run_id   INTEGER NOT NULL UNIQUE REFERENCES analysis_runs(id) ON DELETE CASCADE,
    purpose           TEXT NOT NULL DEFAULT '',
    suspicious_params TEXT NOT NULL DEFAULT '[]',
    summary           TEXT NOT NULL DEFAULT '',
    raw_json          TEXT NOT NULL DEFAULT '{}',
    model             TEXT NOT NULL DEFAULT '',
    created_at        TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);
CREATE INDEX IF NOT EXISTS idx_analyses_traffic ON analyses(traffic_id, id);

-- 任务树节点与 Finding 双向关联
CREATE TABLE IF NOT EXISTS task_findings (
    task_id    INTEGER NOT NULL REFERENCES task_nodes(id) ON DELETE CASCADE,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    PRIMARY KEY (task_id, finding_id)
);
