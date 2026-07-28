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

-- Repeater 工作区：会话保存标签、来源流量、TLS 策略和项目内选中状态；
-- 每次点击发送都会追加一条不可变 run，失败/拒绝也保留请求快照和稳定原因。
CREATE TABLE IF NOT EXISTS replay_sessions (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id        INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    title             TEXT NOT NULL CHECK(length(trim(title)) BETWEEN 1 AND 120),
    source_traffic_id INTEGER REFERENCES traffic(id) ON DELETE SET NULL,
    tls_policy        TEXT NOT NULL DEFAULT 'ignore_invalid'
                      CHECK(tls_policy IN ('strict', 'ignore_invalid')),
    is_selected       INTEGER NOT NULL DEFAULT 0 CHECK(is_selected IN (0, 1)),
    created_at        TEXT NOT NULL DEFAULT (
                          strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                      ),
    updated_at        TEXT NOT NULL DEFAULT (
                          strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                      )
);
CREATE INDEX IF NOT EXISTS idx_replay_sessions_project
    ON replay_sessions(project_id, updated_at DESC, id DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_replay_sessions_selected
    ON replay_sessions(project_id) WHERE is_selected = 1;

-- 仅供父级生命周期删除触发器使用；没有应用命令直接暴露该表。
CREATE TABLE IF NOT EXISTS replay_run_delete_guards (
    session_id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL
);

CREATE TRIGGER IF NOT EXISTS trg_replay_session_source_project_insert
BEFORE INSERT ON replay_sessions
WHEN NEW.source_traffic_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'replay session source traffic must belong to its project')
    WHERE NOT EXISTS (
        SELECT 1 FROM traffic
        WHERE id = NEW.source_traffic_id AND project_id = NEW.project_id
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_replay_session_source_project_update
BEFORE UPDATE OF source_traffic_id, project_id ON replay_sessions
WHEN NEW.source_traffic_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'replay session source traffic must belong to its project')
    WHERE NOT EXISTS (
        SELECT 1 FROM traffic
        WHERE id = NEW.source_traffic_id AND project_id = NEW.project_id
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_replay_session_prepare_run_delete
BEFORE DELETE ON replay_sessions
BEGIN
    INSERT OR IGNORE INTO replay_run_delete_guards(session_id, project_id)
    VALUES(OLD.id, OLD.project_id);
END;

CREATE TRIGGER IF NOT EXISTS trg_replay_session_finish_run_delete
AFTER DELETE ON replay_sessions
BEGIN
    DELETE FROM replay_run_delete_guards WHERE session_id = OLD.id;
END;

-- 项目删除可能先经 replay_runs.project_id 触发 run 级联，因此项目级
-- BEFORE/AFTER 触发器也覆盖全部会话。
CREATE TRIGGER IF NOT EXISTS trg_project_prepare_replay_run_delete
BEFORE DELETE ON projects
BEGIN
    INSERT OR IGNORE INTO replay_run_delete_guards(session_id, project_id)
    SELECT id, project_id FROM replay_sessions WHERE project_id = OLD.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_project_finish_replay_run_delete
AFTER DELETE ON projects
BEGIN
    DELETE FROM replay_run_delete_guards WHERE project_id = OLD.id;
END;

-- 网络副作用之前先写入不可变 attempt。正常完成时 replay_runs.attempt_id
-- 指向它；应用异常退出后，启动恢复会把没有结果的 attempt 转成明确的
-- APP_INTERRUPTED run。
CREATE TABLE IF NOT EXISTS replay_attempts (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    execution_token          TEXT NOT NULL UNIQUE,
    session_id               INTEGER NOT NULL REFERENCES replay_sessions(id) ON DELETE CASCADE,
    project_id               INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    method                   TEXT NOT NULL CHECK(length(trim(method)) BETWEEN 1 AND 64),
    url                      TEXT NOT NULL CHECK(length(trim(url)) BETWEEN 1 AND 8192),
    request_headers          TEXT NOT NULL DEFAULT '[]'
                             CHECK(json_valid(request_headers)
                                   AND json_type(request_headers) = 'array'),
    request_wire_body        BLOB,
    req_wire_size            INTEGER NOT NULL DEFAULT 0 CHECK(req_wire_size >= 0),
    req_wire_captured_size   INTEGER NOT NULL DEFAULT 0
                             CHECK(req_wire_captured_size >= 0
                                   AND req_wire_captured_size <= req_wire_size),
    req_wire_truncated       INTEGER NOT NULL DEFAULT 0 CHECK(req_wire_truncated IN (0, 1)),
    request_input            TEXT NOT NULL
                             CHECK(json_valid(request_input)
                                   AND json_type(request_input) = 'object'),
    request_body             BLOB,
    req_captured_size        INTEGER NOT NULL DEFAULT 0 CHECK(req_captured_size >= 0),
    req_truncated            INTEGER NOT NULL DEFAULT 0 CHECK(req_truncated IN (0, 1)),
    req_decode_status        TEXT NOT NULL DEFAULT 'empty'
                             CHECK(req_decode_status IN (
                                 'not_received', 'empty', 'identity_text', 'identity_binary',
                                 'decoded_text', 'decoded_binary', 'decode_failed',
                                 'unsupported_encoding', 'encoded_truncated', 'decode_truncated',
                                 'stream_error', 'stream_incomplete'
                             )),
    tls_policy               TEXT NOT NULL
                             CHECK(tls_policy IN ('strict', 'ignore_invalid')),
    scope_decision           TEXT NOT NULL
                             CHECK(json_valid(scope_decision)
                                   AND json_type(scope_decision) = 'object'),
    request_hash             TEXT NOT NULL CHECK(length(request_hash) = 64),
    req_body_hash            TEXT NOT NULL CHECK(length(req_body_hash) = 64),
    created_at               TEXT NOT NULL DEFAULT (
                                 strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                             ),
    CHECK(
        req_captured_size <= req_wire_size
        OR req_decode_status LIKE 'decoded_%'
        OR req_decode_status = 'decode_truncated'
    )
);
CREATE INDEX IF NOT EXISTS idx_replay_attempts_session
    ON replay_attempts(session_id, id DESC);

CREATE TABLE IF NOT EXISTS replay_runs (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    attempt_id          INTEGER UNIQUE REFERENCES replay_attempts(id) ON DELETE CASCADE,
    session_id          INTEGER NOT NULL REFERENCES replay_sessions(id) ON DELETE CASCADE,
    project_id          INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    method              TEXT NOT NULL CHECK(length(trim(method)) BETWEEN 1 AND 64),
    url                 TEXT NOT NULL CHECK(length(trim(url)) BETWEEN 1 AND 8192),
    request_headers     TEXT NOT NULL DEFAULT '[]'
                        CHECK(json_valid(request_headers)
                              AND json_type(request_headers) = 'array'),
    request_wire_body   BLOB,
    req_wire_captured_size INTEGER NOT NULL DEFAULT 0
                        CHECK(req_wire_captured_size >= 0),
    req_wire_truncated  INTEGER NOT NULL DEFAULT 0 CHECK(req_wire_truncated IN (0, 1)),
    request_input       TEXT NOT NULL
                        CHECK(json_valid(request_input)
                              AND json_type(request_input) = 'object'),
    request_body        BLOB,
    req_wire_size       INTEGER NOT NULL DEFAULT 0 CHECK(req_wire_size >= 0),
    req_captured_size   INTEGER NOT NULL DEFAULT 0 CHECK(req_captured_size >= 0),
    req_truncated       INTEGER NOT NULL DEFAULT 0 CHECK(req_truncated IN (0, 1)),
    req_decode_status   TEXT NOT NULL DEFAULT 'empty'
                        CHECK(req_decode_status IN (
                            'not_received', 'empty', 'identity_text', 'identity_binary',
                            'decoded_text', 'decoded_binary', 'decode_failed',
                            'unsupported_encoding', 'encoded_truncated', 'decode_truncated',
                            'stream_error', 'stream_incomplete'
                        )),
    tls_policy          TEXT NOT NULL
                        CHECK(tls_policy IN ('strict', 'ignore_invalid')),
    scope_allowed       INTEGER NOT NULL CHECK(scope_allowed IN (0, 1)),
    scope_decision      TEXT NOT NULL
                        CHECK(json_valid(scope_decision)
                              AND json_type(scope_decision) = 'object'),
    outcome             TEXT NOT NULL
                        CHECK(outcome IN (
                            'completed', 'scope_rejected',
                            'request_failed', 'response_incomplete'
                        )),
    error_code          TEXT,
    error_message       TEXT,
    status              INTEGER CHECK(status BETWEEN 100 AND 599),
    status_text         TEXT NOT NULL DEFAULT '',
    response_headers    TEXT NOT NULL DEFAULT '[]'
                        CHECK(json_valid(response_headers)
                              AND json_type(response_headers) = 'array'),
    response_body       BLOB,
    resp_wire_size      INTEGER NOT NULL DEFAULT 0 CHECK(resp_wire_size >= 0),
    resp_captured_size  INTEGER NOT NULL DEFAULT 0 CHECK(resp_captured_size >= 0),
    resp_truncated      INTEGER NOT NULL DEFAULT 0 CHECK(resp_truncated IN (0, 1)),
    resp_decode_status  TEXT NOT NULL DEFAULT 'not_received'
                        CHECK(resp_decode_status IN (
                            'not_received', 'empty', 'identity_text', 'identity_binary',
                            'decoded_text', 'decoded_binary', 'decode_failed',
                            'unsupported_encoding', 'encoded_truncated', 'decode_truncated',
                            'stream_error', 'stream_incomplete'
                        )),
    duration_ms         INTEGER NOT NULL DEFAULT 0 CHECK(duration_ms >= 0),
    request_hash        TEXT NOT NULL CHECK(length(request_hash) = 64),
    req_body_hash       TEXT CHECK(req_body_hash IS NULL OR length(req_body_hash) = 64),
    response_hash       TEXT CHECK(response_hash IS NULL OR length(response_hash) = 64),
    resp_body_hash      TEXT CHECK(resp_body_hash IS NULL OR length(resp_body_hash) = 64),
    created_at          TEXT NOT NULL DEFAULT (
                            strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                        ),
    CHECK(req_wire_captured_size <= req_wire_size),
    CHECK(
        req_captured_size <= req_wire_size
        OR req_decode_status LIKE 'decoded_%'
        OR req_decode_status = 'decode_truncated'
    ),
    CHECK(
        (outcome IN ('completed', 'response_incomplete')
             AND scope_allowed = 1 AND status IS NOT NULL)
        OR
        (outcome = 'scope_rejected'
             AND scope_allowed = 0 AND status IS NULL)
        OR
        (outcome = 'request_failed' AND status IS NULL)
    )
);
CREATE INDEX IF NOT EXISTS idx_replay_runs_session
    ON replay_runs(session_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_replay_runs_project
    ON replay_runs(project_id, id DESC);

CREATE TRIGGER IF NOT EXISTS trg_replay_attempt_same_project_insert
BEFORE INSERT ON replay_attempts
BEGIN
    SELECT RAISE(ABORT, 'replay attempt must belong to its session project')
    WHERE NOT EXISTS (
        SELECT 1 FROM replay_sessions
        WHERE id = NEW.session_id AND project_id = NEW.project_id
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_replay_run_same_project_insert
BEFORE INSERT ON replay_runs
BEGIN
    SELECT RAISE(ABORT, 'replay run must belong to its session project')
    WHERE NOT EXISTS (
        SELECT 1 FROM replay_sessions
        WHERE id = NEW.session_id AND project_id = NEW.project_id
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_replay_attempts_immutable_update
BEFORE UPDATE ON replay_attempts
BEGIN
    SELECT RAISE(ABORT, 'replay attempts are immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_replay_attempts_immutable_delete
BEFORE DELETE ON replay_attempts
WHEN NOT EXISTS(
    SELECT 1 FROM replay_run_delete_guards WHERE session_id = OLD.session_id
)
BEGIN
    SELECT RAISE(ABORT, 'replay attempts are immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_replay_runs_immutable_update
BEFORE UPDATE ON replay_runs
BEGIN
    SELECT RAISE(ABORT, 'replay runs are immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_replay_runs_immutable_delete
BEFORE DELETE ON replay_runs
WHEN NOT EXISTS(
    SELECT 1 FROM replay_run_delete_guards WHERE session_id = OLD.session_id
)
BEGIN
    SELECT RAISE(ABORT, 'replay runs are immutable');
END;

-- 正在运行的请求不能随标签/项目一起被删除，否则网络可能继续执行而审计
-- 容器已经消失。应用重启时会先恢复无结果 attempt，再允许生命周期删除。
CREATE TRIGGER IF NOT EXISTS trg_replay_session_blocks_pending_attempt_delete
BEFORE DELETE ON replay_sessions
WHEN EXISTS(
    SELECT 1 FROM replay_attempts a
    WHERE a.session_id = OLD.id
      AND NOT EXISTS(SELECT 1 FROM replay_runs r WHERE r.attempt_id = a.id)
)
BEGIN
    SELECT RAISE(ABORT, 'replay session has an in-flight request');
END;

CREATE TRIGGER IF NOT EXISTS trg_project_blocks_pending_replay_attempt_delete
BEFORE DELETE ON projects
WHEN EXISTS(
    SELECT 1 FROM replay_attempts a
    WHERE a.project_id = OLD.id
      AND NOT EXISTS(SELECT 1 FROM replay_runs r WHERE r.attempt_id = a.id)
)
BEGIN
    SELECT RAISE(ABORT, 'project has an in-flight replay request');
END;

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

CREATE TRIGGER IF NOT EXISTS trg_analysis_run_traffic_project_insert
BEFORE INSERT ON analysis_runs
WHEN NEW.traffic_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'analysis run traffic must belong to its project')
    WHERE NOT EXISTS (
        SELECT 1 FROM traffic
        WHERE id = NEW.traffic_id AND project_id = NEW.project_id
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_analysis_run_traffic_project_update
BEFORE UPDATE OF traffic_id, project_id ON analysis_runs
WHEN NEW.traffic_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'analysis run traffic must belong to its project')
    WHERE NOT EXISTS (
        SELECT 1 FROM traffic
        WHERE id = NEW.traffic_id AND project_id = NEW.project_id
    );
END;

-- 漏洞发现（来源：AI 分析 或被动规则）
--
-- fingerprint 是"同一项目 + 同一规则 + 同一接口 + 同一字段"的稳定身份，规则
-- 命中走它去重（规则版本刻意不参与，见 rules::fingerprint）。AI Finding 目前
-- 不产生指纹，留空；SQLite 的唯一索引把多个 NULL 视为互不相同。
CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id   INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    traffic_id   INTEGER REFERENCES traffic(id) ON DELETE SET NULL,
    analysis_run_id INTEGER REFERENCES analysis_runs(id) ON DELETE SET NULL,
    source       TEXT NOT NULL CHECK(source IN ('ai', 'rule')),
    title        TEXT NOT NULL,
    vuln_type    TEXT NOT NULL DEFAULT '',
    standard_references TEXT NOT NULL DEFAULT '[]'
                 CHECK(json_valid(standard_references) AND json_type(standard_references) = 'array'),
    severity     TEXT NOT NULL DEFAULT 'info'
                 CHECK(severity IN ('critical', 'high', 'medium', 'low', 'info')),
    confidence   INTEGER NOT NULL DEFAULT 0 CHECK(confidence BETWEEN 0 AND 100),
    reasoning    TEXT NOT NULL DEFAULT '',
    verify_steps TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'pending'
                 CHECK(status IN ('pending', 'confirmed', 'rejected')),
    analyst_notes TEXT NOT NULL DEFAULT '' CHECK(length(analyst_notes) <= 4000),
    fingerprint  TEXT CHECK(fingerprint IS NULL OR length(fingerprint) = 64),
    -- 累计关联过的不同流量数；流量删除后保留历史计数。
    occurrences  INTEGER NOT NULL DEFAULT 1 CHECK(occurrences >= 1),
    last_seen_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    created_at   TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    updated_at   TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);
CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_fingerprint
    ON findings(fingerprint) WHERE fingerprint IS NOT NULL;

CREATE TRIGGER IF NOT EXISTS trg_finding_sources_same_project_insert
BEFORE INSERT ON findings
BEGIN
    SELECT RAISE(ABORT, 'finding traffic must belong to its project')
    WHERE NEW.traffic_id IS NOT NULL
      AND NOT EXISTS (
          SELECT 1 FROM traffic
          WHERE id = NEW.traffic_id AND project_id = NEW.project_id
      );
    SELECT RAISE(ABORT, 'finding analysis run must belong to its project')
    WHERE NEW.analysis_run_id IS NOT NULL
      AND NOT EXISTS (
          SELECT 1 FROM analysis_runs
          WHERE id = NEW.analysis_run_id AND project_id = NEW.project_id
      );
END;

CREATE TRIGGER IF NOT EXISTS trg_finding_sources_same_project_update
BEFORE UPDATE OF traffic_id, analysis_run_id, project_id ON findings
BEGIN
    SELECT RAISE(ABORT, 'finding traffic must belong to its project')
    WHERE NEW.traffic_id IS NOT NULL
      AND NOT EXISTS (
          SELECT 1 FROM traffic
          WHERE id = NEW.traffic_id AND project_id = NEW.project_id
      );
    SELECT RAISE(ABORT, 'finding analysis run must belong to its project')
    WHERE NEW.analysis_run_id IS NOT NULL
      AND NOT EXISTS (
          SELECT 1 FROM analysis_runs
          WHERE id = NEW.analysis_run_id AND project_id = NEW.project_id
      );
END;

-- Finding 的不可变审计时间线。created 由数据库触发器生成，其余事件与
-- Finding 变更在 evidence::service 的同一事务中写入。
CREATE TABLE IF NOT EXISTS finding_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id   INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    event_type   TEXT NOT NULL CHECK(event_type IN (
                     'created', 'status_changed', 'severity_changed', 'notes_changed',
                     'evidence_accepted', 'evidence_revoked'
                 )),
    old_value    TEXT,
    new_value    TEXT,
    reason       TEXT NOT NULL DEFAULT '' CHECK(length(reason) <= 4000),
    actor        TEXT NOT NULL CHECK(length(trim(actor)) BETWEEN 1 AND 120),
    created_at   TEXT NOT NULL DEFAULT (
                     strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                 )
);
CREATE INDEX IF NOT EXISTS idx_finding_events_finding
    ON finding_events(finding_id, created_at, id);

CREATE TRIGGER IF NOT EXISTS trg_finding_initial_status_pending
BEFORE INSERT ON findings
WHEN NEW.status <> 'pending'
BEGIN
    SELECT RAISE(ABORT, 'new findings must start pending');
END;

CREATE TRIGGER IF NOT EXISTS trg_finding_initial_event
AFTER INSERT ON findings
BEGIN
    INSERT INTO finding_events(
        finding_id, event_type, old_value, new_value, reason, actor, created_at
    ) VALUES(
        NEW.id, 'created', NULL, NEW.status, 'Finding created',
        'system:' || NEW.source, NEW.created_at
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_finding_events_immutable_update
BEFORE UPDATE ON finding_events
BEGIN
    SELECT RAISE(ABORT, 'finding events are immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_finding_events_immutable_delete
BEFORE DELETE ON finding_events
WHEN EXISTS(SELECT 1 FROM findings WHERE id = OLD.finding_id)
BEGIN
    SELECT RAISE(ABORT, 'finding events are immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_finding_rejected_event_requires_reason
BEFORE INSERT ON finding_events
WHEN NEW.event_type = 'status_changed'
 AND NEW.new_value = 'rejected'
 AND length(trim(NEW.reason)) = 0
BEGIN
    SELECT RAISE(ABORT, 'rejected finding requires a reason');
END;

CREATE TRIGGER IF NOT EXISTS trg_finding_status_requires_event
BEFORE UPDATE OF status ON findings
WHEN OLD.status <> NEW.status
BEGIN
    SELECT RAISE(ABORT, 'finding status change requires an audit event')
    WHERE NOT EXISTS (
        SELECT 1 FROM finding_events
        WHERE id = (
            SELECT MAX(id) FROM finding_events WHERE finding_id = OLD.id
        )
          AND finding_id = OLD.id
          AND event_type = 'status_changed'
          AND old_value = OLD.status
          AND new_value = NEW.status
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_finding_severity_requires_event
BEFORE UPDATE OF severity ON findings
WHEN OLD.severity <> NEW.severity
BEGIN
    SELECT RAISE(ABORT, 'finding severity change requires an audit event')
    WHERE NOT EXISTS (
        SELECT 1 FROM finding_events
        WHERE id = (
            SELECT MAX(id) FROM finding_events WHERE finding_id = OLD.id
        )
          AND finding_id = OLD.id
          AND event_type = 'severity_changed'
          AND old_value = OLD.severity
          AND new_value = NEW.severity
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_finding_notes_requires_event
BEFORE UPDATE OF analyst_notes ON findings
WHEN OLD.analyst_notes <> NEW.analyst_notes
BEGIN
    SELECT RAISE(ABORT, 'finding notes change requires an audit event')
    WHERE NOT EXISTS (
        SELECT 1 FROM finding_events
        WHERE id = (
            SELECT MAX(id) FROM finding_events WHERE finding_id = OLD.id
        )
          AND finding_id = OLD.id
          AND event_type = 'notes_changed'
          AND old_value = OLD.analyst_notes
          AND new_value = NEW.analyst_notes
    );
END;

-- 同一个 Finding 命中过的全部流量。重复命中只追加这里的关联，不再新建 Finding。
CREATE TABLE IF NOT EXISTS finding_traffic (
    finding_id    INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    traffic_id    INTEGER NOT NULL REFERENCES traffic(id) ON DELETE CASCADE,
    first_seen_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    PRIMARY KEY (finding_id, traffic_id)
);
CREATE INDEX IF NOT EXISTS idx_finding_traffic_finding
    ON finding_traffic(finding_id, traffic_id);

CREATE TRIGGER IF NOT EXISTS trg_finding_traffic_same_project_insert
BEFORE INSERT ON finding_traffic
BEGIN
    SELECT RAISE(ABORT, 'finding traffic link must stay within one project')
    WHERE NOT EXISTS (
        SELECT 1
        FROM findings finding
        JOIN traffic request ON request.id = NEW.traffic_id
        WHERE finding.id = NEW.finding_id
          AND finding.project_id = request.project_id
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_finding_traffic_same_project_update
BEFORE UPDATE OF finding_id, traffic_id ON finding_traffic
BEGIN
    SELECT RAISE(ABORT, 'finding traffic link must stay within one project')
    WHERE NOT EXISTS (
        SELECT 1
        FROM findings finding
        JOIN traffic request ON request.id = NEW.traffic_id
        WHERE finding.id = NEW.finding_id
          AND finding.project_id = request.project_id
    );
END;

-- Evidence 是从可变来源提取出的独立、脱敏、小尺寸快照。source_id 刻意不设
-- 多态外键：原 traffic 被删除时保留来源标识、快照和哈希，source_available
-- 由读取服务实时计算。
CREATE TABLE IF NOT EXISTS evidence (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id        INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    source_type       TEXT NOT NULL
                      CHECK(source_type IN ('traffic', 'analysis_run', 'replay_run')),
    source_id         INTEGER NOT NULL CHECK(source_id > 0),
    observation       TEXT NOT NULL CHECK(length(trim(observation)) BETWEEN 1 AND 4000),
    redacted_snapshot TEXT NOT NULL
                      CHECK(json_valid(redacted_snapshot) AND length(redacted_snapshot) <= 65536),
    content_hash      TEXT NOT NULL CHECK(length(content_hash) = 64),
    qualifies_for_confirmation INTEGER NOT NULL DEFAULT 1
                      CHECK(qualifies_for_confirmation IN (0, 1)),
    created_by        TEXT NOT NULL CHECK(length(trim(created_by)) BETWEEN 1 AND 120),
    created_at        TEXT NOT NULL DEFAULT (
                          strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                      )
);
CREATE INDEX IF NOT EXISTS idx_evidence_source
    ON evidence(project_id, source_type, source_id, id);

CREATE TRIGGER IF NOT EXISTS trg_evidence_immutable_update
BEFORE UPDATE ON evidence
BEGIN
    SELECT RAISE(ABORT, 'evidence is immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_evidence_immutable_delete
BEFORE DELETE ON evidence
WHEN EXISTS(SELECT 1 FROM projects WHERE id = OLD.project_id)
BEGIN
    SELECT RAISE(ABORT, 'evidence is immutable');
END;

-- “接受”属于 Finding 与 Evidence 的人工判断，而不是 Evidence 自身属性。
-- 同一 Evidence 因此可以被多个 Finding 独立接受或撤销。
CREATE TABLE IF NOT EXISTS finding_evidence (
    finding_id     INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    evidence_id    INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    accepted       INTEGER NOT NULL DEFAULT 0 CHECK(accepted IN (0, 1)),
    acceptance_note TEXT NOT NULL DEFAULT '' CHECK(length(acceptance_note) <= 4000),
    accepted_by    TEXT,
    accepted_at    TEXT,
    linked_at      TEXT NOT NULL DEFAULT (
                       strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                   ),
    PRIMARY KEY (finding_id, evidence_id),
    CHECK(
        (accepted = 0 AND accepted_by IS NULL AND accepted_at IS NULL)
        OR
        (accepted = 1 AND length(trim(accepted_by)) BETWEEN 1 AND 120
                      AND accepted_at IS NOT NULL)
    )
);
CREATE INDEX IF NOT EXISTS idx_finding_evidence_evidence
    ON finding_evidence(evidence_id, finding_id);

CREATE TRIGGER IF NOT EXISTS trg_finding_evidence_same_project_insert
BEFORE INSERT ON finding_evidence
BEGIN
    SELECT RAISE(ABORT, 'finding and evidence must belong to the same project')
    WHERE (
        SELECT project_id FROM findings WHERE id = NEW.finding_id
    ) <> (
        SELECT project_id FROM evidence WHERE id = NEW.evidence_id
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_finding_evidence_initial_unaccepted
BEFORE INSERT ON finding_evidence
WHEN NEW.accepted <> 0
BEGIN
    SELECT RAISE(ABORT, 'new evidence links must start unaccepted');
END;

CREATE TRIGGER IF NOT EXISTS trg_finding_evidence_acceptance_requires_event
BEFORE UPDATE OF accepted ON finding_evidence
WHEN OLD.accepted <> NEW.accepted
BEGIN
    SELECT RAISE(ABORT, 'evidence acceptance change requires an audit event')
    WHERE NOT EXISTS (
        SELECT 1 FROM finding_events
        WHERE id = (
            SELECT MAX(id) FROM finding_events WHERE finding_id = OLD.finding_id
        )
          AND finding_id = OLD.finding_id
          AND event_type = CASE
              WHEN NEW.accepted = 1 THEN 'evidence_accepted'
              ELSE 'evidence_revoked'
          END
          AND old_value = (
              'evidence:' || OLD.evidence_id || ':' ||
              CASE WHEN OLD.accepted = 1 THEN 'accepted' ELSE 'unaccepted' END
          )
          AND new_value = (
              'evidence:' || NEW.evidence_id || ':' ||
              CASE WHEN NEW.accepted = 1 THEN 'accepted' ELSE 'unaccepted' END
          )
          AND reason = NEW.acceptance_note
          AND (
              NEW.accepted = 0
              OR actor = NEW.accepted_by
          )
    );
END;

-- 接受状态、判断说明、操作者和时间戳必须作为同一个审计转换原子更新。
-- linked_at 是关联创建时间，任何后续写入都不得改写。
CREATE TRIGGER IF NOT EXISTS trg_finding_evidence_metadata_requires_transition
BEFORE UPDATE OF acceptance_note, accepted_by, accepted_at, linked_at ON finding_evidence
WHEN OLD.linked_at IS NOT NEW.linked_at
 OR (
     OLD.accepted = NEW.accepted
     AND (
         OLD.acceptance_note IS NOT NEW.acceptance_note
         OR OLD.accepted_by IS NOT NEW.accepted_by
         OR OLD.accepted_at IS NOT NEW.accepted_at
     )
 )
BEGIN
    SELECT RAISE(ABORT, 'evidence acceptance metadata requires an audited transition');
END;

-- Finding 仍存在时，关联只能通过 Finding/项目生命周期级联删除。
CREATE TRIGGER IF NOT EXISTS trg_finding_evidence_immutable_delete
BEFORE DELETE ON finding_evidence
WHEN EXISTS(
    SELECT 1
    FROM findings f
    JOIN projects p ON p.id = f.project_id
    WHERE f.id = OLD.finding_id
)
BEGIN
    SELECT RAISE(ABORT, 'finding evidence links are immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_confirmed_finding_keeps_accepted_evidence_update
BEFORE UPDATE OF accepted ON finding_evidence
WHEN OLD.accepted = 1 AND NEW.accepted = 0
 AND EXISTS(
     SELECT 1 FROM evidence
     WHERE id = OLD.evidence_id AND qualifies_for_confirmation = 1
 )
 AND EXISTS(
     SELECT 1 FROM findings
     WHERE id = OLD.finding_id AND status = 'confirmed'
 )
BEGIN
    SELECT RAISE(ABORT, 'confirmed finding requires accepted evidence')
    WHERE (
        SELECT COUNT(*)
        FROM finding_evidence fe
        JOIN evidence e ON e.id = fe.evidence_id
        WHERE fe.finding_id = OLD.finding_id
          AND fe.accepted = 1
          AND e.qualifies_for_confirmation = 1
    ) <= 1;
END;

CREATE TRIGGER IF NOT EXISTS trg_confirmed_finding_keeps_accepted_evidence_delete
BEFORE DELETE ON finding_evidence
WHEN OLD.accepted = 1
 AND EXISTS(
     SELECT 1 FROM evidence
     WHERE id = OLD.evidence_id AND qualifies_for_confirmation = 1
 )
 AND EXISTS(
     SELECT 1
     FROM findings f
     JOIN projects p ON p.id = f.project_id
     WHERE f.id = OLD.finding_id AND f.status = 'confirmed'
 )
BEGIN
    SELECT RAISE(ABORT, 'confirmed finding requires accepted evidence')
    WHERE (
        SELECT COUNT(*)
        FROM finding_evidence fe
        JOIN evidence e ON e.id = fe.evidence_id
        WHERE fe.finding_id = OLD.finding_id
          AND fe.accepted = 1
          AND e.qualifies_for_confirmation = 1
    ) <= 1;
END;

-- Defense in depth：即使未来调用方绕过 service，也不能在没有人工接受证据时
-- 把 Finding 改为 confirmed。
CREATE TRIGGER IF NOT EXISTS trg_finding_confirmed_requires_evidence
BEFORE UPDATE OF status ON findings
WHEN NEW.status = 'confirmed' AND OLD.status <> NEW.status
BEGIN
    SELECT RAISE(ABORT, 'confirmed finding requires accepted evidence')
    WHERE NOT EXISTS (
        SELECT 1
        FROM finding_evidence fe
        JOIN evidence e ON e.id = fe.evidence_id
        WHERE fe.finding_id = OLD.id
          AND fe.accepted = 1
          AND e.qualifies_for_confirmation = 1
    );
END;

-- 被动规则的后台求值审计。(traffic_id, pack_id, pack_version) 是幂等键：
-- 求值在事务外完成，写库时靠它保证失败可重试、重启不会重复建 Finding。
CREATE TABLE IF NOT EXISTS rule_evaluations (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id    INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    traffic_id    INTEGER NOT NULL REFERENCES traffic(id) ON DELETE CASCADE,
    pack_id       TEXT NOT NULL,
    pack_version  TEXT NOT NULL,
    status        TEXT NOT NULL
                  CHECK(status IN ('completed', 'timed_out', 'pack_disabled')),
    hit_count     INTEGER NOT NULL DEFAULT 0 CHECK(hit_count >= 0),
    finding_count INTEGER NOT NULL DEFAULT 0 CHECK(finding_count >= 0),
    duration_ms   INTEGER NOT NULL DEFAULT 0 CHECK(duration_ms >= 0),
    diagnostics   TEXT NOT NULL DEFAULT '[]'
                  CHECK(json_valid(diagnostics) AND json_type(diagnostics) = 'array'),
    created_at    TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    UNIQUE(traffic_id, pack_id, pack_version)
);
CREATE INDEX IF NOT EXISTS idx_rule_evaluations_traffic
    ON rule_evaluations(traffic_id, id);

-- 每个升级为 Finding 的规则命中都留下独立快照。Finding 的稳定身份不包含规则
-- 补丁版本，因此补丁包再次命中同一流量时仍可在这里看到新版本与新证据。
CREATE TABLE IF NOT EXISTS finding_rule_hits (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id          INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    evaluation_id       INTEGER NOT NULL REFERENCES rule_evaluations(id) ON DELETE CASCADE,
    traffic_id          INTEGER NOT NULL REFERENCES traffic(id) ON DELETE CASCADE,
    pack_id             TEXT NOT NULL CHECK(length(trim(pack_id)) BETWEEN 1 AND 200),
    pack_version        TEXT NOT NULL CHECK(length(pack_version) <= 120),
    rule_id             TEXT NOT NULL CHECK(length(trim(rule_id)) BETWEEN 1 AND 200),
    rule_version        TEXT NOT NULL CHECK(length(trim(rule_version)) BETWEEN 1 AND 120),
    field_path          TEXT NOT NULL CHECK(length(field_path) BETWEEN 1 AND 1000),
    evidence            TEXT NOT NULL CHECK(length(evidence) <= 2000),
    confidence          INTEGER NOT NULL CHECK(confidence BETWEEN 0 AND 100),
    incomplete_evidence INTEGER NOT NULL DEFAULT 0
                        CHECK(incomplete_evidence IN (0, 1)),
    hit_fingerprint     TEXT NOT NULL CHECK(length(hit_fingerprint) = 64),
    created_at          TEXT NOT NULL DEFAULT (
                            strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                        ),
    UNIQUE(evaluation_id, hit_fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_finding_rule_hits_finding
    ON finding_rule_hits(finding_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_finding_rule_hits_evaluation
    ON finding_rule_hits(evaluation_id, id);

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

-- 版本化测试计划提案。AI 输出先持久化为不可直接执行的 proposal，
-- 只有显式确认后才由后端事务合并到当前计划。
CREATE TABLE IF NOT EXISTS task_plan_proposals (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id        INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    proposal_key      TEXT NOT NULL,
    operation         TEXT NOT NULL DEFAULT 'generate'
                      CHECK(operation IN ('generate', 'expand', 'alternative')),
    target_node_id    INTEGER,
    base_revision     INTEGER NOT NULL DEFAULT 0 CHECK(base_revision >= 0),
    analysis_run_id   INTEGER REFERENCES analysis_runs(id) ON DELETE SET NULL,
    status            TEXT NOT NULL DEFAULT 'pending'
                      CHECK(status IN ('pending', 'applied', 'rejected', 'superseded')),
    proposed_plan     TEXT NOT NULL DEFAULT '{"phases":[]}'
                      CHECK(json_valid(proposed_plan) AND json_type(proposed_plan) = 'object'),
    diff_json         TEXT NOT NULL DEFAULT '{}'
                      CHECK(json_valid(diff_json) AND json_type(diff_json) = 'object'),
    created_at        TEXT NOT NULL DEFAULT (
                          strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                      ),
    applied_at        TEXT,
    UNIQUE(project_id, proposal_key)
);
CREATE INDEX IF NOT EXISTS idx_task_plan_proposals_project
    ON task_plan_proposals(project_id, status, id);

CREATE TABLE IF NOT EXISTS task_plan_delete_guards (
    project_id INTEGER PRIMARY KEY
);

CREATE TRIGGER IF NOT EXISTS trg_project_prepare_task_plan_delete
BEFORE DELETE ON projects
BEGIN
    INSERT OR IGNORE INTO task_plan_delete_guards(project_id) VALUES(OLD.id);
END;

CREATE TRIGGER IF NOT EXISTS trg_project_finish_task_plan_delete
AFTER DELETE ON projects
BEGIN
    DELETE FROM task_plan_delete_guards WHERE project_id=OLD.id;
END;

-- 每个项目只有一个当前测试计划头；节点状态和关系保存在下方规范化表中。
CREATE TABLE IF NOT EXISTS test_plans (
    project_id               INTEGER PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    revision                 INTEGER NOT NULL DEFAULT 0 CHECK(revision >= 0),
    needs_update             INTEGER NOT NULL DEFAULT 0 CHECK(needs_update IN (0, 1)),
    update_reason            TEXT NOT NULL DEFAULT '',
    last_applied_proposal_id INTEGER REFERENCES task_plan_proposals(id) ON DELETE SET NULL,
    created_at               TEXT NOT NULL DEFAULT (
                                 strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                             ),
    updated_at               TEXT NOT NULL DEFAULT (
                                 strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                             )
);

CREATE TABLE IF NOT EXISTS task_plan_revisions (
    project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    revision    INTEGER NOT NULL CHECK(revision > 0),
    proposal_id INTEGER REFERENCES task_plan_proposals(id) ON DELETE SET NULL,
    actor       TEXT NOT NULL,
    summary     TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (
                    strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                ),
    PRIMARY KEY(project_id, revision)
);

-- 测试计划节点。stable_key 是跨 proposal 匹配身份；人工节点由插入触发器
-- 生成稳定键。priority 数字越小越优先（0 为最高）。
CREATE TABLE IF NOT EXISTS task_nodes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    parent_id       INTEGER REFERENCES task_nodes(id) ON DELETE CASCADE,
    stable_key      TEXT NOT NULL DEFAULT '',
    node_type       TEXT NOT NULL DEFAULT 'test'
                    CHECK(node_type IN ('hypothesis', 'test', 'decision', 'manual_note')),
    title           TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    why             TEXT NOT NULL DEFAULT '',
    how_to          TEXT NOT NULL DEFAULT '',
    verify_criteria TEXT NOT NULL DEFAULT '',
    priority        INTEGER NOT NULL DEFAULT 50 CHECK(priority BETWEEN 0 AND 100),
    required_role   TEXT NOT NULL DEFAULT '',
    required_session TEXT NOT NULL DEFAULT '',
    expected_observation TEXT NOT NULL DEFAULT '',
    actual_observation   TEXT NOT NULL DEFAULT '',
    blocker_reason       TEXT NOT NULL DEFAULT '',
    standard_references TEXT NOT NULL DEFAULT '[]'
                    CHECK(json_valid(standard_references) AND json_type(standard_references) = 'array'),
    source          TEXT NOT NULL DEFAULT 'manual'
                    CHECK(source IN ('ai', 'rule', 'manual')),
    locked_fields   TEXT NOT NULL DEFAULT '[]'
                    CHECK(json_valid(locked_fields) AND json_type(locked_fields) = 'array'),
    status          TEXT NOT NULL DEFAULT 'todo'
                    CHECK(status IN (
                        'todo', 'in_progress', 'done', 'blocked', 'skipped', 'not_applicable'
                    )),
    sort_order      INTEGER NOT NULL DEFAULT 0,
    archived        INTEGER NOT NULL DEFAULT 0 CHECK(archived IN (0, 1)),
    archived_at     TEXT,
    created_revision INTEGER NOT NULL DEFAULT 0 CHECK(created_revision >= 0),
    updated_revision INTEGER NOT NULL DEFAULT 0 CHECK(updated_revision >= 0),
    created_at      TEXT NOT NULL DEFAULT (
                        strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                    ),
    updated_at      TEXT NOT NULL DEFAULT (
                        strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                    ),
    CHECK(
        status NOT IN ('blocked', 'skipped', 'not_applicable')
        OR length(trim(blocker_reason)) > 0
    ),
    CHECK(
        (archived = 0 AND archived_at IS NULL)
        OR (archived = 1 AND archived_at IS NOT NULL)
    )
);
CREATE INDEX IF NOT EXISTS idx_task_nodes_project ON task_nodes(project_id, parent_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_task_nodes_stable_key
    ON task_nodes(project_id, stable_key)
    WHERE stable_key <> '';
CREATE INDEX IF NOT EXISTS idx_task_nodes_actionable
    ON task_nodes(project_id, archived, status, priority, created_at, id);

CREATE TRIGGER IF NOT EXISTS trg_task_nodes_assign_stable_key
AFTER INSERT ON task_nodes
WHEN NEW.stable_key = ''
BEGIN
    UPDATE task_nodes
    SET stable_key = 'manual:' || NEW.id
    WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_task_nodes_parent_same_project_insert
BEFORE INSERT ON task_nodes
WHEN NEW.parent_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'task parent must belong to the same project')
    WHERE NOT EXISTS(
        SELECT 1 FROM task_nodes
        WHERE id = NEW.parent_id AND project_id = NEW.project_id AND archived = 0
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_task_nodes_parent_same_project_update
BEFORE UPDATE OF parent_id, project_id ON task_nodes
WHEN NEW.parent_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'task parent must belong to the same project')
    WHERE NEW.parent_id = NEW.id OR NOT EXISTS(
        SELECT 1 FROM task_nodes
        WHERE id = NEW.parent_id AND project_id = NEW.project_id AND archived = 0
    );
END;

-- prerequisite 是独立于 parent 的执行依赖。递归检查拒绝自依赖和依赖环。
CREATE TABLE IF NOT EXISTS task_prerequisites (
    task_id         INTEGER NOT NULL REFERENCES task_nodes(id) ON DELETE CASCADE,
    prerequisite_id INTEGER NOT NULL REFERENCES task_nodes(id) ON DELETE CASCADE,
    created_at      TEXT NOT NULL DEFAULT (
                        strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                    ),
    PRIMARY KEY(task_id, prerequisite_id),
    CHECK(task_id <> prerequisite_id)
);
CREATE INDEX IF NOT EXISTS idx_task_prerequisites_reverse
    ON task_prerequisites(prerequisite_id, task_id);

CREATE TRIGGER IF NOT EXISTS trg_task_prerequisites_valid_insert
BEFORE INSERT ON task_prerequisites
BEGIN
    SELECT RAISE(ABORT, 'task prerequisite must belong to the same active project')
    WHERE NOT EXISTS(
        SELECT 1
        FROM task_nodes task
        JOIN task_nodes prerequisite
          ON prerequisite.id = NEW.prerequisite_id
         AND prerequisite.project_id = task.project_id
        WHERE task.id = NEW.task_id
          AND task.archived = 0
          AND prerequisite.archived = 0
    );
    SELECT RAISE(ABORT, 'task prerequisite cycle')
    WHERE EXISTS(
        WITH RECURSIVE dependencies(id) AS (
            SELECT prerequisite_id
            FROM task_prerequisites
            WHERE task_id = NEW.prerequisite_id
            UNION
            SELECT edge.prerequisite_id
            FROM task_prerequisites edge
            JOIN dependencies ON edge.task_id = dependencies.id
        )
        SELECT 1 FROM dependencies WHERE id = NEW.task_id
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_task_prerequisites_immutable_update
BEFORE UPDATE ON task_prerequisites
BEGIN
    SELECT RAISE(ABORT, 'replace task prerequisite rows instead of updating them');
END;

-- Evidence 只通过关系关联，不复制不可变快照。
CREATE TABLE IF NOT EXISTS task_evidence (
    task_id      INTEGER NOT NULL REFERENCES task_nodes(id) ON DELETE CASCADE,
    evidence_id  INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    linked_at    TEXT NOT NULL DEFAULT (
                     strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                 ),
    PRIMARY KEY (task_id, evidence_id)
);
CREATE INDEX IF NOT EXISTS idx_task_evidence_evidence
    ON task_evidence(evidence_id, task_id);

CREATE TRIGGER IF NOT EXISTS trg_task_evidence_same_project_insert
BEFORE INSERT ON task_evidence
BEGIN
    SELECT RAISE(ABORT, 'task and evidence must belong to the same project')
    WHERE (
        SELECT project_id FROM task_nodes WHERE id = NEW.task_id
    ) <> (
        SELECT project_id FROM evidence WHERE id = NEW.evidence_id
    );
END;

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

-- 测试计划节点与 Finding 双向关联
CREATE TABLE IF NOT EXISTS task_findings (
    task_id    INTEGER NOT NULL REFERENCES task_nodes(id) ON DELETE CASCADE,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    PRIMARY KEY (task_id, finding_id)
);

CREATE TRIGGER IF NOT EXISTS trg_task_findings_same_project_insert
BEFORE INSERT ON task_findings
BEGIN
    SELECT RAISE(ABORT, 'task and active finding must belong to the same project')
    WHERE NOT EXISTS (
        SELECT 1
        FROM task_nodes task
        JOIN findings finding ON finding.id = NEW.finding_id
        WHERE task.id = NEW.task_id
          AND task.project_id = finding.project_id
          AND finding.status <> 'rejected'
    );
END;

-- 计划事件是 append-only 审计轨迹；同一 revision 可以记录多个节点变化。
CREATE TABLE IF NOT EXISTS task_plan_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    revision    INTEGER NOT NULL CHECK(revision >= 0),
    event_type  TEXT NOT NULL,
    proposal_id INTEGER REFERENCES task_plan_proposals(id) ON DELETE SET NULL,
    node_id     INTEGER REFERENCES task_nodes(id) ON DELETE CASCADE,
    details_json TEXT NOT NULL DEFAULT '{}'
                 CHECK(json_valid(details_json) AND json_type(details_json) = 'object'),
    actor       TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (
                    strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                )
);
CREATE INDEX IF NOT EXISTS idx_task_plan_events_project
    ON task_plan_events(project_id, revision, id);
CREATE INDEX IF NOT EXISTS idx_task_plan_events_node
    ON task_plan_events(node_id, id);

CREATE TRIGGER IF NOT EXISTS trg_task_plan_event_context_insert
BEFORE INSERT ON task_plan_events
BEGIN
    SELECT RAISE(ABORT, 'task plan event revision is outside the current project context')
    WHERE NOT EXISTS (
        SELECT 1
        FROM test_plans plan
        WHERE plan.project_id = NEW.project_id
          AND NEW.revision BETWEEN plan.revision AND plan.revision + 1
    );
    SELECT RAISE(ABORT, 'task plan event node must belong to its project')
    WHERE NEW.node_id IS NOT NULL
      AND NOT EXISTS (
          SELECT 1 FROM task_nodes
          WHERE id = NEW.node_id AND project_id = NEW.project_id
      );
    SELECT RAISE(ABORT, 'task plan event proposal must belong to its project')
    WHERE NEW.proposal_id IS NOT NULL
      AND NOT EXISTS (
          SELECT 1 FROM task_plan_proposals
          WHERE id = NEW.proposal_id AND project_id = NEW.project_id
      );
END;

CREATE TRIGGER IF NOT EXISTS trg_task_plan_events_immutable_update
BEFORE UPDATE ON task_plan_events
WHEN NOT EXISTS(
    SELECT 1 FROM task_plan_delete_guards WHERE project_id=OLD.project_id
)
BEGIN
    SELECT RAISE(ABORT, 'task plan events are immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_task_plan_events_immutable_delete
BEFORE DELETE ON task_plan_events
WHEN NOT EXISTS(
    SELECT 1 FROM task_plan_delete_guards WHERE project_id=OLD.project_id
)
BEGIN
    SELECT RAISE(ABORT, 'task plan events are immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_task_status_requires_event
BEFORE UPDATE OF status ON task_nodes
WHEN OLD.status <> NEW.status
BEGIN
    SELECT RAISE(ABORT, 'task status change requires an audit event')
    WHERE NOT EXISTS(
        SELECT 1
        FROM task_plan_events event
        WHERE event.id = (
            SELECT MAX(candidate.id)
             FROM task_plan_events candidate
             WHERE candidate.node_id = OLD.id
               AND candidate.project_id = OLD.project_id
         )
           AND event.node_id = OLD.id
           AND event.project_id = OLD.project_id
           AND event.revision = NEW.updated_revision
           AND event.revision = (
               SELECT revision FROM test_plans WHERE project_id = OLD.project_id
           )
           AND event.event_type = 'status_changed'
          AND json_extract(event.details_json, '$.from') = OLD.status
          AND json_extract(event.details_json, '$.to') = NEW.status
          AND (
              NEW.status NOT IN ('blocked', 'skipped', 'not_applicable')
              OR length(trim(json_extract(event.details_json, '$.reason'))) > 0
          )
    );
END;
