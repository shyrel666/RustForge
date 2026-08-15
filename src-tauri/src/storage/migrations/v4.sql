-- AI 安全评估 v2：目标驱动 mission、可信工具、分级审批与人工接力。
--
-- v3 assessment_runs 继续作为确定性的真实网络执行/证据层。mission 在目标请求
-- 获批之前不会创建 active run，因此持久化等待不会占用全局 socket 执行槽。

-- v3 的 planner 上限是 3；v2 预算档位需要真实支持 2/4/6。迁移器在整个
-- v4 事务期间临时关闭 FK enforcement，下面重建两个父表后会在提交前执行
-- foreign_key_check，任何关系漂移都会使整步回滚。
CREATE TABLE assessment_runs_v4 (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id            INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    status                TEXT NOT NULL DEFAULT 'queued'
                          CHECK(status IN (
                              'queued', 'discovering', 'planning', 'executing',
                              'verifying', 'completed', 'stopped', 'cancelled',
                              'failed', 'interrupted'
                          )),
    start_url             TEXT NOT NULL CHECK(length(trim(start_url)) BETWEEN 1 AND 4096),
    exact_origin          TEXT NOT NULL CHECK(length(trim(exact_origin)) BETWEEN 1 AND 1024),
    contract_json         TEXT NOT NULL CHECK(json_valid(contract_json)),
    contract_hash         TEXT NOT NULL CHECK(length(contract_hash) = 64),
    template_registry_hash TEXT NOT NULL CHECK(length(template_registry_hash) = 64),
    identity_a_profile_id INTEGER REFERENCES assessment_auth_profiles(id) ON DELETE SET NULL,
    identity_b_profile_id INTEGER REFERENCES assessment_auth_profiles(id) ON DELETE SET NULL,
    provider_id           TEXT NOT NULL CHECK(length(trim(provider_id)) BETWEEN 1 AND 120),
    model                 TEXT NOT NULL CHECK(length(trim(model)) BETWEEN 1 AND 240),
    tls_policy            TEXT NOT NULL DEFAULT 'strict'
                          CHECK(tls_policy IN ('strict', 'ignore_invalid')),
    request_budget        INTEGER NOT NULL CHECK(request_budget BETWEEN 1 AND 300),
    request_count         INTEGER NOT NULL DEFAULT 0
                          CHECK(request_count >= 0 AND request_count <= request_budget),
    discovery_budget      INTEGER NOT NULL CHECK(discovery_budget BETWEEN 0 AND 40),
    requests_per_second   REAL NOT NULL CHECK(requests_per_second > 0 AND requests_per_second <= 2),
    response_byte_budget  INTEGER NOT NULL DEFAULT 20971520
                          CHECK(response_byte_budget BETWEEN 1 AND 20971520),
    response_bytes_read   INTEGER NOT NULL DEFAULT 0
                          CHECK(response_bytes_read >= 0 AND response_bytes_read <= response_byte_budget),
    max_rounds            INTEGER NOT NULL DEFAULT 3 CHECK(max_rounds BETWEEN 1 AND 6),
    completed_rounds      INTEGER NOT NULL DEFAULT 0
                          CHECK(completed_rounds >= 0 AND completed_rounds <= max_rounds),
    stop_reason           TEXT NOT NULL DEFAULT '' CHECK(length(stop_reason) <= 2000),
    created_at            TEXT NOT NULL DEFAULT (
                              strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                          ),
    started_at            TEXT,
    ended_at              TEXT,
    CHECK(identity_a_profile_id IS NULL OR identity_a_profile_id <> identity_b_profile_id)
);
INSERT INTO assessment_runs_v4
SELECT * FROM assessment_runs;

CREATE TABLE assessment_rounds_v4 (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER NOT NULL REFERENCES assessment_runs(id) ON DELETE CASCADE,
    round_number    INTEGER NOT NULL CHECK(round_number BETWEEN 1 AND 6),
    status          TEXT NOT NULL
                    CHECK(status IN ('planning', 'valid', 'invalid', 'skipped', 'failed')),
    analysis_run_id INTEGER REFERENCES analysis_runs(id) ON DELETE SET NULL,
    input_hash      TEXT NOT NULL CHECK(length(input_hash) = 64),
    output_hash     TEXT CHECK(output_hash IS NULL OR length(output_hash) = 64),
    selected_checks INTEGER NOT NULL DEFAULT 0 CHECK(selected_checks BETWEEN 0 AND 12),
    rejection_json  TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(rejection_json)),
    created_at      TEXT NOT NULL DEFAULT (
                        strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                    ),
    completed_at    TEXT,
    UNIQUE(run_id, round_number)
);
INSERT INTO assessment_rounds_v4
SELECT * FROM assessment_rounds;

PRAGMA legacy_alter_table = ON;
ALTER TABLE assessment_rounds RENAME TO assessment_rounds_v3;
ALTER TABLE assessment_runs RENAME TO assessment_runs_v3;
ALTER TABLE assessment_runs_v4 RENAME TO assessment_runs;
ALTER TABLE assessment_rounds_v4 RENAME TO assessment_rounds;
DROP TABLE assessment_rounds_v3;
DROP TABLE assessment_runs_v3;
PRAGMA legacy_alter_table = OFF;

CREATE INDEX idx_assessment_runs_project
    ON assessment_runs(project_id, id DESC);
CREATE UNIQUE INDEX idx_assessment_runs_one_active
    ON assessment_runs((1))
    WHERE status IN ('queued', 'discovering', 'planning', 'executing', 'verifying');
CREATE INDEX idx_assessment_rounds_run
    ON assessment_rounds(run_id, round_number);

CREATE TRIGGER trg_assessment_run_profiles_same_project_insert
BEFORE INSERT ON assessment_runs
BEGIN
    SELECT RAISE(ABORT, 'assessment identity A must belong to its project')
    WHERE NEW.identity_a_profile_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM assessment_auth_profiles
        WHERE id = NEW.identity_a_profile_id AND project_id = NEW.project_id
    );
    SELECT RAISE(ABORT, 'assessment identity B must belong to its project')
    WHERE NEW.identity_b_profile_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM assessment_auth_profiles
        WHERE id = NEW.identity_b_profile_id AND project_id = NEW.project_id
    );
END;

CREATE TRIGGER trg_assessment_run_profiles_same_project_update
BEFORE UPDATE OF project_id, identity_a_profile_id, identity_b_profile_id ON assessment_runs
BEGIN
    SELECT RAISE(ABORT, 'assessment identity A must belong to its project')
    WHERE NEW.identity_a_profile_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM assessment_auth_profiles
        WHERE id = NEW.identity_a_profile_id AND project_id = NEW.project_id
    );
    SELECT RAISE(ABORT, 'assessment identity B must belong to its project')
    WHERE NEW.identity_b_profile_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM assessment_auth_profiles
        WHERE id = NEW.identity_b_profile_id AND project_id = NEW.project_id
    );
END;

CREATE TRIGGER trg_assessment_round_same_project_insert
BEFORE INSERT ON assessment_rounds
WHEN NEW.analysis_run_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'assessment round analysis must belong to its project')
    WHERE NOT EXISTS (
        SELECT 1
        FROM assessment_runs ar
        JOIN analysis_runs ai ON ai.project_id = ar.project_id
        WHERE ar.id = NEW.run_id AND ai.id = NEW.analysis_run_id
    );
END;

CREATE TRIGGER trg_assessment_run_status_requires_event
BEFORE UPDATE OF status ON assessment_runs
WHEN OLD.status <> NEW.status
BEGIN
    SELECT RAISE(ABORT, 'assessment status change requires an audit event')
    WHERE NOT EXISTS (
        SELECT 1 FROM assessment_events
        WHERE id = (SELECT MAX(id) FROM assessment_events WHERE run_id = OLD.id)
          AND run_id = OLD.id
          AND event_type = 'status_changed'
          AND old_value = OLD.status
          AND new_value = NEW.status
    );
END;

CREATE TABLE assessment_missions (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id            INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    title                 TEXT NOT NULL CHECK(length(trim(title)) BETWEEN 1 AND 160),
    goal                  TEXT NOT NULL CHECK(length(trim(goal)) BETWEEN 1 AND 12000),
    start_url             TEXT NOT NULL CHECK(length(trim(start_url)) BETWEEN 1 AND 4096),
    exact_origin          TEXT NOT NULL DEFAULT '' CHECK(length(exact_origin) <= 1024),
    status                TEXT NOT NULL DEFAULT 'draft'
                          CHECK(status IN (
                              'draft', 'awaiting_context_approval', 'queued',
                              'discovering', 'planning', 'awaiting_action_approval',
                              'executing', 'verifying', 'awaiting_manual_handoff',
                              'completed', 'stopped', 'cancelled', 'failed',
                              'interrupted'
                          )),
    autonomy_mode         TEXT NOT NULL DEFAULT 'smart'
                          CHECK(autonomy_mode IN ('manual', 'smart', 'automatic')),
    budget_profile        TEXT NOT NULL DEFAULT 'standard'
                          CHECK(budget_profile IN ('quick', 'standard', 'deep')),
    request_budget        INTEGER NOT NULL DEFAULT 120
                          CHECK(request_budget IN (40, 120, 300)),
    request_count         INTEGER NOT NULL DEFAULT 0
                          CHECK(request_count >= 0 AND request_count <= request_budget),
    max_planning_cycles   INTEGER NOT NULL DEFAULT 4
                          CHECK(max_planning_cycles IN (2, 4, 6)),
    completed_cycles      INTEGER NOT NULL DEFAULT 0
                          CHECK(completed_cycles >= 0
                                AND completed_cycles <= max_planning_cycles),
    requests_per_second   REAL NOT NULL DEFAULT 2.0
                          CHECK(requests_per_second > 0 AND requests_per_second <= 2),
    identity_a_profile_id INTEGER REFERENCES assessment_auth_profiles(id) ON DELETE SET NULL,
    identity_b_profile_id INTEGER REFERENCES assessment_auth_profiles(id) ON DELETE SET NULL,
    provider_id           TEXT NOT NULL CHECK(length(trim(provider_id)) BETWEEN 1 AND 120),
    model                 TEXT NOT NULL CHECK(length(trim(model)) BETWEEN 1 AND 240),
    tls_policy            TEXT NOT NULL DEFAULT 'strict'
                          CHECK(tls_policy IN ('strict', 'ignore_invalid')),
    include_recent_traffic INTEGER NOT NULL DEFAULT 0
                          CHECK(include_recent_traffic IN (0, 1)),
    contract_json         TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(contract_json)),
    contract_hash         TEXT NOT NULL CHECK(length(contract_hash) = 64),
    tool_registry_hash    TEXT NOT NULL CHECK(length(tool_registry_hash) = 64),
    permission_hash       TEXT NOT NULL CHECK(length(permission_hash) = 64),
    context_hash          TEXT CHECK(context_hash IS NULL OR length(context_hash) = 64),
    disclosure_manifest_json TEXT NOT NULL DEFAULT '[]'
                          CHECK(json_valid(disclosure_manifest_json)
                                AND json_type(disclosure_manifest_json) = 'array'),
    context_approved_hash TEXT
                          CHECK(context_approved_hash IS NULL
                                OR length(context_approved_hash) = 64),
    active_run_id         INTEGER REFERENCES assessment_runs(id) ON DELETE SET NULL,
    legacy_run_id         INTEGER UNIQUE REFERENCES assessment_runs(id) ON DELETE CASCADE,
    legacy                INTEGER NOT NULL DEFAULT 0 CHECK(legacy IN (0, 1)),
    revision              INTEGER NOT NULL DEFAULT 1 CHECK(revision > 0),
    pending_steering      INTEGER NOT NULL DEFAULT 0 CHECK(pending_steering IN (0, 1)),
    stop_reason           TEXT NOT NULL DEFAULT '' CHECK(length(stop_reason) <= 2000),
    created_at            TEXT NOT NULL DEFAULT (
                              strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                          ),
    updated_at            TEXT NOT NULL DEFAULT (
                              strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                          ),
    started_at            TEXT,
    ended_at              TEXT,
    CHECK(identity_a_profile_id IS NULL
          OR identity_a_profile_id <> identity_b_profile_id),
    CHECK((legacy = 1 AND legacy_run_id IS NOT NULL)
          OR (legacy = 0 AND legacy_run_id IS NULL))
);
CREATE INDEX idx_assessment_missions_project
    ON assessment_missions(project_id, id DESC);
CREATE INDEX idx_assessment_missions_status
    ON assessment_missions(status, id);
CREATE UNIQUE INDEX idx_assessment_missions_one_network_active
    ON assessment_missions((1))
    WHERE status IN ('discovering', 'planning', 'executing', 'verifying');

CREATE TABLE assessment_messages (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    mission_id          INTEGER NOT NULL
                        REFERENCES assessment_missions(id) ON DELETE CASCADE,
    role                TEXT NOT NULL
                        CHECK(role IN ('user', 'assistant', 'system', 'action')),
    message_kind        TEXT NOT NULL
                        CHECK(message_kind IN (
                            'goal', 'follow_up', 'summary', 'status', 'approval',
                            'result', 'error', 'handoff'
                        )),
    content             TEXT NOT NULL CHECK(length(content) <= 16000),
    content_hash        TEXT NOT NULL CHECK(length(content_hash) = 64),
    old_value           TEXT,
    new_value           TEXT,
    details_json        TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(details_json)),
    redaction_manifest_json TEXT NOT NULL DEFAULT '[]'
                        CHECK(json_valid(redaction_manifest_json)
                              AND json_type(redaction_manifest_json) = 'array'),
    revision            INTEGER NOT NULL CHECK(revision > 0),
    created_at          TEXT NOT NULL DEFAULT (
                            strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                        )
);
CREATE INDEX idx_assessment_messages_mission
    ON assessment_messages(mission_id, id);

CREATE TABLE assessment_workstreams (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    mission_id     INTEGER NOT NULL REFERENCES assessment_missions(id) ON DELETE CASCADE,
    parent_id      INTEGER REFERENCES assessment_workstreams(id) ON DELETE CASCADE,
    stable_key     TEXT NOT NULL CHECK(length(trim(stable_key)) BETWEEN 1 AND 120),
    title          TEXT NOT NULL CHECK(length(trim(title)) BETWEEN 1 AND 160),
    objective      TEXT NOT NULL DEFAULT '' CHECK(length(objective) <= 2000),
    status         TEXT NOT NULL DEFAULT 'pending'
                   CHECK(status IN (
                       'pending', 'in_progress', 'awaiting_human', 'completed',
                       'skipped', 'failed', 'cancelled'
                   )),
    sort_order     INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT NOT NULL DEFAULT (
                       strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                   ),
    updated_at     TEXT NOT NULL DEFAULT (
                       strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                   ),
    UNIQUE(mission_id, stable_key)
);
CREATE INDEX idx_assessment_workstreams_mission
    ON assessment_workstreams(mission_id, sort_order, id);

CREATE TABLE assessment_actions (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    mission_id            INTEGER NOT NULL
                          REFERENCES assessment_missions(id) ON DELETE CASCADE,
    workstream_id         INTEGER REFERENCES assessment_workstreams(id) ON DELETE SET NULL,
    tool_id               TEXT NOT NULL CHECK(length(trim(tool_id)) BETWEEN 1 AND 120),
    tool_version          TEXT NOT NULL CHECK(length(trim(tool_version)) BETWEEN 1 AND 40),
    execution_kind        TEXT NOT NULL
                          CHECK(execution_kind IN ('observe', 'safe_probe', 'manual_recipe')),
    risk_level            TEXT NOT NULL
                          CHECK(risk_level IN ('local', 'low', 'guarded', 'manual')),
    surface_id            TEXT CHECK(surface_id IS NULL
                                     OR length(trim(surface_id)) BETWEEN 1 AND 120),
    identity_mode         TEXT NOT NULL DEFAULT 'anonymous'
                          CHECK(identity_mode IN ('anonymous', 'a', 'b', 'a_vs_b')),
    parameter_json        TEXT NOT NULL DEFAULT '{}'
                          CHECK(json_valid(parameter_json)
                                AND json_type(parameter_json) = 'object'),
    rationale             TEXT NOT NULL CHECK(length(trim(rationale)) BETWEEN 1 AND 2000),
    expected_signal       TEXT NOT NULL CHECK(length(trim(expected_signal)) BETWEEN 1 AND 2000),
    request_cost          INTEGER NOT NULL DEFAULT 0 CHECK(request_cost BETWEEN 0 AND 8),
    permission_snapshot   TEXT NOT NULL
                          CHECK(permission_snapshot IN ('disabled', 'ask', 'execute')),
    permission_hash       TEXT NOT NULL CHECK(length(permission_hash) = 64),
    approval_status       TEXT NOT NULL DEFAULT 'pending'
                          CHECK(approval_status IN (
                              'not_required', 'pending', 'approved', 'rejected'
                          )),
    approval_source       TEXT NOT NULL DEFAULT 'policy'
                          CHECK(approval_source IN (
                              'policy', 'user', 'bulk_user', 'tool_override'
                          )),
    status                TEXT NOT NULL DEFAULT 'proposed'
                          CHECK(status IN (
                              'proposed', 'awaiting_approval', 'queued', 'executing',
                              'completed', 'manual_ready', 'manual_result_pending',
                              'skipped', 'rejected', 'failed', 'cancelled'
                          )),
    policy_reason         TEXT NOT NULL DEFAULT '' CHECK(length(policy_reason) <= 2000),
    redacted_request_json TEXT CHECK(redacted_request_json IS NULL
                                     OR json_valid(redacted_request_json)),
    request_hash          TEXT CHECK(request_hash IS NULL OR length(request_hash) = 64),
    redacted_response_json TEXT CHECK(redacted_response_json IS NULL
                                      OR json_valid(redacted_response_json)),
    response_hash         TEXT CHECK(response_hash IS NULL OR length(response_hash) = 64),
    result_json           TEXT CHECK(result_json IS NULL OR json_valid(result_json)),
    result_hash           TEXT CHECK(result_hash IS NULL OR length(result_hash) = 64),
    revision              INTEGER NOT NULL DEFAULT 1 CHECK(revision > 0),
    created_at            TEXT NOT NULL DEFAULT (
                              strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                          ),
    approved_at           TEXT,
    started_at            TEXT,
    completed_at          TEXT
);
CREATE INDEX idx_assessment_actions_mission
    ON assessment_actions(mission_id, id);
CREATE INDEX idx_assessment_actions_waiting
    ON assessment_actions(mission_id, approval_status, status, id);

CREATE TABLE assessment_mission_resources (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    mission_id          INTEGER NOT NULL
                        REFERENCES assessment_missions(id) ON DELETE CASCADE,
    resource_type       TEXT NOT NULL
                        CHECK(resource_type IN (
                            'traffic', 'finding', 'assessment_run', 'openapi'
                        )),
    source_id           INTEGER,
    display_name        TEXT NOT NULL CHECK(length(trim(display_name)) BETWEEN 1 AND 240),
    media_type          TEXT NOT NULL DEFAULT '' CHECK(length(media_type) <= 120),
    summary_json        TEXT NOT NULL CHECK(json_valid(summary_json)),
    content_hash        TEXT NOT NULL CHECK(length(content_hash) = 64),
    created_at          TEXT NOT NULL DEFAULT (
                            strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                        ),
    CHECK((resource_type = 'openapi' AND source_id IS NULL)
          OR (resource_type <> 'openapi' AND source_id IS NOT NULL)),
    UNIQUE(mission_id, resource_type, source_id, content_hash)
);
CREATE INDEX idx_assessment_mission_resources_mission
    ON assessment_mission_resources(mission_id, id);

CREATE TABLE assessment_surfaces (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id                 INTEGER NOT NULL REFERENCES assessment_runs(id) ON DELETE CASCADE,
    surface_id             TEXT NOT NULL CHECK(length(trim(surface_id)) BETWEEN 1 AND 120),
    surface_kind           TEXT NOT NULL
                           CHECK(surface_kind IN (
                               'page', 'form', 'script', 'resource', 'api',
                               'traffic', 'redirect'
                           )),
    method                 TEXT NOT NULL
                           CHECK(method IN (
                               'GET', 'HEAD', 'OPTIONS', 'POST', 'PUT',
                               'PATCH', 'DELETE', 'TRACE'
                           )),
    path_shape             TEXT NOT NULL CHECK(length(path_shape) BETWEEN 1 AND 2048),
    query_parameter_names  TEXT NOT NULL DEFAULT '[]'
                           CHECK(json_valid(query_parameter_names)
                                 AND json_type(query_parameter_names)='array'),
    form_fields_json       TEXT NOT NULL DEFAULT '[]'
                           CHECK(json_valid(form_fields_json)
                                 AND json_type(form_fields_json)='array'),
    content_types_json     TEXT NOT NULL DEFAULT '[]'
                           CHECK(json_valid(content_types_json)
                                 AND json_type(content_types_json)='array'),
    identity_visibility_json TEXT NOT NULL DEFAULT '{}'
                           CHECK(json_valid(identity_visibility_json)
                                 AND json_type(identity_visibility_json)='object'),
    response_structure_hash TEXT
                           CHECK(response_structure_hash IS NULL
                                 OR length(response_structure_hash)=64),
    source_kinds_json      TEXT NOT NULL DEFAULT '[]'
                           CHECK(json_valid(source_kinds_json)
                                 AND json_type(source_kinds_json)='array'),
    safe_to_request        INTEGER NOT NULL DEFAULT 0 CHECK(safe_to_request IN (0,1)),
    concrete_count         INTEGER NOT NULL DEFAULT 1 CHECK(concrete_count > 0),
    created_at             TEXT NOT NULL DEFAULT (
                               strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                           ),
    updated_at             TEXT NOT NULL DEFAULT (
                               strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                           ),
    UNIQUE(run_id, surface_id)
);
CREATE INDEX idx_assessment_surfaces_run
    ON assessment_surfaces(run_id, surface_kind, id);

CREATE TABLE assessment_tool_permissions (
    project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    tool_id         TEXT NOT NULL CHECK(length(trim(tool_id)) BETWEEN 1 AND 120),
    decision        TEXT NOT NULL CHECK(decision IN ('disabled', 'ask', 'execute')),
    revision        INTEGER NOT NULL DEFAULT 1 CHECK(revision > 0),
    updated_at      TEXT NOT NULL DEFAULT (
                        strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                    ),
    PRIMARY KEY(project_id, tool_id)
);
CREATE INDEX idx_assessment_tool_permissions_project
    ON assessment_tool_permissions(project_id, tool_id);

CREATE TABLE assessment_action_checks (
    action_id   INTEGER NOT NULL REFERENCES assessment_actions(id) ON DELETE CASCADE,
    check_id    INTEGER NOT NULL UNIQUE REFERENCES assessment_checks(id) ON DELETE CASCADE,
    linked_at   TEXT NOT NULL DEFAULT (
                    strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                ),
    PRIMARY KEY(action_id, check_id)
);
CREATE INDEX idx_assessment_action_checks_check
    ON assessment_action_checks(check_id, action_id);

CREATE TABLE assessment_mission_runs (
    mission_id  INTEGER NOT NULL REFERENCES assessment_missions(id) ON DELETE CASCADE,
    run_id      INTEGER NOT NULL UNIQUE REFERENCES assessment_runs(id) ON DELETE CASCADE,
    cycle       INTEGER NOT NULL DEFAULT 1 CHECK(cycle BETWEEN 1 AND 6),
    linked_at   TEXT NOT NULL DEFAULT (
                    strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                ),
    PRIMARY KEY(mission_id, run_id)
);
CREATE INDEX idx_assessment_mission_runs_mission
    ON assessment_mission_runs(mission_id, cycle, run_id);

CREATE TABLE assessment_manual_handoffs (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id           INTEGER NOT NULL UNIQUE
                        REFERENCES assessment_actions(id) ON DELETE CASCADE,
    recipe_id           TEXT NOT NULL CHECK(length(trim(recipe_id)) BETWEEN 1 AND 120),
    recipe_version      TEXT NOT NULL CHECK(length(trim(recipe_version)) BETWEEN 1 AND 40),
    draft_json          TEXT NOT NULL CHECK(json_valid(draft_json)),
    draft_hash          TEXT NOT NULL CHECK(length(draft_hash) = 64),
    replay_session_id   INTEGER REFERENCES replay_sessions(id) ON DELETE SET NULL,
    replay_run_id       INTEGER REFERENCES replay_runs(id) ON DELETE RESTRICT,
    evidence_id         INTEGER REFERENCES evidence(id) ON DELETE RESTRICT,
    status              TEXT NOT NULL DEFAULT 'draft_created'
                        CHECK(status IN (
                            'draft_created', 'opened', 'sent', 'result_linked',
                            'cancelled'
                        )),
    created_at          TEXT NOT NULL DEFAULT (
                            strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                        ),
    updated_at          TEXT NOT NULL DEFAULT (
                            strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                        )
);
CREATE INDEX idx_assessment_manual_handoffs_status
    ON assessment_manual_handoffs(status, id);

-- Existing v3 runs are exposed as immutable legacy missions. No v2 action may
-- be added to them and the old task_nodes tree remains unrelated.
INSERT INTO assessment_missions(
    project_id, title, goal, start_url, exact_origin, status, autonomy_mode,
    budget_profile, request_budget, request_count, max_planning_cycles,
    completed_cycles, requests_per_second, identity_a_profile_id,
    identity_b_profile_id, provider_id, model, tls_policy,
    include_recent_traffic, contract_json, contract_hash, tool_registry_hash,
    permission_hash, context_hash, context_approved_hash, legacy_run_id,
    legacy, revision, stop_reason, created_at, updated_at, started_at, ended_at
)
SELECT
    project_id,
    '旧版评估 #' || id,
    '旧版固定轮次 AI 安全评估（只读）',
    start_url,
    exact_origin,
    status,
    'smart',
    CASE WHEN request_budget <= 40 THEN 'quick'
         WHEN request_budget <= 120 THEN 'standard' ELSE 'deep' END,
    CASE WHEN request_budget <= 40 THEN 40
         WHEN request_budget <= 120 THEN 120 ELSE 300 END,
    request_count,
    CASE WHEN max_rounds <= 2 THEN 2 WHEN max_rounds <= 4 THEN 4 ELSE 6 END,
    completed_rounds,
    requests_per_second,
    identity_a_profile_id,
    identity_b_profile_id,
    provider_id,
    model,
    tls_policy,
    CASE WHEN json_extract(contract_json, '$.includeRecentTraffic') = 1 THEN 1 ELSE 0 END,
    contract_json,
    contract_hash,
    template_registry_hash,
    template_registry_hash,
    contract_hash,
    contract_hash,
    id,
    1,
    1,
    stop_reason,
    created_at,
    COALESCE(ended_at, started_at, created_at),
    started_at,
    ended_at
FROM assessment_runs;

INSERT INTO assessment_mission_runs(mission_id, run_id, cycle)
SELECT m.id, m.legacy_run_id, 1
FROM assessment_missions m
WHERE m.legacy = 1;

INSERT INTO assessment_messages(
    mission_id, role, message_kind, content, content_hash, details_json, revision, created_at
)
SELECT
    m.id,
    'system',
    'summary',
    '此任务来自旧版 Phase 6 运行，仅支持只读查看与 legacy 报告。',
    m.contract_hash,
    json_object('legacyRunId', m.legacy_run_id),
    1,
    m.created_at
FROM assessment_missions m
WHERE m.legacy = 1;

-- Project/context isolation.
CREATE TRIGGER trg_assessment_mission_profiles_same_project_insert
BEFORE INSERT ON assessment_missions
BEGIN
    SELECT RAISE(ABORT, 'mission identity A must belong to its project')
    WHERE NEW.identity_a_profile_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM assessment_auth_profiles
        WHERE id = NEW.identity_a_profile_id AND project_id = NEW.project_id
    );
    SELECT RAISE(ABORT, 'mission identity B must belong to its project')
    WHERE NEW.identity_b_profile_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM assessment_auth_profiles
        WHERE id = NEW.identity_b_profile_id AND project_id = NEW.project_id
    );
    SELECT RAISE(ABORT, 'mission run must belong to its project')
    WHERE NEW.active_run_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM assessment_runs
        WHERE id = NEW.active_run_id AND project_id = NEW.project_id
    );
    SELECT RAISE(ABORT, 'legacy mission run must belong to its project')
    WHERE NEW.legacy_run_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM assessment_runs
        WHERE id = NEW.legacy_run_id AND project_id = NEW.project_id
    );
END;

CREATE TRIGGER trg_assessment_mission_profiles_same_project_update
BEFORE UPDATE OF project_id, identity_a_profile_id, identity_b_profile_id,
                 active_run_id, legacy_run_id ON assessment_missions
BEGIN
    SELECT RAISE(ABORT, 'mission identity A must belong to its project')
    WHERE NEW.identity_a_profile_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM assessment_auth_profiles
        WHERE id = NEW.identity_a_profile_id AND project_id = NEW.project_id
    );
    SELECT RAISE(ABORT, 'mission identity B must belong to its project')
    WHERE NEW.identity_b_profile_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM assessment_auth_profiles
        WHERE id = NEW.identity_b_profile_id AND project_id = NEW.project_id
    );
    SELECT RAISE(ABORT, 'mission run must belong to its project')
    WHERE NEW.active_run_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM assessment_runs
        WHERE id = NEW.active_run_id AND project_id = NEW.project_id
    );
    SELECT RAISE(ABORT, 'legacy mission run must belong to its project')
    WHERE NEW.legacy_run_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM assessment_runs
        WHERE id = NEW.legacy_run_id AND project_id = NEW.project_id
    );
END;

CREATE TRIGGER trg_assessment_workstream_parent_context_insert
BEFORE INSERT ON assessment_workstreams
WHEN NEW.parent_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'workstream parent must belong to its mission')
    WHERE NOT EXISTS (
        SELECT 1 FROM assessment_workstreams
        WHERE id = NEW.parent_id
          AND mission_id = NEW.mission_id
          AND parent_id IS NULL
    );
END;

CREATE TRIGGER trg_assessment_workstream_parent_context_update
BEFORE UPDATE OF mission_id, parent_id ON assessment_workstreams
WHEN NEW.parent_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'workstream parent must belong to its mission')
    WHERE NOT EXISTS (
        SELECT 1 FROM assessment_workstreams
        WHERE id = NEW.parent_id
          AND mission_id = NEW.mission_id
          AND parent_id IS NULL
    );
END;

CREATE TRIGGER trg_assessment_action_context_insert
BEFORE INSERT ON assessment_actions
BEGIN
    SELECT RAISE(ABORT, 'legacy missions cannot receive v2 actions')
    WHERE EXISTS (
        SELECT 1 FROM assessment_missions WHERE id = NEW.mission_id AND legacy = 1
    );
    SELECT RAISE(ABORT, 'action workstream must belong to its mission')
    WHERE NEW.workstream_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM assessment_workstreams
        WHERE id = NEW.workstream_id AND mission_id = NEW.mission_id
    );
    SELECT RAISE(ABORT, 'manual recipe cannot be auto-approved')
    WHERE NEW.execution_kind = 'manual_recipe'
      AND NEW.approval_status = 'not_required';
    SELECT RAISE(ABORT, 'disabled tool cannot be queued')
    WHERE NEW.permission_snapshot = 'disabled'
      AND NEW.status IN ('queued', 'executing', 'completed');
END;

CREATE TRIGGER trg_assessment_action_identity_immutable_update
BEFORE UPDATE OF mission_id, workstream_id, tool_id, tool_version,
                 execution_kind, risk_level, surface_id, identity_mode,
                 parameter_json, rationale, expected_signal, request_cost,
                 permission_hash ON assessment_actions
BEGIN
    SELECT RAISE(ABORT, 'assessment action definition is immutable');
END;

CREATE TRIGGER trg_assessment_resource_context_insert
BEFORE INSERT ON assessment_mission_resources
BEGIN
    SELECT RAISE(ABORT, 'resource traffic must belong to mission project')
    WHERE NEW.resource_type = 'traffic' AND NOT EXISTS (
        SELECT 1 FROM assessment_missions m
        JOIN traffic t ON t.project_id = m.project_id
        WHERE m.id = NEW.mission_id AND t.id = NEW.source_id
    );
    SELECT RAISE(ABORT, 'resource finding must belong to mission project')
    WHERE NEW.resource_type = 'finding' AND NOT EXISTS (
        SELECT 1 FROM assessment_missions m
        JOIN findings f ON f.project_id = m.project_id
        WHERE m.id = NEW.mission_id AND f.id = NEW.source_id
    );
    SELECT RAISE(ABORT, 'resource run must belong to mission project')
    WHERE NEW.resource_type = 'assessment_run' AND NOT EXISTS (
        SELECT 1 FROM assessment_missions m
        JOIN assessment_runs r ON r.project_id = m.project_id
        WHERE m.id = NEW.mission_id AND r.id = NEW.source_id
    );
END;

CREATE TRIGGER trg_assessment_action_check_context_insert
BEFORE INSERT ON assessment_action_checks
BEGIN
    SELECT RAISE(ABORT, 'action check must belong to a run of the same mission')
    WHERE NOT EXISTS (
        SELECT 1
        FROM assessment_actions a
        JOIN assessment_checks c ON c.id = NEW.check_id
        JOIN assessment_mission_runs mr
          ON mr.mission_id = a.mission_id AND mr.run_id = c.run_id
        WHERE a.id = NEW.action_id
    );
END;

CREATE TRIGGER trg_assessment_mission_run_context_insert
BEFORE INSERT ON assessment_mission_runs
BEGIN
    SELECT RAISE(ABORT, 'mission run must stay in one project')
    WHERE NOT EXISTS (
        SELECT 1 FROM assessment_missions m
        JOIN assessment_runs r ON r.project_id = m.project_id
        WHERE m.id = NEW.mission_id AND r.id = NEW.run_id
    );
END;

CREATE TRIGGER trg_assessment_handoff_context_insert
BEFORE INSERT ON assessment_manual_handoffs
BEGIN
    SELECT RAISE(ABORT, 'handoff requires a manual recipe action')
    WHERE NOT EXISTS (
        SELECT 1 FROM assessment_actions
        WHERE id = NEW.action_id AND execution_kind = 'manual_recipe'
    );
    SELECT RAISE(ABORT, 'handoff session must be manual and in mission project')
    WHERE NEW.replay_session_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM assessment_actions a
        JOIN assessment_missions m ON m.id = a.mission_id
        JOIN replay_sessions rs ON rs.project_id = m.project_id
        WHERE a.id = NEW.action_id
          AND rs.id = NEW.replay_session_id
          AND rs.owner_kind = 'manual'
    );
    SELECT RAISE(ABORT, 'handoff ReplayRun must be from its manual session and project')
    WHERE NEW.replay_run_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM assessment_actions a
        JOIN assessment_missions m ON m.id = a.mission_id
        JOIN replay_runs rr ON rr.project_id = m.project_id
        JOIN replay_sessions rs ON rs.id = rr.session_id
        WHERE a.id = NEW.action_id
          AND rr.id = NEW.replay_run_id
          AND rs.owner_kind = 'manual'
          AND (NEW.replay_session_id IS NULL OR rs.id = NEW.replay_session_id)
    );
    SELECT RAISE(ABORT, 'handoff Evidence must be in mission project')
    WHERE NEW.evidence_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM assessment_actions a
        JOIN assessment_missions m ON m.id = a.mission_id
        JOIN evidence e ON e.project_id = m.project_id
        WHERE a.id = NEW.action_id AND e.id = NEW.evidence_id
    );
END;

CREATE TRIGGER trg_assessment_handoff_context_update
BEFORE UPDATE OF replay_session_id, replay_run_id, evidence_id ON assessment_manual_handoffs
BEGIN
    SELECT RAISE(ABORT, 'handoff session must be manual and in mission project')
    WHERE NEW.replay_session_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM assessment_actions a
        JOIN assessment_missions m ON m.id = a.mission_id
        JOIN replay_sessions rs ON rs.project_id = m.project_id
        WHERE a.id = NEW.action_id
          AND rs.id = NEW.replay_session_id
          AND rs.owner_kind = 'manual'
    );
    SELECT RAISE(ABORT, 'handoff ReplayRun must be from its manual session and project')
    WHERE NEW.replay_run_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM assessment_actions a
        JOIN assessment_missions m ON m.id = a.mission_id
        JOIN replay_runs rr ON rr.project_id = m.project_id
        JOIN replay_sessions rs ON rs.id = rr.session_id
        WHERE a.id = NEW.action_id
          AND rr.id = NEW.replay_run_id
          AND rs.owner_kind = 'manual'
          AND (NEW.replay_session_id IS NULL OR rs.id = NEW.replay_session_id)
    );
    SELECT RAISE(ABORT, 'handoff Evidence must be in mission project')
    WHERE NEW.evidence_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM assessment_actions a
        JOIN assessment_missions m ON m.id = a.mission_id
        JOIN evidence e ON e.project_id = m.project_id
        WHERE a.id = NEW.action_id AND e.id = NEW.evidence_id
    );
END;

-- A status mutation is only legal when the caller appended the matching timeline
-- event first. This also gives restart recovery and optimistic revisions an audit trail.
CREATE TRIGGER trg_assessment_mission_status_requires_message
BEFORE UPDATE OF status ON assessment_missions
WHEN OLD.status <> NEW.status
BEGIN
    SELECT RAISE(ABORT, 'mission status change requires an audit message')
    WHERE NOT EXISTS (
        SELECT 1 FROM assessment_messages
        WHERE id = (SELECT MAX(id) FROM assessment_messages WHERE mission_id = OLD.id)
          AND mission_id = OLD.id
          AND message_kind = 'status'
          AND old_value = OLD.status
          AND new_value = NEW.status
          AND revision = OLD.revision + 1
    );
END;

CREATE TRIGGER trg_assessment_messages_immutable_update
BEFORE UPDATE ON assessment_messages
BEGIN
    SELECT RAISE(ABORT, 'assessment messages are immutable');
END;

CREATE TRIGGER trg_assessment_messages_immutable_delete
BEFORE DELETE ON assessment_messages
WHEN EXISTS(SELECT 1 FROM assessment_missions WHERE id = OLD.mission_id)
BEGIN
    SELECT RAISE(ABORT, 'assessment messages are immutable');
END;

CREATE TRIGGER trg_assessment_resources_immutable_update
BEFORE UPDATE ON assessment_mission_resources
BEGIN
    SELECT RAISE(ABORT, 'assessment mission resources are immutable');
END;

CREATE TRIGGER trg_assessment_resources_immutable_delete
BEFORE DELETE ON assessment_mission_resources
WHEN EXISTS(SELECT 1 FROM assessment_missions WHERE id = OLD.mission_id)
BEGIN
    SELECT RAISE(ABORT, 'assessment mission resources are immutable');
END;
