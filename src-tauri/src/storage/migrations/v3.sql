-- AI 非破坏式安全评估。评估数据与旧的文字测试计划并存，互不复用语义。

CREATE TABLE assessment_auth_profiles (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id        INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    label             TEXT NOT NULL CHECK(length(trim(label)) BETWEEN 1 AND 80),
    source_traffic_id INTEGER REFERENCES traffic(id) ON DELETE SET NULL,
    header_name       TEXT NOT NULL
                      CHECK(header_name IN (
                          'Authorization', 'Cookie', 'X-API-Key', 'X-Auth-Token'
                      )),
    secret_revision   INTEGER NOT NULL DEFAULT 1 CHECK(secret_revision > 0),
    created_at        TEXT NOT NULL DEFAULT (
                          strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                      ),
    updated_at        TEXT NOT NULL DEFAULT (
                          strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                      ),
    UNIQUE(project_id, label)
);
CREATE INDEX idx_assessment_auth_profiles_project
    ON assessment_auth_profiles(project_id, id);

CREATE TABLE assessment_runs (
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
    max_rounds            INTEGER NOT NULL DEFAULT 3 CHECK(max_rounds BETWEEN 1 AND 3),
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
CREATE INDEX idx_assessment_runs_project
    ON assessment_runs(project_id, id DESC);
CREATE UNIQUE INDEX idx_assessment_runs_one_active
    ON assessment_runs((1))
    WHERE status IN ('queued', 'discovering', 'planning', 'executing', 'verifying');

CREATE TABLE assessment_rounds (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER NOT NULL REFERENCES assessment_runs(id) ON DELETE CASCADE,
    round_number    INTEGER NOT NULL CHECK(round_number BETWEEN 1 AND 3),
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
CREATE INDEX idx_assessment_rounds_run
    ON assessment_rounds(run_id, round_number);

CREATE TABLE assessment_endpoints (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id                INTEGER NOT NULL REFERENCES assessment_runs(id) ON DELETE CASCADE,
    endpoint_key          TEXT NOT NULL CHECK(length(endpoint_key) = 64),
    method                TEXT NOT NULL CHECK(method IN ('GET', 'HEAD')),
    url                   TEXT NOT NULL CHECK(length(trim(url)) BETWEEN 1 AND 4096),
    path                  TEXT NOT NULL CHECK(length(path) BETWEEN 1 AND 2048),
    query_parameter_names TEXT NOT NULL DEFAULT '[]'
                          CHECK(json_valid(query_parameter_names)
                                AND json_type(query_parameter_names) = 'array'),
    source_kind           TEXT NOT NULL
                          CHECK(source_kind IN ('start_url', 'crawl', 'redirect', 'traffic')),
    source_traffic_id     INTEGER REFERENCES traffic(id) ON DELETE SET NULL,
    status                INTEGER CHECK(status IS NULL OR status BETWEEN 100 AND 599),
    content_type          TEXT NOT NULL DEFAULT '' CHECK(length(content_type) <= 512),
    has_authentication    INTEGER NOT NULL DEFAULT 0
                          CHECK(has_authentication IN (0, 1)),
    passive_tags          TEXT NOT NULL DEFAULT '[]'
                          CHECK(json_valid(passive_tags) AND json_type(passive_tags) = 'array'),
    response_complete     INTEGER NOT NULL DEFAULT 1
                          CHECK(response_complete IN (0, 1)),
    resource_owner_profile_id INTEGER
                          REFERENCES assessment_auth_profiles(id) ON DELETE SET NULL,
    discovered_at         TEXT NOT NULL DEFAULT (
                              strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                          ),
    UNIQUE(run_id, endpoint_key)
);
CREATE INDEX idx_assessment_endpoints_run
    ON assessment_endpoints(run_id, id);

CREATE TABLE assessment_checks (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id            INTEGER NOT NULL REFERENCES assessment_runs(id) ON DELETE CASCADE,
    round_id          INTEGER REFERENCES assessment_rounds(id) ON DELETE SET NULL,
    endpoint_id       INTEGER REFERENCES assessment_endpoints(id) ON DELETE CASCADE,
    requested_endpoint_id TEXT NOT NULL
                      CHECK(length(trim(requested_endpoint_id)) BETWEEN 1 AND 80),
    template_id       TEXT NOT NULL CHECK(length(trim(template_id)) BETWEEN 1 AND 120),
    template_version  TEXT NOT NULL CHECK(length(trim(template_version)) BETWEEN 1 AND 40),
    parameter_name    TEXT,
    identity_mode     TEXT NOT NULL
                      CHECK(identity_mode IN ('anonymous', 'a', 'b', 'a_vs_b')),
    rationale         TEXT NOT NULL DEFAULT '' CHECK(length(rationale) <= 1000),
    policy_result     TEXT NOT NULL
                      CHECK(policy_result IN ('allowed', 'rejected', 'skipped')),
    policy_reason     TEXT NOT NULL DEFAULT '' CHECK(length(policy_reason) <= 1000),
    status            TEXT NOT NULL DEFAULT 'queued'
                      CHECK(status IN (
                          'queued', 'executing', 'verifying', 'completed',
                          'skipped', 'cancelled', 'failed'
                      )),
    request_cost      INTEGER NOT NULL DEFAULT 0 CHECK(request_cost BETWEEN 0 AND 4),
    created_at        TEXT NOT NULL DEFAULT (
                          strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                      ),
    completed_at      TEXT,
    UNIQUE(run_id, round_id, template_id, requested_endpoint_id, parameter_name, identity_mode)
);
CREATE INDEX idx_assessment_checks_run
    ON assessment_checks(run_id, id);

-- Assessment 会话不会出现在手动 Repeater API 中。
ALTER TABLE replay_sessions
ADD COLUMN owner_kind TEXT NOT NULL DEFAULT 'manual'
    CHECK(owner_kind IN ('manual', 'assessment'));
ALTER TABLE replay_sessions
ADD COLUMN assessment_run_id INTEGER REFERENCES assessment_runs(id) ON DELETE CASCADE;
CREATE INDEX idx_replay_sessions_assessment
    ON replay_sessions(assessment_run_id, id);

CREATE TABLE assessment_check_replays (
    check_id       INTEGER NOT NULL REFERENCES assessment_checks(id) ON DELETE CASCADE,
    replay_run_id  INTEGER NOT NULL REFERENCES replay_runs(id) ON DELETE RESTRICT,
    role           TEXT NOT NULL
                   CHECK(role IN (
                       'baseline', 'probe', 'anonymous', 'identity_a', 'identity_b',
                       'signature_probe', 'alg_none_probe', 'preflight'
                   )),
    linked_at      TEXT NOT NULL DEFAULT (
                       strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                   ),
    PRIMARY KEY(check_id, replay_run_id)
);
CREATE INDEX idx_assessment_check_replays_run
    ON assessment_check_replays(replay_run_id, check_id);

CREATE TABLE assessment_verifications (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    check_id          INTEGER NOT NULL UNIQUE
                      REFERENCES assessment_checks(id) ON DELETE CASCADE,
    verifier_id       TEXT NOT NULL CHECK(length(trim(verifier_id)) BETWEEN 1 AND 120),
    verifier_version  TEXT NOT NULL CHECK(length(trim(verifier_version)) BETWEEN 1 AND 40),
    verdict           TEXT NOT NULL
                      CHECK(verdict IN (
                          'confirmed', 'suspected', 'not_observed',
                          'inconclusive', 'skipped'
                      )),
    observations_json TEXT NOT NULL CHECK(json_valid(observations_json)),
    content_hash      TEXT NOT NULL CHECK(length(content_hash) = 64),
    created_at        TEXT NOT NULL DEFAULT (
                          strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                      )
);
CREATE INDEX idx_assessment_verifications_verdict
    ON assessment_verifications(verdict, id);

CREATE TABLE assessment_finding_links (
    verification_id INTEGER NOT NULL
                    REFERENCES assessment_verifications(id) ON DELETE CASCADE,
    finding_id      INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    relation        TEXT NOT NULL DEFAULT 'supports'
                    CHECK(relation IN ('supports', 'human_conflict')),
    linked_at       TEXT NOT NULL DEFAULT (
                        strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                    ),
    PRIMARY KEY(verification_id, finding_id)
);
CREATE INDEX idx_assessment_finding_links_finding
    ON assessment_finding_links(finding_id, verification_id);

CREATE TABLE assessment_coverage_gaps (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER NOT NULL REFERENCES assessment_runs(id) ON DELETE CASCADE,
    check_id    INTEGER REFERENCES assessment_checks(id) ON DELETE SET NULL,
    category    TEXT NOT NULL CHECK(length(trim(category)) BETWEEN 1 AND 80),
    reason_code TEXT NOT NULL CHECK(length(trim(reason_code)) BETWEEN 1 AND 120),
    detail      TEXT NOT NULL DEFAULT '' CHECK(length(detail) <= 2000),
    created_at  TEXT NOT NULL DEFAULT (
                    strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                )
);
CREATE INDEX idx_assessment_coverage_gaps_run
    ON assessment_coverage_gaps(run_id, id);

CREATE TABLE assessment_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id       INTEGER NOT NULL REFERENCES assessment_runs(id) ON DELETE CASCADE,
    check_id     INTEGER REFERENCES assessment_checks(id) ON DELETE SET NULL,
    event_type   TEXT NOT NULL CHECK(length(trim(event_type)) BETWEEN 1 AND 80),
    old_value    TEXT,
    new_value    TEXT,
    details_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(details_json)),
    created_at   TEXT NOT NULL DEFAULT (
                     strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')
                 )
);
CREATE INDEX idx_assessment_events_run
    ON assessment_events(run_id, id);

ALTER TABLE findings
ADD COLUMN producer TEXT NOT NULL DEFAULT 'passive_rule'
    CHECK(producer IN ('ai', 'passive_rule', 'safe_verifier'));
UPDATE findings SET producer = 'ai' WHERE source = 'ai';

ALTER TABLE finding_evidence
ADD COLUMN acceptance_kind TEXT NOT NULL DEFAULT 'human'
    CHECK(acceptance_kind IN ('human', 'safe_verifier'));
ALTER TABLE finding_evidence
ADD COLUMN verification_id INTEGER REFERENCES assessment_verifications(id) ON DELETE RESTRICT;
CREATE INDEX idx_finding_evidence_verification
    ON finding_evidence(verification_id, finding_id);

-- Project isolation.
CREATE TRIGGER trg_assessment_auth_source_project_insert
BEFORE INSERT ON assessment_auth_profiles
WHEN NEW.source_traffic_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'assessment auth source traffic must belong to its project')
    WHERE NOT EXISTS (
        SELECT 1 FROM traffic
        WHERE id = NEW.source_traffic_id AND project_id = NEW.project_id
    );
END;

CREATE TRIGGER trg_assessment_auth_source_project_update
BEFORE UPDATE OF source_traffic_id, project_id ON assessment_auth_profiles
WHEN NEW.source_traffic_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'assessment auth source traffic must belong to its project')
    WHERE NOT EXISTS (
        SELECT 1 FROM traffic
        WHERE id = NEW.source_traffic_id AND project_id = NEW.project_id
    );
END;

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

CREATE TRIGGER trg_assessment_endpoint_same_project_insert
BEFORE INSERT ON assessment_endpoints
BEGIN
    SELECT RAISE(ABORT, 'assessment endpoint traffic must belong to its project')
    WHERE NEW.source_traffic_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM assessment_runs ar
        JOIN traffic t ON t.project_id = ar.project_id
        WHERE ar.id = NEW.run_id AND t.id = NEW.source_traffic_id
    );
    SELECT RAISE(ABORT, 'assessment endpoint owner must belong to its project')
    WHERE NEW.resource_owner_profile_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM assessment_runs ar
        JOIN assessment_auth_profiles ap ON ap.project_id = ar.project_id
        WHERE ar.id = NEW.run_id AND ap.id = NEW.resource_owner_profile_id
    );
END;

CREATE TRIGGER trg_assessment_check_context_insert
BEFORE INSERT ON assessment_checks
BEGIN
    SELECT RAISE(ABORT, 'assessment check endpoint must belong to its run')
    WHERE NEW.endpoint_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM assessment_endpoints
        WHERE id = NEW.endpoint_id AND run_id = NEW.run_id
    );
    SELECT RAISE(ABORT, 'assessment check round must belong to its run')
    WHERE NEW.round_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM assessment_rounds
        WHERE id = NEW.round_id AND run_id = NEW.run_id
    );
END;

CREATE TRIGGER trg_assessment_replay_session_context_insert
BEFORE INSERT ON replay_sessions
BEGIN
    SELECT RAISE(ABORT, 'manual replay session cannot reference an assessment')
    WHERE NEW.owner_kind = 'manual' AND NEW.assessment_run_id IS NOT NULL;
    SELECT RAISE(ABORT, 'assessment replay session requires its assessment')
    WHERE NEW.owner_kind = 'assessment' AND (
        NEW.assessment_run_id IS NULL OR NOT EXISTS (
            SELECT 1 FROM assessment_runs
            WHERE id = NEW.assessment_run_id AND project_id = NEW.project_id
        )
    );
END;

CREATE TRIGGER trg_assessment_replay_session_context_update
BEFORE UPDATE OF owner_kind, assessment_run_id, project_id ON replay_sessions
BEGIN
    SELECT RAISE(ABORT, 'replay session ownership is immutable')
    WHERE OLD.owner_kind IS NOT NEW.owner_kind
       OR OLD.assessment_run_id IS NOT NEW.assessment_run_id;
    SELECT RAISE(ABORT, 'assessment replay session must stay in its project')
    WHERE NEW.owner_kind = 'assessment' AND NOT EXISTS (
        SELECT 1 FROM assessment_runs
        WHERE id = NEW.assessment_run_id AND project_id = NEW.project_id
    );
END;

CREATE TRIGGER trg_assessment_check_replay_context_insert
BEFORE INSERT ON assessment_check_replays
BEGIN
    SELECT RAISE(ABORT, 'assessment replay must belong to the check run')
    WHERE NOT EXISTS (
        SELECT 1
        FROM assessment_checks c
        JOIN assessment_runs ar ON ar.id = c.run_id
        JOIN replay_runs rr ON rr.project_id = ar.project_id
        JOIN replay_sessions rs ON rs.id = rr.session_id
        WHERE c.id = NEW.check_id
          AND rr.id = NEW.replay_run_id
          AND rs.owner_kind = 'assessment'
          AND rs.assessment_run_id = ar.id
    );
END;

CREATE TRIGGER trg_assessment_finding_link_context_insert
BEFORE INSERT ON assessment_finding_links
BEGIN
    SELECT RAISE(ABORT, 'assessment finding must belong to verification project')
    WHERE NOT EXISTS (
        SELECT 1
        FROM assessment_verifications v
        JOIN assessment_checks c ON c.id = v.check_id
        JOIN assessment_runs ar ON ar.id = c.run_id
        JOIN findings f ON f.project_id = ar.project_id
        WHERE v.id = NEW.verification_id AND f.id = NEW.finding_id
    );
END;

CREATE TRIGGER trg_assessment_gap_context_insert
BEFORE INSERT ON assessment_coverage_gaps
WHEN NEW.check_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'assessment coverage gap check must belong to its run')
    WHERE NOT EXISTS (
        SELECT 1 FROM assessment_checks
        WHERE id = NEW.check_id AND run_id = NEW.run_id
    );
END;

CREATE TRIGGER trg_assessment_event_context_insert
BEFORE INSERT ON assessment_events
WHEN NEW.check_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'assessment event check must belong to its run')
    WHERE NOT EXISTS (
        SELECT 1 FROM assessment_checks
        WHERE id = NEW.check_id AND run_id = NEW.run_id
    );
END;

-- State transitions require an append-only event written first.
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

CREATE TRIGGER trg_assessment_events_immutable_update
BEFORE UPDATE ON assessment_events
BEGIN
    SELECT RAISE(ABORT, 'assessment events are immutable');
END;

CREATE TRIGGER trg_assessment_events_immutable_delete
BEFORE DELETE ON assessment_events
WHEN EXISTS(SELECT 1 FROM assessment_runs WHERE id = OLD.run_id)
BEGIN
    SELECT RAISE(ABORT, 'assessment events are immutable');
END;

CREATE TRIGGER trg_assessment_verifications_immutable_update
BEFORE UPDATE ON assessment_verifications
BEGIN
    SELECT RAISE(ABORT, 'assessment verifications are immutable');
END;

CREATE TRIGGER trg_assessment_verifications_immutable_delete
BEFORE DELETE ON assessment_verifications
WHEN EXISTS(
    SELECT 1 FROM assessment_checks c
    JOIN assessment_runs ar ON ar.id = c.run_id
    JOIN projects p ON p.id = ar.project_id
    WHERE c.id = OLD.check_id
)
BEGIN
    SELECT RAISE(ABORT, 'assessment verifications are immutable');
END;

CREATE TRIGGER trg_assessment_finding_links_immutable_update
BEFORE UPDATE ON assessment_finding_links
BEGIN
    SELECT RAISE(ABORT, 'assessment finding links are immutable');
END;

CREATE TRIGGER trg_assessment_finding_links_immutable_delete
BEFORE DELETE ON assessment_finding_links
WHEN EXISTS(SELECT 1 FROM assessment_verifications WHERE id = OLD.verification_id)
BEGIN
    SELECT RAISE(ABORT, 'assessment finding links are immutable');
END;

-- A verifier acceptance is valid only for a confirmed immutable verification and
-- a ReplayRun linked to the same check. Human acceptance must not claim a verifier.
CREATE TRIGGER trg_finding_evidence_verifier_authority_insert
BEFORE INSERT ON finding_evidence
BEGIN
    SELECT RAISE(ABORT, 'human evidence cannot reference a safe verification')
    WHERE NEW.acceptance_kind = 'human' AND NEW.verification_id IS NOT NULL;
    SELECT RAISE(ABORT, 'safe verifier evidence requires a same-check verification replay')
    WHERE NEW.acceptance_kind = 'safe_verifier' AND NOT EXISTS (
        SELECT 1
        FROM assessment_verifications v
        JOIN assessment_finding_links afl
          ON afl.verification_id = v.id AND afl.finding_id = NEW.finding_id
        JOIN assessment_check_replays acr ON acr.check_id = v.check_id
        JOIN evidence e
          ON e.id = NEW.evidence_id
         AND e.source_type = 'replay_run'
         AND e.source_id = acr.replay_run_id
        WHERE v.id = NEW.verification_id
    );
    SELECT RAISE(ABORT, 'accepted safe verifier evidence requires a confirmed complete replay')
    WHERE NEW.acceptance_kind = 'safe_verifier' AND NEW.accepted = 1 AND NOT EXISTS (
        SELECT 1
        FROM assessment_verifications v
        JOIN assessment_finding_links afl
          ON afl.verification_id = v.id AND afl.finding_id = NEW.finding_id
        JOIN assessment_check_replays acr ON acr.check_id = v.check_id
        JOIN evidence e
          ON e.id = NEW.evidence_id
         AND e.source_type = 'replay_run'
         AND e.source_id = acr.replay_run_id
        WHERE v.id = NEW.verification_id
          AND v.verdict = 'confirmed'
          AND e.qualifies_for_confirmation = 1
    );
END;

CREATE TRIGGER trg_finding_evidence_verifier_authority_update
BEFORE UPDATE OF accepted, acceptance_kind, verification_id ON finding_evidence
BEGIN
    SELECT RAISE(ABORT, 'evidence acceptance authority is immutable')
    WHERE OLD.acceptance_kind IS NOT NEW.acceptance_kind
       OR OLD.verification_id IS NOT NEW.verification_id;
    SELECT RAISE(ABORT, 'safe verifier evidence requires a same-check verification replay')
    WHERE NEW.acceptance_kind = 'safe_verifier' AND NOT EXISTS (
        SELECT 1
        FROM assessment_verifications v
        JOIN assessment_finding_links afl
          ON afl.verification_id = v.id AND afl.finding_id = NEW.finding_id
        JOIN assessment_check_replays acr ON acr.check_id = v.check_id
        JOIN evidence e
          ON e.id = NEW.evidence_id
         AND e.source_type = 'replay_run'
         AND e.source_id = acr.replay_run_id
        WHERE v.id = NEW.verification_id
    );
    SELECT RAISE(ABORT, 'accepted safe verifier evidence requires a confirmed complete replay')
    WHERE NEW.acceptance_kind = 'safe_verifier' AND NEW.accepted = 1 AND NOT EXISTS (
        SELECT 1
        FROM assessment_verifications v
        JOIN assessment_finding_links afl
          ON afl.verification_id = v.id AND afl.finding_id = NEW.finding_id
        JOIN assessment_check_replays acr ON acr.check_id = v.check_id
        JOIN evidence e
          ON e.id = NEW.evidence_id
         AND e.source_type = 'replay_run'
         AND e.source_id = acr.replay_run_id
        WHERE v.id = NEW.verification_id
          AND v.verdict = 'confirmed'
          AND e.qualifies_for_confirmation = 1
    );
END;
