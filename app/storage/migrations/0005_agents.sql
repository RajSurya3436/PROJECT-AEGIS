-- 0005: agent runs (with a resumable checkpoint) and their step log

CREATE TABLE agent_runs (
    run_id           TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(investigation_id) ON DELETE CASCADE,
    status           TEXT NOT NULL,
    model            TEXT NOT NULL,
    model_calls      INTEGER NOT NULL DEFAULT 0,
    tool_calls       INTEGER NOT NULL DEFAULT 0,
    checkpoint_json  TEXT NOT NULL DEFAULT '{}',
    assessment_json  TEXT,
    error            TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    finished_at      TEXT
);

CREATE INDEX idx_agent_runs_investigation ON agent_runs(investigation_id, created_at);
CREATE INDEX idx_agent_runs_status ON agent_runs(status);

-- One row per routing decision, model output, tool call/result or error. Payloads hold
-- validated, length-capped data; tool results are summaries, never raw provider bodies.
CREATE TABLE agent_steps (
    run_id      TEXT NOT NULL REFERENCES agent_runs(run_id) ON DELETE CASCADE,
    seq         INTEGER NOT NULL,
    role        TEXT NOT NULL,
    kind        TEXT NOT NULL,
    summary     TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}',
    duration_ms INTEGER,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (run_id, seq)
);
