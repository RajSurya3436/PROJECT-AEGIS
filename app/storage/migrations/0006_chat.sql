-- 0006: analyst chat (every message and instruction) and run control requests

-- pause or stop requested for an executing run; the worker reads it between steps.
ALTER TABLE agent_runs ADD COLUMN control TEXT;

CREATE TABLE chat_messages (
    seq              INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id       TEXT NOT NULL UNIQUE,
    investigation_id TEXT NOT NULL REFERENCES investigations(investigation_id) ON DELETE CASCADE,
    author           TEXT NOT NULL,
    mode             TEXT NOT NULL,
    kind             TEXT NOT NULL,
    target_role      TEXT,
    content          TEXT NOT NULL,
    run_id           TEXT,
    -- directives only: pending until a run applies them, or discarded when the case closes
    status           TEXT,
    payload_json     TEXT NOT NULL DEFAULT '{}',
    created_at       TEXT NOT NULL,
    applied_at       TEXT
);

CREATE INDEX idx_chat_investigation ON chat_messages(investigation_id, seq);
CREATE INDEX idx_chat_pending ON chat_messages(investigation_id, status);
