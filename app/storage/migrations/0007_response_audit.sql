-- 0007: response recommendations (simulation only) and the append-only audit log

CREATE TABLE recommendations (
    seq                INTEGER PRIMARY KEY AUTOINCREMENT,
    recommendation_id  TEXT NOT NULL UNIQUE,
    investigation_id   TEXT NOT NULL REFERENCES investigations(investigation_id) ON DELETE CASCADE,
    action             TEXT NOT NULL,
    target             TEXT NOT NULL,
    rationale          TEXT NOT NULL,
    evidence_ids_json  TEXT NOT NULL DEFAULT '[]',
    risk               TEXT NOT NULL,
    reversible         INTEGER NOT NULL,
    requires_approval  INTEGER NOT NULL,
    status             TEXT NOT NULL,
    policy_notes_json  TEXT NOT NULL DEFAULT '[]',
    proposed_by        TEXT NOT NULL,
    proposed_at        TEXT NOT NULL,
    decided_by         TEXT,
    decided_at         TEXT,
    decision_note      TEXT,
    simulation_json    TEXT,
    simulated_at       TEXT
);

CREATE INDEX idx_recommendations_investigation ON recommendations(investigation_id, seq);

CREATE TABLE audit_events (
    seq              INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id         TEXT NOT NULL UNIQUE,
    at               TEXT NOT NULL,
    actor            TEXT NOT NULL,
    action           TEXT NOT NULL,
    target_type      TEXT NOT NULL,
    target_id        TEXT NOT NULL,
    investigation_id TEXT,
    outcome          TEXT NOT NULL,
    details_json     TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_audit_investigation ON audit_events(investigation_id, seq);
CREATE INDEX idx_audit_action ON audit_events(action, seq);

-- Append-only: the app never edits or removes audit rows, and the database refuses to.
CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit log is append-only');
END;

CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit log is append-only');
END;
