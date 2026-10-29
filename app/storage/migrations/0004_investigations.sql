-- 0004: investigations, their event scope and evidence

CREATE TABLE investigations (
    investigation_id    TEXT PRIMARY KEY,
    title               TEXT NOT NULL,
    objective           TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'open',
    disposition         TEXT,
    confidence          TEXT,
    disposition_reason  TEXT,
    disposition_evidence_json TEXT NOT NULL DEFAULT '[]',
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    closed_at           TEXT
);

CREATE INDEX idx_investigations_status ON investigations(status);

CREATE TABLE investigation_alerts (
    investigation_id TEXT NOT NULL REFERENCES investigations(investigation_id) ON DELETE CASCADE,
    alert_id         TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
    added_at         TEXT NOT NULL,
    PRIMARY KEY (investigation_id, alert_id)
);

CREATE INDEX idx_investigation_alerts_alert ON investigation_alerts(alert_id);

-- Events brought into the investigation, and why. Evidence may only cite these.
CREATE TABLE investigation_events (
    investigation_id TEXT NOT NULL REFERENCES investigations(investigation_id) ON DELETE CASCADE,
    event_id         TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    reason           TEXT NOT NULL,
    added_by         TEXT NOT NULL,
    added_at         TEXT NOT NULL,
    PRIMARY KEY (investigation_id, event_id)
);

CREATE TABLE evidence (
    evidence_id      TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(investigation_id) ON DELETE CASCADE,
    category         TEXT NOT NULL,
    source_type      TEXT NOT NULL,
    source_ref       TEXT NOT NULL,
    claim            TEXT NOT NULL,
    event_ids_json   TEXT NOT NULL DEFAULT '[]',
    observed_at      TEXT,
    collected_at     TEXT NOT NULL,
    collected_by     TEXT NOT NULL,
    provenance_json  TEXT NOT NULL DEFAULT '{}',
    reliability      TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_evidence_investigation ON evidence(investigation_id, collected_at);
