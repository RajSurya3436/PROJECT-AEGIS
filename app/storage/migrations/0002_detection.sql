-- 0002: deterministic detection (rule settings, alerts, alert-event links, local IOCs)

CREATE TABLE detection_rules (
    rule_id     TEXT PRIMARY KEY,
    version     INTEGER NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    config_json TEXT NOT NULL DEFAULT '{}',
    updated_at  TEXT NOT NULL
);

CREATE TABLE alerts (
    alert_id     TEXT PRIMARY KEY,
    rule_id      TEXT NOT NULL,
    rule_version INTEGER NOT NULL,
    severity     TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'new',
    title        TEXT NOT NULL,
    explanation  TEXT NOT NULL,
    dedup_key    TEXT NOT NULL UNIQUE,
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);

CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_rule ON alerts(rule_id);
CREATE INDEX idx_alerts_first_seen ON alerts(first_seen);

CREATE TABLE alert_events (
    alert_id TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
    event_id TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    reason   TEXT NOT NULL,
    PRIMARY KEY (alert_id, event_id)
);

CREATE INDEX idx_alert_events_event ON alert_events(event_id);

CREATE TABLE local_iocs (
    indicator   TEXT NOT NULL,
    ioc_type    TEXT NOT NULL,
    source      TEXT NOT NULL,
    confidence  TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    added       TEXT,
    PRIMARY KEY (indicator, ioc_type)
);
