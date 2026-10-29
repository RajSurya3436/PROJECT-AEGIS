-- 0001: data foundation (sources, events, parse errors, non-secret settings)

CREATE TABLE data_sources (
    source_id     TEXT PRIMARY KEY,
    source_type   TEXT NOT NULL,
    name          TEXT NOT NULL,
    enabled       INTEGER NOT NULL DEFAULT 1,
    status        TEXT NOT NULL DEFAULT 'idle',
    last_seen     TEXT,
    cursor_json   TEXT NOT NULL DEFAULT '{}',
    event_count   INTEGER NOT NULL DEFAULT 0,
    error_count   INTEGER NOT NULL DEFAULT 0,
    last_error    TEXT,
    created_at    TEXT NOT NULL
);

CREATE TABLE events (
    event_id        TEXT PRIMARY KEY,
    source_id       TEXT NOT NULL REFERENCES data_sources(source_id) ON DELETE CASCADE,
    source_locator  TEXT NOT NULL,
    event_time      TEXT NOT NULL,
    ingest_time     TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    user            TEXT,
    host            TEXT,
    src_ip          TEXT,
    dst_ip          TEXT,
    dst_port        INTEGER,
    process_name    TEXT,
    command_line    TEXT,
    parent_process  TEXT,
    outcome         TEXT NOT NULL,
    action          TEXT,
    message         TEXT,
    extra_json      TEXT NOT NULL DEFAULT '{}',
    raw_json        TEXT NOT NULL,
    parse_status    TEXT NOT NULL,
    schema_version  INTEGER NOT NULL
);

CREATE INDEX idx_events_time ON events(event_time);
CREATE INDEX idx_events_type_time ON events(event_type, event_time);
CREATE INDEX idx_events_user ON events(user);
CREATE INDEX idx_events_src_ip ON events(src_ip);
CREATE INDEX idx_events_dst_ip ON events(dst_ip);
CREATE INDEX idx_events_host ON events(host);
CREATE INDEX idx_events_source ON events(source_id);

CREATE TABLE parse_errors (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id    TEXT NOT NULL REFERENCES data_sources(source_id) ON DELETE CASCADE,
    locator      TEXT NOT NULL,
    error        TEXT NOT NULL,
    raw_snippet  TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    UNIQUE (source_id, locator, error)
);

CREATE TABLE app_settings (
    key         TEXT PRIMARY KEY,
    value_json  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
