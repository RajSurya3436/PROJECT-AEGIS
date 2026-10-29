-- 0003: reputation cache. Holds parsed, allowlisted summaries only: no raw responses, no keys.

CREATE TABLE reputation_cache (
    provider     TEXT NOT NULL,
    indicator    TEXT NOT NULL,
    found        INTEGER NOT NULL,
    signal       TEXT,
    summary_json TEXT NOT NULL DEFAULT '{}',
    queried_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    PRIMARY KEY (provider, indicator)
);

CREATE INDEX idx_reputation_cache_expires ON reputation_cache(expires_at);
