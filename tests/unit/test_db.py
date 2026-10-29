from __future__ import annotations

import pytest

from app.storage.db import current_version, migrate, open_database, transaction


def test_migrations_apply_once_and_are_idempotent():
    conn = open_database(":memory:")
    assert current_version(conn) == 6
    assert migrate(conn) == []
    tables = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"events", "data_sources", "parse_errors", "app_settings", "schema_migrations"} <= tables
    assert {"detection_rules", "alerts", "alert_events", "local_iocs", "reputation_cache"} <= tables
    assert {"investigations", "evidence", "agent_runs", "agent_steps", "chat_messages"} <= tables


def test_foreign_keys_enforced():
    conn = open_database(":memory:")
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    with pytest.raises(Exception, match="FOREIGN KEY"):
        conn.execute(
            "INSERT INTO parse_errors (source_id, locator, error, raw_snippet, created_at)"
            " VALUES ('nope', 'l', 'e', 's', 'now')"
        )


def test_transaction_rolls_back_on_error():
    conn = open_database(":memory:")
    with pytest.raises(RuntimeError), transaction(conn):
        conn.execute(
            "INSERT INTO app_settings (key, value_json, updated_at) VALUES ('k', '1', 'now')"
        )
        raise RuntimeError("boom")
    assert conn.execute("SELECT COUNT(*) FROM app_settings").fetchone()[0] == 0
