"""Repositories: the only place SQL is written. All queries are parameterised and every
column name that reaches SQL comes from a fixed allowlist, never from user or model input."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from app.domain.enums import EventType, Outcome, SourceStatus, SourceType
from app.domain.errors import InvalidFilterError
from app.domain.models import DataSource, NormalizedEvent, ParseErrorRecord
from app.storage.db import transaction, utc_now_iso

# Columns that may be used as exact-match filters or for related-event correlation.
FILTERABLE_FIELDS: frozenset[str] = frozenset(
    {
        "event_type",
        "user",
        "host",
        "src_ip",
        "dst_ip",
        "dst_port",
        "process_name",
        "outcome",
        "action",
        "source_id",
    }
)
CORRELATION_FIELDS: frozenset[str] = frozenset({"user", "host", "src_ip", "dst_ip"})
MAX_PAGE_SIZE = 500
MAX_QUERY_ROWS = 10_000  # cap for internal (detection) queries that are not paginated


@dataclass(frozen=True)
class EventFilters:
    equals: dict[str, Any] = field(default_factory=dict)
    start: datetime | None = None
    end: datetime | None = None
    text: str | None = None  # substring match on message/command_line

    def validate(self) -> None:
        unknown = set(self.equals) - FILTERABLE_FIELDS
        if unknown:
            raise InvalidFilterError(f"unsupported filter field(s): {sorted(unknown)}")
        if self.start and self.end and self.start > self.end:
            raise InvalidFilterError("start must be before end")


@dataclass(frozen=True)
class EventPage:
    events: list[NormalizedEvent]
    total: int
    page: int
    page_size: int


def _iso(value: datetime) -> str:
    return value.isoformat()


def _row_to_event(row: sqlite3.Row) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=row["event_id"],
        source_id=row["source_id"],
        source_locator=row["source_locator"],
        event_time=datetime.fromisoformat(row["event_time"]),
        ingest_time=datetime.fromisoformat(row["ingest_time"]),
        event_type=EventType(row["event_type"]),
        user=row["user"],
        host=row["host"],
        src_ip=row["src_ip"],
        dst_ip=row["dst_ip"],
        dst_port=row["dst_port"],
        process_name=row["process_name"],
        command_line=row["command_line"],
        parent_process=row["parent_process"],
        outcome=Outcome(row["outcome"]),
        action=row["action"],
        message=row["message"],
        extra=json.loads(row["extra_json"]),
        raw=json.loads(row["raw_json"]),
        parse_status=row["parse_status"],
        schema_version=row["schema_version"],
    )


class DataSourceRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def ensure(self, source_id: str, source_type: SourceType, name: str) -> DataSource:
        self.conn.execute(
            "INSERT OR IGNORE INTO data_sources (source_id, source_type, name, created_at)"
            " VALUES (?, ?, ?, ?)",
            (source_id, source_type.value, name, utc_now_iso()),
        )
        source = self.get(source_id)
        assert source is not None
        return source

    def get(self, source_id: str) -> DataSource | None:
        row = self.conn.execute(
            "SELECT * FROM data_sources WHERE source_id = ?", (source_id,)
        ).fetchone()
        return self._row(row) if row else None

    def list_all(self) -> list[DataSource]:
        rows = self.conn.execute("SELECT * FROM data_sources ORDER BY created_at").fetchall()
        return [self._row(r) for r in rows]

    def set_status(self, source_id: str, status: SourceStatus, error: str | None = None) -> None:
        self.conn.execute(
            "UPDATE data_sources SET status = ?, last_error = ? WHERE source_id = ?",
            (status.value, error, source_id),
        )

    def set_cursor(self, source_id: str, cursor: dict[str, Any]) -> None:
        """Where a live source (file tail) has read up to; survives restarts."""
        self.conn.execute(
            "UPDATE data_sources SET cursor_json = ? WHERE source_id = ?",
            (json.dumps(cursor, sort_keys=True), source_id),
        )

    def record_ingest(self, source_id: str, inserted: int, quarantined: int) -> None:
        self.conn.execute(
            "UPDATE data_sources SET last_seen = ?, event_count = event_count + ?,"
            " error_count = error_count + ? WHERE source_id = ?",
            (utc_now_iso(), inserted, quarantined, source_id),
        )

    @staticmethod
    def _row(row: sqlite3.Row) -> DataSource:
        return DataSource(
            source_id=row["source_id"],
            source_type=SourceType(row["source_type"]),
            name=row["name"],
            enabled=bool(row["enabled"]),
            status=SourceStatus(row["status"]),
            last_seen=datetime.fromisoformat(row["last_seen"]) if row["last_seen"] else None,
            cursor=json.loads(row["cursor_json"]),
            event_count=row["event_count"],
            error_count=row["error_count"],
            last_error=row["last_error"],
        )


class EventRepository:
    _INSERT_SQL = (
        "INSERT OR IGNORE INTO events (event_id, source_id, source_locator, event_time,"
        " ingest_time, event_type, user, host, src_ip, dst_ip, dst_port, process_name,"
        " command_line, parent_process, outcome, action, message, extra_json, raw_json,"
        " parse_status, schema_version)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def insert_many(self, events: list[NormalizedEvent]) -> list[str]:
        """Insert events, skipping ones whose ID already exists. Returns inserted IDs."""
        inserted: list[str] = []
        with transaction(self.conn):
            for e in events:
                cur = self.conn.execute(
                    self._INSERT_SQL,
                    (
                        e.event_id,
                        e.source_id,
                        e.source_locator,
                        _iso(e.event_time),
                        _iso(e.ingest_time),
                        e.event_type.value,
                        e.user,
                        e.host,
                        e.src_ip,
                        e.dst_ip,
                        e.dst_port,
                        e.process_name,
                        e.command_line,
                        e.parent_process,
                        e.outcome.value,
                        e.action,
                        e.message,
                        json.dumps(e.extra, sort_keys=True, default=str),
                        json.dumps(e.raw, sort_keys=True, default=str),
                        e.parse_status,
                        e.schema_version,
                    ),
                )
                if cur.rowcount == 1:
                    inserted.append(e.event_id)
        return inserted

    def get(self, event_id: str) -> NormalizedEvent | None:
        row = self.conn.execute("SELECT * FROM events WHERE event_id = ?", (event_id,)).fetchone()
        return _row_to_event(row) if row else None

    def get_many(self, event_ids: list[str]) -> list[NormalizedEvent]:
        if not event_ids:
            return []
        placeholders = ",".join("?" for _ in event_ids)
        rows = self.conn.execute(
            f"SELECT * FROM events WHERE event_id IN ({placeholders})"  # noqa: S608 - placeholders only
            " ORDER BY event_time, event_id",
            event_ids,
        ).fetchall()
        return [_row_to_event(r) for r in rows]

    def search(self, filters: EventFilters, page: int = 1, page_size: int = 50) -> EventPage:
        filters.validate()
        page = max(page, 1)
        page_size = min(max(page_size, 1), MAX_PAGE_SIZE)
        where, params = self._where(filters)
        total = self.conn.execute(
            f"SELECT COUNT(*) AS n FROM events{where}",  # noqa: S608 - allowlisted columns
            params,
        ).fetchone()["n"]
        rows = self.conn.execute(
            f"SELECT * FROM events{where} ORDER BY event_time, event_id LIMIT ? OFFSET ?",  # noqa: S608
            [*params, page_size, (page - 1) * page_size],
        ).fetchall()
        return EventPage([_row_to_event(r) for r in rows], total, page, page_size)

    def query(self, filters: EventFilters, limit: int = MAX_QUERY_ROWS) -> list[NormalizedEvent]:
        """All events matching ``filters`` in time order, capped at ``limit`` (detection use)."""
        filters.validate()
        where, params = self._where(filters)
        rows = self.conn.execute(
            f"SELECT * FROM events{where} ORDER BY event_time, event_id LIMIT ?",  # noqa: S608
            [*params, min(max(limit, 1), MAX_QUERY_ROWS)],
        ).fetchall()
        return [_row_to_event(r) for r in rows]

    def iter_batches(self, batch_size: int = 500) -> Iterator[list[NormalizedEvent]]:
        """Every stored event in time order, in batches (used to re-run detection)."""
        offset = 0
        while True:
            rows = self.conn.execute(
                "SELECT * FROM events ORDER BY event_time, event_id LIMIT ? OFFSET ?",
                (batch_size, offset),
            ).fetchall()
            if not rows:
                return
            yield [_row_to_event(r) for r in rows]
            offset += len(rows)

    def related(
        self,
        seed_event_id: str,
        window: timedelta,
        fields: list[str] | None = None,
        limit: int = 200,
    ) -> list[NormalizedEvent]:
        """Events sharing any of ``fields`` with the seed event within +/- ``window``."""
        fields = fields or sorted(CORRELATION_FIELDS)
        unknown = set(fields) - CORRELATION_FIELDS
        if unknown:
            raise InvalidFilterError(f"unsupported correlation field(s): {sorted(unknown)}")
        seed = self.get(seed_event_id)
        if seed is None:
            return []
        clauses: list[str] = []
        params: list[Any] = []
        for name in fields:
            value = getattr(seed, name)
            if value is not None:
                clauses.append(f"{name} = ?")
                params.append(value)
        if not clauses:
            return []
        sql = (
            "SELECT * FROM events WHERE event_id != ? AND event_time BETWEEN ? AND ?"  # noqa: S608
            f" AND ({' OR '.join(clauses)}) ORDER BY event_time, event_id LIMIT ?"
        )
        rows = self.conn.execute(
            sql,
            [
                seed_event_id,
                _iso(seed.event_time - window),
                _iso(seed.event_time + window),
                *params,
                min(limit, MAX_PAGE_SIZE),
            ],
        ).fetchall()
        return [_row_to_event(r) for r in rows]

    def count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"]

    def count_by_type(self) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT event_type, COUNT(*) AS n FROM events GROUP BY event_type ORDER BY event_type"
        ).fetchall()
        return {r["event_type"]: r["n"] for r in rows}

    def time_range(self) -> tuple[datetime, datetime] | None:
        row = self.conn.execute(
            "SELECT MIN(event_time) AS lo, MAX(event_time) AS hi FROM events"
        ).fetchone()
        if row["lo"] is None:
            return None
        return datetime.fromisoformat(row["lo"]), datetime.fromisoformat(row["hi"])

    @staticmethod
    def _where(filters: EventFilters) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        for name in sorted(filters.equals):
            value = filters.equals[name]
            if value is None or value == "":
                continue
            clauses.append(f"{name} = ?")
            params.append(value.value if hasattr(value, "value") else value)
        if filters.start:
            clauses.append("event_time >= ?")
            params.append(_iso(filters.start))
        if filters.end:
            clauses.append("event_time <= ?")
            params.append(_iso(filters.end))
        if filters.text:
            pattern = (
                "%"
                + filters.text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                + "%"
            )
            clauses.append("(message LIKE ? ESCAPE '\\' OR command_line LIKE ? ESCAPE '\\')")
            params.extend([pattern, pattern])
        return (" WHERE " + " AND ".join(clauses) if clauses else ""), params


class ParseErrorRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def add_many(self, errors: list[ParseErrorRecord]) -> int:
        added = 0
        with transaction(self.conn):
            for err in errors:
                cur = self.conn.execute(
                    "INSERT OR IGNORE INTO parse_errors"
                    " (source_id, locator, error, raw_snippet, created_at) VALUES (?, ?, ?, ?, ?)",
                    (err.source_id, err.locator, err.error, err.raw_snippet, utc_now_iso()),
                )
                added += cur.rowcount
        return added

    def list_recent(self, source_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        if source_id:
            rows = self.conn.execute(
                "SELECT * FROM parse_errors WHERE source_id = ? ORDER BY id DESC LIMIT ?",
                (source_id, limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM parse_errors ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) AS n FROM parse_errors").fetchone()["n"]


class AppSettingsRepository:
    """Non-secret runtime settings changed from the UI. API keys never go here."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def get(self, key: str, default: Any = None) -> Any:
        row = self.conn.execute(
            "SELECT value_json FROM app_settings WHERE key = ?", (key,)
        ).fetchone()
        return json.loads(row["value_json"]) if row else default

    def set(self, key: str, value: Any) -> None:
        self.conn.execute(
            "INSERT INTO app_settings (key, value_json, updated_at) VALUES (?, ?, ?)"
            " ON CONFLICT (key) DO UPDATE SET value_json = excluded.value_json,"
            " updated_at = excluded.updated_at",
            (key, json.dumps(value), utc_now_iso()),
        )
