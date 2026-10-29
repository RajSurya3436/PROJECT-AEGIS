"""Reputation cache. Timestamps are stored as UTC ISO strings with fixed precision, so string
comparison in SQL matches time order."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime

from app.domain.enums import ReputationStatus
from app.domain.models import ReputationResult


def iso_utc(value: datetime) -> str:
    return value.isoformat(timespec="seconds")


class ReputationCacheRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def get(self, provider: str, indicator: str, now: datetime) -> ReputationResult | None:
        """Return an unexpired entry as a ``cached`` result, or None."""
        row = self.conn.execute(
            "SELECT * FROM reputation_cache WHERE provider = ? AND indicator = ?"
            " AND expires_at > ?",
            (provider, indicator, iso_utc(now)),
        ).fetchone()
        if row is None:
            return None
        return ReputationResult(
            provider=row["provider"],
            indicator=row["indicator"],
            status=ReputationStatus.CACHED,
            found=bool(row["found"]),
            signal=row["signal"],
            summary=json.loads(row["summary_json"]),
            queried_at=datetime.fromisoformat(row["queried_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]),
        )

    def put(self, result: ReputationResult) -> None:
        if result.status is not ReputationStatus.FRESH:
            raise ValueError("only fresh provider results are cached")
        assert result.queried_at is not None and result.expires_at is not None
        self.conn.execute(
            "INSERT INTO reputation_cache (provider, indicator, found, signal, summary_json,"
            " queried_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
            " ON CONFLICT (provider, indicator) DO UPDATE SET found = excluded.found,"
            " signal = excluded.signal, summary_json = excluded.summary_json,"
            " queried_at = excluded.queried_at, expires_at = excluded.expires_at",
            (
                result.provider,
                result.indicator,
                int(bool(result.found)),
                result.signal,
                json.dumps(result.summary, sort_keys=True),
                iso_utc(result.queried_at),
                iso_utc(result.expires_at),
            ),
        )

    def stats(self, now: datetime) -> dict[str, dict[str, int]]:
        """Per provider: total entries and how many have expired."""
        rows = self.conn.execute(
            "SELECT provider, COUNT(*) AS total, SUM(expires_at <= ?) AS expired"
            " FROM reputation_cache GROUP BY provider ORDER BY provider",
            (iso_utc(now),),
        ).fetchall()
        return {r["provider"]: {"total": r["total"], "expired": r["expired"] or 0} for r in rows}

    def purge_expired(self, now: datetime) -> int:
        cur = self.conn.execute(
            "DELETE FROM reputation_cache WHERE expires_at <= ?", (iso_utc(now),)
        )
        return cur.rowcount

    def clear(self) -> int:
        return self.conn.execute("DELETE FROM reputation_cache").rowcount
