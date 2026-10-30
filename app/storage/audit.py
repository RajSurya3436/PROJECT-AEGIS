"""Audit events (all SQL). Append-only: there is no update or delete here, and triggers in
migration 0007 make the database refuse them too."""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.domain.models import AuditEvent
from app.storage.db import utc_now_iso

MAX_DETAILS_CHARS = 4_000
MAX_AUDIT_ROWS = 2_000


@dataclass(frozen=True)
class AuditFilters:
    investigation_id: str | None = None
    actor: str | None = None  # exact
    action_prefix: str | tuple[str, ...] | None = None  # "response.", or several
    outcome: str | None = None


class AuditRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def add(
        self,
        *,
        actor: str,
        action: str,
        target_type: str,
        target_id: str,
        investigation_id: str | None,
        outcome: str,
        details: dict[str, Any],
    ) -> str:
        audit_id = "aud-" + uuid.uuid4().hex[:16]
        text = json.dumps(details, sort_keys=True, default=str)
        if len(text) > MAX_DETAILS_CHARS:
            text = json.dumps({"truncated": True, "preview": text[: MAX_DETAILS_CHARS - 100]})
        self.conn.execute(
            "INSERT INTO audit_events (audit_id, at, actor, action, target_type, target_id,"
            " investigation_id, outcome, details_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                audit_id,
                utc_now_iso(),
                actor[:100],
                action[:100],
                target_type[:50],
                target_id[:200],
                investigation_id,
                outcome[:50],
                text,
            ),
        )
        return audit_id

    def list(self, filters: AuditFilters | None = None, limit: int = 500) -> list[AuditEvent]:
        """Newest first."""
        f = filters or AuditFilters()
        clauses, params = [], []
        if f.investigation_id:
            clauses.append("investigation_id = ?")
            params.append(f.investigation_id)
        if f.actor:
            clauses.append("actor = ?")
            params.append(f.actor)
        if f.action_prefix:
            prefixes = (f.action_prefix,) if isinstance(f.action_prefix, str) else f.action_prefix
            clauses.append("(" + " OR ".join(["substr(action, 1, ?) = ?"] * len(prefixes)) + ")")
            for prefix in prefixes:
                params += [len(prefix), prefix]
        if f.outcome:
            clauses.append("outcome = ?")
            params.append(f.outcome)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self.conn.execute(
            f"SELECT * FROM audit_events{where} ORDER BY seq DESC LIMIT ?",  # noqa: S608
            (*params, min(max(limit, 1), MAX_AUDIT_ROWS)),
        ).fetchall()
        return [self._row(r) for r in rows]

    def actors(self) -> list[str]:
        return [r[0] for r in self.conn.execute("SELECT DISTINCT actor FROM audit_events")]

    @staticmethod
    def _row(row: sqlite3.Row) -> AuditEvent:
        return AuditEvent(
            seq=row["seq"],
            audit_id=row["audit_id"],
            at=datetime.fromisoformat(row["at"]),
            actor=row["actor"],
            action=row["action"],
            target_type=row["target_type"],
            target_id=row["target_id"],
            investigation_id=row["investigation_id"],
            outcome=row["outcome"],
            details=json.loads(row["details_json"]),
        )
