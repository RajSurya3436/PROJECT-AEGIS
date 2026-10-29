"""Investigations, their alert links, event scope and evidence (all SQL)."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime

from app.domain.enums import (
    Confidence,
    Disposition,
    EvidenceCategory,
    EvidenceSource,
    InvestigationStatus,
)
from app.domain.models import Evidence, Investigation, ScopeEvent
from app.storage.db import transaction, utc_now_iso

MAX_INVESTIGATION_ROWS = 1_000


def _dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


class InvestigationRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    # --- investigations --------------------------------------------------------------------

    def create(self, investigation_id: str, title: str, objective: str) -> None:
        now = utc_now_iso()
        self.conn.execute(
            "INSERT INTO investigations (investigation_id, title, objective, status, created_at,"
            " updated_at) VALUES (?, ?, ?, 'open', ?, ?)",
            (investigation_id, title, objective, now, now),
        )

    def get(self, investigation_id: str) -> Investigation | None:
        row = self.conn.execute(
            "SELECT * FROM investigations WHERE investigation_id = ?", (investigation_id,)
        ).fetchone()
        return self._row(row) if row else None

    def list(
        self, status: InvestigationStatus | None = None, limit: int = 200
    ) -> list[Investigation]:
        limit = min(max(limit, 1), MAX_INVESTIGATION_ROWS)
        if status:
            rows = self.conn.execute(
                "SELECT * FROM investigations WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                (status.value, limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM investigations ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._row(r) for r in rows]

    def count_by_status(self) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT status, COUNT(*) AS n FROM investigations GROUP BY status"
        ).fetchall()
        return {r["status"]: r["n"] for r in rows}

    def open_for_alert(self, alert_id: str) -> Investigation | None:
        row = self.conn.execute(
            "SELECT i.* FROM investigations i JOIN investigation_alerts ia"
            " ON ia.investigation_id = i.investigation_id"
            " WHERE ia.alert_id = ? AND i.status = 'open' ORDER BY i.created_at LIMIT 1",
            (alert_id,),
        ).fetchone()
        return self._row(row) if row else None

    def close(
        self,
        investigation_id: str,
        disposition: Disposition,
        confidence: Confidence,
        reason: str,
        evidence_ids: list[str],
    ) -> None:
        now = utc_now_iso()
        self.conn.execute(
            "UPDATE investigations SET status = 'closed', disposition = ?, confidence = ?,"
            " disposition_reason = ?, disposition_evidence_json = ?, closed_at = ?,"
            " updated_at = ? WHERE investigation_id = ?",
            (
                disposition.value,
                confidence.value,
                reason,
                json.dumps(evidence_ids),
                now,
                now,
                investigation_id,
            ),
        )

    def reopen(self, investigation_id: str) -> None:
        self.conn.execute(
            "UPDATE investigations SET status = 'open', disposition = NULL, confidence = NULL,"
            " disposition_reason = NULL, disposition_evidence_json = '[]', closed_at = NULL,"
            " updated_at = ? WHERE investigation_id = ?",
            (utc_now_iso(), investigation_id),
        )

    def touch(self, investigation_id: str) -> None:
        self.conn.execute(
            "UPDATE investigations SET updated_at = ? WHERE investigation_id = ?",
            (utc_now_iso(), investigation_id),
        )

    def _row(self, row: sqlite3.Row) -> Investigation:
        alert_ids = [
            r["alert_id"]
            for r in self.conn.execute(
                "SELECT alert_id FROM investigation_alerts WHERE investigation_id = ?"
                " ORDER BY added_at, alert_id",
                (row["investigation_id"],),
            ).fetchall()
        ]
        return Investigation(
            investigation_id=row["investigation_id"],
            title=row["title"],
            objective=row["objective"],
            status=InvestigationStatus(row["status"]),
            disposition=Disposition(row["disposition"]) if row["disposition"] else None,
            confidence=Confidence(row["confidence"]) if row["confidence"] else None,
            disposition_reason=row["disposition_reason"],
            disposition_evidence_ids=json.loads(row["disposition_evidence_json"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            closed_at=_dt(row["closed_at"]),
            alert_ids=alert_ids,
        )

    # --- alerts and scope ------------------------------------------------------------------

    def link_alert(self, investigation_id: str, alert_id: str) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO investigation_alerts (investigation_id, alert_id, added_at)"
            " VALUES (?, ?, ?)",
            (investigation_id, alert_id, utc_now_iso()),
        )

    def add_scope(
        self, investigation_id: str, event_ids: list[str], reason: str, added_by: str
    ) -> int:
        """Add events to the scope; events already in scope keep their first reason."""
        now = utc_now_iso()
        added = 0
        with transaction(self.conn):
            for event_id in event_ids:
                cur = self.conn.execute(
                    "INSERT OR IGNORE INTO investigation_events (investigation_id, event_id,"
                    " reason, added_by, added_at) VALUES (?, ?, ?, ?, ?)",
                    (investigation_id, event_id, reason, added_by, now),
                )
                added += cur.rowcount
        return added

    def scope(self, investigation_id: str) -> list[ScopeEvent]:
        rows = self.conn.execute(
            "SELECT ie.* FROM investigation_events ie JOIN events e ON e.event_id = ie.event_id"
            " WHERE ie.investigation_id = ? ORDER BY e.event_time, e.event_id",
            (investigation_id,),
        ).fetchall()
        return [
            ScopeEvent(
                event_id=r["event_id"],
                reason=r["reason"],
                added_by=r["added_by"],
                added_at=datetime.fromisoformat(r["added_at"]),
            )
            for r in rows
        ]

    def scope_ids(self, investigation_id: str) -> set[str]:
        rows = self.conn.execute(
            "SELECT event_id FROM investigation_events WHERE investigation_id = ?",
            (investigation_id,),
        ).fetchall()
        return {r["event_id"] for r in rows}

    def scope_count(self, investigation_id: str) -> int:
        return self.conn.execute(
            "SELECT COUNT(*) AS n FROM investigation_events WHERE investigation_id = ?",
            (investigation_id,),
        ).fetchone()["n"]

    # --- evidence --------------------------------------------------------------------------

    def add_evidence(self, evidence: Evidence) -> bool:
        """Insert; returns False when an identical item (same ID) already exists."""
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO evidence (evidence_id, investigation_id, category, source_type,"
            " source_ref, claim, event_ids_json, observed_at, collected_at, collected_by,"
            " provenance_json, reliability) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                evidence.evidence_id,
                evidence.investigation_id,
                evidence.category.value,
                evidence.source_type.value,
                evidence.source_ref,
                evidence.claim,
                json.dumps(evidence.event_ids),
                evidence.observed_at.isoformat() if evidence.observed_at else None,
                evidence.collected_at.isoformat(),
                evidence.collected_by,
                json.dumps(evidence.provenance, sort_keys=True),
                evidence.reliability,
            ),
        )
        return cur.rowcount == 1

    def evidence(self, investigation_id: str) -> list[Evidence]:
        rows = self.conn.execute(
            "SELECT * FROM evidence WHERE investigation_id = ? ORDER BY collected_at, evidence_id",
            (investigation_id,),
        ).fetchall()
        return [
            Evidence(
                evidence_id=r["evidence_id"],
                investigation_id=r["investigation_id"],
                category=EvidenceCategory(r["category"]),
                source_type=EvidenceSource(r["source_type"]),
                source_ref=r["source_ref"],
                claim=r["claim"],
                event_ids=json.loads(r["event_ids_json"]),
                observed_at=_dt(r["observed_at"]),
                collected_at=datetime.fromisoformat(r["collected_at"]),
                collected_by=r["collected_by"],
                provenance=json.loads(r["provenance_json"]),
                reliability=r["reliability"],
            )
            for r in rows
        ]
