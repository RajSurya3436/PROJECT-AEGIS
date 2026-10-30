"""Response recommendations (all SQL)."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Any

from app.domain.enums import (
    OPEN_RECOMMENDATION_STATUSES,
    RecommendationStatus,
    ResponseAction,
    RiskLevel,
)
from app.domain.models import Recommendation
from app.storage.db import utc_now_iso


def _dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


class RecommendationRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def add(self, rec: Recommendation) -> None:
        self.conn.execute(
            "INSERT INTO recommendations (recommendation_id, investigation_id, action, target,"
            " rationale, evidence_ids_json, risk, reversible, requires_approval, status,"
            " policy_notes_json, proposed_by, proposed_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                rec.recommendation_id,
                rec.investigation_id,
                rec.action.value,
                rec.target,
                rec.rationale,
                json.dumps(rec.evidence_ids),
                rec.risk.value,
                int(rec.reversible),
                int(rec.requires_approval),
                rec.status.value,
                json.dumps(rec.policy_notes),
                rec.proposed_by,
                rec.proposed_at.isoformat(),
            ),
        )

    def get(self, recommendation_id: str) -> Recommendation | None:
        row = self.conn.execute(
            "SELECT * FROM recommendations WHERE recommendation_id = ?", (recommendation_id,)
        ).fetchone()
        return self._row(row) if row else None

    def for_investigation(self, investigation_id: str) -> list[Recommendation]:
        rows = self.conn.execute(
            "SELECT * FROM recommendations WHERE investigation_id = ? ORDER BY seq",
            (investigation_id,),
        ).fetchall()
        return [self._row(r) for r in rows]

    def open_for(
        self, investigation_id: str, action: ResponseAction, target: str
    ) -> Recommendation | None:
        """The undecided recommendation for this action and target, if any."""
        statuses = sorted(s.value for s in OPEN_RECOMMENDATION_STATUSES)
        row = self.conn.execute(
            "SELECT * FROM recommendations WHERE investigation_id = ? AND action = ? AND"
            " target = ? AND status IN (?, ?) ORDER BY seq LIMIT 1",
            (investigation_id, action.value, target, *statuses),
        ).fetchone()
        return self._row(row) if row else None

    def decide(
        self,
        recommendation_id: str,
        expected: RecommendationStatus,
        status: RecommendationStatus,
        actor: str,
        note: str,
    ) -> bool:
        """Move from ``expected`` to ``status``; False if it was no longer ``expected``."""
        cur = self.conn.execute(
            "UPDATE recommendations SET status = ?, decided_by = ?, decided_at = ?,"
            " decision_note = ? WHERE recommendation_id = ? AND status = ?",
            (status.value, actor, utc_now_iso(), note, recommendation_id, expected.value),
        )
        return cur.rowcount == 1

    def record_simulation(
        self, recommendation_id: str, expected: RecommendationStatus, simulation: dict[str, Any]
    ) -> bool:
        cur = self.conn.execute(
            "UPDATE recommendations SET status = ?, simulation_json = ?, simulated_at = ?"
            " WHERE recommendation_id = ? AND status = ?",
            (
                RecommendationStatus.SIMULATED.value,
                json.dumps(simulation, sort_keys=True),
                utc_now_iso(),
                recommendation_id,
                expected.value,
            ),
        )
        return cur.rowcount == 1

    def count_open(self) -> int:
        statuses = sorted(s.value for s in OPEN_RECOMMENDATION_STATUSES)
        row = self.conn.execute(
            "SELECT COUNT(*) FROM recommendations WHERE status IN (?, ?)", statuses
        ).fetchone()
        return int(row[0])

    @staticmethod
    def _row(row: sqlite3.Row) -> Recommendation:
        return Recommendation(
            recommendation_id=row["recommendation_id"],
            investigation_id=row["investigation_id"],
            action=ResponseAction(row["action"]),
            target=row["target"],
            rationale=row["rationale"],
            evidence_ids=json.loads(row["evidence_ids_json"]),
            risk=RiskLevel(row["risk"]),
            reversible=bool(row["reversible"]),
            requires_approval=bool(row["requires_approval"]),
            status=RecommendationStatus(row["status"]),
            policy_notes=json.loads(row["policy_notes_json"]),
            proposed_by=row["proposed_by"],
            proposed_at=datetime.fromisoformat(row["proposed_at"]),
            decided_by=row["decided_by"],
            decided_at=_dt(row["decided_at"]),
            decision_note=row["decision_note"],
            simulation=json.loads(row["simulation_json"]) if row["simulation_json"] else None,
            simulated_at=_dt(row["simulated_at"]),
        )
