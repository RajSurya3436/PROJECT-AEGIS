"""Agent runs and their step log (all SQL)."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Any

from app.domain.enums import ACTIVE_RUN_STATUSES, AgentRole, AgentRunStatus
from app.domain.models import AgentRun, AgentStep, Assessment
from app.storage.db import transaction, utc_now_iso

MAX_RUN_ROWS = 200
MAX_STEP_ROWS = 2_000
_ACTIVE = tuple(sorted(s.value for s in ACTIVE_RUN_STATUSES))
RESUMABLE = (
    AgentRunStatus.QUEUED.value,
    AgentRunStatus.INTERRUPTED.value,
    AgentRunStatus.STOPPED.value,
)


def _dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


class AgentRunRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def create(self, run_id: str, investigation_id: str, model: str) -> bool:
        """Insert a queued run unless the investigation already has an active one. The check
        and the insert share one transaction, so two starts cannot both succeed."""
        now = utc_now_iso()
        with transaction(self.conn):
            row = self.conn.execute(
                "SELECT 1 FROM agent_runs WHERE investigation_id = ? AND status IN (?, ?)",
                (investigation_id, *_ACTIVE),
            ).fetchone()
            if row is not None:
                return False
            self.conn.execute(
                "INSERT INTO agent_runs (run_id, investigation_id, status, model, created_at,"
                " updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (run_id, investigation_id, AgentRunStatus.QUEUED.value, model, now, now),
            )
        return True

    def get(self, run_id: str) -> AgentRun | None:
        row = self.conn.execute("SELECT * FROM agent_runs WHERE run_id = ?", (run_id,)).fetchone()
        return self._row(row) if row else None

    def for_investigation(self, investigation_id: str, limit: int = 50) -> list[AgentRun]:
        rows = self.conn.execute(
            "SELECT * FROM agent_runs WHERE investigation_id = ?"
            " ORDER BY created_at DESC, run_id LIMIT ?",
            (investigation_id, min(max(limit, 1), MAX_RUN_ROWS)),
        ).fetchall()
        return [self._row(r) for r in rows]

    def recent(self, limit: int = 10) -> list[AgentRun]:
        rows = self.conn.execute(
            "SELECT * FROM agent_runs ORDER BY created_at DESC, run_id LIMIT ?",
            (min(max(limit, 1), MAX_RUN_ROWS),),
        ).fetchall()
        return [self._row(r) for r in rows]

    def count_by_status(self) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT status, COUNT(*) AS n FROM agent_runs GROUP BY status"
        ).fetchall()
        return {r["status"]: r["n"] for r in rows}

    def set_status(self, run_id: str, status: AgentRunStatus) -> None:
        self.conn.execute(
            "UPDATE agent_runs SET status = ?, updated_at = ? WHERE run_id = ?",
            (status.value, utc_now_iso(), run_id),
        )

    def claim(self, run_id: str) -> bool:
        """Move a queued, interrupted or stopped run to running. False if it is in another
        state, or if a different run of the same investigation is active."""
        cur = self.conn.execute(
            "UPDATE agent_runs SET status = ?, error = NULL, finished_at = NULL, updated_at = ?"
            " WHERE run_id = ? AND status IN (?, ?, ?) AND NOT EXISTS (SELECT 1 FROM agent_runs"
            " other WHERE other.investigation_id = agent_runs.investigation_id"
            " AND other.run_id != agent_runs.run_id AND other.status IN (?, ?))",
            (
                AgentRunStatus.RUNNING.value,
                utc_now_iso(),
                run_id,
                *RESUMABLE,
                *_ACTIVE,
            ),
        )
        return cur.rowcount == 1

    def save_checkpoint(
        self, run_id: str, checkpoint: dict[str, Any], model_calls: int, tool_calls: int
    ) -> None:
        self.conn.execute(
            "UPDATE agent_runs SET checkpoint_json = ?, model_calls = ?, tool_calls = ?,"
            " updated_at = ? WHERE run_id = ?",
            (
                json.dumps(checkpoint, sort_keys=True),
                model_calls,
                tool_calls,
                utc_now_iso(),
                run_id,
            ),
        )

    def finish(
        self,
        run_id: str,
        status: AgentRunStatus,
        assessment: Assessment | None,
        error: str | None,
    ) -> None:
        now = utc_now_iso()
        self.conn.execute(
            "UPDATE agent_runs SET status = ?, assessment_json = ?, error = ?, updated_at = ?,"
            " finished_at = ? WHERE run_id = ?",
            (
                status.value,
                assessment.model_dump_json() if assessment else None,
                error,
                now,
                now,
                run_id,
            ),
        )

    def mark_interrupted(self) -> int:
        """Runs left active by an earlier process cannot still be running. Mark them
        resumable instead of letting them block their investigation forever."""
        cur = self.conn.execute(
            "UPDATE agent_runs SET status = ?, updated_at = ? WHERE status IN (?, ?)",
            (AgentRunStatus.INTERRUPTED.value, utc_now_iso(), *_ACTIVE),
        )
        return cur.rowcount

    @staticmethod
    def _row(row: sqlite3.Row) -> AgentRun:
        assessment = row["assessment_json"]
        return AgentRun(
            run_id=row["run_id"],
            investigation_id=row["investigation_id"],
            status=AgentRunStatus(row["status"]),
            model=row["model"],
            model_calls=row["model_calls"],
            tool_calls=row["tool_calls"],
            checkpoint=json.loads(row["checkpoint_json"]),
            assessment=Assessment.model_validate_json(assessment) if assessment else None,
            error=row["error"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            finished_at=_dt(row["finished_at"]),
        )

    # --- steps -----------------------------------------------------------------------------

    def add_step(
        self,
        run_id: str,
        role: AgentRole,
        kind: str,
        summary: str,
        payload: dict[str, Any] | None = None,
        duration_ms: int | None = None,
    ) -> int:
        with transaction(self.conn):
            seq = self.conn.execute(
                "SELECT COALESCE(MAX(seq), 0) + 1 AS n FROM agent_steps WHERE run_id = ?",
                (run_id,),
            ).fetchone()["n"]
            self.conn.execute(
                "INSERT INTO agent_steps (run_id, seq, role, kind, summary, payload_json,"
                " duration_ms, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    seq,
                    role.value,
                    kind,
                    summary,
                    json.dumps(payload or {}, sort_keys=True, default=str),
                    duration_ms,
                    utc_now_iso(),
                ),
            )
        return seq

    def steps(self, run_id: str, limit: int = MAX_STEP_ROWS) -> list[AgentStep]:
        rows = self.conn.execute(
            "SELECT * FROM agent_steps WHERE run_id = ? ORDER BY seq LIMIT ?",
            (run_id, min(max(limit, 1), MAX_STEP_ROWS)),
        ).fetchall()
        return [
            AgentStep(
                run_id=r["run_id"],
                seq=r["seq"],
                role=AgentRole(r["role"]),
                kind=r["kind"],
                summary=r["summary"],
                payload=json.loads(r["payload_json"]),
                duration_ms=r["duration_ms"],
                created_at=datetime.fromisoformat(r["created_at"]),
            )
            for r in rows
        ]
