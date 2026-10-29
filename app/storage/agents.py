"""Agent runs and their step log (all SQL)."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Any

from app.domain.enums import (
    ACTIVE_RUN_STATUSES,
    OPEN_RUN_STATUSES,
    RESUMABLE_RUN_STATUSES,
    AgentRole,
    AgentRunStatus,
)
from app.domain.models import AgentRun, AgentStep, Assessment
from app.storage.db import transaction, utc_now_iso

MAX_RUN_ROWS = 200
MAX_STEP_ROWS = 2_000
CONTROLS = ("pause", "stop")
_ACTIVE = tuple(sorted(s.value for s in ACTIVE_RUN_STATUSES))
_OPEN = tuple(sorted(s.value for s in OPEN_RUN_STATUSES))
RESUMABLE = tuple(sorted(s.value for s in RESUMABLE_RUN_STATUSES))
_UNFINISHED = tuple(sorted(s.value for s in OPEN_RUN_STATUSES | RESUMABLE_RUN_STATUSES))


def _dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def _marks(values: tuple[str, ...]) -> str:
    return "(" + ", ".join("?" for _ in values) + ")"


class AgentRunRepository:
    """Concurrency rule: an investigation has at most one *open* run (queued, running, paused
    or waiting). Creating and claiming check that in the same statement or transaction as the
    write, so two analysts or two workers cannot both win."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def create(self, run_id: str, investigation_id: str, model: str) -> bool:
        """Insert a queued run unless the investigation already has an open one."""
        now = utc_now_iso()
        with transaction(self.conn):
            row = self.conn.execute(
                "SELECT 1 FROM agent_runs WHERE investigation_id = ?"  # noqa: S608 - placeholders
                f" AND status IN {_marks(_OPEN)}",
                (investigation_id, *_OPEN),
            ).fetchone()
            if row is not None:
                return False
            self.conn.execute(
                "INSERT INTO agent_runs (run_id, investigation_id, status, model, created_at,"
                " updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (run_id, investigation_id, AgentRunStatus.QUEUED.value, model, now, now),
            )
        return True

    def open_run(self, investigation_id: str) -> AgentRun | None:
        row = self.conn.execute(
            "SELECT * FROM agent_runs WHERE investigation_id = ?"  # noqa: S608 - placeholders
            f" AND status IN {_marks(_OPEN)} ORDER BY created_at DESC LIMIT 1",
            (investigation_id, *_OPEN),
        ).fetchone()
        return self._row(row) if row else None

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
        """Move a resumable run (queued, paused, waiting, interrupted) to running. False if
        it is in another state, or if a different run of the same investigation is open. A
        pause or stop requested while the run was still queued is kept, so the worker honours
        it before its first step (``finish`` and ``mark_interrupted`` clear old requests)."""
        cur = self.conn.execute(
            "UPDATE agent_runs SET status = ?, error = NULL, finished_at = NULL,"  # noqa: S608
            f" updated_at = ? WHERE run_id = ? AND status IN {_marks(RESUMABLE)}"
            " AND NOT EXISTS (SELECT 1 FROM agent_runs other"
            " WHERE other.investigation_id = agent_runs.investigation_id"
            f" AND other.run_id != agent_runs.run_id AND other.status IN {_marks(_OPEN)})",
            (AgentRunStatus.RUNNING.value, utc_now_iso(), run_id, *RESUMABLE, *_OPEN),
        )
        return cur.rowcount == 1

    def request_control(self, run_id: str, control: str) -> bool:
        """Ask an executing run to pause or stop at its next step boundary."""
        if control not in CONTROLS:
            raise ValueError(f"unknown control {control!r}")
        cur = self.conn.execute(
            "UPDATE agent_runs SET control = ?, updated_at = ? WHERE run_id = ?"  # noqa: S608
            f" AND status IN {_marks(_ACTIVE)}",
            (control, utc_now_iso(), run_id, *_ACTIVE),
        )
        return cur.rowcount == 1

    def requested_control(self, run_id: str) -> str | None:
        row = self.conn.execute(
            "SELECT control FROM agent_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        return row["control"] if row else None

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
            "UPDATE agent_runs SET status = ?, assessment_json = ?, error = ?, control = NULL,"
            " updated_at = ?, finished_at = ? WHERE run_id = ?",
            (
                status.value,
                assessment.model_dump_json() if assessment else None,
                error,
                now,
                now,
                run_id,
            ),
        )

    def stop_unfinished(self, run_id: str, error: str) -> bool:
        """Mark a run stopped only if it has not finished in the meantime, so a stop that
        races a completing worker never overwrites its assessment."""
        now = utc_now_iso()
        cur = self.conn.execute(
            "UPDATE agent_runs SET status = ?, error = ?, control = NULL, updated_at = ?,"  # noqa: S608
            f" finished_at = ? WHERE run_id = ? AND status IN {_marks(_UNFINISHED)}",
            (AgentRunStatus.STOPPED.value, error, now, now, run_id, *_UNFINISHED),
        )
        return cur.rowcount == 1

    def mark_interrupted(self) -> int:
        """Runs left executing by an earlier process cannot still be running. Mark them
        resumable instead of letting them block their investigation forever. Paused and
        waiting runs are parked on purpose and keep their status."""
        cur = self.conn.execute(
            "UPDATE agent_runs SET status = ?, control = NULL, updated_at = ?"  # noqa: S608
            f" WHERE status IN {_marks(_ACTIVE)}",
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
            control=row["control"],
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
