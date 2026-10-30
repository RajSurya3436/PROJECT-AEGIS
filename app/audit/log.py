"""The audit trail: who did what to which object, when, and how it went.

Recorded: analyst instructions and run control, agent runs and every agent tool call (including
refusals), external reputation requests, response proposals, approvals, rejections and
simulations, investigation and alert lifecycle changes, rule and settings changes, and report
exports. Details are capped in size and never contain API keys (keys are not in any argument).
Services build their own ``AuditLog`` from the shared connection, like their repositories.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from app.domain.models import AuditEvent
from app.storage.audit import AuditFilters, AuditRepository

OK, REJECTED, FAILED = "ok", "rejected", "failed"


class AuditLog:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.repo = AuditRepository(conn)

    def record(
        self,
        actor: str,
        action: str,
        target_type: str,
        target_id: str,
        *,
        investigation_id: str | None = None,
        outcome: str = OK,
        details: dict[str, Any] | None = None,
    ) -> str:
        return self.repo.add(
            actor=actor,
            action=action,
            target_type=target_type,
            target_id=target_id,
            investigation_id=investigation_id,
            outcome=outcome,
            details=details or {},
        )

    def list(self, filters: AuditFilters | None = None, limit: int = 500) -> list[AuditEvent]:
        return self.repo.list(filters, limit)

    def for_investigation(self, investigation_id: str, limit: int = 500) -> list[AuditEvent]:
        """Oldest first, for reports."""
        return list(
            reversed(self.repo.list(AuditFilters(investigation_id=investigation_id), limit))
        )
