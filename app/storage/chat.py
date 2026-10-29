"""Analyst chat messages and the directives among them (all SQL)."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime
from typing import Any

from app.domain.enums import DIRECTIVE_KINDS, AgentRole, ChatKind, ChatMode
from app.domain.models import ChatEntry
from app.storage.db import transaction, utc_now_iso

MAX_CHAT_ROWS = 1_000
MAX_CONTENT_CHARS = 4_000
PENDING, APPLIED, DISCARDED = "pending", "applied", "discarded"


def _dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


class ChatRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def add(
        self,
        investigation_id: str,
        *,
        author: str,
        mode: ChatMode,
        kind: ChatKind,
        content: str,
        target_role: AgentRole | None = None,
        run_id: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> ChatEntry:
        """Store a message. Directive kinds start ``pending``."""
        message_id = "msg-" + uuid.uuid4().hex[:12]
        self.conn.execute(
            "INSERT INTO chat_messages (message_id, investigation_id, author, mode, kind,"
            " target_role, content, run_id, status, payload_json, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                message_id,
                investigation_id,
                author,
                mode.value,
                kind.value,
                target_role.value if target_role else None,
                content[:MAX_CONTENT_CHARS],
                run_id,
                PENDING if kind in DIRECTIVE_KINDS else None,
                json.dumps(payload or {}, sort_keys=True, default=str),
                utc_now_iso(),
            ),
        )
        entry = self.get(message_id)
        assert entry is not None
        return entry

    def get(self, message_id: str) -> ChatEntry | None:
        row = self.conn.execute(
            "SELECT * FROM chat_messages WHERE message_id = ?", (message_id,)
        ).fetchone()
        return self._row(row) if row else None

    def for_investigation(self, investigation_id: str, limit: int = 500) -> list[ChatEntry]:
        """Oldest first, the most recent ``limit`` messages."""
        rows = self.conn.execute(
            "SELECT * FROM (SELECT * FROM chat_messages WHERE investigation_id = ?"
            " ORDER BY seq DESC LIMIT ?) ORDER BY seq",
            (investigation_id, min(max(limit, 1), MAX_CHAT_ROWS)),
        ).fetchall()
        return [self._row(r) for r in rows]

    def pending(self, investigation_id: str) -> list[ChatEntry]:
        rows = self.conn.execute(
            "SELECT * FROM chat_messages WHERE investigation_id = ? AND status = ? ORDER BY seq",
            (investigation_id, PENDING),
        ).fetchall()
        return [self._row(r) for r in rows]

    def take_pending(self, investigation_id: str, run_id: str) -> list[ChatEntry]:
        """Atomically mark this investigation's pending directives as applied by ``run_id``
        and return them, so two workers can never apply the same instruction."""
        with transaction(self.conn):
            entries = self.pending(investigation_id)
            now = utc_now_iso()
            for entry in entries:
                self.conn.execute(
                    "UPDATE chat_messages SET status = ?, run_id = ?, applied_at = ?"
                    " WHERE message_id = ? AND status = ?",
                    (APPLIED, run_id, now, entry.message_id, PENDING),
                )
        return entries

    def discard_pending(self, investigation_id: str) -> int:
        cur = self.conn.execute(
            "UPDATE chat_messages SET status = ?, applied_at = ? WHERE investigation_id = ?"
            " AND status = ?",
            (DISCARDED, utc_now_iso(), investigation_id, PENDING),
        )
        return cur.rowcount

    @staticmethod
    def _row(row: sqlite3.Row) -> ChatEntry:
        return ChatEntry(
            seq=row["seq"],
            message_id=row["message_id"],
            investigation_id=row["investigation_id"],
            author=row["author"],
            mode=ChatMode(row["mode"]),
            kind=ChatKind(row["kind"]),
            target_role=AgentRole(row["target_role"]) if row["target_role"] else None,
            content=row["content"],
            run_id=row["run_id"],
            status=row["status"],
            payload=json.loads(row["payload_json"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            applied_at=_dt(row["applied_at"]),
        )
