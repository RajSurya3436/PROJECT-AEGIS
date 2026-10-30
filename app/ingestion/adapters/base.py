from __future__ import annotations

from typing import Any, Protocol

from app.domain.enums import EventType


class RecordAdapter(Protocol):
    name: str
    title: str
    default_event_type: EventType | None

    def transform(self, record: dict[str, Any]) -> dict[str, Any]:
        """Return the record reshaped for the alias table. Must not raise for odd input:
        missing or malformed vendor fields simply produce fewer canonical fields."""
        ...


class GenericAdapter:
    """No reshaping: the alias table maps the record's own keys."""

    name = "generic"
    title = "Generic JSON (field aliases)"
    default_event_type: EventType | None = None

    def transform(self, record: dict[str, Any]) -> dict[str, Any]:
        return record
