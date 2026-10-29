"""Deterministic one-line descriptions of events for timelines and reports."""

from __future__ import annotations

from app.domain.enums import EventType
from app.domain.models import NormalizedEvent

MAX_DETAIL_CHARS = 160


def _clip(value: str) -> str:
    value = " ".join(value.split())
    return value if len(value) <= MAX_DETAIL_CHARS else value[: MAX_DETAIL_CHARS - 1] + "…"


def describe_event(event: NormalizedEvent) -> str:
    """Plain text built only from normalized fields. Values are untrusted log data, so callers
    must render the result with escaping."""
    who = f" user {event.user}" if event.user else ""
    where = f" on {event.host}" if event.host else ""
    outcome = event.outcome.value
    if event.event_type is EventType.AUTH:
        source = f" from {event.src_ip}" if event.src_ip else ""
        action = event.action or "logon"
        return f"{action} {outcome}:{who}{source}{where}"
    if event.event_type is EventType.PROCESS:
        name = event.process_name or "process"
        parent = f" (parent {event.parent_process})" if event.parent_process else ""
        command = f": {_clip(event.command_line)}" if event.command_line else ""
        return f"{name} started{where}{who}{parent}{command}"
    if event.event_type is EventType.NETWORK:
        port = f":{event.dst_port}" if event.dst_port is not None else ""
        action = f" ({event.action})" if event.action else ""
        return f"connection {event.src_ip or '?'} -> {event.dst_ip or '?'}{port}{action}{where}"
    detail = f": {_clip(event.message)}" if event.message else ""
    return f"{event.event_type.value} event{where}{who}{detail}"
