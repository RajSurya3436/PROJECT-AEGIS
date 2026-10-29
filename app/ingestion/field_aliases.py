"""Explicit field alias mapping.

Each canonical field lists the input keys it accepts, in priority order. Matching is
case-insensitive on the full (flattened, dot-joined) key. Keys not listed here are kept
unchanged in ``extra``; we never guess what an unknown field means.

Note: Windows ``EventID`` (e.g. 4625) is an event *code*, not a unique record ID, so it is
deliberately not an alias of ``source_event_id``.
"""

from __future__ import annotations

FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "source_event_id": ("event_id", "record_id", "EventRecordID", "event.id"),
    "timestamp": (
        "timestamp",
        "@timestamp",
        "event_time",
        "time",
        "eventtime",
        "TimeCreated",
        "datetime",
        "ts",
    ),
    "event_type": ("event_type", "type", "category", "event_category", "event.category"),
    "user": ("user", "username", "user_name", "account_name", "TargetUserName", "user.name"),
    "host": ("host", "hostname", "host_name", "computer", "device_name", "host.name"),
    "src_ip": (
        "src_ip",
        "source_ip",
        "client_ip",
        "IpAddress",
        "SourceAddress",
        "source.ip",
        "src",
    ),
    "dst_ip": ("dst_ip", "dest_ip", "destination_ip", "DestAddress", "destination.ip", "dst"),
    "dst_port": ("dst_port", "dest_port", "destination_port", "DestPort", "destination.port"),
    "process_name": ("process_name", "process", "image", "NewProcessName", "process.name"),
    "command_line": ("command_line", "commandline", "cmdline", "process.command_line"),
    "parent_process": (
        "parent_process",
        "parent_image",
        "ParentProcessName",
        "process.parent.name",
    ),
    "outcome": ("outcome", "result", "status", "event.outcome"),
    "action": ("action", "event_action", "event.action"),
    "message": ("message", "msg", "description"),
}

# lower-cased alias -> (canonical field, priority index)
ALIAS_LOOKUP: dict[str, tuple[str, int]] = {}
for _canonical, _aliases in FIELD_ALIASES.items():
    for _priority, _alias in enumerate(_aliases):
        _key = _alias.lower()
        if _key in ALIAS_LOOKUP:
            raise RuntimeError(f"alias {_alias!r} is mapped to more than one field")
        ALIAS_LOOKUP[_key] = (_canonical, _priority)

EVENT_TYPE_VALUES: dict[str, str] = {
    **dict.fromkeys(("auth", "authentication", "logon", "login", "iam"), "auth"),
    **dict.fromkeys(("process", "process_creation", "process_start", "process_launch"), "process"),
    **dict.fromkeys(("network", "connection", "network_connection", "netflow", "flow"), "network"),
}

OUTCOME_VALUES: dict[str, str] = {
    **dict.fromkeys(
        ("success", "succeeded", "successful", "ok", "allow", "allowed", "pass"), "success"
    ),
    **dict.fromkeys(
        ("failure", "failed", "fail", "denied", "deny", "blocked", "error", "rejected"), "failure"
    ),
}


def resolve_alias(key: str) -> str | None:
    """Return the canonical field for an input key, or None if it is not mapped."""
    hit = ALIAS_LOOKUP.get(key.lower())
    return hit[0] if hit else None
