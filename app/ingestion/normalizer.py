"""Turn a raw record into a ``NormalizedEvent`` using explicit aliases only.

Only a missing or unparseable timestamp is fatal (the record is quarantined). Other invalid
values (bad IP, bad port, nested value where a scalar is expected) are dropped from the
canonical field, recorded under ``extra['_invalid_fields']`` and the event is marked
``parse_status='partial'``; the untouched raw record is always kept.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import UTC, datetime
from typing import Any

from app.domain.enums import EventType, Outcome
from app.domain.errors import NormalizationError
from app.domain.models import NormalizedEvent
from app.ingestion.field_aliases import ALIAS_LOOKUP, EVENT_TYPE_VALUES, OUTCOME_VALUES

_MAX_FLATTEN_DEPTH = 5
_MIN_YEAR, _MAX_YEAR = 1990, 2100
_EXTRA_TS_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y/%m/%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z",
    "%m/%d/%Y %H:%M:%S",
)
_STRING_FIELDS = (
    "user",
    "host",
    "process_name",
    "command_line",
    "parent_process",
    "action",
    "message",
)


def flatten(data: dict[str, Any], prefix: str = "", depth: int = 0) -> dict[str, Any]:
    """Flatten nested objects to dot-joined keys (``{"source": {"ip": x}}`` -> ``source.ip``)."""
    flat: dict[str, Any] = {}
    for key, value in data.items():
        name = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict) and value and depth < _MAX_FLATTEN_DEPTH:
            flat.update(flatten(value, name, depth + 1))
        else:
            flat[name] = value
    return flat


def map_fields(flat: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
    """Split flattened keys into (canonical values, unmapped extras, key->canonical mapping).

    When several input keys map to one canonical field, the highest-priority alias with a
    value wins and the others stay in ``extra`` under their original names.
    """
    best: dict[str, tuple[int, str]] = {}
    for key, value in flat.items():
        hit = ALIAS_LOOKUP.get(key.lower())
        if hit is None or value is None or value == "":
            continue
        canonical, priority = hit
        if canonical not in best or priority < best[canonical][0]:
            best[canonical] = (priority, key)
    chosen = {key: canonical for canonical, (_, key) in best.items()}
    mapped = {canonical: flat[key] for key, canonical in chosen.items()}
    extra = {k: v for k, v in flat.items() if k not in chosen}
    return mapped, extra, chosen


def parse_timestamp(value: Any) -> tuple[datetime, bool]:
    """Parse to aware UTC. Returns (timestamp, tz_assumed). Raises NormalizationError."""
    if isinstance(value, bool) or value is None:
        raise NormalizationError(f"unparseable timestamp: {value!r}")
    if isinstance(value, int | float) or (isinstance(value, str) and _is_number(value)):
        number = float(value)
        if number > 1e12:  # epoch milliseconds
            number /= 1000.0
        try:
            ts = datetime.fromtimestamp(number, tz=UTC)
        except (OverflowError, OSError, ValueError) as exc:
            raise NormalizationError(f"epoch timestamp out of range: {value!r}") from exc
        return _check_range(ts, value), False
    if not isinstance(value, str):
        raise NormalizationError(f"unparseable timestamp: {value!r}")
    text = value.strip()
    parsed: datetime | None = None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        for fmt in _EXTRA_TS_FORMATS:
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
    if parsed is None:
        raise NormalizationError(f"unparseable timestamp: {value!r}")
    tz_assumed = parsed.tzinfo is None or parsed.utcoffset() is None
    ts = parsed.replace(tzinfo=UTC) if tz_assumed else parsed.astimezone(UTC)
    return _check_range(ts, value), tz_assumed


def _is_number(text: str) -> bool:
    try:
        float(text)
    except ValueError:
        return False
    return True


def _check_range(ts: datetime, original: Any) -> datetime:
    if not _MIN_YEAR <= ts.year <= _MAX_YEAR:
        raise NormalizationError(f"timestamp outside {_MIN_YEAR}-{_MAX_YEAR}: {original!r}")
    return ts


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def stable_event_id(source_id: str, raw: dict[str, Any], source_event_id: Any = None) -> str:
    """Deterministic ID: same source + same record always yields the same ID, so
    re-ingesting a file or restarting a replay cannot create duplicates."""
    if source_event_id not in (None, ""):
        basis = f"{source_id}\x1fid\x1f{source_event_id}"
    else:
        basis = f"{source_id}\x1fraw\x1f{canonical_json(raw)}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:32]


def normalize_record(
    raw: dict[str, Any],
    *,
    source_id: str,
    locator: str,
    ingest_time: datetime | None = None,
    default_event_type: EventType | None = None,
    received: dict[str, Any] | None = None,
) -> NormalizedEvent:
    """``raw`` is what the aliases are applied to. When an adapter has reshaped a vendor
    record first, ``received`` is the record as it arrived: it is what gets stored and what the
    event ID is derived from, so the same vendor record always gives the same event."""
    flat = flatten(raw)
    mapped, extra, _ = map_fields(flat)
    invalid: dict[str, Any] = {}

    if "timestamp" not in mapped:
        raise NormalizationError("missing timestamp (no recognised timestamp field)")
    event_time, tz_assumed = parse_timestamp(mapped["timestamp"])
    if tz_assumed:
        extra["_tz_assumed"] = "UTC"

    fields: dict[str, Any] = {}
    for name in _STRING_FIELDS:
        if name in mapped:
            value = _scalar_str(mapped[name])
            if value is None:
                invalid[name] = mapped[name]
            else:
                fields[name] = value

    for name in ("src_ip", "dst_ip"):
        if name in mapped:
            ip = _normalize_ip(mapped[name])
            if ip is None:
                invalid[name] = mapped[name]
            else:
                fields[name] = ip

    if "dst_port" in mapped:
        port = _normalize_port(mapped["dst_port"])
        if port is None:
            invalid["dst_port"] = mapped["dst_port"]
        else:
            fields["dst_port"] = port

    event_type = default_event_type or EventType.OTHER
    if "event_type" in mapped:
        original = str(mapped["event_type"]).strip()
        resolved = EVENT_TYPE_VALUES.get(original.lower())
        if resolved:
            event_type = EventType(resolved)
        else:
            event_type = EventType.OTHER
            extra["_original_event_type"] = original

    outcome = Outcome.UNKNOWN
    if "outcome" in mapped:
        original = str(mapped["outcome"]).strip()
        resolved = OUTCOME_VALUES.get(original.lower())
        if resolved:
            outcome = Outcome(resolved)
        else:
            extra["_original_outcome"] = original

    if invalid:
        extra["_invalid_fields"] = invalid

    return NormalizedEvent(
        event_id=stable_event_id(source_id, received or raw, mapped.get("source_event_id")),
        source_id=source_id,
        source_locator=locator,
        event_time=event_time,
        ingest_time=ingest_time or datetime.now(UTC),
        event_type=event_type,
        outcome=outcome,
        extra=extra,
        raw=received or raw,
        parse_status="partial" if invalid else "ok",
        **fields,
    )


def _scalar_str(value: Any) -> str | None:
    if isinstance(value, dict | list):
        return None
    text = str(value).strip()
    return text or None


def _normalize_ip(value: Any) -> str | None:
    if not isinstance(value, str | int) or isinstance(value, bool):
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def _normalize_port(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        port = int(str(value).strip())
    except ValueError:
        return None
    return port if 0 <= port <= 65535 else None
