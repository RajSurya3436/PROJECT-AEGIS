"""Format parsers. They only split input into raw dict records (with a locator such as
``line:12``) or ``ParseErrorRecord``s; meaning is assigned later by the normalizer."""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from app.domain.enums import InputFormat
from app.domain.errors import UnsupportedInputError
from app.domain.models import ParseErrorRecord

DEFAULT_SNIPPET_CHARS = 500


@dataclass(frozen=True)
class RawRecord:
    locator: str
    data: dict[str, Any]


ParsedItem = RawRecord | ParseErrorRecord


def safe_snippet(text: str, limit: int = DEFAULT_SNIPPET_CHARS) -> str:
    """Truncate and strip control characters so a raw snippet is safe to store and display."""
    cleaned = "".join(ch if ch.isprintable() or ch in "\t" else "�" for ch in text)
    return cleaned if len(cleaned) <= limit else cleaned[:limit] + "…[truncated]"


def decode_bytes(content: bytes) -> str:
    try:
        return content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise UnsupportedInputError(f"input is not valid UTF-8: {exc.reason}") from exc


def detect_format(filename: str) -> InputFormat | None:
    lower = filename.lower()
    for suffix, fmt in (
        (".jsonl", InputFormat.JSONL),
        (".ndjson", InputFormat.NDJSON),
        (".csv", InputFormat.CSV),
        (".json", InputFormat.JSON),
    ):
        if lower.endswith(suffix):
            return fmt
    return None


def parse_jsonl(
    text: str, source_id: str, snippet_chars: int = DEFAULT_SNIPPET_CHARS
) -> Iterator[ParsedItem]:
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        locator = f"line:{number}"
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            yield ParseErrorRecord(
                source_id=source_id,
                locator=locator,
                error=f"invalid JSON: {exc.msg} (col {exc.colno})",
                raw_snippet=safe_snippet(line, snippet_chars),
            )
            continue
        if not isinstance(value, dict):
            yield ParseErrorRecord(
                source_id=source_id,
                locator=locator,
                error=f"expected a JSON object, got {type(value).__name__}",
                raw_snippet=safe_snippet(line, snippet_chars),
            )
            continue
        yield RawRecord(locator, value)


def parse_csv(
    text: str, source_id: str, snippet_chars: int = DEFAULT_SNIPPET_CHARS
) -> Iterator[ParsedItem]:
    reader = csv.DictReader(io.StringIO(text), restkey="__overflow__")
    if not reader.fieldnames:
        return
    for row in reader:
        locator = f"row:{reader.line_num}"
        if "__overflow__" in row:
            yield ParseErrorRecord(
                source_id=source_id,
                locator=locator,
                error=f"row has more columns than the header ({len(reader.fieldnames)})",
                raw_snippet=safe_snippet(json.dumps(row, default=str), snippet_chars),
            )
            continue
        # Empty cells mean "no value"; keep only populated columns.
        data = {k: v for k, v in row.items() if k and v not in (None, "")}
        if not data:
            continue
        yield RawRecord(locator, data)


def parse_json_document(
    text: str, source_id: str, snippet_chars: int = DEFAULT_SNIPPET_CHARS
) -> Iterator[ParsedItem]:
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        yield ParseErrorRecord(
            source_id=source_id,
            locator="document",
            error=f"invalid JSON document: {exc.msg} (line {exc.lineno})",
            raw_snippet=safe_snippet(text, snippet_chars),
        )
        return
    if isinstance(doc, dict) and isinstance(doc.get("events"), list):
        items = doc["events"]
    elif isinstance(doc, list):
        items = doc
    else:
        yield ParseErrorRecord(
            source_id=source_id,
            locator="document",
            error="expected a JSON array or an object with an 'events' array",
            raw_snippet=safe_snippet(text, snippet_chars),
        )
        return
    for index, item in enumerate(items):
        locator = f"index:{index}"
        if isinstance(item, dict):
            yield RawRecord(locator, item)
        else:
            yield ParseErrorRecord(
                source_id=source_id,
                locator=locator,
                error=f"expected a JSON object, got {type(item).__name__}",
                raw_snippet=safe_snippet(json.dumps(item, default=str), snippet_chars),
            )


def parse_text(
    text: str,
    fmt: InputFormat,
    source_id: str,
    snippet_chars: int = DEFAULT_SNIPPET_CHARS,
) -> Iterator[ParsedItem]:
    if fmt in (InputFormat.JSONL, InputFormat.NDJSON):
        return parse_jsonl(text, source_id, snippet_chars)
    if fmt is InputFormat.CSV:
        return parse_csv(text, source_id, snippet_chars)
    if fmt is InputFormat.JSON:
        return parse_json_document(text, source_id, snippet_chars)
    raise UnsupportedInputError(f"unsupported format: {fmt}")
