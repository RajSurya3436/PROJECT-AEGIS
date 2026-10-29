from __future__ import annotations

import pytest

from app.domain.enums import InputFormat
from app.domain.errors import UnsupportedInputError
from app.domain.models import ParseErrorRecord
from app.ingestion.parsers import (
    RawRecord,
    decode_bytes,
    detect_format,
    parse_csv,
    parse_json_document,
    parse_jsonl,
    safe_snippet,
)


def test_jsonl_skips_blank_lines_and_quarantines_bad_lines():
    text = '{"a": 1}\n\nnot json\n[1]\n{"b": 2}\n'
    items = list(parse_jsonl(text, "s"))
    records = [i for i in items if isinstance(i, RawRecord)]
    errors = [i for i in items if isinstance(i, ParseErrorRecord)]
    assert [r.locator for r in records] == ["line:1", "line:5"]
    assert [e.locator for e in errors] == ["line:3", "line:4"]
    assert "invalid JSON" in errors[0].error
    assert "expected a JSON object" in errors[1].error


def test_csv_drops_empty_cells_and_flags_overflow():
    text = "timestamp,user,host\n2026-03-10T00:00:00Z,a,\n2026-03-10T00:00:01Z,b,h,extra\n"
    items = list(parse_csv(text, "s"))
    assert isinstance(items[0], RawRecord)
    assert items[0].data == {"timestamp": "2026-03-10T00:00:00Z", "user": "a"}
    assert isinstance(items[1], ParseErrorRecord)
    assert "more columns" in items[1].error


def test_json_document_array_and_events_object():
    assert len(list(parse_json_document('[{"a":1},{"a":2}]', "s"))) == 2
    assert len(list(parse_json_document('{"events":[{"a":1}]}', "s"))) == 1
    bad = list(parse_json_document('{"x": 1}', "s"))
    assert isinstance(bad[0], ParseErrorRecord)
    broken = list(parse_json_document("{oops", "s"))
    assert isinstance(broken[0], ParseErrorRecord)


def test_safe_snippet_truncates_and_strips_control_chars():
    out = safe_snippet("a\x00b\x1b[31m" + "x" * 1000, limit=50)
    assert "\x00" not in out and "\x1b" not in out
    assert out.endswith("[truncated]")
    assert len(out) < 80


def test_decode_rejects_non_utf8_and_strips_bom():
    assert decode_bytes(b"\xef\xbb\xbf{}") == "{}"
    with pytest.raises(UnsupportedInputError):
        decode_bytes(b"\xff\xfe\x00bad")


def test_detect_format():
    assert detect_format("x.JSONL") is InputFormat.JSONL
    assert detect_format("x.csv") is InputFormat.CSV
    assert detect_format("x.txt") is None
