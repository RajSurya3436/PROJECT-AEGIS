from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from fixtures.settings import make_settings

from app.config import PROJECT_ROOT
from app.context import build_context
from app.domain.enums import SourceStatus
from app.ingestion.file_tail import TailError, tail_source_id
from app.storage.audit import AuditFilters

SAMPLE = PROJECT_ROOT / "data" / "samples" / "wazuh_alerts.jsonl"


def _line(i: int, user: str = "dave") -> bytes:
    record = {
        "timestamp": f"2026-03-10T10:{i // 60:02d}:{i % 60:02d}Z",
        "event_type": "auth",
        "outcome": "failure",
        "user": user,
        "src_ip": "198.51.100.7",
        "record": i,
    }
    return (json.dumps(record) + "\n").encode()


def _append(path: Path, data: bytes) -> None:
    with path.open("ab") as handle:
        handle.write(data)


def _count(ctx) -> int:
    return ctx.events.count()


@pytest.fixture
def log(tmp_path: Path) -> Path:
    path = tmp_path / "events.jsonl"
    path.write_bytes(b"")
    return path


def test_reads_appended_lines_and_waits_for_partial_ones(ctx, log):
    ctx.tails.add(str(log))
    _append(log, _line(0) + _line(1))
    (first,) = ctx.tails.poll_all()
    assert (first.inserted, first.waiting_partial) == (2, False)
    whole = _line(2)
    _append(log, whole[:25])  # the writer is half-way through a line
    (partial,) = ctx.tails.poll_all()
    assert (partial.inserted, partial.waiting_partial, partial.bytes_read) == (0, True, 0)
    _append(log, whole[25:])
    (rest,) = ctx.tails.poll_all()
    assert rest.inserted == 1
    assert _count(ctx) == 3
    source = ctx.sources.get(tail_source_id(log))
    assert source.cursor["offset"] == log.stat().st_size and source.status is SourceStatus.OK


def test_truncation_and_rotation_restart_from_the_beginning(ctx, log):
    ctx.tails.add(str(log))
    _append(log, _line(0) + _line(1) + _line(2))
    ctx.tails.poll_all()
    log.write_bytes(_line(0))  # truncated (same first line, now shorter)
    (truncated,) = ctx.tails.poll_all()
    assert truncated.reset == "truncated" and truncated.duplicates == 1
    log.write_bytes(_line(50, user="erin") + _line(51, user="erin") + _line(52, user="erin"))
    (rotated,) = ctx.tails.poll_all()  # a new file of a similar size under the same name
    assert rotated.reset == "rotated" and rotated.inserted == 3


def test_cursor_survives_a_restart(settings, tmp_path, log):
    database = str(tmp_path / "tail.db")
    first = build_context(settings, database)
    first.tails.add(str(log))
    first.tails.stop()  # build_context started it; drive polls by hand here
    _append(log, _line(0) + _line(1))
    first.tails.poll_all()
    first.conn.close()

    second = build_context(settings, database)  # resumes following the file on its own
    try:
        assert second.tails.running
        _append(log, _line(2))
        deadline = time.monotonic() + 10
        while _count(second) < 3 and time.monotonic() < deadline:
            time.sleep(0.1)
        assert _count(second) == 3  # only the new line was added; nothing re-read twice
        source = second.sources.get(tail_source_id(log))
        assert source is not None and source.event_count == 3
    finally:
        second.tails.stop()


def test_start_at_end_skips_existing_lines_and_a_half_line(ctx, log):
    log.write_bytes(_line(0) + _line(1) + _line(2)[:10])
    ctx.tails.add(str(log), start_at_end=True)
    (first,) = ctx.tails.poll_all()
    assert first.inserted == 0
    _append(log, _line(2)[10:] + _line(3))
    (second,) = ctx.tails.poll_all()
    assert second.inserted == 1 and second.quarantined == 0  # the half line was not mangled


def test_bad_and_overlong_lines_are_quarantined_not_fatal(settings, tmp_path, log):
    small = make_settings(file_tail_max_line_bytes=1_024)
    ctx = build_context(small, ":memory:")
    ctx.tails.add(str(log))
    _append(log, b"not json\n" + b'"a string"\n' + b"x" * 3_000 + b"\n" + _line(0))
    (result,) = ctx.tails.poll_all()
    assert (result.inserted, result.quarantined) == (1, 3)
    errors = [e["error"] for e in ctx.parse_errors.list_recent()]
    assert any("invalid JSON" in e for e in errors)
    assert any("expected a JSON object" in e for e in errors)
    assert any("longer than 1,024 bytes" in e for e in errors)


def test_an_overlong_line_split_across_polls_is_skipped(settings, tmp_path, log):
    small = make_settings(file_tail_max_line_bytes=1_024, file_tail_max_bytes_per_poll=4_096)
    ctx = build_context(small, ":memory:")
    ctx.tails.add(str(log))
    _append(log, b"y" * 10_000 + b"\n" + _line(0))
    results = [ctx.tails.poll_all()[0] for _ in range(4)]
    assert sum(r.inserted for r in results) == 1
    assert sum(r.quarantined for r in results) == 1


def test_missing_file_is_reported_on_the_source(ctx, log):
    ctx.tails.add(str(log))
    log.unlink()
    (result,) = ctx.tails.poll_all()
    assert "cannot read" in result.error
    source = ctx.sources.get(tail_source_id(log))
    assert source.status is SourceStatus.ERROR and "cannot read" in source.last_error


def test_adding_needs_an_existing_file_and_known_layout(ctx, tmp_path):
    with pytest.raises(TailError, match="not an existing file"):
        ctx.tails.add(str(tmp_path / "nope.jsonl"))
    with pytest.raises(TailError, match="not an existing file"):
        ctx.tails.add(str(tmp_path))
    with pytest.raises(Exception, match="unknown adapter"):
        ctx.tails.add(str(SAMPLE), "splunk")


def test_following_wazuh_alerts_detects_and_is_audited(ctx, tmp_path):
    from app.ingestion.iocs import load_demo_iocs

    load_demo_iocs(ctx.iocs)
    alerts_json = tmp_path / "alerts.json"
    lines = SAMPLE.read_bytes().splitlines(keepends=True)
    alerts_json.write_bytes(b"".join(lines[:8]))  # the sshd story so far
    config = ctx.tails.add(str(alerts_json), "wazuh")
    ctx.tails.poll_all()
    assert {a.rule_id for a in ctx.alerts.list()} == {
        "auth.repeated_failures",
        "auth.failures_then_success",
        "siem.high_severity_alert",
    }
    _append(alerts_json, b"".join(lines[8:]))  # Wazuh keeps writing
    ctx.tails.poll_all()
    assert len(ctx.alerts.list()) == 7
    ctx.tails.remove(config.source_id)
    assert not ctx.tails.configs()
    actions = [e.action for e in ctx.audit.list(AuditFilters(action_prefix="ingestion."))]
    assert actions == ["ingestion.file_tail_removed", "ingestion.file_tail_added"]


def test_in_memory_databases_cannot_follow_live(ctx, log):
    ctx.tails.add(str(log))
    with pytest.raises(TailError, match="file database"):
        ctx.tails.start()
