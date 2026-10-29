from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from app.domain.enums import InputFormat, SourceStatus, SourceType
from app.domain.errors import InvalidFilterError
from app.ingestion.demo import ingest_demo, load_manifest
from app.ingestion.upload import ingest_upload, preview_upload, upload_source_id
from app.storage.repositories import EventFilters

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def test_demo_ingest_counts_match_manifest(ctx):
    manifest = load_manifest()
    results = ingest_demo(ctx.ingestion)
    for entry, result in zip(manifest["files"], results, strict=True):
        assert result.inserted == entry["expected_records"]
        assert result.quarantined == 0
    assert ctx.events.count() == sum(f["expected_records"] for f in manifest["files"])
    assert set(ctx.events.count_by_type()) == {"auth", "process", "network"}


def test_demo_ingest_twice_inserts_nothing_new(ctx):
    ingest_demo(ctx.ingestion)
    before = ctx.events.count()
    second = ingest_demo(ctx.ingestion)
    assert sum(r.inserted for r in second) == 0
    assert sum(r.duplicates for r in second) == before
    assert ctx.events.count() == before


def test_upload_quarantines_bad_rows_and_keeps_good_ones(ctx):
    content = (FIXTURES / "mixed_aliases.jsonl").read_bytes()
    result = ingest_upload(ctx.ingestion, "mixed.jsonl", content, InputFormat.JSONL)
    assert result.received == 7
    assert result.inserted == 3  # two clean rows + one partial (bad IP/port)
    assert result.quarantined == 4  # missing ts, not json, not an object, garbage ts
    errors = ctx.parse_errors.list_recent(upload_source_id("mixed.jsonl"))
    assert {e["locator"] for e in errors} == {"line:5", "line:6", "line:7", "line:8"}
    source = ctx.sources.get(upload_source_id("mixed.jsonl"))
    assert source.status is SourceStatus.OK
    assert source.source_type is SourceType.UPLOAD
    assert (source.event_count, source.error_count) == (3, 4)


def test_reupload_same_file_is_deduplicated(ctx):
    content = (FIXTURES / "mixed_aliases.jsonl").read_bytes()
    ingest_upload(ctx.ingestion, "mixed.jsonl", content, InputFormat.JSONL)
    again = ingest_upload(ctx.ingestion, "mixed.jsonl", content, InputFormat.JSONL)
    assert again.inserted == 0 and again.duplicates == 3
    assert ctx.parse_errors.count() == 4  # quarantine rows are not duplicated either


def test_identical_rows_in_one_file_collapse_to_one_event(ctx):
    row = b'{"timestamp": "2026-03-10T00:00:00Z", "user": "a"}\n'
    result = ingest_upload(ctx.ingestion, "dup.jsonl", row * 3, InputFormat.JSONL)
    assert (result.inserted, result.duplicates) == (1, 2)


def test_preview_has_no_side_effects_and_shows_mapping(ctx):
    content = (FIXTURES / "mixed_aliases.jsonl").read_bytes()
    preview = preview_upload(content, InputFormat.JSONL, ctx.settings)
    assert ctx.events.count() == 0 and ctx.parse_errors.count() == 0
    assert preview.mapping["@timestamp"] == "timestamp"
    assert preview.mapping["source.ip"] == "src_ip"
    assert "weird_field" in preview.unmapped
    assert len(preview.errors) == 4


def test_csv_upload(ctx):
    csv = b"time,username,source_ip,result\n2026-03-10T00:00:00Z,a,10.0.0.1,success\n,b,,\n"
    result = ingest_upload(ctx.ingestion, "x.csv", csv, InputFormat.CSV)
    assert result.inserted == 1
    assert result.quarantined == 1  # ",b,," has data but no timestamp; ",,," is skipped


def test_row_limit_truncates_and_flags_source(ctx):
    ctx.ingestion.settings = ctx.settings.model_copy(update={"max_rows_per_ingest": 2})
    rows = b"".join(b'{"timestamp": "2026-03-10T00:00:0%dZ", "user": "u"}\n' % i for i in range(5))
    result = ingest_upload(ctx.ingestion, "big.jsonl", rows, InputFormat.JSONL)
    assert result.truncated and result.inserted == 2
    assert ctx.sources.get(upload_source_id("big.jsonl")).status is SourceStatus.ERROR


def test_hook_receives_only_new_events_and_failure_does_not_lose_data(ctx):
    seen: list[int] = []

    def ok_hook(events):
        seen.append(len(events))

    def bad_hook(events):
        raise RuntimeError("detector crashed")

    ctx.ingestion.hooks = [bad_hook, ok_hook]
    content = b'{"timestamp": "2026-03-10T00:00:00Z", "user": "a"}\n'
    first = ingest_upload(ctx.ingestion, "h.jsonl", content, InputFormat.JSONL)
    ingest_upload(ctx.ingestion, "h.jsonl", content, InputFormat.JSONL)
    assert first.inserted == 1 and "detector crashed" in first.hook_errors[0]
    assert seen == [1]  # second ingest inserted nothing, so hooks did not fire
    assert ctx.events.count() == 1


class TestSearch:
    @pytest.fixture(autouse=True)
    def _load(self, ctx):
        ingest_demo(ctx.ingestion)
        self.repo = ctx.events

    def test_filters_and_pagination(self):
        page = self.repo.search(EventFilters(equals={"user": "dave", "outcome": "failure"}))
        assert page.total == 12
        assert all(e.user == "dave" for e in page.events)
        p1 = self.repo.search(EventFilters(), page=1, page_size=50)
        p3 = self.repo.search(EventFilters(), page=3, page_size=50)
        assert p1.total == p3.total == 136
        assert (len(p1.events), len(p3.events)) == (50, 36)
        assert {e.event_id for e in p1.events}.isdisjoint(e.event_id for e in p3.events)

    def test_text_search_escapes_wildcards(self):
        assert self.repo.search(EventFilters(text="DownloadString")).total == 1
        assert self.repo.search(EventFilters(text="%")).total == 0  # literal, not a wildcard

    def test_time_range_filter(self):
        everything = self.repo.search(EventFilters(), page_size=500)
        mid = everything.events[60].event_time
        later = self.repo.search(EventFilters(start=mid))
        assert 0 < later.total < everything.total

    def test_related_events_window(self):
        seed = self.repo.search(
            EventFilters(equals={"user": "dave", "outcome": "success", "event_type": "auth"})
        ).events[0]
        narrow = self.repo.related(seed.event_id, timedelta(minutes=3), ["user"])
        wide = self.repo.related(seed.event_id, timedelta(minutes=10), ["user"])
        assert seed.event_id not in {e.event_id for e in wide}
        assert 0 < len(narrow) < len(wide)
        assert all(e.user == "dave" for e in wide)

    def test_prompt_injection_record_is_stored_verbatim_as_data(self):
        hits = self.repo.search(EventFilters(equals={"user": "dave"}), page_size=500).events
        injected = [e for e in hits if "IGNORE ALL PREVIOUS" in str(e.extra.get("user_agent"))]
        assert len(injected) == 1

    def test_unknown_filter_field_rejected(self):
        with pytest.raises(InvalidFilterError):
            self.repo.search(EventFilters(equals={"raw_json": "x"}))
        with pytest.raises(InvalidFilterError):
            self.repo.related("x", timedelta(minutes=1), ["message"])
