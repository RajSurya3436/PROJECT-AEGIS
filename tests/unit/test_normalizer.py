from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.domain.enums import EventType, Outcome
from app.domain.errors import NormalizationError
from app.ingestion.field_aliases import ALIAS_LOOKUP
from app.ingestion.normalizer import normalize_record, parse_timestamp, stable_event_id


def norm(raw, **kw):
    return normalize_record(raw, source_id="s", locator="line:1", **kw)


def test_aliases_nested_keys_and_value_mapping():
    e = norm(
        {
            "@timestamp": "2026-03-10T09:00:00+02:00",
            "username": "zoe",
            "source": {"ip": "10.0.0.5"},
            "result": "Failed",
            "type": "logon",
            "weird_field": 1,
        }
    )
    assert e.event_time == datetime(2026, 3, 10, 7, 0, tzinfo=UTC)
    assert (e.user, e.src_ip) == ("zoe", "10.0.0.5")
    assert e.outcome is Outcome.FAILURE
    assert e.event_type is EventType.AUTH
    assert e.extra["weird_field"] == 1  # unknown fields stay unknown, not guessed
    assert e.raw["source"] == {"ip": "10.0.0.5"}


def test_naive_timestamp_assumed_utc_and_flagged():
    e = norm({"time": "2026-03-10 09:05:00"})
    assert e.event_time == datetime(2026, 3, 10, 9, 5, tzinfo=UTC)
    assert e.extra["_tz_assumed"] == "UTC"


@pytest.mark.parametrize("value", [1773133200, "1773133200", 1773133200000])
def test_epoch_seconds_and_millis(value):
    ts, assumed = parse_timestamp(value)
    assert ts == datetime(2026, 3, 10, 9, 0, tzinfo=UTC)
    assert assumed is False


@pytest.mark.parametrize("value", ["garbage", None, True, "", {"a": 1}, "1800-01-01T00:00:00Z"])
def test_bad_timestamps_raise(value):
    with pytest.raises(NormalizationError):
        parse_timestamp(value)


def test_missing_timestamp_is_fatal():
    with pytest.raises(NormalizationError, match="missing timestamp"):
        norm({"user": "x"})


def test_invalid_values_are_dropped_but_recorded_and_raw_kept():
    e = norm({"time": "2026-03-10T00:00:00Z", "src_ip": "not-an-ip", "dst_port": 70000})
    assert e.src_ip is None and e.dst_port is None
    assert e.parse_status == "partial"
    assert e.extra["_invalid_fields"] == {"src_ip": "not-an-ip", "dst_port": 70000}
    assert e.raw["src_ip"] == "not-an-ip"


def test_ip_is_canonicalised_and_unknown_type_preserved():
    e = norm({"time": 1773133200, "src_ip": "2001:DB8:0:0:0:0:0:1", "type": "weird"})
    assert e.src_ip == "2001:db8::1"
    assert e.event_type is EventType.OTHER
    assert e.extra["_original_event_type"] == "weird"


def test_default_event_type_only_used_when_no_type_field():
    assert norm({"time": 1773133200}, default_event_type=EventType.NETWORK).event_type is (
        EventType.NETWORK
    )
    explicit = norm({"time": 1773133200, "type": "auth"}, default_event_type=EventType.NETWORK)
    assert explicit.event_type is EventType.AUTH


def test_stable_ids():
    raw = {"a": 1, "b": 2}
    assert stable_event_id("s", raw) == stable_event_id("s", {"b": 2, "a": 1})
    assert stable_event_id("s", raw) != stable_event_id("t", raw)
    assert stable_event_id("s", raw, "X1") == stable_event_id("s", {"different": 1}, "X1")
    assert len(stable_event_id("s", raw)) == 32


def test_alias_table_has_no_collisions():
    # Import would already raise on duplicates; make the guarantee explicit.
    assert len(ALIAS_LOOKUP) == len({k.lower() for k in ALIAS_LOOKUP})


def test_higher_priority_alias_wins_and_other_stays_in_extra():
    e = norm({"time": 1773133200, "user": "primary", "username": "secondary"})
    assert e.user == "primary"
    assert e.extra["username"] == "secondary"
