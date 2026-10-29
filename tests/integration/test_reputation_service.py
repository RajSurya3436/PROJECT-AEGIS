from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fixtures.reputation import (
    ABUSE_KEY,
    VT_KEY,
    FakeTransport,
    RoutingTransport,
    abuse_body,
    vt_body,
)

from app.config import Settings
from app.context import build_context
from app.domain.enums import ReputationStatus
from app.ingestion.demo import ingest_demo
from app.ingestion.iocs import load_demo_iocs
from app.storage.db import open_database
from app.tools.reputation.http import HttpResponse
from app.tools.reputation.service import ReputationService, build_providers

PUBLIC_IP = "8.8.8.8"


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


def _keyed(**overrides) -> Settings:
    return Settings(
        _env_file=None, abuseipdb_api_key=ABUSE_KEY, virustotal_api_key=VT_KEY, **overrides
    )


def _service(settings, transport, clock=None, conn=None):
    clock = clock or Clock()
    conn = conn or open_database(":memory:")
    providers = build_providers(settings, transport, sleep=lambda _s: None, clock=clock)
    return ReputationService(conn, settings, providers, clock=clock)


def _routing():
    return RoutingTransport(HttpResponse(200, abuse_body(score=80)), HttpResponse(200, vt_body()))


def _statuses(report):
    return {r.provider: r.status for r in report.results}


def test_without_keys_everything_is_not_configured(settings):
    transport = FakeTransport()
    report = _service(settings, transport).lookup_ip(PUBLIC_IP)
    assert set(_statuses(report).values()) == {ReputationStatus.NOT_CONFIGURED}
    assert transport.calls == []


def test_external_lookups_are_off_by_default():
    transport = FakeTransport()
    report = _service(_keyed(), transport).lookup_ip(PUBLIC_IP)
    assert set(_statuses(report).values()) == {ReputationStatus.DISABLED}
    assert transport.calls == []


def test_enabled_lookup_is_fresh_then_cached_then_refreshable():
    transport = _routing()
    service = _service(_keyed(enable_external_reputation=True), transport)
    first = service.lookup_ip(PUBLIC_IP)
    assert set(_statuses(first).values()) == {ReputationStatus.FRESH}
    assert len(transport.calls) == 2
    second = service.lookup_ip(PUBLIC_IP)
    assert set(_statuses(second).values()) == {ReputationStatus.CACHED}
    assert [r.summary for r in second.results] == [r.summary for r in first.results]
    assert len(transport.calls) == 2
    service.lookup_ip(PUBLIC_IP, force_refresh=True)
    assert len(transport.calls) == 4


def test_cache_expires():
    clock = Clock()
    transport = _routing()
    service = _service(
        _keyed(enable_external_reputation=True, reputation_cache_ttl_hours=1), transport, clock
    )
    service.lookup_ip(PUBLIC_IP, ["abuseipdb"])
    clock.now += timedelta(minutes=59)
    assert service.lookup_ip(PUBLIC_IP, ["abuseipdb"]).results[0].status is ReputationStatus.CACHED
    assert service.cache_stats() == {"abuseipdb": {"total": 1, "expired": 0}}
    clock.now += timedelta(minutes=2)
    assert service.cache_stats() == {"abuseipdb": {"total": 1, "expired": 1}}
    assert service.lookup_ip(PUBLIC_IP, ["abuseipdb"]).results[0].status is ReputationStatus.FRESH
    assert len(transport.calls) == 2


def test_cached_results_are_served_even_when_lookups_are_switched_off():
    service = _service(_keyed(enable_external_reputation=True), _routing())
    service.lookup_ip(PUBLIC_IP)
    service.set_external_enabled(False)
    assert set(_statuses(service.lookup_ip(PUBLIC_IP)).values()) == {ReputationStatus.CACHED}
    assert set(_statuses(service.lookup_ip("8.8.4.4")).values()) == {ReputationStatus.DISABLED}


def test_failures_are_not_cached_and_do_not_raise():
    transport = FakeTransport(
        TimeoutError(), TimeoutError(), TimeoutError(), *[HttpResponse(500)] * 3
    )
    settings = _keyed(enable_external_reputation=True, reputation_max_retries=2)
    service = _service(settings, transport)
    report = service.lookup_ip(PUBLIC_IP)
    statuses = _statuses(report)
    assert statuses["abuseipdb"] is ReputationStatus.TIMEOUT
    assert statuses["virustotal"] is ReputationStatus.PROVIDER_ERROR
    assert service.cache_stats() == {}


@pytest.mark.parametrize("value", ["10.0.0.5", "127.0.0.1", "169.254.0.1", "224.0.0.9", "garbage"])
def test_non_public_or_invalid_ips_are_never_sent(value):
    transport = FakeTransport()
    report = _service(_keyed(enable_external_reputation=True), transport).lookup_ip(value)
    assert set(_statuses(report).values()) == {ReputationStatus.SKIPPED}
    assert transport.calls == []
    assert report.valid is (value != "garbage")


def test_local_ioc_match_works_offline_for_demo_ips(ctx):
    load_demo_iocs(ctx.iocs)
    report = ctx.reputation.lookup_ip("203.0.113.80")
    assert report.local_ioc is not None and report.local_ioc.confidence == "high"
    assert report.scope == "documentation"
    assert set(_statuses(report).values()) == {ReputationStatus.SKIPPED}
    assert ctx.reputation.lookup_ip("8.8.8.8").local_ioc is None


def test_provider_selection_and_unknown_provider():
    service = _service(_keyed(enable_external_reputation=True), _routing())
    assert [r.provider for r in service.lookup_ip(PUBLIC_IP, ["virustotal"]).results] == [
        "virustotal"
    ]
    with pytest.raises(ValueError, match="unknown"):
        service.lookup_ip(PUBLIC_IP, ["shodan"])


def test_toggle_persists_in_app_settings(tmp_path):
    db = str(tmp_path / "rep.db")
    service = _service(_keyed(), FakeTransport(), conn=open_database(db))
    assert service.external_enabled is False
    service.set_external_enabled(True)
    again = _service(_keyed(), FakeTransport(), conn=open_database(db))
    assert again.external_enabled is True


def test_cache_and_settings_never_contain_keys_or_raw_bodies():
    abuse = HttpResponse(200, abuse_body(extra_field="RAW-ONLY-MARKER"))
    transport = RoutingTransport(abuse, HttpResponse(200, vt_body()))
    service = _service(_keyed(enable_external_reputation=True), transport)
    service.lookup_ip(PUBLIC_IP)
    service.set_external_enabled(True)
    conn = service.cache.conn
    dump = "\n".join(conn.iterdump())
    for secret in (ABUSE_KEY, VT_KEY, "RAW-ONLY-MARKER"):
        assert secret not in dump


def test_purge_and_clear():
    clock = Clock()
    service = _service(_keyed(enable_external_reputation=True), _routing(), clock)
    service.lookup_ip(PUBLIC_IP)
    clock.now += timedelta(days=2)
    service.lookup_ip("8.8.4.4", ["abuseipdb"])
    assert service.purge_expired() == 2
    assert service.clear_cache() == 1
    assert service.cache_stats() == {}


def test_ingestion_and_detection_never_query_providers(settings):
    transport = FakeTransport()
    keyed = _keyed(enable_external_reputation=True)
    ctx = build_context(keyed, ":memory:", reputation_transport=transport)
    load_demo_iocs(ctx.iocs)
    ingest_demo(ctx.ingestion)
    assert ctx.alerts.count() == 5
    assert transport.calls == []
