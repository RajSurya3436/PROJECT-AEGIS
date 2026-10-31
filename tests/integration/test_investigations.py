from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from fixtures.reputation import ABUSE_KEY, VT_KEY, RoutingTransport, abuse_body, vt_body
from fixtures.settings import make_settings

from app.context import build_context
from app.domain.enums import (
    AlertStatus,
    Confidence,
    Disposition,
    EvidenceCategory,
    EvidenceSource,
    InputFormat,
    InvestigationStatus,
)
from app.domain.errors import InvestigationError, NotFoundError
from app.ingestion.demo import ingest_demo
from app.ingestion.iocs import load_demo_iocs
from app.ingestion.upload import ingest_upload
from app.reporting.report import build_report, to_json, to_markdown
from app.storage.repositories import EventFilters
from app.tools.reputation.http import HttpResponse

GENERATED = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)


@pytest.fixture
def demo(ctx):
    load_demo_iocs(ctx.iocs)
    ingest_demo(ctx.ingestion)
    return ctx


def _alert(ctx, rule_id):
    return next(a for a in ctx.alerts.list() if a.rule_id == rule_id)


def _start(ctx, rule_id="auth.failures_then_success"):
    return ctx.investigations.start_from_alert(_alert(ctx, rule_id).alert_id)


def test_tables_exist(ctx):
    tables = {r["name"] for r in ctx.conn.execute("SELECT name FROM sqlite_master")}
    assert {"investigations", "investigation_alerts", "investigation_events", "evidence"} <= tables


def test_start_collects_alert_events_related_events_and_evidence(demo):
    alert = _alert(demo, "auth.failures_then_success")
    inv = demo.investigations.start_from_alert(alert.alert_id)
    assert inv.status is InvestigationStatus.OPEN and inv.alert_ids == [alert.alert_id]
    assert demo.alerts.get(alert.alert_id).status is AlertStatus.INVESTIGATING

    timeline = demo.investigations.timeline(inv.investigation_id)
    linked = {link.event_id for link in demo.alerts.events_for(alert.alert_id)}
    in_scope = {t.event_id for t in timeline}
    assert linked <= in_scope and len(in_scope) > len(linked)  # related events were added
    assert {t.event_id for t in timeline if t.alert_match} == linked
    assert [t.event_time for t in timeline] == sorted(t.event_time for t in timeline)

    evidence = demo.investigations.evidence(inv.investigation_id)
    alert_ev = next(e for e in evidence if e.source_type is EvidenceSource.ALERT)
    assert alert_ev.category is EvidenceCategory.OBSERVATION
    assert set(alert_ev.event_ids) == linked
    assert alert_ev.provenance["tool"] == "get_alert_rule_explanation"
    assert any(e.source_type is EvidenceSource.LOCAL_IOC for e in evidence)
    gaps = [e for e in evidence if e.category is EvidenceCategory.MISSING_TELEMETRY]
    assert any("No process events for host VPN-GW01" in g.claim for g in gaps)
    for item in evidence:
        assert set(item.event_ids) <= in_scope


def test_start_is_idempotent_for_an_open_investigation(demo):
    first = _start(demo)
    again = _start(demo)
    assert again.investigation_id == first.investigation_id
    assert len(demo.investigations.repo.list()) == 1


def test_unknown_alert(demo):
    with pytest.raises(NotFoundError):
        demo.investigations.start_from_alert("nope")


def test_evidence_can_only_cite_events_in_scope(demo):
    inv = _start(demo, "auth.password_spray")
    outside = next(
        e.event_id
        for e in demo.events.query(EventFilters())
        if e.event_id not in demo.investigations.repo.scope_ids(inv.investigation_id)
    )
    with pytest.raises(InvestigationError, match="not in this investigation's scope"):
        demo.investigations.add_evidence(
            inv.investigation_id,
            category=EvidenceCategory.INFERENCE,
            claim="made up",
            source_type=EvidenceSource.ANALYST,
            source_ref="analyst",
            collected_by="analyst",
            event_ids=[outside],
        )
    with pytest.raises(InvestigationError, match="claim"):
        demo.investigations.add_evidence(
            inv.investigation_id,
            category=EvidenceCategory.INFERENCE,
            claim="   ",
            source_type=EvidenceSource.ANALYST,
            source_ref="analyst",
            collected_by="analyst",
        )


def test_duplicate_evidence_is_not_stored_twice(demo):
    inv = _start(demo)
    kwargs = {
        "category": EvidenceCategory.INFERENCE,
        "claim": "Success after failures suggests a guessed password.",
        "source_type": EvidenceSource.ANALYST,
        "source_ref": "analyst",
        "collected_by": "analyst",
    }
    a = demo.investigations.add_evidence(inv.investigation_id, **kwargs)
    b = demo.investigations.add_evidence(inv.investigation_id, **kwargs)
    assert a.evidence_id == b.evidence_id
    ids = [e.evidence_id for e in demo.investigations.evidence(inv.investigation_id)]
    assert ids.count(a.evidence_id) == 1


def test_expand_around_user_adds_events_and_preserves_existing(demo):
    inv = _start(demo)
    before = demo.investigations.repo.scope_ids(inv.investigation_id)
    evidence_before = demo.investigations.evidence(inv.investigation_id)
    alert = demo.alerts.get(inv.alert_ids[0])
    added = demo.investigations.expand_around_entity(
        inv.investigation_id, "user", "dave", alert.first_seen, alert.last_seen, 600, "analyst"
    )
    after = demo.investigations.repo.scope_ids(inv.investigation_id)
    assert added == len(after - before) and added > 0 and before <= after
    assert demo.investigations.evidence(inv.investigation_id) == evidence_before
    with pytest.raises(InvestigationError):
        demo.investigations.expand_around_entity(
            inv.investigation_id, "command_line", "x", alert.first_seen, alert.last_seen, 5, "a"
        )


def test_scope_cap_limits_related_events_but_keeps_alert_events():
    ctx = build_context(make_settings(investigation_max_scope_events=15), ":memory:")
    load_demo_iocs(ctx.iocs)
    ingest_demo(ctx.ingestion)
    inv = _start(ctx)  # this alert links 13 events
    assert ctx.investigations.repo.scope_count(inv.investigation_id) == 15
    claims = [e.claim for e in ctx.investigations.evidence(inv.investigation_id)]
    assert any("15-event cap" in c for c in claims)
    report = build_report(ctx.investigations, inv.investigation_id, GENERATED)
    assert any("size cap" in item for item in report.limitations)


def test_close_rules(demo):
    inv = _start(demo)
    service = demo.investigations
    evidence = service.evidence(inv.investigation_id)
    gap = next(e for e in evidence if e.category is EvidenceCategory.MISSING_TELEMETRY)
    observation = next(e for e in evidence if e.category is EvidenceCategory.OBSERVATION)
    iid = inv.investigation_id
    with pytest.raises(InvestigationError, match="explain"):
        service.close(
            iid, Disposition.LIKELY_MALICIOUS, Confidence.HIGH, " ", [observation.evidence_id]
        )
    with pytest.raises(InvestigationError, match="cite"):
        service.close(iid, Disposition.BENIGN_OR_EXPECTED, Confidence.LOW, "looks fine", [])
    with pytest.raises(InvestigationError, match="observation"):
        service.close(
            iid, Disposition.CONFIRMED_MALICIOUS, Confidence.HIGH, "bad", [gap.evidence_id]
        )
    with pytest.raises(InvestigationError, match="not in this investigation"):
        service.close(iid, Disposition.LIKELY_MALICIOUS, Confidence.HIGH, "bad", ["ev-fake"])

    closed = service.close(
        iid,
        Disposition.LIKELY_MALICIOUS,
        Confidence.MEDIUM,
        "IOC plus guessed password",
        [observation.evidence_id, gap.evidence_id],
    )
    assert closed.status is InvestigationStatus.CLOSED and closed.closed_at is not None
    assert closed.disposition_evidence_ids == [observation.evidence_id, gap.evidence_id]
    with pytest.raises(InvestigationError, match="closed"):
        service.add_evidence(
            iid,
            category=EvidenceCategory.INFERENCE,
            claim="late",
            source_type=EvidenceSource.ANALYST,
            source_ref="analyst",
            collected_by="analyst",
        )
    reopened = service.reopen(iid)
    assert reopened.status is InvestigationStatus.OPEN and reopened.disposition is None
    assert service.evidence(iid)  # evidence survives reopen
    with pytest.raises(InvestigationError):
        service.reopen(iid)


def test_insufficient_data_needs_no_evidence(demo):
    inv = _start(demo, "auth.password_spray")
    closed = demo.investigations.close(
        inv.investigation_id, Disposition.INSUFFICIENT_DATA, Confidence.LOW, "no endpoint data", []
    )
    assert closed.disposition is Disposition.INSUFFICIENT_DATA


def test_new_investigation_after_close(demo):
    first = _start(demo)
    demo.investigations.close(
        first.investigation_id, Disposition.INSUFFICIENT_DATA, Confidence.LOW, "x", []
    )
    second = _start(demo)
    assert second.investigation_id != first.investigation_id


def test_reputation_evidence_records_provider_results_with_timestamps():
    transport = RoutingTransport(
        HttpResponse(200, abuse_body(score=90)), HttpResponse(200, vt_body(malicious=4))
    )
    settings = make_settings(
        abuseipdb_api_key=ABUSE_KEY,
        virustotal_api_key=VT_KEY,
        enable_external_reputation=True,
    )
    ctx = build_context(settings, ":memory:", reputation_transport=transport)
    rows = b"".join(
        f'{{"timestamp": "2026-03-10T10:00:{i:02d}Z", "event_type": "auth", "outcome": "failure",'
        f' "user": "zoe", "src_ip": "8.8.8.8", "host": "VPN", "record": {i}}}\n'.encode()
        for i in range(12)
    )
    ingest_upload(ctx.ingestion, "auth.jsonl", rows, InputFormat.JSONL)
    alert = ctx.alerts.list()[0]
    inv = ctx.investigations.start_from_alert(alert.alert_id)
    assert transport.calls == []  # starting an investigation never contacts providers
    items = ctx.investigations.check_reputation(inv.investigation_id, "8.8.8.8", "analyst")
    assert len(transport.calls) == 2
    assert {e.category for e in items} == {EvidenceCategory.OBSERVATION}
    abuse = next(e for e in items if e.source_ref == "abuseipdb:8.8.8.8")
    assert "score 90" in abuse.claim and abuse.provenance["queried_at"]
    assert abuse.provenance["status"] == "fresh" and abuse.event_ids
    with pytest.raises(InvestigationError, match="does not appear"):
        ctx.investigations.check_reputation(inv.investigation_id, "1.1.1.1", "analyst")

    report = build_report(ctx.investigations, inv.investigation_id, GENERATED)
    assert {e.evidence_id for e in report.provider_findings} >= {e.evidence_id for e in items}
    assert ABUSE_KEY not in to_json(report) and VT_KEY not in to_markdown(report)


def test_non_public_addresses_record_no_reputation_gap(demo):
    """Documentation/private IPs are never sent out by design; that is not missing telemetry."""
    inv = _start(demo, "network.local_ioc_match")
    items = demo.investigations.check_reputation(inv.investigation_id, "203.0.113.80", "analyst")
    assert {e.source_type for e in items} == {EvidenceSource.LOCAL_IOC}


def test_reputation_without_keys_is_recorded_as_missing_telemetry(ctx):
    """A public IP with no provider keys: a real gap, so it is recorded."""
    row = {
        "timestamp": "2026-03-10T10:00:00Z",
        "event_type": "network",
        "host": "H1",
        "src_ip": "10.0.0.5",
        "dst_ip": "8.8.8.8",
        "dst_port": 443,
    }
    ingest_upload(ctx.ingestion, "net.jsonl", json.dumps(row).encode(), InputFormat.JSONL)
    event = ctx.events.query(EventFilters())[0]
    inv_id = "inv-test-keys"
    ctx.investigations.repo.create(inv_id, "t", "o")
    ctx.investigations.repo.add_scope(inv_id, [event.event_id], "test", "analyst")
    items = ctx.investigations.check_reputation(inv_id, "8.8.8.8", "analyst")
    assert items and all(e.category is EvidenceCategory.MISSING_TELEMETRY for e in items)
    assert all("not_configured" in e.claim for e in items)
