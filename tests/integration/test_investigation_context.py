"""Related alerts, upstream SIEM detections and "seen before" history recorded at the start of
an investigation (app/investigations/context.py)."""

from __future__ import annotations

import json

import pytest

from app.domain.enums import EvidenceCategory, EvidenceSource, InputFormat, SourceType
from app.evaluation.runner import EVAL_DIR, load_scenarios
from app.ingestion.adapters import get_adapter
from app.ingestion.demo import ingest_demo
from app.ingestion.iocs import load_demo_iocs
from app.ingestion.upload import ingest_upload

SCENARIOS = {s["id"]: s for s in load_scenarios()}


def _start(ctx, scenario_id: str):
    scenario = SCENARIOS[scenario_id]
    load_demo_iocs(ctx.iocs)
    ctx.ingestion.ingest_bytes(
        (EVAL_DIR / scenario["file"]).read_bytes(),
        InputFormat.JSONL,
        source_id="ctx-test",
        source_type=SourceType.UPLOAD,
        source_name="test",
        adapter=get_adapter(scenario.get("adapter")),
    )
    alert = max(
        (a for a in ctx.alerts.list() if a.rule_id == scenario["investigate"]),
        key=lambda a: (a.last_seen, a.alert_id),
    )
    inv = ctx.investigations.start_from_alert(alert.alert_id)
    return inv, alert


def _context(ctx, inv, kind: str):
    return [
        e
        for e in ctx.investigations.evidence(inv.investigation_id)
        if e.provenance.get("check") == kind
    ]


def test_related_alerts_on_the_same_entities_become_evidence(ctx):
    inv, alert = _start(ctx, "s1_stolen_password_payload")
    related = _context(ctx, inv, "related_alert")
    rules = sorted(e.provenance["rule_id"] for e in related)
    assert rules == [
        "auth.repeated_failures",
        "network.local_ioc_match",
        "process.suspicious_powershell",
    ]
    for item in related:
        assert item.category is EvidenceCategory.OBSERVATION
        assert item.source_type is EvidenceSource.ALERT and item.event_ids
        assert item.provenance["alert_id"] != alert.alert_id
        # cited events are in the scope, as every evidence item's must be
        scope = ctx.investigations.repo.scope_ids(inv.investigation_id)
        assert set(item.event_ids) <= scope


def test_logon_history_says_whether_the_source_was_seen_before(ctx):
    inv, _ = _start(ctx, "s1_stolen_password_payload")
    (maria,) = _context(ctx, inv, "history")
    assert "10.30.1.21 (3 day(s))" in maria.claim
    assert "203.0.113.77 had never been used" in maria.claim
    assert maria.source_type is EvidenceSource.HISTORY and maria.event_ids == []
    assert len(maria.provenance["sample"]) == 3  # the earlier logons it was computed from


def test_benign_history_for_logons_and_commands(settings):
    from app.context import build_context

    tom = build_context(settings, ":memory:")
    inv, _ = _start(tom, "s2_mistyped_password")
    (item,) = _context(tom, inv, "history")
    assert "10.30.1.44 was used on 5 of those days" in item.claim

    deploy = build_context(settings, ":memory:")
    inv, _ = _start(deploy, "s3_deployment_powershell")
    (item,) = _context(deploy, inv, "history")
    assert "ran on SRV-APP03 on 5 earlier day(s)" in item.claim
    assert "parent ccmexec.exe" in item.claim and "user svc_deploy" in item.claim


def test_many_accounts_get_one_summary_line(ctx):
    inv, _ = _start(ctx, "s4_password_spray")
    (item,) = _context(ctx, inv, "history")
    assert item.claim.startswith("[first seen] Logon history for the 8 accounts in this alert")
    assert item.provenance["baseline"] == "first seen"
    assert "1 had successful logons before (anna)" in item.claim
    assert "198.51.100.66 had been used by none of them" in item.claim


def test_first_seen_connection(ctx):
    inv, _ = _start(ctx, "s5_lone_ioc_hit")
    (item,) = _context(ctx, inv, "history")
    assert "WS-LAB07 had not connected to 203.0.113.80" in item.claim
    assert "first seen in this alert" in item.claim


def test_upstream_siem_detections_without_their_own_alert(ctx):
    inv, _ = _start(ctx, "s6_wazuh_ssh_backdoor_user")
    (siem,) = _context(ctx, inv, "siem")  # rule 5720 already has an alert: reported as related
    assert siem.claim.startswith("Wazuh rule 5902 (level 8, MITRE T1136.001) on web-02")
    assert "user sysupd" in siem.claim and "New user added to the system" in siem.claim
    assert siem.source_type is EvidenceSource.EVENT and len(siem.event_ids) == 1
    related = {e.provenance["rule_id"] for e in _context(ctx, inv, "related_alert")}
    assert related == {"auth.repeated_failures", "siem.high_severity_alert"}


@pytest.mark.parametrize("level", [6, "9", True])
def test_low_or_untrusted_siem_levels_are_not_reported(ctx, level):
    rows = [
        {
            "timestamp": f"2026-03-10T10:00:0{i}Z",
            "event_type": "auth",
            "outcome": "failure",
            "user": "zoe",
            "src_ip": "198.51.100.9",
            "host": "H1",
            "record": i,
        }
        for i in range(5)
    ] + [
        {
            "timestamp": "2026-03-10T10:01:00Z",
            "host": "H1",
            "user": "zoe",
            "message": "something",
            "siem": {"vendor": "wazuh", "rule_level": level},
        }
    ]
    body = "".join(json.dumps(r) + "\n" for r in rows).encode()
    ingest_upload(ctx.ingestion, "x.jsonl", body, InputFormat.JSONL)
    alert = next(a for a in ctx.alerts.list() if a.rule_id == "auth.repeated_failures")
    inv = ctx.investigations.start_from_alert(alert.alert_id)
    assert _context(ctx, inv, "siem") == []


def test_demo_investigation_gets_context(ctx):
    load_demo_iocs(ctx.iocs)
    ingest_demo(ctx.ingestion)
    alert = next(a for a in ctx.alerts.list() if a.rule_id == "auth.failures_then_success")
    first = ctx.investigations.start_from_alert(alert.alert_id)
    claims = sorted(
        e.claim
        for e in ctx.investigations.evidence(first.investigation_id)
        if e.provenance.get("check")
    )
    assert any("Related alert on the same entities" in c for c in claims)
    # The demo covers one day, so there is no earlier logon to compare with; it says so.
    assert (
        "[no baseline] No successful logons for dave in the 30 days before 2026-03-10: no "
        "baseline to "
        "compare with." in claims
    )


@pytest.mark.parametrize(
    ("scenario_id", "label"),
    [
        ("s1_stolen_password_payload", "first seen"),
        ("s2_mistyped_password", "seen before"),
        ("s3_deployment_powershell", "seen before"),
        ("s4_password_spray", "first seen"),
        ("s5_lone_ioc_hit", "first seen"),
        ("s6_wazuh_ssh_backdoor_user", "no baseline"),
        ("s7_unfamiliar_ip_login", "first seen"),
    ],
)
def test_history_lines_carry_a_computed_label(settings, scenario_id, label):
    """The verifier may only call activity routine on a [seen before] line, so the label is
    computed by code from the alert's own source, command or connection."""
    from app.context import build_context

    ctx = build_context(settings, ":memory:")
    inv, _ = _start(ctx, scenario_id)
    (item,) = _context(ctx, inv, "history")
    assert item.provenance["baseline"] == label
    assert item.claim.startswith(f"[{label}] ")
