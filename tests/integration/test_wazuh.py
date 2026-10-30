from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from app.config import PROJECT_ROOT
from app.domain.enums import EventType, InputFormat, Outcome, SourceType
from app.ingestion.adapters import WazuhAlertAdapter, get_adapter
from app.ingestion.iocs import load_demo_iocs
from app.ingestion.normalizer import normalize_record
from app.ingestion.upload import ingest_upload, preview_upload
from app.storage.repositories import EventFilters

SAMPLE = PROJECT_ROOT / "data" / "samples" / "wazuh_alerts.jsonl"
WAZUH = WazuhAlertAdapter()


def _records() -> list[dict]:
    return [json.loads(line) for line in SAMPLE.read_text(encoding="utf-8").splitlines()]


def _normalize(record: dict):
    return normalize_record(WAZUH.transform(record), source_id="w", locator="x", received=record)


def _ingest(ctx, content: bytes | None = None):
    load_demo_iocs(ctx.iocs)
    return ctx.ingestion.ingest_bytes(
        content if content is not None else SAMPLE.read_bytes(),
        InputFormat.JSONL,
        source_id="wazuh-sample",
        source_type=SourceType.FILE_TAIL,
        source_name="sample",
        adapter=get_adapter("wazuh"),
    )


def test_sample_is_current():
    """The checked-in sample is what the generator script writes."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "make_wazuh_sample", PROJECT_ROOT / "scripts" / "make_wazuh_sample.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    expected = "".join(json.dumps(r, sort_keys=True) + "\n" for r in module.build())
    assert SAMPLE.read_text(encoding="utf-8") == expected


def test_sshd_and_windows_logons_map_to_auth_events():
    by_rule = {}
    for record in _records():
        by_rule.setdefault(record["rule"]["id"], record)
    ssh_fail = _normalize(by_rule["5760"])
    assert (ssh_fail.event_type, ssh_fail.outcome) == (EventType.AUTH, Outcome.FAILURE)
    assert (ssh_fail.user, ssh_fail.host, ssh_fail.src_ip) == ("deploy", "web-01", "198.51.100.23")
    assert ssh_fail.action == "logon" and ssh_fail.message == "sshd: authentication failed."
    assert ssh_fail.extra["siem.vendor"] == "wazuh" and ssh_fail.extra["siem.rule_level"] == 5
    assert ssh_fail.extra["siem.mitre_ids"] == ["T1110.001"]
    win_fail = _normalize(by_rule["60122"])
    assert (win_fail.event_type, win_fail.outcome, win_fail.user) == (
        EventType.AUTH,
        Outcome.FAILURE,
        "alice",
    )
    assert win_fail.src_ip == "198.51.100.40" and win_fail.host == "WIN-FIN01"
    assert win_fail.extra["siem.windows_event_id"] == "4625"


def test_sysmon_process_and_network_events():
    by_rule = {r["rule"]["id"]: r for r in _records()}
    proc = _normalize(by_rule["92057"])
    assert proc.event_type is EventType.PROCESS
    assert proc.process_name.endswith("powershell.exe") and "-enc" in proc.command_line
    assert proc.parent_process.endswith("explorer.exe")
    net = _normalize(by_rule["92101"])
    assert net.event_type is EventType.NETWORK
    assert (net.src_ip, net.dst_ip, net.dst_port) == ("10.10.0.31", "203.0.113.80", 443)


def test_aggregate_and_unknown_alerts_stay_other_and_raw_is_kept():
    by_rule = {r["rule"]["id"]: r for r in _records()}
    aggregate = _normalize(by_rule["5720"])  # "multiple failures": not a logon of its own
    assert aggregate.event_type is EventType.OTHER and aggregate.outcome is Outcome.UNKNOWN
    fim = _normalize(by_rule["550"])
    assert fim.event_type is EventType.OTHER and fim.user is None
    assert fim.raw == by_rule["550"]  # the record as Wazuh wrote it, not the reshaped one


@pytest.mark.parametrize(
    "record",
    [
        {"timestamp": "2026-09-14T08:00:00.000+0000"},
        {"timestamp": "2026-09-14T08:00:00.000+0000", "rule": "x", "agent": [], "data": 5},
        {"timestamp": "2026-09-14T08:00:00.000+0000", "rule": {"groups": "sshd", "level": "9"}},
        {
            "timestamp": "2026-09-14T08:00:00.000+0000",
            "data": {"win": {"system": {"eventID": "4625"}, "eventdata": {"targetUserName": "-"}}},
        },
    ],
)
def test_odd_wazuh_records_never_raise(record):
    event = _normalize(record)
    assert event.user is None and event.extra["siem.vendor"] == "wazuh"
    assert "siem.rule_level" not in event.extra  # a string level is not trusted as a number


def test_wazuh_ids_make_reingest_duplicate_free(ctx):
    first = _ingest(ctx)
    assert (first.inserted, first.quarantined) == (17, 0)
    again = _ingest(ctx)
    assert (again.inserted, again.duplicates) == (0, 17)


def test_our_rules_and_the_siem_rule_fire_on_wazuh_alerts(ctx):
    _ingest(ctx)
    alerts = Counter(a.rule_id for a in ctx.alerts.list())
    assert alerts == {
        "auth.failures_then_success": 2,  # deploy on web-01, alice on WIN-FIN01
        "auth.repeated_failures": 1,  # six sshd failures
        "process.suspicious_powershell": 1,
        "network.local_ioc_match": 1,
        "siem.high_severity_alert": 2,  # Wazuh levels 10 and 12; levels 3-7 stay events
    }
    siem = {a.title: a for a in ctx.alerts.list() if a.rule_id == "siem.high_severity_alert"}
    level12 = siem["Wazuh rule 92057 (level 12) on WIN-FIN01"]
    assert level12.severity.value == "high" and "T1059.001" in level12.explanation
    assert siem["Wazuh rule 5720 (level 10) on web-01"].severity.value == "medium"
    benign = ctx.events.query(EventFilters(equals={"user": "bob"}))
    linked = {
        link.event_id for a in ctx.alerts.list() for link in ctx.alerts.events_for(a.alert_id)
    }
    assert benign and not {e.event_id for e in benign} & linked


def test_siem_rule_threshold_is_configurable(ctx):
    ctx.detection.configure("siem.high_severity_alert", enabled=True, config={"min_level": 13})
    _ingest(ctx)
    assert not [a for a in ctx.alerts.list() if a.rule_id == "siem.high_severity_alert"]


def test_investigation_from_a_wazuh_alert(ctx):
    _ingest(ctx)
    alert = next(a for a in ctx.alerts.list() if a.rule_id == "process.suspicious_powershell")
    inv = ctx.investigations.start_from_alert(alert.alert_id)
    scope = ctx.investigations.scope_events(inv.investigation_id)
    # Host correlation brings in alice's logons and the IOC connection on WIN-FIN01.
    assert {e.event_type for e in scope} >= {EventType.AUTH, EventType.PROCESS, EventType.NETWORK}


def test_upload_with_the_wazuh_layout(ctx, tmp_path: Path):
    content = SAMPLE.read_bytes()
    preview = preview_upload(content, InputFormat.JSONL, ctx.settings, adapter=WAZUH)
    assert preview.mapping["user"] == "user" and "siem.rule_level" in preview.unmapped
    assert len(preview.rows) == 17 and not preview.errors
    result = ingest_upload(ctx.ingestion, "alerts.json", content, InputFormat.JSONL, adapter=WAZUH)
    assert result.inserted == 17
