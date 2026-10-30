"""Wazuh alerts (``/var/ossec/logs/alerts/alerts.json``, one JSON alert per line).

Explicit mapping, nothing guessed:

- time ``timestamp``; unique ID ``id``; host ``agent.name`` (else the Windows computer name);
- user ``data.dstuser`` / ``data.win.eventdata.targetUserName`` / ``data.srcuser`` /
  ``data.win.eventdata.user``; IPs and port from ``data.srcip``/``dstip``/``dstport`` or the
  Windows/Sysmon event data; process, command line and parent from Sysmon / 4688 event data;
- the event type and outcome come from Wazuh's rule groups and the Windows event ID:
  ``authentication_success`` / 4624 is a successful logon, ``authentication_failed`` /
  ``win_authentication_failed`` / ``invalid_login`` / 4625 a failed one, Sysmon 1 / 4688 a process
  start, Sysmon 3 a network connection. Everything else is ``other``.
  Wazuh's *aggregate* alerts (``authentication_failures``, "multiple failed logons") stay
  ``other``: counting them as logons would double-count the individual failures.
- Wazuh's own verdict is kept under ``siem.*`` (vendor, rule id, level, description, groups,
  MITRE IDs, agent id, decoder, location) for the ``siem.high_severity_alert`` rule and the
  analyst. ``-`` (the Windows "no value" placeholder) counts as missing.
"""

from __future__ import annotations

from typing import Any

from app.domain.enums import EventType

AUTH_SUCCESS_GROUPS = frozenset({"authentication_success"})
AUTH_FAILURE_GROUPS = frozenset(
    {"authentication_failed", "win_authentication_failed", "invalid_login"}
)
PROCESS_GROUPS = frozenset({"sysmon_event1", "process_creation"})
NETWORK_GROUPS = frozenset({"sysmon_event3"})
WINDOWS_EVENT_TYPES = {
    "4624": ("auth", "success"),
    "4625": ("auth", "failure"),
    "4688": ("process", None),
}
SYSMON_EVENT_TYPES = {"1": "process", "3": "network"}
ACTIONS = {"auth": "logon", "process": "process_start", "network": "connection"}


def _obj(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _level(value: Any) -> int | None:
    """Wazuh levels are integers 0-15; anything else is not trusted as a level."""
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 15:
        return value
    return None


def _first(*values: Any) -> Any:
    for value in values:
        if isinstance(value, str | int) and not isinstance(value, bool):
            text = str(value).strip()
            if text and text != "-":
                return text
    return None


class WazuhAlertAdapter:
    name = "wazuh"
    title = "Wazuh alerts (alerts.json)"
    default_event_type: EventType | None = None

    def transform(self, record: dict[str, Any]) -> dict[str, Any]:
        rule = _obj(record.get("rule"))
        agent = _obj(record.get("agent"))
        data = _obj(record.get("data"))
        win = _obj(data.get("win"))
        system = _obj(win.get("system"))
        ed = _obj(win.get("eventdata"))
        raw_groups = rule.get("groups")
        groups = (
            [g.lower() for g in raw_groups if isinstance(g, str)]
            if isinstance(raw_groups, list)
            else []
        )
        event_type, outcome = self._classify(set(groups), _first(system.get("eventID")), system)
        mitre = _obj(rule.get("mitre")).get("id")

        out: dict[str, Any] = {
            "timestamp": record.get("timestamp"),
            "event_id": _first(record.get("id")),
            "host": _first(agent.get("name"), system.get("computer")),
            "user": _first(
                data.get("dstuser"), ed.get("targetUserName"), data.get("srcuser"), ed.get("user")
            ),
            "src_ip": _first(data.get("srcip"), ed.get("ipAddress"), ed.get("sourceIp")),
            "dst_ip": _first(data.get("dstip"), ed.get("destinationIp")),
            "dst_port": _first(data.get("dstport"), ed.get("destinationPort")),
            "process_name": _first(ed.get("image"), ed.get("newProcessName")),
            "command_line": _first(ed.get("commandLine")),
            "parent_process": _first(ed.get("parentImage"), ed.get("parentProcessName")),
            "message": _first(rule.get("description")),
            "event_type": event_type,
            "outcome": outcome,
            "action": ACTIONS.get(event_type or ""),
            "siem": {
                "vendor": "wazuh",
                "rule_id": _first(rule.get("id")),
                "rule_level": _level(rule.get("level")),
                "rule_description": _first(rule.get("description")),
                "rule_groups": groups,
                "mitre_ids": [m for m in mitre if isinstance(m, str)]
                if isinstance(mitre, list)
                else [],
                "agent_id": _first(agent.get("id")),
                "decoder": _first(_obj(record.get("decoder")).get("name")),
                "location": _first(record.get("location")),
                "windows_event_id": _first(system.get("eventID")),
            },
        }
        out["siem"] = {k: v for k, v in out["siem"].items() if v not in (None, [])}
        return {k: v for k, v in out.items() if v is not None}

    @staticmethod
    def _classify(
        groups: set[str], windows_event_id: str | None, system: dict[str, Any]
    ) -> tuple[str | None, str | None]:
        if "authentication_failures" in groups:
            return None, None  # aggregate alert, not a logon of its own
        if (
            windows_event_id in WINDOWS_EVENT_TYPES
            and "sysmon" not in str(system.get("providerName", "")).lower()
        ):
            return WINDOWS_EVENT_TYPES[windows_event_id]
        if groups & AUTH_FAILURE_GROUPS:
            return "auth", "failure"
        if groups & AUTH_SUCCESS_GROUPS:
            return "auth", "success"
        if groups & PROCESS_GROUPS:
            return "process", None
        if groups & NETWORK_GROUPS:
            return "network", None
        if "sysmon" in str(system.get("providerName", "")).lower():
            return SYSMON_EVENT_TYPES.get(windows_event_id or ""), None
        return None, None
