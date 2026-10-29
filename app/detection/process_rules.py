"""Process rules based on explicit fields (process name and command line)."""

from __future__ import annotations

import ntpath
import re
from collections.abc import Sequence
from typing import ClassVar

from app.detection.base import DetectionContext, Rule, fmt_ts, sessions
from app.domain.enums import EventType, Severity
from app.domain.models import NormalizedEvent
from app.storage.alerts import Finding
from app.storage.repositories import EventFilters

POWERSHELL_NAMES = frozenset({"powershell.exe", "pwsh.exe", "powershell", "pwsh"})

# Each indicator is an explicit, documented pattern. Flags such as -ExecutionPolicy Bypass or
# -NoProfile are deliberately NOT indicators: they are routine in admin scripts.
INDICATORS: dict[str, re.Pattern[str]] = {
    "encoded command": re.compile(
        r"(?:^|\s)[-/]e(?:nc?|ncodedcommand|c)?\s+[A-Za-z0-9+/=]{16,}", re.IGNORECASE
    ),
    "hidden window": re.compile(
        r"(?:^|\s)[-/]w(?:in(?:dow(?:style)?)?)?\s+hidden\b", re.IGNORECASE
    ),
    "download cradle": re.compile(
        r"\b(?:downloadstring|downloadfile|downloaddata|net\.webclient|start-bitstransfer)\b",
        re.IGNORECASE,
    ),
    "invoke-expression": re.compile(r"\b(?:iex|invoke-expression)\b", re.IGNORECASE),
}


def powershell_indicators(event: NormalizedEvent) -> list[str]:
    if (
        event.event_type is not EventType.PROCESS
        or not event.process_name
        or ntpath.basename(event.process_name).lower() not in POWERSHELL_NAMES
        or not event.command_line
    ):
        return []
    return [name for name, pattern in INDICATORS.items() if pattern.search(event.command_line)]


class SuspiciousPowerShell(Rule):
    rule_id: ClassVar[str] = "process.suspicious_powershell"
    version: ClassVar[int] = 1
    title: ClassVar[str] = "Suspicious PowerShell command line"
    description: ClassVar[str] = (
        "PowerShell started with an encoded command, hidden window, download cradle or "
        "Invoke-Expression. Matches the process name and command line fields only."
    )
    severity: ClassVar[Severity] = Severity.HIGH
    default_config: ClassVar[dict[str, int]] = {"min_indicators": 1, "session_gap_seconds": 600}
    config_help: ClassVar[dict[str, str]] = {
        "min_indicators": "Distinct indicator types one command line needs",
        "session_gap_seconds": "Matches on one host/user closer than this share an alert",
    }

    def evaluate(
        self, new_events: Sequence[NormalizedEvent], ctx: DetectionContext, config: dict[str, int]
    ) -> list[Finding]:
        needed = self.setting(config, "min_indicators")
        gap = self.setting(config, "session_gap_seconds")
        scopes = sorted(
            {
                (e.host, e.user or "")
                for e in new_events
                if e.host and len(powershell_indicators(e)) >= needed
            }
        )
        findings: list[Finding] = []
        for host, user in scopes:
            history = ctx.events.query(
                EventFilters(equals={"event_type": EventType.PROCESS, "host": host})
            )
            hits = [
                (e, powershell_indicators(e))
                for e in history
                if (e.user or "") == user and len(powershell_indicators(e)) >= needed
            ]
            indicators = {e.event_id: names for e, names in hits}
            for group in sessions([e for e, _ in hits], gap):
                names = sorted({n for e in group for n in indicators[e.event_id]})
                who = f" as {user}" if user else ""
                findings.append(
                    self.finding(
                        key_parts=[host, user],
                        title=f"Suspicious PowerShell on {host}{who}",
                        explanation=(
                            f"{len(group)} PowerShell process event(s) on {host}{who} between "
                            f"{fmt_ts(group[0].event_time)} and {fmt_ts(group[-1].event_time)} "
                            f"with indicators: {', '.join(names)}. Rule: command line shows at "
                            f"least {needed} indicator type(s)."
                        ),
                        matched=[
                            (e, "indicators: " + ", ".join(indicators[e.event_id])) for e in group
                        ],
                    )
                )
        return findings
