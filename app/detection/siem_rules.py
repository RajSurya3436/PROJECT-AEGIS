"""Rules over verdicts that an upstream SIEM already reached (fields under ``siem.*``, set by a
record adapter such as Wazuh's). The SIEM's own rule ID and level are kept; this app does not
re-judge them, it only decides which ones become alerts here."""

from __future__ import annotations

from collections.abc import Sequence
from typing import ClassVar

from app.detection.base import DetectionContext, Rule, fmt_ts
from app.domain.enums import Severity
from app.domain.models import NormalizedEvent
from app.storage.alerts import Finding


def siem_level(event: NormalizedEvent) -> int | None:
    level = event.extra.get("siem.rule_level")
    return level if isinstance(level, int) and not isinstance(level, bool) else None


class SiemHighSeverityAlert(Rule):
    rule_id: ClassVar[str] = "siem.high_severity_alert"
    version: ClassVar[int] = 1
    title: ClassVar[str] = "High-level alert from an upstream SIEM"
    description: ClassVar[str] = (
        "One alert per upstream SIEM alert (e.g. Wazuh) at or above the configured level, "
        "keeping the SIEM's rule ID, level, description and MITRE IDs. Severity: high from "
        "high_level up, medium below it."
    )
    severity: ClassVar[Severity] = Severity.MEDIUM
    default_config: ClassVar[dict[str, int]] = {"min_level": 10, "high_level": 12}
    config_help: ClassVar[dict[str, str]] = {
        "min_level": "Lowest SIEM rule level that becomes an alert here (Wazuh: 0-15)",
        "high_level": "SIEM rule level from which the alert is high severity",
    }

    def evaluate(
        self, new_events: Sequence[NormalizedEvent], ctx: DetectionContext, config: dict[str, int]
    ) -> list[Finding]:
        min_level = self.setting(config, "min_level")
        high_level = self.setting(config, "high_level")
        findings = []
        for event in new_events:
            level = siem_level(event)
            if level is None or level < min_level:
                continue
            vendor = str(event.extra.get("siem.vendor") or "siem")
            rule = str(event.extra.get("siem.rule_id") or "?")
            description = str(event.extra.get("siem.rule_description") or event.message or "")
            mitre = event.extra.get("siem.mitre_ids") or []
            where = event.host or event.src_ip or "unknown host"
            mitre_text = f" MITRE: {', '.join(map(str, mitre))}." if mitre else ""
            findings.append(
                self.finding(
                    key_parts=[vendor, rule, event.event_id],
                    severity=Severity.HIGH if level >= high_level else Severity.MEDIUM,
                    title=f"{vendor.capitalize()} rule {rule} (level {level}) on {where}",
                    explanation=(
                        f"{vendor.capitalize()} raised rule {rule} at level {level} on {where} at "
                        f"{fmt_ts(event.event_time)}: {description}.{mitre_text} The level is "
                        f"the upstream SIEM's; this app only applies the threshold {min_level}."
                    ),
                    matched=[(event, f"{vendor} rule {rule} level {level} >= {min_level}")],
                )
            )
        return findings
