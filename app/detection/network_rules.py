"""Network rules driven by the local IOC list."""

from __future__ import annotations

from collections.abc import Sequence
from typing import ClassVar

from app.detection.base import DetectionContext, Rule, fmt_ts, sessions
from app.domain.enums import EventType, Severity
from app.domain.models import NormalizedEvent
from app.storage.alerts import Finding
from app.storage.repositories import EventFilters

_CONFIDENCE_SEVERITY = {"high": Severity.HIGH, "medium": Severity.MEDIUM}


class LocalIocConnection(Rule):
    rule_id: ClassVar[str] = "network.local_ioc_match"
    version: ClassVar[int] = 1
    title: ClassVar[str] = "Connection to a locally listed IOC"
    description: ClassVar[str] = (
        "A network event whose destination IP is in the local IOC list. Severity follows the "
        "IOC's confidence. Needs a host or source IP to say who connected."
    )
    severity: ClassVar[Severity] = Severity.LOW
    default_config: ClassVar[dict[str, int]] = {"session_gap_seconds": 3600}
    config_help: ClassVar[dict[str, str]] = {
        "session_gap_seconds": "Connections from one client to one IOC closer than this join"
    }

    def evaluate(
        self, new_events: Sequence[NormalizedEvent], ctx: DetectionContext, config: dict[str, int]
    ) -> list[Finding]:
        gap = self.setting(config, "session_gap_seconds")
        iocs = ctx.iocs.ip_map()
        if not iocs:
            return []
        scopes = sorted(
            {
                (e.dst_ip, "host" if e.host else "src_ip", e.host or e.src_ip)
                for e in new_events
                if e.event_type is EventType.NETWORK and e.dst_ip in iocs and (e.host or e.src_ip)
            }
        )
        findings: list[Finding] = []
        for dst_ip, client_field, client in scopes:
            ioc = iocs[dst_ip]
            history = ctx.events.query(
                EventFilters(
                    equals={
                        "event_type": EventType.NETWORK,
                        "dst_ip": dst_ip,
                        client_field: client,
                    }
                )
            )
            for group in sessions(history, gap):
                detail = f" ({ioc.description})" if ioc.description else ""
                findings.append(
                    self.finding(
                        key_parts=[dst_ip, client],
                        severity=_CONFIDENCE_SEVERITY.get(ioc.confidence.lower(), Severity.LOW),
                        title=f"{client} connected to IOC {dst_ip}",
                        explanation=(
                            f"{len(group)} network event(s) from {client} to {dst_ip} between "
                            f"{fmt_ts(group[0].event_time)} and {fmt_ts(group[-1].event_time)}. "
                            f"Local IOC list: {dst_ip}{detail}, source '{ioc.source}', "
                            f"confidence {ioc.confidence}."
                        ),
                        matched=[
                            (e, f"destination {dst_ip} is in the local IOC list") for e in group
                        ],
                    )
                )
        return findings
