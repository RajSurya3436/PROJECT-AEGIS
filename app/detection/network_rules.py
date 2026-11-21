"""Network rules: local IOC matches, port scans, lateral-movement fan-out, connections to
ports favoured by malware, and large outbound transfers."""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from typing import ClassVar

from app.detection.base import DetectionContext, Rule, fmt_ts, qualifying_runs, sessions
from app.domain.enums import EventType, Severity
from app.domain.models import NormalizedEvent
from app.storage.alerts import Finding
from app.storage.repositories import EventFilters

_CONFIDENCE_SEVERITY = {"high": Severity.HIGH, "medium": Severity.MEDIUM}


class LocalIocConnection(Rule):
    rule_id: ClassVar[str] = "network.local_ioc_match"
    category: ClassVar[str] = "command_and_control"
    mitre: ClassVar[tuple[str, ...]] = ("T1071",)
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
            assert dst_ip and client  # guaranteed by the filter above
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


# --- behaviour rules ------------------------------------------------------------------------


def _ip(value: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value) if value else None
    except ValueError:
        return None


# RFC 5737 / 3849 documentation ranges. Python counts them as private, but synthetic data uses
# them to stand for internet addresses, so these rules treat them as public.
_DOCUMENTATION_NETS = tuple(
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)


def _documentation(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(ip.version == net.version and ip in net for net in _DOCUMENTATION_NETS)


def is_internal(value: str | None) -> bool:
    ip = _ip(value)
    return bool(ip and ip.is_private and not _documentation(ip))


def is_public(value: str | None) -> bool:
    """Globally routable, or a documentation address (see above)."""
    ip = _ip(value)
    return bool(ip and (ip.is_global or _documentation(ip)))


def _client(event: NormalizedEvent) -> tuple[str, str] | None:
    """Who made the connection: the source IP if known, else the host."""
    if event.src_ip:
        return "src_ip", event.src_ip
    if event.host:
        return "host", event.host
    return None


def _network_history(ctx: DetectionContext, field: str, value: str) -> list[NormalizedEvent]:
    return ctx.events.query(EventFilters(equals={"event_type": EventType.NETWORK, field: value}))


class _FanOutRule(Rule):
    """One client reaching many distinct targets in a window. Subclasses pick the events and
    the target of each event."""

    count_key: ClassVar[str]

    def relevant(self, event: NormalizedEvent) -> bool:
        raise NotImplementedError

    def target(self, event: NormalizedEvent) -> str:
        raise NotImplementedError

    def describe(self, client: str, run: list[NormalizedEvent], targets: list[str]) -> str:
        raise NotImplementedError

    def runs_for(
        self, ctx: DetectionContext, field: str, client: str, needed: int, window: int
    ) -> list[list[NormalizedEvent]]:
        events = [e for e in _network_history(ctx, field, client) if self.relevant(e)]

        def distinct(window_events: Sequence[NormalizedEvent]) -> bool:
            return len({self.target(e) for e in window_events}) >= needed

        return qualifying_runs(events, window, distinct)

    def evaluate(
        self, new_events: Sequence[NormalizedEvent], ctx: DetectionContext, config: dict[str, int]
    ) -> list[Finding]:
        needed = self.setting(config, self.count_key)
        window = self.setting(config, "window_seconds")
        clients = sorted(
            {
                c
                for e in new_events
                if e.event_type is EventType.NETWORK and self.relevant(e) and (c := _client(e))
            }
        )
        findings: list[Finding] = []
        for field, client in clients:
            for run in self.runs_for(ctx, field, client, needed, window):
                targets = sorted({self.target(e) for e in run})
                findings.append(
                    self.finding(
                        key_parts=[client],
                        title=self.describe(client, run, targets),
                        explanation=(
                            f"{len(run)} connection(s) from {client} to {len(targets)} distinct "
                            f"target(s) between {fmt_ts(run[0].event_time)} and "
                            f"{fmt_ts(run[-1].event_time)}: {', '.join(targets[:25])}"
                            f"{' ...' if len(targets) > 25 else ''}. Rule: at least {needed} "
                            f"distinct targets within {window}s."
                        ),
                        matched=[(e, f"connection to {self.target(e)}") for e in run],
                    )
                )
        return findings


class PortScan(_FanOutRule):
    rule_id: ClassVar[str] = "network.port_scan"
    category: ClassVar[str] = "discovery"
    mitre: ClassVar[tuple[str, ...]] = ("T1046",)
    version: ClassVar[int] = 1
    title: ClassVar[str] = "Port or host scan"
    description: ClassVar[str] = (
        "One client connecting to many distinct destination IP:port pairs in a short time, "
        "whether across ports on one host or one port across many hosts."
    )
    severity: ClassVar[Severity] = Severity.MEDIUM
    count_key: ClassVar[str] = "distinct_targets"
    default_config: ClassVar[dict[str, int]] = {"distinct_targets": 20, "window_seconds": 120}
    config_help: ClassVar[dict[str, str]] = {
        "distinct_targets": "Distinct destination IP:port pairs from one client to alert",
        "window_seconds": "Window the connections must fall in (inclusive)",
    }

    def relevant(self, event: NormalizedEvent) -> bool:
        return bool(event.dst_ip and event.dst_port is not None)

    def target(self, event: NormalizedEvent) -> str:
        return f"{event.dst_ip}:{event.dst_port}"

    def describe(self, client: str, run: list[NormalizedEvent], targets: list[str]) -> str:
        return f"{client} probed {len(targets)} IP:port targets"


ADMIN_PORTS = frozenset({22, 135, 139, 445, 3389, 5985, 5986})


class LateralMovementFanOut(_FanOutRule):
    rule_id: ClassVar[str] = "network.lateral_movement"
    category: ClassVar[str] = "lateral_movement"
    mitre: ClassVar[tuple[str, ...]] = ("T1021.001", "T1021.002", "T1021.004", "T1021.006")
    version: ClassVar[int] = 1
    title: ClassVar[str] = "Remote-admin connections to many internal hosts"
    description: ClassVar[str] = (
        "One client connecting to many internal hosts on remote-administration ports (SSH 22, "
        "RPC 135, SMB 139/445, RDP 3389, WinRM 5985/5986) in a short time."
    )
    severity: ClassVar[Severity] = Severity.HIGH
    count_key: ClassVar[str] = "distinct_hosts"
    default_config: ClassVar[dict[str, int]] = {"distinct_hosts": 5, "window_seconds": 900}
    config_help: ClassVar[dict[str, str]] = {
        "distinct_hosts": "Distinct internal hosts reached on admin ports to alert",
        "window_seconds": "Window the connections must fall in (inclusive)",
    }

    def relevant(self, event: NormalizedEvent) -> bool:
        return event.dst_port in ADMIN_PORTS and is_internal(event.dst_ip)

    def target(self, event: NormalizedEvent) -> str:
        return event.dst_ip or ""

    def describe(self, client: str, run: list[NormalizedEvent], targets: list[str]) -> str:
        ports = sorted({e.dst_port for e in run if e.dst_port is not None})
        return f"{client} reached {len(targets)} internal hosts on ports {ports}"


# Ports default-configured by common C2 frameworks, RATs, IRC botnets and Tor. A connection to
# one of them is not proof of anything, so the severity is medium.
SUSPICIOUS_PORTS: dict[int, str] = {
    1337: "common backdoor/'leet' port",
    4444: "Metasploit default handler",
    4445: "Metasploit alternate handler",
    5555: "common RAT / adb",
    6666: "IRC botnet",
    6667: "IRC botnet",
    6697: "IRC over TLS",
    8888: "common C2 panel",
    9001: "Tor relay",
    9050: "Tor SOCKS",
    9150: "Tor Browser SOCKS",
    12345: "NetBus RAT",
    31337: "Back Orifice / 'eleet'",
    50050: "Cobalt Strike team server",
}


class SuspiciousPortConnection(Rule):
    rule_id: ClassVar[str] = "network.suspicious_port"
    category: ClassVar[str] = "command_and_control"
    mitre: ClassVar[tuple[str, ...]] = ("T1571",)
    version: ClassVar[int] = 1
    title: ClassVar[str] = "Outbound connection to a port favoured by malware"
    description: ClassVar[str] = (
        "A connection to a public IP on a port used by default by C2 frameworks, RATs, IRC "
        "botnets or Tor (4444, 1337, 31337, 6667, 9050, 50050, ...). Internal traffic is ignored."
    )
    severity: ClassVar[Severity] = Severity.MEDIUM
    default_config: ClassVar[dict[str, int]] = {"session_gap_seconds": 3600}
    config_help: ClassVar[dict[str, str]] = {
        "session_gap_seconds": "Connections from one client to one IP:port closer than this join"
    }

    @staticmethod
    def matches(event: NormalizedEvent) -> bool:
        return (
            event.event_type is EventType.NETWORK
            and event.dst_port in SUSPICIOUS_PORTS
            and is_public(event.dst_ip)
        )

    def evaluate(
        self, new_events: Sequence[NormalizedEvent], ctx: DetectionContext, config: dict[str, int]
    ) -> list[Finding]:
        gap = self.setting(config, "session_gap_seconds")
        scopes = sorted(
            {(c, e.dst_ip, e.dst_port) for e in new_events if self.matches(e) and (c := _client(e))}
        )
        findings: list[Finding] = []
        for (field, client), dst_ip, port in scopes:
            assert dst_ip and port is not None  # guaranteed by matches()
            history = [
                e
                for e in _network_history(ctx, field, client)
                if e.dst_ip == dst_ip and e.dst_port == port
            ]
            why = SUSPICIOUS_PORTS[port]
            for group in sessions(history, gap):
                findings.append(
                    self.finding(
                        key_parts=[client, dst_ip, str(port)],
                        title=f"{client} connected to {dst_ip}:{port}",
                        explanation=(
                            f"{len(group)} connection(s) from {client} to {dst_ip}:{port} "
                            f"between {fmt_ts(group[0].event_time)} and "
                            f"{fmt_ts(group[-1].event_time)}. Port {port}: {why}."
                        ),
                        matched=[(e, f"port {port}: {why}") for e in group],
                    )
                )
        return findings


BYTES_OUT_FIELDS = ("bytes_out", "bytes_sent", "sent_bytes", "out_bytes", "network.bytes_out")


def bytes_out(event: NormalizedEvent) -> int:
    for key in BYTES_OUT_FIELDS:
        value = event.extra.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, int | float) and value > 0:
            return int(value)
        if isinstance(value, str) and value.isdigit():
            return int(value)
    return 0


class LargeOutboundTransfer(Rule):
    rule_id: ClassVar[str] = "network.large_upload"
    category: ClassVar[str] = "exfiltration"
    mitre: ClassVar[tuple[str, ...]] = ("T1048", "T1041")
    version: ClassVar[int] = 1
    title: ClassVar[str] = "Large outbound transfer to one external IP"
    description: ClassVar[str] = (
        "The bytes one client sent to a single public IP add up past a threshold within a "
        "window: possible data exfiltration. Needs a bytes_out (or bytes_sent) field."
    )
    severity: ClassVar[Severity] = Severity.MEDIUM
    default_config: ClassVar[dict[str, int]] = {"megabytes": 100, "window_seconds": 3600}
    config_help: ClassVar[dict[str, str]] = {
        "megabytes": "Total MB sent to one external IP to alert",
        "window_seconds": "Window the transfers must fall in (inclusive)",
    }

    def evaluate(
        self, new_events: Sequence[NormalizedEvent], ctx: DetectionContext, config: dict[str, int]
    ) -> list[Finding]:
        limit = self.setting(config, "megabytes") * 1024 * 1024
        window = self.setting(config, "window_seconds")
        scopes = sorted(
            {
                (c, e.dst_ip)
                for e in new_events
                if e.event_type is EventType.NETWORK
                and bytes_out(e)
                and is_public(e.dst_ip)
                and (c := _client(e))
            }
        )
        findings: list[Finding] = []
        for (field, client), dst_ip in scopes:
            assert dst_ip
            history = [
                e
                for e in _network_history(ctx, field, client)
                if e.dst_ip == dst_ip and bytes_out(e)
            ]
            for run in qualifying_runs(history, window, lambda w: sum(map(bytes_out, w)) >= limit):
                total = sum(map(bytes_out, run))
                findings.append(
                    self.finding(
                        key_parts=[client, dst_ip],
                        title=f"{client} sent {total / 1048576:.1f} MB to {dst_ip}",
                        explanation=(
                            f"{len(run)} connection(s) from {client} to {dst_ip} sent "
                            f"{total:,} bytes ({total / 1048576:.1f} MB) between "
                            f"{fmt_ts(run[0].event_time)} and {fmt_ts(run[-1].event_time)}. "
                            f"Rule: at least {limit // 1048576} MB within {window}s."
                        ),
                        matched=[(e, f"{bytes_out(e):,} bytes out") for e in run],
                    )
                )
        return findings
