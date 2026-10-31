"""Investigation service: lifecycle, event scope, evidence and timeline.

Everything here is deterministic. Phase 5 agents will call the same methods as tools, so the
rules live here: evidence may only cite events in the investigation's scope, closed
investigations are read-only, and a malicious verdict must cite at least one observation.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from app.audit.log import AuditLog
from app.config import Settings
from app.detection.engine import DetectionEngine
from app.domain.enums import (
    AlertStatus,
    Confidence,
    Disposition,
    EventType,
    EvidenceCategory,
    EvidenceSource,
    InvestigationStatus,
    ReputationStatus,
)
from app.domain.errors import InvestigationError, NotFoundError
from app.domain.models import (
    Alert,
    Evidence,
    Investigation,
    NormalizedEvent,
    ReputationResult,
    TimelineEntry,
)
from app.investigations import context
from app.investigations.timeline import describe_event
from app.storage.db import transaction
from app.storage.investigations import InvestigationRepository
from app.storage.repositories import CORRELATION_FIELDS, EventFilters, EventRepository
from app.tools.local_ioc import lookup_local_ioc
from app.tools.reputation.service import ReputationService

SYSTEM = "system"
ANALYST = "analyst"
MAX_CLAIM_CHARS = 2_000
MAX_CITED_EVENTS = 50
MALICIOUS = (Disposition.CONFIRMED_MALICIOUS, Disposition.LIKELY_MALICIOUS)
REPUTATION_RELIABILITY = (
    "Third-party reputation data; it can lag, be incomplete or be wrong. Corroborate with events."
)


def _fmt(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S UTC")


def evidence_id_for(
    investigation_id: str,
    category: EvidenceCategory,
    source_type: EvidenceSource,
    source_ref: str,
    claim: str,
    event_ids: list[str],
) -> str:
    """Same statement from the same source in the same investigation -> same ID, so repeating
    a collection step does not duplicate evidence."""
    key = json.dumps(
        [investigation_id, category, source_type, source_ref, claim, sorted(event_ids)]
    )
    return "ev-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


class InvestigationService:
    def __init__(
        self,
        conn: sqlite3.Connection,
        settings: Settings,
        detection: DetectionEngine,
        reputation: ReputationService,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.conn = conn
        self.settings = settings
        self.repo = InvestigationRepository(conn)
        self.events = EventRepository(conn)
        self.detection = detection
        self.alerts = detection.alerts
        self.reputation = reputation
        self._clock = clock
        # Called with the investigation ID after it closes (e.g. to stop its agent run).
        self.close_hooks: list[Callable[[str], None]] = []
        self.audit = AuditLog(conn)

    # --- lifecycle -------------------------------------------------------------------------

    def get(self, investigation_id: str) -> Investigation:
        investigation = self.repo.get(investigation_id)
        if investigation is None:
            raise NotFoundError(f"unknown investigation: {investigation_id}")
        return investigation

    def start_from_alert(
        self, alert_id: str, objective: str | None = None, actor: str = ANALYST
    ) -> Investigation:
        """Open an investigation for an alert (or return the open one that already covers it)
        and run the deterministic baseline: alert evidence, related events, local IOC matches
        and telemetry coverage checks."""
        alert = self.alerts.get(alert_id)
        if alert is None:
            raise NotFoundError(f"unknown alert: {alert_id}")
        existing = self.repo.open_for_alert(alert_id)
        if existing is not None:
            return existing
        investigation_id = "inv-" + uuid.uuid4().hex[:12]
        objective = (objective or "").strip() or (
            f"Determine whether alert '{alert.title}' reflects malicious activity, and find "
            "evidence for and against compromise."
        )
        with transaction(self.conn):
            self.repo.create(investigation_id, alert.title[:200], objective[:MAX_CLAIM_CHARS])
            self.repo.link_alert(investigation_id, alert_id)
            self._baseline(investigation_id, alert)
        self.audit.record(
            actor,
            "investigation.opened",
            "investigation",
            investigation_id,
            investigation_id=investigation_id,
            details={"alert_id": alert_id, "rule_id": alert.rule_id},
        )
        if alert.status in (AlertStatus.NEW, AlertStatus.ACKNOWLEDGED):
            self.detection.transition(alert_id, AlertStatus.INVESTIGATING, actor=SYSTEM)
        return self.get(investigation_id)

    def close(
        self,
        investigation_id: str,
        disposition: Disposition,
        confidence: Confidence,
        reason: str,
        evidence_ids: list[str],
        actor: str = ANALYST,
    ) -> Investigation:
        self._require_open(investigation_id)
        reason = reason.strip()
        if not reason:
            raise InvestigationError("explain the disposition")
        known = {e.evidence_id: e for e in self.repo.evidence(investigation_id)}
        cited = list(dict.fromkeys(evidence_ids))
        unknown = [e for e in cited if e not in known]
        if unknown:
            raise InvestigationError(f"evidence not in this investigation: {', '.join(unknown)}")
        if disposition is not Disposition.INSUFFICIENT_DATA and not cited:
            raise InvestigationError("cite the evidence that supports this disposition")
        if disposition in MALICIOUS and not any(
            known[e].category is EvidenceCategory.OBSERVATION for e in cited
        ):
            raise InvestigationError("a malicious disposition must cite at least one observation")
        self.repo.close(investigation_id, disposition, confidence, reason[:MAX_CLAIM_CHARS], cited)
        self.audit.record(
            actor,
            "investigation.closed",
            "investigation",
            investigation_id,
            investigation_id=investigation_id,
            details={
                "disposition": disposition.value,
                "confidence": confidence.value,
                "evidence_ids": cited,
            },
        )
        for hook in self.close_hooks:
            hook(investigation_id)
        return self.get(investigation_id)

    def reopen(self, investigation_id: str, actor: str = ANALYST) -> Investigation:
        if self.get(investigation_id).status is not InvestigationStatus.CLOSED:
            raise InvestigationError("investigation is already open")
        self.repo.reopen(investigation_id)
        self.audit.record(
            actor,
            "investigation.reopened",
            "investigation",
            investigation_id,
            investigation_id=investigation_id,
        )
        return self.get(investigation_id)

    def _require_open(self, investigation_id: str) -> Investigation:
        investigation = self.get(investigation_id)
        if investigation.status is not InvestigationStatus.OPEN:
            raise InvestigationError("investigation is closed; reopen it to make changes")
        return investigation

    # --- scope -----------------------------------------------------------------------------

    def search_into_scope(
        self, investigation_id: str, filters: EventFilters, reason: str, actor: str
    ) -> int:
        """Run an event search and add the results to the scope (up to the scope cap).
        Returns the number of newly added events."""
        self._require_open(investigation_id)
        added = self._add_matches(investigation_id, filters, reason.strip()[:300], actor)
        self.repo.touch(investigation_id)
        if not actor.startswith("agent:"):  # agent searches are audited as tool calls
            self.audit.record(
                actor,
                "investigation.scope_expanded",
                "investigation",
                investigation_id,
                investigation_id=investigation_id,
                details={"reason": reason.strip()[:300], "added": added},
            )
        return added

    def expand_around_entity(
        self,
        investigation_id: str,
        field: str,
        value: str,
        center_start: datetime,
        center_end: datetime,
        minutes: int,
        actor: str,
    ) -> int:
        """Add every event with ``field == value`` within ``minutes`` before/after a period."""
        if field not in CORRELATION_FIELDS:
            raise InvestigationError(f"cannot correlate on {field!r}")
        window = timedelta(minutes=minutes)
        filters = EventFilters(
            equals={field: value}, start=center_start - window, end=center_end + window
        )
        reason = f"same {field} {value} within ±{minutes} min"
        return self.search_into_scope(investigation_id, filters, reason, actor)

    def _add_matches(
        self, investigation_id: str, filters: EventFilters, reason: str, actor: str
    ) -> int:
        in_scope = self.repo.scope_ids(investigation_id)
        room = self.settings.investigation_max_scope_events - len(in_scope)
        if room <= 0:
            return 0
        # Over-fetch by the scope size so events already in scope do not use up the room.
        matches = self.events.query(filters, limit=room + len(in_scope))
        new_ids = [e.event_id for e in matches if e.event_id not in in_scope][:room]
        return self.repo.add_scope(investigation_id, new_ids, reason, actor)

    def add_to_scope(
        self, investigation_id: str, event_ids: list[str], reason: str, actor: str
    ) -> int:
        """Bring specific stored events into the scope (e.g. events an agent's search returned
        and now cites). Unknown IDs are rejected; the scope cap still applies."""
        self._require_open(investigation_id)
        wanted = list(dict.fromkeys(event_ids))
        found = {e.event_id for e in self.events.get_many(wanted)}
        unknown = [e for e in wanted if e not in found]
        if unknown:
            raise InvestigationError(f"unknown event(s): {', '.join(unknown)}")
        in_scope = self.repo.scope_ids(investigation_id)
        new_ids = [e for e in wanted if e not in in_scope]
        room = self.settings.investigation_max_scope_events - len(in_scope)
        if len(new_ids) > room:
            raise InvestigationError(
                f"scope is at its {self.settings.investigation_max_scope_events}-event cap"
            )
        added = self.repo.add_scope(investigation_id, new_ids, reason.strip()[:300], actor)
        self.repo.touch(investigation_id)
        return added

    def scope_events(self, investigation_id: str) -> list[NormalizedEvent]:
        return self.events.get_many(sorted(self.repo.scope_ids(investigation_id)))

    # --- evidence --------------------------------------------------------------------------

    def add_evidence(
        self,
        investigation_id: str,
        *,
        category: EvidenceCategory,
        claim: str,
        source_type: EvidenceSource,
        source_ref: str,
        collected_by: str,
        event_ids: list[str] | None = None,
        observed_at: datetime | None = None,
        provenance: dict[str, Any] | None = None,
        reliability: str = "",
    ) -> Evidence:
        """Record one statement. Cited events must already be in the investigation's scope,
        which stops anyone (later: any agent) citing an event no tool returned."""
        self._require_open(investigation_id)
        claim = claim.strip()
        if not claim:
            raise InvestigationError("evidence needs a claim")
        if len(claim) > MAX_CLAIM_CHARS:
            raise InvestigationError(f"claim is longer than {MAX_CLAIM_CHARS} characters")
        cited = list(dict.fromkeys(event_ids or []))
        missing = set(cited) - self.repo.scope_ids(investigation_id)
        if missing:
            raise InvestigationError(
                f"cited event(s) not in this investigation's scope: {', '.join(sorted(missing))}"
            )
        evidence = Evidence(
            evidence_id=evidence_id_for(
                investigation_id, category, source_type, source_ref, claim, cited
            ),
            investigation_id=investigation_id,
            category=category,
            source_type=source_type,
            source_ref=source_ref[:200],
            claim=claim,
            event_ids=cited,
            observed_at=observed_at,
            collected_at=self._clock(),
            collected_by=collected_by,
            provenance=provenance or {},
            reliability=reliability[:500],
        )
        if not self.repo.add_evidence(evidence):
            return next(
                e
                for e in self.repo.evidence(investigation_id)
                if e.evidence_id == evidence.evidence_id
            )
        self.repo.touch(investigation_id)
        if (
            source_type is EvidenceSource.ANALYST
        ):  # system and agent evidence come from audited steps
            self.audit.record(
                collected_by,
                "evidence.added",
                "evidence",
                evidence.evidence_id,
                investigation_id=investigation_id,
                details={"category": category.value, "event_ids": cited[:10]},
            )
        return evidence

    def evidence(self, investigation_id: str) -> list[Evidence]:
        return self.repo.evidence(investigation_id)

    def check_reputation(
        self,
        investigation_id: str,
        ip: str,
        actor: str,
        providers: list[str] | None = None,
    ) -> list[Evidence]:
        """Look up an IP that appears in the scope and record each outcome as evidence:
        provider data as observations, unavailable providers as missing telemetry.
        ``providers`` limits the lookup (default: all configured adapters)."""
        self._require_open(investigation_id)
        citing = [e for e in self.scope_events(investigation_id) if ip in (e.src_ip, e.dst_ip)]
        if not citing:
            raise InvestigationError(f"{ip} does not appear in this investigation's events")
        event_ids = [e.event_id for e in citing][:MAX_CITED_EVENTS]
        report = self.reputation.lookup_ip(
            ip, providers, actor=actor, investigation_id=investigation_id
        )
        added: list[Evidence] = []
        if report.local_ioc is not None:
            added.append(self._ioc_evidence(investigation_id, ip, event_ids, actor))
        for result in report.results:
            if result.status is ReputationStatus.SKIPPED:
                # Private, documentation or invalid addresses are never sent to a provider.
                # That is by design, not a gap in the data, so nothing is recorded.
                continue
            added.append(self._reputation_evidence(investigation_id, result, event_ids, actor))
        return added

    def _reputation_evidence(
        self, investigation_id: str, result: ReputationResult, event_ids: list[str], actor: str
    ) -> Evidence:
        provenance = {
            "tool": f"lookup_{result.provider}",
            "provider": result.provider,
            "indicator": result.indicator,
            "status": result.status.value,
            "queried_at": result.queried_at.isoformat() if result.queried_at else None,
            "expires_at": result.expires_at.isoformat() if result.expires_at else None,
            "summary": result.summary,
        }
        common = {
            "source_type": EvidenceSource.REPUTATION,
            "source_ref": f"{result.provider}:{result.indicator}",
            "collected_by": actor,
            "event_ids": event_ids,
            "provenance": provenance,
        }
        if not result.has_data:
            return self.add_evidence(
                investigation_id,
                category=EvidenceCategory.MISSING_TELEMETRY,
                claim=(
                    f"{result.provider} reputation for {result.indicator} unavailable"
                    f" ({result.status.value}): {result.message}"
                ),
                reliability="No provider data was obtained.",
                **common,
            )
        return self.add_evidence(
            investigation_id,
            category=EvidenceCategory.OBSERVATION,
            claim=reputation_claim(result),
            observed_at=result.queried_at,
            reliability=REPUTATION_RELIABILITY
            + (" Served from cache." if result.status is ReputationStatus.CACHED else ""),
            **common,
        )

    def _ioc_evidence(
        self, investigation_id: str, ip: str, event_ids: list[str], actor: str
    ) -> Evidence:
        ioc = lookup_local_ioc(self.reputation.iocs, ip)
        assert ioc is not None
        return self.add_evidence(
            investigation_id,
            category=EvidenceCategory.OBSERVATION,
            claim=(
                f"{ip} is on the local IOC list ({ioc.confidence} confidence, source "
                f"{ioc.source}): {ioc.description}"
            ),
            source_type=EvidenceSource.LOCAL_IOC,
            source_ref=f"ip:{ip}",
            collected_by=actor,
            event_ids=event_ids,
            provenance={"tool": "lookup_local_ioc", "indicator": ip, "added": ioc.added},
            reliability="Local list; only as current as its last import.",
        )

    # --- timeline --------------------------------------------------------------------------

    def timeline(self, investigation_id: str) -> list[TimelineEntry]:
        investigation = self.get(investigation_id)
        scope = {s.event_id: s for s in self.repo.scope(investigation_id)}
        events = self.events.get_many(list(scope))
        matched = {
            link.event_id
            for alert_id in investigation.alert_ids
            for link in self.alerts.events_for(alert_id)
        }
        cited: dict[str, list[str]] = {}
        for item in self.repo.evidence(investigation_id):
            for event_id in item.event_ids:
                cited.setdefault(event_id, []).append(item.evidence_id)
        return [
            TimelineEntry(
                event_id=e.event_id,
                event_time=e.event_time,
                event_type=e.event_type,
                summary=describe_event(e),
                user=e.user,
                host=e.host,
                src_ip=e.src_ip,
                dst_ip=e.dst_ip,
                scope_reason=scope[e.event_id].reason,
                alert_match=e.event_id in matched,
                cited_by=cited.get(e.event_id, []),
            )
            for e in events
        ]

    # --- deterministic baseline ------------------------------------------------------------

    def _baseline(self, investigation_id: str, alert: Alert) -> None:
        links = self.alerts.events_for(alert.alert_id)
        alert_event_ids = [link.event_id for link in links]
        self.repo.add_scope(
            investigation_id, alert_event_ids, f"matched by alert ({alert.rule_id})", SYSTEM
        )
        rule = self.detection.rules.get(alert.rule_id)
        self.add_evidence(
            investigation_id,
            category=EvidenceCategory.OBSERVATION,
            claim=f"Rule {alert.rule_id} v{alert.rule_version} ({alert.severity.value}) fired: "
            f"{alert.explanation}",
            source_type=EvidenceSource.ALERT,
            source_ref=alert.alert_id,
            collected_by=SYSTEM,
            event_ids=alert_event_ids[:MAX_CITED_EVENTS],
            observed_at=alert.first_seen,
            provenance={
                "tool": "get_alert_rule_explanation",
                "alert_id": alert.alert_id,
                "rule_title": rule.title if rule else None,
                "dedup_key": alert.dedup_key,
            },
            reliability="Deterministic rule match over stored events.",
        )

        alert_events = self.events.get_many(alert_event_ids)
        minutes = self.settings.investigation_window_minutes
        window = timedelta(minutes=minutes)
        start, end = alert.first_seen - window, alert.last_seen + window
        entities = sorted(
            {
                (name, getattr(e, name))
                for e in alert_events
                for name in CORRELATION_FIELDS
                if getattr(e, name)
            }
        )
        for name, value in entities:
            self._add_matches(
                investigation_id,
                EventFilters(equals={name: value}, start=start, end=end),
                f"same {name} {value} within ±{minutes} min of the alert",
                SYSTEM,
            )
        if self.repo.scope_count(investigation_id) >= self.settings.investigation_max_scope_events:
            self.add_evidence(
                investigation_id,
                category=EvidenceCategory.MISSING_TELEMETRY,
                claim=(
                    f"Scope reached the {self.settings.investigation_max_scope_events}-event cap;"
                    " some related events were not collected."
                ),
                source_type=EvidenceSource.COVERAGE_CHECK,
                source_ref="scope_cap",
                collected_by=SYSTEM,
            )

        scope_events = self.scope_events(investigation_id)
        ips = sorted({ip for e in scope_events for ip in (e.src_ip, e.dst_ip) if ip})
        for ip in ips:
            if lookup_local_ioc(self.reputation.iocs, ip) is not None:
                citing = [e.event_id for e in scope_events if ip in (e.src_ip, e.dst_ip)]
                self._ioc_evidence(investigation_id, ip, citing[:MAX_CITED_EVENTS], SYSTEM)

        self._context(investigation_id, alert, alert_events, start, scope_events)
        self._coverage_checks(investigation_id, alert_events, start, end, scope_events)

    def _context(
        self,
        investigation_id: str,
        alert: Alert,
        alert_events: list[NormalizedEvent],
        window_start: datetime,
        scope_events: list[NormalizedEvent],
    ) -> None:
        """Related alerts, upstream SIEM detections and "seen before" history as evidence
        (see ``app/investigations/context.py``)."""
        scope_ids = sorted(e.event_id for e in scope_events)
        alerted = {i for linked in self.alerts.links_for_events(scope_ids).values() for i in linked}
        items = [
            *context.related_alerts(self.alerts, alert, set(scope_ids)),
            *context.siem_detections(scope_events, alerted),
            *context.history(self.events, alert_events, window_start),
        ]
        sources = {
            "related_alert": EvidenceSource.ALERT,
            "siem": EvidenceSource.EVENT,
            "history": EvidenceSource.HISTORY,
        }
        for item in items:
            self.add_evidence(
                investigation_id,
                category=EvidenceCategory.OBSERVATION,
                claim=item.claim,
                source_type=sources[item.kind],
                source_ref=item.ref,
                collected_by=SYSTEM,
                event_ids=item.event_ids,
                provenance={"check": item.kind, **item.provenance},
                reliability="Computed by code from stored events.",
            )

    def _coverage_checks(
        self,
        investigation_id: str,
        alert_events: list[NormalizedEvent],
        start: datetime,
        end: datetime,
        scope_events: list[NormalizedEvent],
    ) -> None:
        """Record telemetry that would help but is absent, so a verdict cannot silently rest
        on data the app never had."""
        span = f"between {_fmt(start)} and {_fmt(end)}"
        gaps: list[tuple[str, str]] = []
        for host in sorted({e.host for e in alert_events if e.host}):
            if not self._exists({"host": host, "event_type": EventType.PROCESS}, start, end):
                gaps.append(
                    (
                        f"host:{host}",
                        f"No process events for host {host} {span}; what ran there "
                        "cannot be checked.",
                    )
                )
        for user in sorted({e.user for e in alert_events if e.user}):
            if not self._exists({"user": user, "event_type": EventType.AUTH}, start, end):
                gaps.append((f"user:{user}", f"No authentication events for user {user} {span}."))
        for ip in sorted({ip for e in alert_events for ip in (e.src_ip, e.dst_ip) if ip}):
            if not (
                self._exists({"src_ip": ip, "event_type": EventType.NETWORK}, start, end)
                or self._exists({"dst_ip": ip, "event_type": EventType.NETWORK}, start, end)
            ):
                gaps.append(
                    (
                        f"ip:{ip}",
                        f"No network flow events involving {ip} {span}; traffic to or "
                        "from it cannot be checked.",
                    )
                )
        partial = [e.event_id for e in scope_events if e.parse_status != "ok"]
        if partial:
            gaps.append(
                (
                    "partial_events",
                    f"{len(partial)} event(s) in scope had invalid fields dropped during import.",
                )
            )
        for ref, claim in gaps:
            self.add_evidence(
                investigation_id,
                category=EvidenceCategory.MISSING_TELEMETRY,
                claim=claim,
                source_type=EvidenceSource.COVERAGE_CHECK,
                source_ref=ref,
                collected_by=SYSTEM,
                event_ids=partial[:MAX_CITED_EVENTS] if ref == "partial_events" else [],
                provenance={
                    "tool": "search_events",
                    "start": start.isoformat(),
                    "end": end.isoformat(),
                },
            )

    def _exists(self, equals: dict[str, Any], start: datetime, end: datetime) -> bool:
        return self.events.search(EventFilters(equals=equals, start=start, end=end), 1, 1).total > 0


def reputation_claim(result: ReputationResult) -> str:
    s = result.summary
    signal = f", signal {result.signal}" if result.signal else ""
    if result.provider == "abuseipdb":
        return (
            f"AbuseIPDB: {result.indicator} has abuse confidence score "
            f"{s.get('abuse_confidence_score')} from {s.get('total_reports')} report(s){signal}."
        )
    if result.provider == "virustotal":
        if not result.found:
            return f"VirusTotal has no record of {result.indicator}."
        return (
            f"VirusTotal: {s.get('malicious')} of {s.get('engines')} engines flag "
            f"{result.indicator} as malicious, {s.get('suspicious')} as suspicious{signal}."
        )
    return f"{result.provider}: data available for {result.indicator}{signal}."
