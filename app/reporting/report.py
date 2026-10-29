"""Build an investigation report from stored data only. The same stored state and
``generated_at`` always produce the same JSON and Markdown.

Values from logs, IOC lists and providers are untrusted: in Markdown they are escaped so they
cannot inject links, HTML, headings or table cells.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.domain.enums import EvidenceCategory, EvidenceSource
from app.domain.models import Evidence, Investigation, TimelineEntry
from app.investigations.service import InvestigationService

REPORT_SCHEMA_VERSION = 1
NOT_YET = "Not available yet: response planning and simulated actions arrive in Phase 7."


class AlertContext(BaseModel):
    alert_id: str
    rule_id: str
    rule_version: int
    rule_title: str | None
    severity: str
    status: str
    title: str
    explanation: str
    first_seen: datetime
    last_seen: datetime
    event_ids: list[str]


class Verdict(BaseModel):
    disposition: str
    confidence: str
    reasoning: str
    evidence_ids: list[str]


class InvestigationReport(BaseModel):
    schema_version: int = REPORT_SCHEMA_VERSION
    generated_at: datetime
    investigation_id: str
    title: str
    objective: str
    status: str
    summary: str
    alerts: list[AlertContext]
    timeline: list[TimelineEntry]
    evidence: list[Evidence]
    provider_findings: list[Evidence]
    analyst_notes: list[Evidence]
    contradictions: list[Evidence]
    gaps: list[Evidence]
    verdict: Verdict | None
    recommendations: list[dict[str, Any]] = Field(default_factory=list)
    simulated_actions: list[dict[str, Any]] = Field(default_factory=list)
    limitations: list[str]


def build_report(
    service: InvestigationService, investigation_id: str, generated_at: datetime
) -> InvestigationReport:
    investigation = service.get(investigation_id)
    timeline = service.timeline(investigation_id)
    evidence = service.evidence(investigation_id)
    alerts = _alert_context(service, investigation)
    provider_sources = (EvidenceSource.REPUTATION, EvidenceSource.LOCAL_IOC)
    provider_findings = [e for e in evidence if e.source_type in provider_sources]
    verdict = None
    if investigation.disposition is not None:
        verdict = Verdict(
            disposition=investigation.disposition.value,
            confidence=investigation.confidence.value if investigation.confidence else "",
            reasoning=investigation.disposition_reason or "",
            evidence_ids=investigation.disposition_evidence_ids,
        )
    return InvestigationReport(
        generated_at=generated_at,
        investigation_id=investigation.investigation_id,
        title=investigation.title,
        objective=investigation.objective,
        status=investigation.status.value,
        summary=_summary(investigation, alerts, timeline, evidence),
        alerts=alerts,
        timeline=timeline,
        evidence=evidence,
        provider_findings=provider_findings,
        analyst_notes=[e for e in evidence if e.source_type is EvidenceSource.ANALYST],
        contradictions=[e for e in evidence if e.category is EvidenceCategory.CONTRADICTION],
        gaps=[e for e in evidence if e.category is EvidenceCategory.MISSING_TELEMETRY],
        verdict=verdict,
        limitations=_limitations(service, investigation, provider_findings),
    )


def _alert_context(
    service: InvestigationService, investigation: Investigation
) -> list[AlertContext]:
    contexts = []
    for alert_id in investigation.alert_ids:
        alert = service.alerts.get(alert_id)
        if alert is None:
            continue
        rule = service.detection.rules.get(alert.rule_id)
        contexts.append(
            AlertContext(
                alert_id=alert.alert_id,
                rule_id=alert.rule_id,
                rule_version=alert.rule_version,
                rule_title=rule.title if rule else None,
                severity=alert.severity.value,
                status=alert.status.value,
                title=alert.title,
                explanation=alert.explanation,
                first_seen=alert.first_seen,
                last_seen=alert.last_seen,
                event_ids=[link.event_id for link in service.alerts.events_for(alert_id)],
            )
        )
    return contexts


def _summary(
    investigation: Investigation,
    alerts: list[AlertContext],
    timeline: list[TimelineEntry],
    evidence: list[Evidence],
) -> str:
    parts = [
        f"Investigation of {len(alerts)} alert(s): "
        + "; ".join(f"{a.title} [{a.severity}]" for a in alerts)
        + "."
    ]
    if timeline:
        parts.append(
            f"Scope: {len(timeline)} event(s) from {_ts(timeline[0].event_time)} to "
            f"{_ts(timeline[-1].event_time)}."
        )
    counts = Counter(e.category.value for e in evidence)
    parts.append(
        "Evidence: "
        + ", ".join(
            f"{counts.get(c.value, 0)} {c.value.replace('_', ' ')}" for c in EvidenceCategory
        )
        + "."
    )
    if investigation.disposition is not None:
        parts.append(
            f"Disposition: {investigation.disposition.value} "
            f"({investigation.confidence.value if investigation.confidence else 'n/a'} confidence)."
        )
    else:
        parts.append("Disposition: none recorded; the investigation is open.")
    return " ".join(parts)


def _limitations(
    service: InvestigationService, investigation: Investigation, provider_findings: list[Evidence]
) -> list[str]:
    items = [
        "Built deterministically from data stored in this app; no AI analysis was used "
        "(agents arrive in Phase 5).",
        "Only telemetry loaded into this app was examined; absence of events is not proof "
        "that nothing happened.",
        "Confidence is a qualitative analyst judgement, not a calibrated probability.",
    ]
    if not any(e.source_type is EvidenceSource.REPUTATION for e in provider_findings):
        items.append("No external reputation lookup was recorded for this investigation.")
    if service.repo.scope_count(investigation.investigation_id) >= (
        service.settings.investigation_max_scope_events
    ):
        items.append("The event scope hit its size cap, so the timeline may be incomplete.")
    return items


def to_json(report: InvestigationReport) -> str:
    return json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True, ensure_ascii=False)


# --- Markdown ------------------------------------------------------------------------------

# Enough to stop emphasis, code spans, links/images ([ ]), raw HTML (< >), headings and
# table-cell breaks (|); text is also collapsed onto one line.
_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>#|~])")


def md(value: Any) -> str:
    """Escape untrusted text for inline Markdown (also safe inside table cells)."""
    text = " ".join(str(value if value is not None else "").split())
    return _MD_SPECIAL.sub(r"\\\1", text)


def _ts(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S UTC") if value else ""


def _table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(md(cell) for cell in row) + " |" for row in rows]
    return lines


def _evidence_rows(items: list[Evidence]) -> list[list[Any]]:
    return [
        [
            e.evidence_id,
            e.category.value,
            e.source_type.value,
            e.claim,
            ", ".join(e.event_ids[:5])
            + (f" (+{len(e.event_ids) - 5})" if len(e.event_ids) > 5 else ""),
            e.collected_by,
        ]
        for e in items
    ]


def to_markdown(report: InvestigationReport) -> str:
    out = [
        f"# Investigation report: {md(report.title)}",
        "",
        f"- Investigation: `{report.investigation_id}`",
        f"- Status: {report.status}",
        f"- Generated: {_ts(report.generated_at)}",
        f"- Objective: {md(report.objective)}",
        "",
        "## Executive summary",
        "",
        md(report.summary),
        "",
        "## Alert and rule context",
        "",
    ]
    for a in report.alerts:
        out += [
            f"### {md(a.title)}",
            "",
            f"- Alert `{a.alert_id}`, rule `{a.rule_id}` v{a.rule_version}"
            + (f" ({md(a.rule_title)})" if a.rule_title else ""),
            f"- Severity {a.severity}, status {a.status}, "
            f"{_ts(a.first_seen)} to {_ts(a.last_seen)}",
            f"- Why it fired: {md(a.explanation)}",
            f"- Matched events: {len(a.event_ids)}",
            "",
        ]
    out += ["## Timeline", ""]
    if report.timeline:
        out += _table(
            ["time", "type", "event", "alert match", "cited by", "event id"],
            [
                [
                    _ts(t.event_time),
                    t.event_type.value,
                    t.summary,
                    "yes" if t.alert_match else "",
                    ", ".join(t.cited_by),
                    t.event_id,
                ]
                for t in report.timeline
            ],
        )
    else:
        out.append("No events in scope.")
    sections = [
        ("Evidence", report.evidence, "No evidence recorded."),
        ("Provider and IOC findings", report.provider_findings, "No lookups recorded."),
        ("Analyst notes", report.analyst_notes, "No analyst notes."),
        ("Contradictions", report.contradictions, "No contradicting evidence recorded."),
        ("Gaps and missing telemetry", report.gaps, "No gaps recorded."),
    ]
    headers = ["id", "category", "source", "claim", "events", "collected by"]
    for title, items, empty in sections:
        out += ["", f"## {title}", ""]
        out += _table(headers, _evidence_rows(items)) if items else [empty]
        if title == "Provider and IOC findings" and items:
            out += [""] + [
                f"- `{e.evidence_id}`: queried {md(e.provenance.get('queried_at') or 'n/a')}, "
                f"status {md(e.provenance.get('status', 'local'))}"
                for e in items
            ]
    out += ["", "## Verdict", ""]
    if report.verdict:
        v = report.verdict
        out += [
            f"- Disposition: **{v.disposition}**",
            f"- Confidence: {v.confidence}",
            f"- Reasoning: {md(v.reasoning)}",
            f"- Supporting evidence: {', '.join(f'`{i}`' for i in v.evidence_ids) or 'none'}",
        ]
    else:
        out.append("No disposition recorded yet.")
    out += [
        "",
        "## Recommendations and simulated actions",
        "",
        NOT_YET,
        "",
        "## Limitations",
        "",
        *[f"- {md(item)}" for item in report.limitations],
        "",
    ]
    return "\n".join(out)
