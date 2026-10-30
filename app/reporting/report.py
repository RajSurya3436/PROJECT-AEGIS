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

from app.audit.log import AuditLog
from app.domain.enums import (
    OPEN_RECOMMENDATION_STATUSES,
    AgentRunStatus,
    EvidenceCategory,
    EvidenceSource,
    InvestigationStatus,
    RecommendationStatus,
)
from app.domain.models import AuditEvent, Evidence, Investigation, Recommendation, TimelineEntry
from app.investigations.service import InvestigationService
from app.storage.agents import AgentRunRepository
from app.storage.chat import ChatRepository
from app.storage.responses import RecommendationRepository

REPORT_SCHEMA_VERSION = 2
ANALYST = "analyst"
MAX_AUDIT_IN_REPORT = 300


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


class AnalystMessage(BaseModel):
    at: datetime
    mode: str
    kind: str
    target_role: str | None
    text: str


class AgentAssessment(BaseModel):
    """The verifier's latest assessment. Advisory; the verdict above is the analyst's."""

    run_id: str
    model: str
    finished_at: datetime | None
    disposition: str
    confidence: str
    rationale: str
    supporting_evidence_ids: list[str]
    contradicting_evidence_ids: list[str]
    gaps: list[str]
    adjustments: list[str]


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
    analyst_instructions: list[AnalystMessage] = Field(default_factory=list)
    agent_assessment: AgentAssessment | None = None
    recommendations: list[Recommendation] = Field(default_factory=list)
    simulated_actions: list[Recommendation] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)
    audit_trail: list[AuditEvent] = Field(default_factory=list)
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
    conn = service.conn
    recommendations = RecommendationRepository(conn).for_investigation(investigation_id)
    gaps = [e for e in evidence if e.category is EvidenceCategory.MISSING_TELEMETRY]
    assessment = _agent_assessment(AgentRunRepository(conn), investigation_id)
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
        gaps=gaps,
        verdict=verdict,
        analyst_instructions=[
            AnalystMessage(
                at=m.created_at,
                mode=m.mode.value,
                kind=m.kind.value,
                target_role=m.target_role.value if m.target_role else None,
                text=m.content,
            )
            for m in ChatRepository(conn).for_investigation(investigation_id)
            if m.author == ANALYST
        ],
        agent_assessment=assessment,
        recommendations=recommendations,
        simulated_actions=[
            r for r in recommendations if r.status is RecommendationStatus.SIMULATED
        ],
        next_steps=_next_steps(investigation, recommendations, gaps),
        audit_trail=AuditLog(conn).for_investigation(investigation_id, MAX_AUDIT_IN_REPORT),
        limitations=_limitations(service, investigation, provider_findings, assessment),
    )


def _agent_assessment(runs: AgentRunRepository, investigation_id: str) -> AgentAssessment | None:
    for run in runs.for_investigation(investigation_id):
        if run.status is AgentRunStatus.COMPLETED and run.assessment is not None:
            a = run.assessment
            return AgentAssessment(
                run_id=run.run_id,
                model=run.model,
                finished_at=run.finished_at,
                disposition=a.disposition.value,
                confidence=a.confidence.value,
                rationale=a.rationale,
                supporting_evidence_ids=a.supporting_evidence_ids,
                contradicting_evidence_ids=a.contradicting_evidence_ids,
                gaps=a.gaps,
                adjustments=a.adjustments,
            )
    return None


def _next_steps(
    investigation: Investigation, recommendations: list[Recommendation], gaps: list[Evidence]
) -> list[str]:
    """Derived from stored state only: undecided recommendations, then telemetry gaps."""
    steps = []
    for r in recommendations:
        if r.status not in OPEN_RECOMMENDATION_STATUSES:
            continue
        if r.status is RecommendationStatus.PROPOSED and r.requires_approval:
            verb = "Approve or reject"
        else:
            verb = "Simulate or reject"
        steps.append(f"{verb} {r.action.value} on {r.target} ({r.recommendation_id}).")
    for gap in gaps[:10]:
        steps.append(f"Close the gap if the data exists: {gap.claim}")
    if investigation.status is InvestigationStatus.OPEN:
        steps.append("Record a disposition when the evidence is sufficient.")
    return steps


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
    service: InvestigationService,
    investigation: Investigation,
    provider_findings: list[Evidence],
    assessment: AgentAssessment | None,
) -> list[str]:
    ai_used = assessment is not None or any(
        e.source_type is EvidenceSource.AGENT
        for e in service.evidence(investigation.investigation_id)
    )
    items = [
        "Built deterministically from data stored in this app."
        + (
            " Agent-written evidence and the agent assessment come from a local language "
            "model; check them against the cited events."
            if ai_used
            else " No AI analysis was recorded for this investigation."
        ),
        "Response actions are simulations only: this app has no firewall, EDR or identity "
        "integration, and nothing outside it was changed.",
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


def _ids(ids: list[str]) -> str:
    return ", ".join(f"`{md(i)}`" for i in ids) or "none"


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
    out += ["", "## Analyst instructions", ""]
    if report.analyst_instructions:
        out += _table(
            ["time", "mode", "kind", "to", "message"],
            [
                [_ts(m.at), m.mode, m.kind, m.target_role or "orchestrator", m.text]
                for m in report.analyst_instructions
            ],
        )
    else:
        out.append("No analyst messages.")
    out += ["", "## Agent assessment (advisory)", ""]
    if report.agent_assessment:
        a = report.agent_assessment
        out += [
            f"- Run `{a.run_id}` ({md(a.model)}), finished {_ts(a.finished_at)}",
            f"- Disposition: {a.disposition}, confidence {a.confidence}",
            f"- Rationale: {md(a.rationale)}",
            f"- Supporting: {_ids(a.supporting_evidence_ids)}",
            f"- Contradicting: {_ids(a.contradicting_evidence_ids)}",
        ]
        out += [f"- Gap: {md(g)}" for g in a.gaps]
        out += [f"- Adjusted by checks: {md(item)}" for item in a.adjustments]
    else:
        out.append("No completed agent assessment.")
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
    out += ["", "## Recommendations and simulated actions", ""]
    out.append(
        "All response actions are simulated; nothing outside this app is changed. Status "
        "and policy notes are set by code, not by the model."
    )
    out.append("")
    if report.recommendations:
        out += _table(
            [
                "id",
                "action",
                "target",
                "risk",
                "reversible",
                "status",
                "proposed by",
                "rationale",
                "evidence",
                "policy",
            ],
            [
                [
                    r.recommendation_id,
                    r.action.value,
                    r.target,
                    r.risk.value,
                    "yes" if r.reversible else "no",
                    r.status.value,
                    r.proposed_by,
                    r.rationale,
                    ", ".join(r.evidence_ids),
                    " ".join(r.policy_notes),
                ]
                for r in report.recommendations
            ],
        )
    else:
        out.append("No recommendations.")
    if report.simulated_actions:
        out += ["", "### Simulated actions", ""]
        for r in report.simulated_actions:
            sim = r.simulation or {}
            out.append(
                f"- `{r.recommendation_id}` {_ts(r.simulated_at)}: {md(sim.get('would', ''))} "
                f"Executed: no. Undo: {md(sim.get('undo', ''))}"
            )
    out += ["", "## Next steps", ""]
    out += [f"- {md(step)}" for step in report.next_steps] or ["None."]
    out += ["", "## Audit trail", ""]
    if report.audit_trail:
        out += _table(
            ["time", "actor", "action", "target", "outcome"],
            [
                [_ts(e.at), e.actor, e.action, f"{e.target_type}:{e.target_id}", e.outcome]
                for e in report.audit_trail
            ],
        )
    else:
        out.append("No audit events.")
    out += [
        "",
        "## Limitations",
        "",
        *[f"- {md(item)}" for item in report.limitations],
        "",
    ]
    return "\n".join(out)
