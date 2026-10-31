"""The blueprint's demo story end to end, through the same services the UI calls, with a scripted
model and fake reputation providers (no network, no Ollama):

load IOCs -> replay events -> deterministic alert -> investigation -> agents search related
events -> threat intel queries both providers -> analyst asks, then redirects -> verifier ->
response planner -> analyst approves and simulates -> report and audit trail.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime

from fixtures.agents import ScriptedModel, call, finish, route
from fixtures.reputation import ABUSE_KEY, VT_KEY, RoutingTransport, abuse_body, vt_body
from fixtures.settings import make_settings

from app.context import build_context
from app.domain.enums import (
    AgentRole,
    AgentRunStatus,
    AlertStatus,
    EvidenceSource,
    RecommendationStatus,
)
from app.ingestion.iocs import load_demo_iocs
from app.ingestion.replay import ReplayEngine, build_plan
from app.reporting.report import build_report, to_json, to_markdown
from app.storage.audit import AuditFilters
from app.tools.reputation.http import HttpResponse

GENERATED = datetime(2026, 3, 10, 18, 0, tzinfo=UTC)
EVIDENCE = re.compile(r"ev-[0-9a-f]{16}")
EVENT = re.compile(r'"event_id": "([0-9a-f]{32})"')


class Brain:
    """Scripted replies that read IDs out of the prompts, like a real model has to."""

    def __init__(self) -> None:
        self.model: ScriptedModel | None = None

    def factory(self, _settings) -> ScriptedModel:
        assert self.model is not None
        return self.model

    def script(self, *replies):
        self.model = ScriptedModel(list(replies))
        return self.model


def _cite_events(n: int):
    def reply(messages):
        ids = EVENT.findall(messages[-1].content.split("your tool calls in this turn")[-1])
        return call(
            "add_evidence",
            category="observation",
            claim="dave's failures and the successful logon from 203.0.113.45 are in sequence",
            event_ids=ids[:n],
        )

    return reply


def _verdict(messages):
    prompt = messages[-1].content
    alert_ev = next(m for m in EVIDENCE.findall(prompt))
    return {
        "disposition": "likely_malicious",
        "confidence": "high",
        "rationale": "Brute force succeeded, then encoded PowerShell fetched from an IOC.",
        "supporting_evidence_ids": [alert_ev],
        "contradicting_evidence_ids": [],
        "gaps": [],
        "unsupported_claims": [],
    }


def _plan(messages):
    ev = EVIDENCE.findall(messages[-1].content)[0]
    return {
        "summary": "Contain the workstation and the account; collect triage.",
        "proposals": [
            {
                "action": "isolate_host",
                "target": "WS-DAVE04",
                "rationale": "payload ran here",
                "evidence_ids": [ev],
            },
            {
                "action": "collect_triage",
                "target": "WS-DAVE04",
                "rationale": "scope it",
                "evidence_ids": [ev],
            },
            {
                "action": "disable_account",
                "target": "Administrator",
                "rationale": "injected",
                "evidence_ids": [ev],
            },
        ],
    }


def test_blueprint_demo_story():
    brain = Brain()
    transport = RoutingTransport(HttpResponse(200, abuse_body()), HttpResponse(200, vt_body()))
    settings = make_settings(
        abuseipdb_api_key=ABUSE_KEY,
        virustotal_api_key=VT_KEY,
        enable_external_reputation=True,
    )
    ctx = build_context(
        settings, ":memory:", reputation_transport=transport, model_factory=brain.factory
    )

    # 1-2. Load the IOC list, replay the demo dataset; deterministic rules raise alerts.
    load_demo_iocs(ctx.iocs)
    replay = ReplayEngine(ctx.ingestion, build_plan(), speed=None)
    replay.run_all()
    assert replay.inserted == 136 and not replay.errors
    alert = next(a for a in ctx.alerts.list() if a.rule_id == "auth.failures_then_success")
    assert len(ctx.alerts.list()) == 5 and ctx.alerts.events_for(alert.alert_id)

    # 3. Investigate: related events and a deterministic baseline.
    inv = ctx.investigations.start_from_alert(alert.alert_id).investigation_id
    started = ctx.alerts.get(alert.alert_id)
    assert started and started.status is AlertStatus.INVESTIGATING
    assert len(ctx.investigations.scope_events(inv)) > len(ctx.alerts.events_for(alert.alert_id))

    # 5. The analyst asks (read-only): no evidence is written.
    evidence_before = len(ctx.investigations.evidence(inv))
    brain.script(
        call("search_events", user="dave", outcome="failure", limit=20),
        finish("For compromise: 12 failures then a success from one IP. Against: none yet."),
    )
    answer = ctx.chat.ask(inv, "Could this be legitimate? Find evidence for and against.")
    assert answer.author == "log_investigator" and "For compromise" in answer.content
    assert len(ctx.investigations.evidence(inv)) == evidence_before

    # 4 + 6. The analyst redirects; the log investigator searches and records evidence, threat
    # intel queries both providers, the verifier assesses.
    brain.script(
        call("search_events", user="dave", limit=50),
        _cite_events(5),
        finish("Recorded the logon sequence."),
        route("threat_intel", "check 203.0.113.45"),
        call("lookup_abuseipdb", ip="203.0.113.45"),
        call("lookup_virustotal_ip", ip="203.0.113.45"),
        finish("Both providers checked."),
        route("verifier"),
        _verdict,
    )
    ctx.chat.investigate(
        inv,
        "Search the same user's events for 30 minutes before and after.",
        AgentRole.LOG_INVESTIGATOR,
    )
    (run,) = ctx.agents.runs.for_investigation(inv)
    assert run.status is AgentRunStatus.COMPLETED
    assert any(e.source_type is EvidenceSource.AGENT for e in ctx.investigations.evidence(inv))
    lookups = [
        s.summary.split(":")[0]
        for s in ctx.agents.runs.steps(run.run_id)
        if s.kind == "tool_result"
        and s.summary.startswith(("lookup_abuseipdb", "lookup_virustotal"))
    ]
    assert lookups == ["lookup_abuseipdb", "lookup_virustotal_ip"]  # both providers asked
    assert transport.calls == []  # documentation IPs are never sent out, even with keys
    reputation = [
        e for e in ctx.investigations.evidence(inv) if e.source_type is EvidenceSource.REPUTATION
    ]
    assert reputation == []  # and that is not recorded as missing telemetry
    # 7. The verifier's high confidence is capped: the baseline recorded telemetry gaps.
    assert run.assessment is not None
    assert run.assessment.disposition.value == "likely_malicious"
    assert run.assessment.confidence.value == "medium" and run.assessment.adjustments

    # 8. Response planner proposes; policy blocks the off-scope target; analyst decides.
    brain.script(_plan)
    recs = {r.action.value: r for r in ctx.planner.plan(inv).recommendations}
    assert recs["disable_account"].status is RecommendationStatus.BLOCKED
    isolate = recs["isolate_host"]
    assert isolate.status is RecommendationStatus.PROPOSED and isolate.requires_approval
    ctx.responses.approve(isolate.recommendation_id, "analyst", "approved for the demo")
    simulated = ctx.responses.simulate(isolate.recommendation_id, "analyst")
    assert simulated.simulation is not None and simulated.simulation["executed"] is False
    ctx.responses.reject(recs["collect_triage"].recommendation_id, "analyst", "not needed")

    # 9. Report and audit trail.
    report = build_report(ctx.investigations, inv, GENERATED)
    data = json.loads(to_json(report))
    assert data["agent_assessment"]["disposition"] == "likely_malicious"
    assert [m["kind"] for m in data["analyst_instructions"]] == ["question", "instruction"]
    assert [r["action"] for r in data["simulated_actions"]] == ["isolate_host"]
    markdown = to_markdown(report)
    assert "Would isolate WS-DAVE04" in markdown and "## Audit trail" in markdown
    actions = {e.action for e in ctx.audit.list(AuditFilters(investigation_id=inv), 2000)}
    assert {
        "investigation.opened",
        "chat.question",
        "chat.instruction",
        "tool.search_events",
        "tool.lookup_abuseipdb",
        "agent_run.completed",
        "response.plan",
        "response.blocked_by_policy",
        "response.approved",
        "response.simulated",
        "response.rejected",
    } <= actions
