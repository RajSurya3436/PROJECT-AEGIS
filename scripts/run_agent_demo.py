"""Run the blueprint's demo story against the real local model and report how it went:
Ask, redirect, verifier assessment, response plan, simulated action, report and audit trail.

    python scripts/run_agent_demo.py [--rule auth.failures_then_success]

Uses a throw-away in-memory database with the demo dataset, so nothing is written to
data/agentic_soc.db. Needs Ollama running with the configured model (default qwen3:8b).
External reputation lookups stay off (the demo IPs are documentation addresses anyway).
"""

from __future__ import annotations

import argparse
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import get_settings
from app.context import build_context
from app.domain.enums import AgentRole, AgentRunStatus, EvidenceSource, RecommendationStatus
from app.domain.errors import ResponseError
from app.ingestion.demo import ingest_demo
from app.ingestion.iocs import load_demo_iocs
from app.ollama_health import ollama_status
from app.reporting.report import build_report, to_markdown
from app.storage.audit import AuditFilters

ASK = "Could this be legitimate? Find evidence for and against compromise."
REDIRECT = "Search the same user's events for 30 minutes before and after."
REPLY = "No more information from me; continue with what the data shows."


def _clip(text: str, n: int = 400) -> str:
    text = " ".join(text.split())
    return text if len(text) <= n else text[: n - 1] + "…"


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").strip().splitlines()[0])
    parser.add_argument("--rule", default="auth.failures_then_success")
    args = parser.parse_args()

    settings = get_settings()
    status, _ = ollama_status(settings.ollama_base_url, settings.ollama_model)
    if status != "reachable_model_present":
        print(f"Ollama not ready ({status}); start it and pull {settings.ollama_model}.")
        return 2

    ctx = build_context(settings, ":memory:")
    ctx.reputation.set_external_enabled(False)
    load_demo_iocs(ctx.iocs)
    ingest_demo(ctx.ingestion)
    alert = next(a for a in ctx.alerts.list() if a.rule_id == args.rule)
    inv = ctx.investigations.start_from_alert(alert.alert_id).investigation_id
    print(f"Investigation {inv} for {alert.rule_id}: {alert.title}\n")

    started = time.monotonic()
    answer = ctx.chat.ask(inv, ASK)
    print(f"ASK ({time.monotonic() - started:.0f} s) -> {answer.author}: {_clip(answer.content)}")
    if answer.payload.get("lookups"):
        print("  lookups:", [(lk["tool"], lk["ok"]) for lk in answer.payload["lookups"]])
    if answer.payload.get("unverified_references"):
        print("  unverified references:", answer.payload["unverified_references"])

    started = time.monotonic()
    ctx.chat.investigate(inv, REDIRECT, AgentRole.LOG_INVESTIGATOR)
    run = ctx.agents.runs.for_investigation(inv)[0]
    replies = 0
    while run.status is AgentRunStatus.WAITING and replies < 3:
        print(f"  agents asked: {run.checkpoint.get('waiting_question')}")
        ctx.chat.investigate(inv, REPLY)
        replies += 1
        run = ctx.agents.runs.for_investigation(inv)[0]
    elapsed = time.monotonic() - started

    steps = ctx.agents.runs.steps(run.run_id)
    kinds = Counter(s.kind for s in steps)
    print(
        f"\nRUN {run.run_id}: {run.status.value} in {elapsed:.0f} s, "
        f"{run.model_calls} model calls, {run.tool_calls} tool calls"
    )
    print("  step kinds:", dict(kinds))
    for s in steps:
        if s.kind in ("route", "redirect", "tool_call", "tool_rejected", "error"):
            print(f"  {s.seq:>3} {s.role.value:<16} {s.kind:<13} {_clip(s.summary, 110)}")
    if run.error:
        print("  error:", run.error)
    agent_ev = [
        e for e in ctx.investigations.evidence(inv) if e.source_type is EvidenceSource.AGENT
    ]
    print(f"\nAGENT EVIDENCE ({len(agent_ev)})")
    for e in agent_ev:
        print(f"  [{e.category.value}] {_clip(e.claim, 150)} (events: {len(e.event_ids)})")
    if run.assessment:
        a = run.assessment
        print(f"\nASSESSMENT {a.disposition.value} ({a.confidence.value})")
        print("  rationale:", _clip(a.rationale))
        print("  supporting:", a.supporting_evidence_ids)
        print("  contradicting:", a.contradicting_evidence_ids)
        for item in a.adjustments:
            print("  adjusted:", item)
    if run.status is not AgentRunStatus.COMPLETED:
        return 1

    started = time.monotonic()
    try:
        plan = ctx.planner.plan(inv)
    except ResponseError as exc:
        print(f"\nRESPONSE PLAN failed: {exc}")
        return 1
    print(f"\nRESPONSE PLAN ({time.monotonic() - started:.0f} s): {_clip(plan.summary, 200)}")
    for rec in plan.recommendations:
        print(f"  {rec.status.value:<9} {rec.action.value} -> {rec.target} ({rec.risk.value})")
        for note in rec.policy_notes:
            print(f"            {_clip(note, 140)}")
    for refused in plan.refused:
        print(f"  refused   {refused}")
    for rec in plan.recommendations:  # the analyst approves and simulates what policy allows
        if rec.status is not RecommendationStatus.PROPOSED:
            continue
        if rec.requires_approval:
            ctx.responses.approve(rec.recommendation_id, "analyst", "demo approval")
        done = ctx.responses.simulate(rec.recommendation_id, "analyst")
        print(f"  simulated {done.action.value}: {(done.simulation or {}).get('would')}")

    report = to_markdown(build_report(ctx.investigations, inv, alert.last_seen))
    audit = ctx.audit.list(AuditFilters(investigation_id=inv), 2000)
    print(f"\nREPORT {len(report.splitlines())} Markdown lines; AUDIT {len(audit)} events:")
    print("  ", dict(Counter(e.action.split(".")[0] for e in audit)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
