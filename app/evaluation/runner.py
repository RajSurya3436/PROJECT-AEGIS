"""Evaluation set runner: does detection fire as expected, and does the verifier's verdict
agree with the known ground truth?

Each scenario runs in its own in-memory database with the demo IOC list and external lookups
off. Detection is deterministic and is checked exactly. The agent verdict is graded against
the ground truth:

- ``correct``: malicious -> likely/confirmed malicious; benign -> benign_or_expected;
  undetermined -> suspicious_inconclusive or insufficient_data.
- ``cautious``: a real attack or a benign case judged inconclusive / insufficient data. Safe
  (a human looks), but it costs analyst time.
- ``wrong``: an attack called benign (missed), a benign case called malicious (false
  accusation), or an undetermined case given a confident verdict either way (overconfident).
- ``no verdict``: the run did not complete (model unavailable, limits, invalid output).
"""

from __future__ import annotations

import json
import statistics
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from app.agents.service import ModelFactory, ollama_model
from app.config import PROJECT_ROOT, Settings
from app.context import build_context
from app.domain.enums import AgentRunStatus, Disposition, EvidenceSource, InputFormat, SourceType
from app.ingestion.adapters import get_adapter
from app.ingestion.iocs import load_demo_iocs

EVAL_DIR = PROJECT_ROOT / "data" / "eval"
MALICIOUS = {Disposition.CONFIRMED_MALICIOUS, Disposition.LIKELY_MALICIOUS}
UNSURE = {Disposition.SUSPICIOUS_INCONCLUSIVE, Disposition.INSUFFICIENT_DATA}
GRADES = ("correct", "cautious", "wrong", "no verdict")


def grade(truth: str, disposition: Disposition | None) -> str:
    if disposition is None:
        return "no verdict"
    if truth == "malicious":
        if disposition in MALICIOUS:
            return "correct"
        return "cautious" if disposition in UNSURE else "wrong"
    if truth == "benign":
        if disposition is Disposition.BENIGN_OR_EXPECTED:
            return "correct"
        return "cautious" if disposition in UNSURE else "wrong"
    if truth == "undetermined":
        return "correct" if disposition in UNSURE else "wrong"
    raise ValueError(f"unknown ground truth {truth!r}")


@dataclass
class ScenarioResult:
    id: str
    title: str
    truth: str
    expected_alerts: dict[str, int]
    found_alerts: dict[str, int]
    detection_ok: bool
    disposition: str | None = None
    confidence: str | None = None
    grade: str | None = None  # None when agents were not run
    run_status: str | None = None
    seconds: float | None = None
    model_calls: int = 0
    tool_calls: int = 0
    agent_evidence: int = 0
    adjustments: list[str] = field(default_factory=list)
    rationale: str = ""
    error: str | None = None


def load_scenarios(eval_dir: Path = EVAL_DIR) -> list[dict[str, Any]]:
    manifest = json.loads((eval_dir / "scenarios.json").read_text(encoding="utf-8"))
    return manifest["scenarios"]


def run_scenario(
    scenario: dict[str, Any],
    settings: Settings,
    *,
    with_agents: bool = True,
    model_factory: ModelFactory = ollama_model,
    eval_dir: Path = EVAL_DIR,
    clock: Callable[[], float] = time.monotonic,
) -> ScenarioResult:
    ctx = build_context(settings, ":memory:", model_factory=model_factory)
    try:
        ctx.reputation.set_external_enabled(False, actor="evaluation")
        load_demo_iocs(ctx.iocs)
        ctx.ingestion.ingest_bytes(
            (eval_dir / scenario["file"]).read_bytes(),
            InputFormat.JSONL,
            source_id=f"eval-{scenario['id']}",
            source_type=SourceType.UPLOAD,
            source_name=scenario["title"],
            adapter=get_adapter(scenario.get("adapter")),
        )
        alerts = ctx.alerts.list()
        found = dict(Counter(a.rule_id for a in alerts))
        result = ScenarioResult(
            id=scenario["id"],
            title=scenario["title"],
            truth=scenario["truth"],
            expected_alerts=scenario["expected_alerts"],
            found_alerts=found,
            detection_ok=found == scenario["expected_alerts"],
        )
        if not with_agents:
            return result
        candidates = [a for a in alerts if a.rule_id == scenario["investigate"]]
        if not candidates:
            result.error = f"no {scenario['investigate']} alert to investigate"
            result.grade = "no verdict"
            return result
        alert = max(candidates, key=lambda a: (a.last_seen, a.alert_id))
        inv = ctx.investigations.start_from_alert(alert.alert_id)
        started = clock()
        run = ctx.agents.run_now(inv.investigation_id)
        result.seconds = round(clock() - started, 1)
        result.run_status = run.status.value
        result.model_calls, result.tool_calls = run.model_calls, run.tool_calls
        result.error = run.error
        result.agent_evidence = sum(
            e.source_type is EvidenceSource.AGENT
            for e in ctx.investigations.evidence(inv.investigation_id)
        )
        assessment = run.assessment if run.status is AgentRunStatus.COMPLETED else None
        if assessment is not None:
            result.disposition = assessment.disposition.value
            result.confidence = assessment.confidence.value
            result.adjustments = assessment.adjustments
            result.rationale = assessment.rationale
        result.grade = grade(scenario["truth"], assessment.disposition if assessment else None)
        return result
    finally:
        ctx.conn.close()


def summarize(results: list[ScenarioResult]) -> dict[str, Any]:
    graded = [r for r in results if r.grade is not None]
    grades = Counter(r.grade for r in graded)
    verdicts = [r for r in graded if r.grade != "no verdict"]
    seconds = [r.seconds for r in graded if r.seconds is not None]
    return {
        "scenarios": len(results),
        "detection_ok": sum(r.detection_ok for r in results),
        "graded": len(graded),
        "grades": {g: grades.get(g, 0) for g in GRADES},
        "agreement": round(grades.get("correct", 0) / len(verdicts), 2) if verdicts else None,
        "missed_attacks": sum(r.grade == "wrong" and r.truth == "malicious" for r in graded),
        "false_accusations": sum(r.grade == "wrong" and r.truth == "benign" for r in graded),
        "overconfident": sum(r.grade == "wrong" and r.truth == "undetermined" for r in graded),
        "median_seconds": statistics.median(seconds) if seconds else None,
        "max_seconds": max(seconds) if seconds else None,
    }


def to_json(results: list[ScenarioResult], summary: dict[str, Any], meta: dict[str, Any]) -> str:
    return json.dumps(
        {"meta": meta, "summary": summary, "results": [asdict(r) for r in results]},
        indent=2,
        sort_keys=True,
    )


def to_markdown(
    results: list[ScenarioResult], summary: dict[str, Any], meta: dict[str, Any]
) -> str:
    g = summary["grades"]
    agreement = summary["agreement"]
    lines = [
        f"# Evaluation run {meta.get('started', '')}",
        "",
        f"- Model: `{meta.get('model', '')}`; scenarios: {summary['scenarios']}",
        f"- Detection as expected: {summary['detection_ok']} of {summary['scenarios']}",
        f"- Verdicts: {g['correct']} correct, {g['cautious']} cautious, {g['wrong']} wrong, "
        f"{g['no verdict']} without a verdict"
        + (f" (agreement {agreement:.0%} of completed runs)" if agreement is not None else ""),
        f"- Wrong in a dangerous direction: {summary['missed_attacks']} missed attack(s), "
        f"{summary['false_accusations']} false accusation(s), "
        f"{summary['overconfident']} overconfident call(s) on undetermined cases",
    ]
    if summary["median_seconds"] is not None:
        lines.append(
            f"- Time per alert: median {summary['median_seconds']:.0f} s, "
            f"max {summary['max_seconds']:.0f} s"
        )
    lines += [
        "",
        "| scenario | truth | detection | verdict | grade | run | time (s) | model/tool calls "
        "| agent evidence |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        verdict = f"{r.disposition} ({r.confidence})" if r.disposition else "-"
        lines.append(
            f"| {r.id} | {r.truth} | {'ok' if r.detection_ok else 'MISMATCH'} | {verdict} "
            f"| {r.grade or '-'} | {r.run_status or '-'} | {r.seconds if r.seconds else '-'} "
            f"| {r.model_calls}/{r.tool_calls} | {r.agent_evidence} |"
        )
    lines.append("")
    for r in results:
        if not r.detection_ok:
            lines.append(f"- {r.id}: expected alerts {r.expected_alerts}, got {r.found_alerts}")
        if r.adjustments:
            lines.append(f"- {r.id}: verifier adjusted by checks: {'; '.join(r.adjustments)}")
        if r.error:
            lines.append(f"- {r.id}: {r.error}")
    return "\n".join(lines) + "\n"
