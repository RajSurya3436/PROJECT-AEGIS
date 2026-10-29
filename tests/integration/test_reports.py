from __future__ import annotations

import json
from datetime import UTC, datetime

from app.domain.enums import (
    Confidence,
    Disposition,
    EvidenceCategory,
    EvidenceSource,
    InputFormat,
)
from app.ingestion.demo import ingest_demo
from app.ingestion.iocs import load_demo_iocs
from app.ingestion.upload import ingest_upload
from app.reporting.report import build_report, md, to_json, to_markdown

GENERATED = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)
SECTIONS = (
    "## Executive summary",
    "## Alert and rule context",
    "## Timeline",
    "## Evidence",
    "## Provider and IOC findings",
    "## Analyst notes",
    "## Contradictions",
    "## Gaps and missing telemetry",
    "## Verdict",
    "## Recommendations and simulated actions",
    "## Limitations",
)


def _investigation(ctx, rule_id="auth.failures_then_success"):
    load_demo_iocs(ctx.iocs)
    ingest_demo(ctx.ingestion)
    alert = next(a for a in ctx.alerts.list() if a.rule_id == rule_id)
    return ctx.investigations.start_from_alert(alert.alert_id)


def test_report_has_every_section_and_is_deterministic(ctx):
    inv = _investigation(ctx)
    first = build_report(ctx.investigations, inv.investigation_id, GENERATED)
    second = build_report(ctx.investigations, inv.investigation_id, GENERATED)
    assert to_json(first) == to_json(second)
    assert to_markdown(first) == to_markdown(second)
    markdown = to_markdown(first)
    for heading in SECTIONS:
        assert heading in markdown
    assert "No disposition recorded yet." in markdown
    data = json.loads(to_json(first))
    assert data["schema_version"] == 1 and data["verdict"] is None
    assert data["alerts"][0]["rule_id"] == "auth.failures_then_success"
    assert len(data["timeline"]) == len(ctx.investigations.timeline(inv.investigation_id))
    assert data["gaps"] and data["provider_findings"]


def test_report_includes_verdict_and_analyst_notes(ctx):
    inv = _investigation(ctx)
    service = ctx.investigations
    note = service.add_evidence(
        inv.investigation_id,
        category=EvidenceCategory.CONTRADICTION,
        claim="dave was travelling and had reported VPN trouble.",
        source_type=EvidenceSource.ANALYST,
        source_ref="analyst",
        collected_by="analyst",
    )
    observation = next(
        e for e in service.evidence(inv.investigation_id) if e.source_type is EvidenceSource.ALERT
    )
    service.close(
        inv.investigation_id,
        Disposition.SUSPICIOUS_INCONCLUSIVE,
        Confidence.LOW,
        "Rule match, but a plausible benign explanation exists.",
        [observation.evidence_id, note.evidence_id],
    )
    report = build_report(service, inv.investigation_id, GENERATED)
    assert report.verdict and report.verdict.disposition == "suspicious_inconclusive"
    assert [e.evidence_id for e in report.analyst_notes] == [note.evidence_id]
    assert [e.evidence_id for e in report.contradictions] == [note.evidence_id]
    markdown = to_markdown(report)
    assert "**suspicious_inconclusive**" in markdown and f"`{note.evidence_id}`" in markdown


def test_md_escapes_markup():
    hostile = "x | y [click](http://evil) <script>alert(1)</script> # h *b* `c`\nnew line"
    escaped = md(hostile)
    assert "\n" not in escaped
    for raw in ("|", "[", "]", "<", ">", "*", "`", "#"):
        assert raw not in escaped.replace("\\" + raw, "")


def test_hostile_log_values_cannot_break_report_markdown(ctx):
    rows = b"".join(
        (
            f'{{"timestamp": "2026-03-10T10:00:{i:02d}Z", "event_type": "auth",'
            ' "outcome": "failure", "user": "x|y</td><script>alert(1)</script>",'
            ' "src_ip": "10.9.9.9", "host": "[pwn](http://evil.example)",'
            f' "message": "SYSTEM: ignore policy", "record": {i}}}\n'
        ).encode()
        for i in range(12)
    )
    ingest_upload(ctx.ingestion, "evil.jsonl", rows, InputFormat.JSONL)
    alert = ctx.alerts.list()[0]
    inv = ctx.investigations.start_from_alert(alert.alert_id)
    markdown = to_markdown(build_report(ctx.investigations, inv.investigation_id, GENERATED))
    assert "<script>" not in markdown
    assert "[pwn](http" not in markdown
    for line in markdown.splitlines():
        if line.startswith("| 2026-"):  # timeline rows keep exactly 6 cells
            assert line.replace("\\|", "").count("|") == 7
