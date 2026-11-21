from __future__ import annotations

import streamlit as st

from app.context import AppContext
from app.detection.registry import CATEGORIES
from app.domain.enums import Severity
from app.ollama_health import ollama_status
from app.ui import theme


def render(ctx: AppContext) -> None:
    theme.page_header(
        "Security overview",
        "Everything the copilot has seen: ingested telemetry, deterministic alerts, open cases "
        "and agent activity.",
        icon="🛰️",
        eyebrow="Monitor",
    )
    total = ctx.events.count()
    by_status = ctx.alerts.count_by("status")
    by_severity = ctx.alerts.count_by("severity")
    by_inv = ctx.investigations.repo.count_by_status()
    by_run = ctx.agents.runs.count_by_status()

    # --- KPI row ------------------------------------------------------------------------
    k = st.columns(6)
    k[0].metric("Events", f"{total:,}", border=True, help="Normalized events stored")
    k[1].metric("Alerts", ctx.alerts.count(), border=True)
    k[2].metric("New", by_status.get("new", 0), border=True, help="Alerts nobody has triaged")
    k[3].metric(
        "High / critical",
        by_severity.get("high", 0) + by_severity.get("critical", 0),
        border=True,
    )
    k[4].metric("Open investigations", by_inv.get("open", 0), border=True)
    k[5].metric("Quarantined rows", ctx.parse_errors.count(), border=True)

    if total == 0:
        theme.empty_state(
            "No events yet. Open Data sources and load the demo dataset, upload a file, or "
            "follow a live log.",
            icon=":material/database:",
        )
    else:
        # --- activity + severity ----------------------------------------------------------
        left, right = st.columns([2.2, 1], gap="medium", border=True)
        with left:
            theme.section("Event activity by hour (UTC)")
            st.altair_chart(theme.activity_chart(ctx.events.activity_by_hour()), width="stretch")
            span = ctx.events.time_range()
            if span:
                st.caption(f"{span[0]:%Y-%m-%d %H:%M} → {span[1]:%Y-%m-%d %H:%M} UTC")
        with right:
            theme.section("Alerts by severity")
            if by_severity:
                st.altair_chart(theme.severity_donut(by_severity), width="stretch")
            else:
                st.caption("No alerts yet.")

    # --- alerts --------------------------------------------------------------------------
    left, right = st.columns([2.2, 1], gap="medium", border=True)
    with left:
        theme.section("Most urgent alerts")
        recent = ctx.alerts.list(limit=8)
        if recent:
            st.dataframe(
                [
                    {
                        "severity": theme.sev_label(a.severity),
                        "status": a.status.value,
                        "title": a.title,
                        "events": a.event_count,
                        "first seen (UTC)": a.first_seen.strftime("%Y-%m-%d %H:%M:%S"),
                    }
                    for a in recent
                ],
                width="stretch",
                hide_index=True,
            )
        else:
            st.caption("No alerts yet.")
    with right:
        theme.section("Alerts by tactic")
        by_rule = ctx.alerts.count_by("rule_id")
        tactics: dict[str, int] = {}
        for rule_id, n in by_rule.items():
            rule = ctx.detection.rules.get(rule_id)
            name = CATEGORIES.get(rule.category if rule else "other", "Other")
            tactics[name] = tactics.get(name, 0) + n
        if tactics:
            st.altair_chart(
                theme.bar_chart(tactics, "tactic", "alerts", theme.SEVERITY_HEX[Severity.LOW]),
                width="stretch",
            )
        else:
            st.caption("No alerts yet.")

    # --- agents + integrations -----------------------------------------------------------
    left, right = st.columns([2.2, 1], gap="medium", border=True)
    with left:
        theme.section("Agent activity")
        r = st.columns(4)
        r[0].metric("Running", by_run.get("running", 0) + by_run.get("queued", 0))
        r[1].metric("Paused / waiting for you", by_run.get("paused", 0) + by_run.get("waiting", 0))
        r[2].metric("Completed runs", by_run.get("completed", 0))
        r[3].metric(
            "Failed / stopped / limited",
            sum(by_run.get(k, 0) for k in ("failed", "stopped", "limit_reached", "interrupted")),
        )
        recent_runs = ctx.agents.runs.recent(limit=5)
        if recent_runs:
            st.dataframe(
                [
                    {
                        "started (UTC)": run.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                        "investigation": run.investigation_id,
                        "status": run.status.value,
                        "proposed": run.assessment.disposition.value if run.assessment else "",
                        "model calls": run.model_calls,
                        "tool calls": run.tool_calls,
                    }
                    for run in recent_runs
                ],
                width="stretch",
                hide_index=True,
            )
        else:
            st.caption("No agent runs yet. Start one from an investigation.")
    with right:
        theme.section("Integrations")
        s = ctx.settings
        status, _ = ollama_status(s.ollama_base_url, s.ollama_model)
        model = {
            "reachable_model_present": (f"Ollama ready ({s.ollama_model})", "ok"),
            "reachable_model_missing": (f"Ollama up, {s.ollama_model} missing", "warn"),
            "unreachable": ("Ollama unavailable", "off"),
        }[status]
        theme.pills(
            [
                model,
                (
                    "AbuseIPDB configured" if s.abuseipdb_configured else "AbuseIPDB not set",
                    "ok" if s.abuseipdb_configured else "idle",
                ),
                (
                    "VirusTotal configured" if s.virustotal_configured else "VirusTotal not set",
                    "ok" if s.virustotal_configured else "idle",
                ),
                (
                    "External lookups enabled"
                    if ctx.reputation.external_enabled
                    else "External lookups disabled",
                    "warn" if ctx.reputation.external_enabled else "idle",
                ),
                (f"{len(ctx.detection.rules)} detection rules", "ok"),
            ]
        )
        st.caption(
            "Detection, search and investigations run without Ollama; only agent runs need it."
        )
