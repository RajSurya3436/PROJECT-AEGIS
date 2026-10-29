from __future__ import annotations

import streamlit as st

from app.context import AppContext
from app.ollama_health import ollama_status


def render(ctx: AppContext) -> None:
    st.title("Overview")
    total = ctx.events.count()
    c1, c2, c3 = st.columns(3)
    c1.metric("Events", f"{total:,}")
    c2.metric("Quarantined rows", ctx.parse_errors.count())
    c3.metric("Data sources", len(ctx.sources.list_all()))

    if total == 0:
        st.info("No events yet. Open **Data sources** and load the demo dataset or upload a file.")
    else:
        st.subheader("Events by type")
        st.bar_chart(ctx.events.count_by_type())
        span = ctx.events.time_range()
        if span:
            st.caption(
                f"Event time range (UTC): {span[0]:%Y-%m-%d %H:%M} → {span[1]:%Y-%m-%d %H:%M}"
            )

    st.subheader("Alerts")
    by_status = ctx.alerts.count_by("status")
    by_severity = ctx.alerts.count_by("severity")
    a1, a2, a3, a4 = st.columns(4)
    a1.metric("Alerts", ctx.alerts.count())
    a2.metric("New", by_status.get("new", 0))
    a3.metric("High / critical", by_severity.get("high", 0) + by_severity.get("critical", 0))
    a4.metric("Investigating", by_status.get("investigating", 0))
    recent = ctx.alerts.list(limit=5)
    if recent:
        st.dataframe(
            [
                {
                    "severity": a.severity.value,
                    "status": a.status.value,
                    "title": a.title,
                    "events": a.event_count,
                    "first seen (UTC)": a.first_seen.strftime("%Y-%m-%d %H:%M:%S"),
                }
                for a in recent
            ],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.caption("No alerts yet.")

    st.subheader("Investigations")
    by_inv = ctx.investigations.repo.count_by_status()
    i1, i2 = st.columns(2)
    i1.metric("Open investigations", by_inv.get("open", 0))
    i2.metric("Closed investigations", by_inv.get("closed", 0))

    st.subheader("Integration status")
    s = ctx.settings
    status, _ = ollama_status(s.ollama_base_url, s.ollama_model)
    labels = {
        "reachable_model_present": f"Ready ({s.ollama_model})",
        "reachable_model_missing": f"Server up, model `{s.ollama_model}` not installed",
        "unreachable": "Unavailable (detection and search still work)",
    }
    st.write(f"**Ollama:** {labels[status]}")
    st.write(f"**AbuseIPDB:** {'configured' if s.abuseipdb_configured else 'not configured'}")
    st.write(f"**VirusTotal:** {'configured' if s.virustotal_configured else 'not configured'}")
    external = "enabled" if ctx.reputation.external_enabled else "disabled"
    st.write(f"**External reputation lookups:** {external}")
    st.caption(
        "Detection runs without Ollama. Manage providers and the lookup switch on **Settings**. "
        "Agents arrive in a later phase."
    )
