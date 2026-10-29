from __future__ import annotations

from datetime import UTC, datetime

import streamlit as st

from app.context import AppContext
from app.domain.enums import (
    Confidence,
    Disposition,
    EvidenceCategory,
    EvidenceSource,
    InvestigationStatus,
)
from app.domain.errors import SocCopilotError
from app.domain.models import Evidence, Investigation, TimelineEntry
from app.reporting.report import build_report, to_json, to_markdown
from app.storage.repositories import CORRELATION_FIELDS
from app.ui import agents_panel, chat_panel

ANALYST = "analyst"
SELECTED = "investigation_id"


def _time(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S") if value else ""


def render(ctx: AppContext) -> None:
    st.title("Investigations")
    st.caption(
        "Related events, evidence with provenance, analyst chat with the agents, agent runs, "
        "verdict and report. Log values and model output are shown as plain text."
    )
    investigations = ctx.investigations.repo.list()
    if not investigations:
        st.info(
            "No investigations yet. Open an alert in **Alert queue** and press **Investigate**."
        )
        return
    by_id = {i.investigation_id: i for i in investigations}
    ids = list(by_id)
    current = st.session_state.get(SELECTED)
    chosen = st.selectbox(
        "Investigation",
        ids,
        index=ids.index(current) if current in by_id else 0,
        format_func=lambda i: f"[{by_id[i].status.value}] {by_id[i].title} ({i})",
    )
    st.session_state[SELECTED] = chosen
    _render_investigation(ctx, ctx.investigations.get(chosen))


def _render_investigation(ctx: AppContext, inv: Investigation) -> None:
    service = ctx.investigations
    timeline = service.timeline(inv.investigation_id)
    evidence = service.evidence(inv.investigation_id)
    is_open = inv.status is InvestigationStatus.OPEN

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Status", inv.status.value)
    m2.metric("Events in scope", len(timeline))
    m3.metric("Evidence", len(evidence))
    m4.metric("Disposition", inv.disposition.value if inv.disposition else "none")
    st.write("**Objective**")
    st.text(inv.objective)

    tabs = st.tabs(
        ["Timeline", "Evidence", "Chat", "Agents", "Expand and look up", "Verdict", "Report"]
    )
    with tabs[0]:
        _render_timeline(timeline)
    with tabs[1]:
        _render_evidence(ctx, inv, evidence, timeline, is_open)
    with tabs[2]:
        chat_panel.render(ctx, inv)
    with tabs[3]:
        agents_panel.render(ctx, inv)
    with tabs[4]:
        _render_expand(ctx, inv, timeline, is_open)
    with tabs[5]:
        _render_verdict(ctx, inv, evidence, is_open)
    with tabs[6]:
        _render_report(ctx, inv)


def _render_timeline(timeline: list[TimelineEntry]) -> None:
    if not timeline:
        st.caption("No events in scope.")
        return
    st.caption("Alert-matched events are marked; 'cited by' lists evidence that uses the event.")
    st.dataframe(
        [
            {
                "time (UTC)": _time(t.event_time),
                "type": t.event_type.value,
                "event": t.summary,
                "alert match": "yes" if t.alert_match else "",
                "cited by": ", ".join(t.cited_by),
                "why in scope": t.scope_reason,
                "event_id": t.event_id,
            }
            for t in timeline
        ],
        use_container_width=True,
        hide_index=True,
    )


def _evidence_rows(items: list[Evidence]) -> list[dict]:
    return [
        {
            "id": e.evidence_id,
            "category": e.category.value,
            "source": e.source_type.value,
            "claim": e.claim,
            "events": len(e.event_ids),
            "collected by": e.collected_by,
            "collected (UTC)": _time(e.collected_at),
            "reliability": e.reliability,
        }
        for e in items
    ]


def _render_evidence(
    ctx: AppContext,
    inv: Investigation,
    evidence: list[Evidence],
    timeline: list[TimelineEntry],
    is_open: bool,
) -> None:
    for category in EvidenceCategory:
        items = [e for e in evidence if e.category is category]
        st.write(f"**{category.value.replace('_', ' ').capitalize()}** ({len(items)})")
        if items:
            st.dataframe(_evidence_rows(items), use_container_width=True, hide_index=True)
    if evidence:
        with st.expander("Provenance of one item"):
            by_id = {e.evidence_id: e for e in evidence}
            pick = st.selectbox("Evidence", list(by_id), key="prov-pick")
            item = by_id[pick]
            st.json({"event_ids": item.event_ids, "provenance": item.provenance})
    if not is_open:
        return
    st.subheader("Add an analyst note")
    entries = {t.event_id: t for t in timeline}
    with st.form("add-evidence", clear_on_submit=True):
        category = st.selectbox("Category", [c.value for c in EvidenceCategory])
        claim = st.text_area("Claim", max_chars=2000)
        cited = st.multiselect(
            "Cite events from the scope",
            list(entries),
            format_func=lambda i: f"{_time(entries[i].event_time)} {entries[i].summary[:80]}",
        )
        submitted = st.form_submit_button("Add evidence")
    if submitted:
        try:
            ctx.investigations.add_evidence(
                inv.investigation_id,
                category=EvidenceCategory(category),
                claim=claim,
                source_type=EvidenceSource.ANALYST,
                source_ref=ANALYST,
                collected_by=ANALYST,
                event_ids=cited,
                provenance={"action": "analyst_note"},
            )
        except SocCopilotError as exc:
            st.error(str(exc))
        else:
            st.rerun()


def _render_expand(
    ctx: AppContext, inv: Investigation, timeline: list[TimelineEntry], is_open: bool
) -> None:
    if not is_open:
        st.caption("Reopen the investigation to expand its scope or run lookups.")
        return
    alerts = [a for a in (ctx.alerts.get(i) for i in inv.alert_ids) if a]
    st.write("**Search around an entity**")
    st.caption(
        "Adds every event for the chosen value within the window before the first alert event "
        "and after the last one."
    )
    values = {
        field: sorted({getattr(t, field) for t in timeline if getattr(t, field)})
        for field in sorted(CORRELATION_FIELDS)
    }
    fields = [f for f, v in values.items() if v]
    if alerts and fields:
        c1, c2, c3 = st.columns([1, 2, 1])
        field = c1.selectbox("Field", fields)
        value = c2.selectbox("Value", values[field])
        minutes = c3.number_input("± minutes", min_value=1, max_value=1440, value=30, step=5)
        if st.button("Add events to scope"):
            try:
                added = ctx.investigations.expand_around_entity(
                    inv.investigation_id,
                    field,
                    value,
                    min(a.first_seen for a in alerts),
                    max(a.last_seen for a in alerts),
                    int(minutes),
                    ANALYST,
                )
            except SocCopilotError as exc:
                st.error(str(exc))
            else:
                st.success(f"Added {added} new event(s) to the scope.")

    st.write("**IP reputation**")
    st.caption(
        "Records the local IOC match and each provider's result as evidence. External providers "
        "are only contacted if allowed on the Settings page."
    )
    ips = sorted({ip for t in timeline for ip in (t.src_ip, t.dst_ip) if ip})
    if ips:
        ip = st.selectbox("IP from the scope", ips)
        if st.button("Check reputation and record"):
            try:
                items = ctx.investigations.check_reputation(inv.investigation_id, ip, ANALYST)
            except SocCopilotError as exc:
                st.error(str(exc))
            else:
                st.success(f"Recorded {len(items)} evidence item(s).")
    else:
        st.caption("No IP addresses in the scope.")


def _render_verdict(
    ctx: AppContext, inv: Investigation, evidence: list[Evidence], is_open: bool
) -> None:
    if not is_open:
        st.write(f"**Disposition:** {inv.disposition.value if inv.disposition else 'none'}")
        st.write(f"**Confidence:** {inv.confidence.value if inv.confidence else 'n/a'}")
        st.text(inv.disposition_reason or "")
        st.caption("Supporting evidence: " + (", ".join(inv.disposition_evidence_ids) or "none"))
        if st.button("Reopen investigation"):
            ctx.investigations.reopen(inv.investigation_id)
            st.rerun()
        return
    st.caption(
        "Every disposition except insufficient_data must cite evidence; a malicious one must "
        "cite at least one observation. Confidence is qualitative."
    )
    by_id = {e.evidence_id: e for e in evidence}
    with st.form("verdict"):
        disposition = st.selectbox("Disposition", [d.value for d in Disposition])
        confidence = st.selectbox("Confidence", [c.value for c in Confidence], index=1)
        reason = st.text_area("Reasoning", max_chars=2000)
        cited = st.multiselect(
            "Supporting evidence",
            list(by_id),
            format_func=lambda i: f"[{by_id[i].category.value}] {by_id[i].claim[:90]}",
        )
        submitted = st.form_submit_button("Close investigation")
    if submitted:
        try:
            ctx.investigations.close(
                inv.investigation_id,
                Disposition(disposition),
                Confidence(confidence),
                reason,
                cited,
            )
        except SocCopilotError as exc:
            st.error(str(exc))
        else:
            st.rerun()


def _render_report(ctx: AppContext, inv: Investigation) -> None:
    report = build_report(
        ctx.investigations, inv.investigation_id, datetime.now(UTC).replace(microsecond=0)
    )
    markdown = to_markdown(report)
    c1, c2 = st.columns(2)
    c1.download_button(
        "Download Markdown",
        markdown,
        file_name=f"{inv.investigation_id}.md",
        mime="text/markdown",
    )
    c2.download_button(
        "Download JSON",
        to_json(report),
        file_name=f"{inv.investigation_id}.json",
        mime="application/json",
    )
    st.caption("Preview (source). Untrusted values are escaped in the Markdown.")
    st.code(markdown, language="markdown")
