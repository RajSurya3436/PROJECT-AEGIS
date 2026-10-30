from __future__ import annotations

import json

import streamlit as st

from app.context import AppContext
from app.storage.audit import AuditFilters

GROUPS = {
    "All": None,
    "Analyst chat": "chat.",
    "Agent tool calls": "tool.",
    "Agent runs": "agent_run.",
    "Response (proposals, approvals, simulations)": "response.",
    "Investigations and evidence": "investigation.",
    "Alerts": "alert.",
    "Reputation requests": "reputation.",
    "Rules and settings": ("rule.", "settings."),
    "Report exports": "report.",
}


def render(ctx: AppContext) -> None:
    st.title("Audit log")
    st.caption(
        "Append-only record of analyst instructions, agent runs and tool calls, external "
        "reputation requests, response proposals, approvals and simulations, and lifecycle "
        "changes. The database refuses edits and deletions of these rows."
    )
    investigations = {i.investigation_id: i for i in ctx.investigations.repo.list()}
    c1, c2, c3, c4 = st.columns([2, 2, 1, 1])
    group = c1.selectbox("Show", list(GROUPS))
    inv = c2.selectbox(
        "Investigation",
        ["(all)", *investigations],
        format_func=lambda i: i if i == "(all)" else f"{investigations[i].title} ({i})",
    )
    outcome = c3.selectbox("Outcome", ["(any)", "ok", "rejected", "failed"])
    limit = c4.number_input("Rows", min_value=10, max_value=2000, value=300, step=50)
    filters = AuditFilters(
        investigation_id=None if inv == "(all)" else inv,
        action_prefix=GROUPS[group],
        outcome=None if outcome == "(any)" else outcome,
    )
    events = ctx.audit.list(filters, int(limit))
    if not events:
        st.info("No audit events match.")
        return
    st.dataframe(
        [
            {
                "time (UTC)": e.at.strftime("%Y-%m-%d %H:%M:%S"),
                "actor": e.actor,
                "action": e.action,
                "target": f"{e.target_type}:{e.target_id}",
                "investigation": e.investigation_id or "",
                "outcome": e.outcome,
                "details": json.dumps(e.details, sort_keys=True)[:300],
            }
            for e in events
        ],
        use_container_width=True,
        hide_index=True,
    )
    st.download_button(
        "Download as JSON",
        json.dumps([e.model_dump(mode="json") for e in events], indent=2, sort_keys=True),
        file_name="audit_log.json",
        mime="application/json",
    )
    with st.expander("Details of one event"):
        by_id = {e.audit_id: e for e in events}
        pick = st.selectbox("Event", list(by_id), format_func=lambda i: f"{by_id[i].action} {i}")
        st.json(by_id[pick].model_dump(mode="json"))
