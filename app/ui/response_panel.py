from __future__ import annotations

import streamlit as st

from app.context import AppContext
from app.domain.enums import InvestigationStatus, RecommendationStatus, ResponseAction
from app.domain.errors import SocCopilotError
from app.domain.models import Investigation, Recommendation
from app.policy.rules import CATALOGUE, NO_TARGET
from app.ui.agents_panel import ai_warning

ANALYST = "analyst"
BADGE = {
    RecommendationStatus.PROPOSED: "🟡",
    RecommendationStatus.APPROVED: "🔵",
    RecommendationStatus.SIMULATED: "🟢",
    RecommendationStatus.REJECTED: "⚪",
    RecommendationStatus.BLOCKED: "🔴",
}


def render(ctx: AppContext, inv: Investigation) -> None:
    st.info(
        "**Simulation only.** This app has no firewall, EDR or identity integration: approving "
        "and simulating an action records what would happen and changes nothing outside it."
    )
    is_open = inv.status is InvestigationStatus.OPEN
    recs = ctx.responses.list(inv.investigation_id)
    if is_open:
        _plan(ctx, inv)
    else:
        st.caption("Reopen the investigation to propose or decide response actions.")
    st.subheader(f"Recommendations ({len(recs)})")
    if not recs:
        st.caption("None yet.")
    for rec in reversed(recs):
        _card(ctx, rec, is_open)
    if is_open:
        _manual(ctx, inv)


def _plan(ctx: AppContext, inv: Investigation) -> None:
    assessment = ctx.responses.latest_assessment(inv.investigation_id)
    st.write("**Response planner (AI)**")
    if assessment is None:
        st.caption(
            "Run the agents first (Chat or Agents tab): the planner works from the verifier's "
            "assessment. You can still propose actions yourself below."
        )
        return
    ai_warning(ctx)
    st.caption(
        f"Latest assessment: {assessment.disposition.value} ({assessment.confidence.value}). "
        "The planner proposes up to five actions; policy code checks each one."
    )
    if st.button("Propose response with AI", key="plan-response"):
        with st.spinner("The response planner is working (one model call)..."):
            try:
                result = ctx.planner.plan(inv.investigation_id, ANALYST)
            except SocCopilotError as exc:
                st.error(str(exc))
                return
        st.success(
            f"{len(result.recommendations)} proposal(s) recorded"
            + (f", {len(result.refused)} refused by the tool layer" if result.refused else "")
            + "."
        )
        st.rerun()


def _card(ctx: AppContext, rec: Recommendation, is_open: bool) -> None:
    spec = CATALOGUE[rec.action]
    title = (
        f"{BADGE[rec.status]} {rec.action.value} → {rec.target} · {rec.status.value} · "
        f"{rec.risk.value} impact"
    )
    with st.expander(title, expanded=rec.status is RecommendationStatus.PROPOSED):
        c1, c2, c3 = st.columns(3)
        c1.write(f"**Proposed by** {rec.proposed_by}")
        c2.write(f"**Reversible** {'yes' if rec.reversible else 'no'}")
        c3.write(f"**Approval** {'required' if rec.requires_approval else 'not required'}")
        st.caption(spec.title)
        st.write("**Rationale**")
        st.text(rec.rationale)
        st.caption("Evidence: " + (", ".join(rec.evidence_ids) or "none"))
        for note in rec.policy_notes:
            (st.error if note.startswith("Blocked") else st.caption)(note)
        if rec.decided_by:
            st.caption(
                f"Decided by {rec.decided_by}"
                + (f": {rec.decision_note}" if rec.decision_note else "")
            )
        if rec.simulation:
            st.write("**Simulation** (nothing was executed)")
            st.json(rec.simulation)
        if is_open and rec.status in (
            RecommendationStatus.PROPOSED,
            RecommendationStatus.APPROVED,
        ):
            _decide(ctx, rec)


def _decide(ctx: AppContext, rec: Recommendation) -> None:
    key = rec.recommendation_id
    note = st.text_input("Note (optional)", key=f"note-{key}", max_chars=500)
    b1, b2, b3 = st.columns(3)
    actions = []
    needs_approval = rec.status is RecommendationStatus.PROPOSED and rec.requires_approval
    if needs_approval and b1.button("Approve", key=f"approve-{key}"):
        actions.append(lambda: ctx.responses.approve(key, ANALYST, note))
    can_simulate = not rec.requires_approval or rec.status is RecommendationStatus.APPROVED
    if can_simulate and b2.button("Simulate", key=f"simulate-{key}", type="primary"):
        actions.append(lambda: ctx.responses.simulate(key, ANALYST))
    if b3.button("Reject", key=f"reject-{key}"):
        actions.append(lambda: ctx.responses.reject(key, ANALYST, note))
    for act in actions:
        try:
            act()
        except SocCopilotError as exc:
            st.error(str(exc))
        else:
            st.rerun()


def _manual(ctx: AppContext, inv: Investigation) -> None:
    st.subheader("Propose an action yourself")
    entities = ctx.responses.scope_entities(inv.investigation_id)
    evidence = {e.evidence_id: e for e in ctx.investigations.evidence(inv.investigation_id)}
    action = st.selectbox(
        "Action",
        list(ResponseAction),
        format_func=lambda a: f"{a.value}: {CATALOGUE[a].title} ({CATALOGUE[a].risk.value} impact)",
        key="manual-action",
    )
    kind = CATALOGUE[action].target_kind
    if kind == "none":
        options = [NO_TARGET]
    elif kind == "entity":
        options = sorted(entities["ip"] | entities["host"] | entities["user"])
    else:
        options = sorted(entities[kind])
    with st.form("manual-response", clear_on_submit=True):
        target = st.selectbox("Target (from this investigation's events)", options)
        rationale = st.text_area("Rationale", max_chars=1000)
        cited = st.multiselect(
            "Supporting evidence",
            list(evidence),
            format_func=lambda i: f"[{evidence[i].category.value}] {evidence[i].claim[:90]}",
        )
        submitted = st.form_submit_button("Propose")
    if submitted:
        try:
            rec = ctx.responses.propose(
                inv.investigation_id, action, target or "", rationale, cited, ANALYST
            )
        except SocCopilotError as exc:
            st.error(str(exc))
        else:
            if rec.status is RecommendationStatus.BLOCKED:
                st.error("Blocked by policy: " + " ".join(rec.policy_notes))
            else:
                st.rerun()
