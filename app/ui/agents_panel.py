from __future__ import annotations

import streamlit as st

from app.context import AppContext
from app.domain.enums import ACTIVE_RUN_STATUSES, OPEN_RUN_STATUSES, AgentRunStatus
from app.domain.errors import SocCopilotError
from app.domain.models import AgentRun, Investigation
from app.ollama_health import ollama_status

_WAS_ACTIVE = "agents_were_active"


def _time(run: AgentRun) -> str:
    return run.created_at.strftime("%Y-%m-%d %H:%M:%S")


def ai_warning(ctx: AppContext) -> None:
    s = ctx.settings
    status, _ = ollama_status(s.ollama_base_url, s.ollama_model)
    if status != "reachable_model_present":
        st.warning(
            f"AI unavailable: Ollama {'is not running' if status == 'unreachable' else 'is up'}"
            f"{'' if status == 'unreachable' else f' but `{s.ollama_model}` is not installed'}."
            " Agent runs and Ask fail straight away; everything else on this page still works."
        )


def render(ctx: AppContext, inv: Investigation) -> None:
    s = ctx.settings
    ai_warning(ctx)
    st.caption(
        "Orchestrator, log investigator, threat intel and verifier (one local model, distinct "
        "prompts). Agents only use allowlisted tools, may only cite events a tool returned, and "
        f"stop at {s.agent_max_model_calls} model calls, {s.agent_max_tool_calls} tool calls or "
        f"{s.agent_max_run_seconds} s. The verifier's assessment is a proposal: you decide."
    )
    runs = ctx.agents.runs.for_investigation(inv.investigation_id)
    is_open = inv.status.value == "open"
    active = any(r.status in ACTIVE_RUN_STATUSES for r in runs)
    held = any(r.status in OPEN_RUN_STATUSES for r in runs)
    if is_open and st.button("Run agents", type="primary", disabled=held):
        _act(lambda: ctx.chat.start(inv.investigation_id))
    if not runs:
        st.caption("No agent runs yet." if is_open else "Reopen the investigation to run agents.")
        return

    by_id = {r.run_id: r for r in runs}
    chosen = st.selectbox(
        "Run",
        list(by_id),
        format_func=lambda i: f"{_time(by_id[i])} [{by_id[i].status.value}] {i}",
    )

    @st.fragment(run_every=2.0 if active else None)
    def live() -> None:
        run = ctx.agents.get(chosen)
        running = run.status in ACTIVE_RUN_STATUSES
        was_active = st.session_state.get(_WAS_ACTIVE, False)
        st.session_state[_WAS_ACTIVE] = running
        if was_active and not running:
            st.rerun()  # finished: refresh the page (evidence, timeline), then stop polling
        _render_run(ctx, inv, run, is_open)

    live()


def _act(action) -> None:
    """Run a chat-service action (inline runs block, so show a spinner) and refresh."""
    try:
        with st.spinner("Working..."):
            action()
    except SocCopilotError as exc:
        st.error(str(exc))
    else:
        st.rerun()


def _render_run(ctx: AppContext, inv: Investigation, run: AgentRun, is_open: bool) -> None:
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Status", run.status.value)
    m2.metric("Model calls", run.model_calls)
    m3.metric("Tool calls", run.tool_calls)
    m4.metric("Model", run.model)
    if run.error:
        (st.error if run.status is AgentRunStatus.FAILED else st.info)(run.error)

    if run.status is AgentRunStatus.WAITING:
        question = run.checkpoint.get("waiting_question", "")
        st.info(f"Waiting for your reply (answer in the **Chat** tab): {question}")
    inv_id = inv.investigation_id
    controllable = is_open and (
        run.status in OPEN_RUN_STATUSES or run.status is AgentRunStatus.INTERRUPTED
    )
    if controllable:
        c1, c2, c3 = st.columns(3)
        executing = run.status in ACTIVE_RUN_STATUSES
        if c1.button("Pause run", disabled=not executing or bool(run.control)):
            _act(lambda: ctx.chat.pause(inv_id))
        if c2.button(
            "Resume from checkpoint",
            disabled=run.status not in (AgentRunStatus.PAUSED, AgentRunStatus.INTERRUPTED),
        ):
            _act(lambda: ctx.chat.resume(inv_id))
        if c3.button("Stop run"):
            _act(lambda: ctx.chat.stop(inv_id))

    if run.assessment is not None:
        _render_assessment(ctx, inv, run, is_open)

    st.write("**Activity**")
    steps = ctx.agents.runs.steps(run.run_id)
    if not steps:
        st.caption("No steps yet.")
        return
    st.dataframe(
        [
            {
                "#": s.seq,
                "time (UTC)": s.created_at.strftime("%H:%M:%S"),
                "role": s.role.value,
                "kind": s.kind,
                "summary": s.summary,
                "ms": s.duration_ms,
            }
            for s in steps
        ],
        use_container_width=True,
        hide_index=True,
    )
    with st.expander("Detail of one step"):
        by_seq = {s.seq: s for s in steps}
        pick = st.selectbox("Step", list(by_seq), index=len(by_seq) - 1, key=f"step-{run.run_id}")
        st.json(by_seq[pick].payload)


def _render_assessment(ctx: AppContext, inv: Investigation, run: AgentRun, is_open: bool) -> None:
    a = run.assessment
    assert a is not None
    st.subheader("Verifier assessment")
    c1, c2 = st.columns(2)
    c1.metric("Proposed disposition", a.disposition.value)
    c2.metric("Confidence", a.confidence.value)
    st.text(a.rationale)
    sections = [
        ("Supporting evidence", a.supporting_evidence_ids),
        ("Contradicting evidence", a.contradicting_evidence_ids),
        ("Gaps", a.gaps),
        ("Unsupported claims", a.unsupported_claims),
        ("Adjusted by deterministic checks", a.adjustments),
        ("Questions for you", a.open_questions),
    ]
    for title, items in sections:
        if items:
            st.write(f"**{title}**")
            st.dataframe([{"item": i} for i in items], use_container_width=True, hide_index=True)
    if is_open and st.button("Close investigation with this assessment"):
        try:
            ctx.investigations.close(
                inv.investigation_id,
                a.disposition,
                a.confidence,
                f"Accepted verifier assessment from {run.run_id}: {a.rationale}",
                a.supporting_evidence_ids,
            )
        except SocCopilotError as exc:
            st.error(str(exc))
        else:
            st.rerun()
