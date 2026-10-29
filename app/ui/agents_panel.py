from __future__ import annotations

import streamlit as st

from app.context import AppContext
from app.domain.enums import ACTIVE_RUN_STATUSES, AgentRunStatus
from app.domain.errors import SocCopilotError
from app.domain.models import AgentRun, Investigation
from app.ollama_health import ollama_status
from app.storage.agents import RESUMABLE

_WAS_ACTIVE = "agents_were_active"


def _time(run: AgentRun) -> str:
    return run.created_at.strftime("%Y-%m-%d %H:%M:%S")


def render(ctx: AppContext, inv: Investigation) -> None:
    s = ctx.settings
    status, _ = ollama_status(s.ollama_base_url, s.ollama_model)
    if status != "reachable_model_present":
        st.warning(
            f"AI unavailable: Ollama {'is not running' if status == 'unreachable' else 'is up'}"
            f"{'' if status == 'unreachable' else f' but `{s.ollama_model}` is not installed'}."
            " A run will fail straight away; everything else on this page still works."
        )
    st.caption(
        "Orchestrator, log investigator, threat intel and verifier (one local model, distinct "
        "prompts). Agents only use allowlisted tools, may only cite events a tool returned, and "
        f"stop at {s.agent_max_model_calls} model calls, {s.agent_max_tool_calls} tool calls or "
        f"{s.agent_max_run_seconds} s. The verifier's assessment is a proposal: you decide."
    )
    runs = ctx.agents.runs.for_investigation(inv.investigation_id)
    is_open = inv.status.value == "open"
    active = any(r.status in ACTIVE_RUN_STATUSES for r in runs)
    if is_open and st.button("Run agents", type="primary", disabled=active):
        _start(ctx, inv)
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


def _start(ctx: AppContext, inv: Investigation) -> None:
    try:
        if ctx.agent_runner is not None:
            ctx.agent_runner.start(ctx.agents, inv.investigation_id)
        else:
            with st.spinner("Agents are working..."):
                ctx.agents.run_now(inv.investigation_id)
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

    runner = ctx.agent_runner
    running = runner is not None and run.status in ACTIVE_RUN_STATUSES
    resumable = runner is not None and is_open and not running and run.status.value in RESUMABLE
    if running and st.button("Stop run"):
        runner.stop(run.run_id)
        st.rerun()
    if resumable and st.button("Resume from checkpoint"):
        try:
            runner.resume(ctx.agents, run.run_id)
        except SocCopilotError as exc:
            st.error(str(exc))
        else:
            st.rerun()

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
