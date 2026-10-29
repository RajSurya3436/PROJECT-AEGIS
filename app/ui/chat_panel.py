from __future__ import annotations

from collections.abc import Callable

import streamlit as st

from app.context import AppContext
from app.domain.enums import ACTIVE_RUN_STATUSES, AgentRole
from app.domain.errors import SocCopilotError
from app.domain.models import ChatEntry, Investigation
from app.ui.agents_panel import ai_warning

MODES = {
    "Ask": "Read-only question. Nothing is recorded as evidence and no provider is contacted.",
    "Investigate": "Instruct the agents. Starts a run, redirects the open one, or answers the "
    "agents' question when they are waiting.",
    "Control": "Pause, resume or stop the open run, or redirect it.",
}
AUTO = "auto (orchestrator decides)"
SPECIALISTS = [AgentRole.LOG_INVESTIGATOR, AgentRole.THREAT_INTEL, AgentRole.VERIFIER]
_WAS_ACTIVE = "chat_run_was_active"


def render(ctx: AppContext, inv: Investigation) -> None:
    ai_warning(ctx)
    inv_id = inv.investigation_id
    is_open = inv.status.value == "open"
    run = ctx.chat.open_run(inv_id)
    executing = run is not None and run.status in ACTIVE_RUN_STATUSES

    @st.fragment(run_every=2.0 if executing else None)
    def live() -> None:
        current = ctx.chat.open_run(inv_id)
        running = current is not None and current.status in ACTIVE_RUN_STATUSES
        was_active = st.session_state.get(_WAS_ACTIVE, False)
        st.session_state[_WAS_ACTIVE] = running
        if was_active and not running:
            st.rerun()  # the run paused, waits or ended: refresh controls and evidence
        state, detail = ctx.chat.status(inv_id)
        (st.warning if state == "waiting" else st.info)(f"**Agents: {state}.** {detail}")
        pending = ctx.chat.pending(inv_id)
        if pending and current is None:
            st.caption(
                f"{len(pending)} instruction(s) not yet applied; the next run reads them first."
            )
        _history(ctx.chat.messages(inv_id))

    live()

    mode = st.radio("Mode", list(MODES), horizontal=True, key=f"chat-mode-{inv_id}")
    st.caption(MODES[mode])
    if mode == "Ask":
        _ask(ctx, inv_id)
    elif not is_open:
        st.caption("The investigation is closed; reopen it to direct the agents. Ask still works.")
    elif mode == "Investigate":
        waiting = run is not None and run.status.value == "waiting"
        _direct(ctx, inv_id, "Reply to the agents" if waiting else "Send to the agents", False)
    else:
        _control(ctx, inv_id)


def _history(messages: list[ChatEntry]) -> None:
    if not messages:
        st.caption("No messages yet.")
        return
    for m in messages:
        name = "user" if m.author == "analyst" else "assistant"
        with st.chat_message(name, avatar="⚙️" if m.author == "system" else None):
            target = f" → {m.target_role.value}" if m.target_role else ""
            state = f" · {m.status}" if m.status else ""
            st.caption(
                f"{m.author}{target} · {m.mode.value}/{m.kind.value}{state} · "
                f"{m.created_at:%H:%M:%S} UTC"
            )
            st.text(m.content)  # plain text: model output and log values are never rendered
            unverified = m.payload.get("unverified_references")
            if unverified:
                st.caption("Unverified references: " + ", ".join(unverified))


def _act(action: Callable[[], object]) -> None:
    try:
        with st.spinner("Working..."):
            action()
    except SocCopilotError as exc:
        st.error(str(exc))
    else:
        st.rerun()


def _ask(ctx: AppContext, inv_id: str) -> None:
    with st.form(f"ask-{inv_id}", clear_on_submit=True):
        role = st.selectbox(
            "Ask", SPECIALISTS, format_func=lambda r: r.value, key=f"ask-role-{inv_id}"
        )
        text = st.text_area("Question", max_chars=2000, key=f"ask-text-{inv_id}")
        submitted = st.form_submit_button("Ask")
    if submitted:
        _act(lambda: ctx.chat.ask(inv_id, text, role))


def _direct(ctx: AppContext, inv_id: str, label: str, redirect: bool) -> None:
    with st.form(f"{'redirect' if redirect else 'investigate'}-{inv_id}", clear_on_submit=True):
        choice = st.selectbox(
            "Send to",
            [AUTO, *SPECIALISTS],
            format_func=lambda r: r if isinstance(r, str) else r.value,
            key=f"direct-role-{redirect}-{inv_id}",
        )
        text = st.text_area(
            "Instruction",
            max_chars=2000,
            placeholder="e.g. Search the same user's events for 30 minutes before and after.",
            key=f"direct-text-{redirect}-{inv_id}",
        )
        submitted = st.form_submit_button("Redirect" if redirect else label)
    if submitted:
        role = None if isinstance(choice, str) else choice
        send = ctx.chat.redirect if redirect else ctx.chat.investigate
        _act(lambda: send(inv_id, text, role))


def _control(ctx: AppContext, inv_id: str) -> None:
    c1, c2, c3 = st.columns(3)
    if c1.button("Pause", key=f"pause-{inv_id}"):
        _act(lambda: ctx.chat.pause(inv_id))
    if c2.button("Resume", key=f"resume-{inv_id}"):
        _act(lambda: ctx.chat.resume(inv_id))
    if c3.button("Stop", key=f"stop-{inv_id}"):
        _act(lambda: ctx.chat.stop(inv_id))
    st.write("**Redirect**")
    st.caption(
        "Ends the current specialist turn and sends the work where you say. Evidence already "
        "collected is kept."
    )
    _direct(ctx, inv_id, "Redirect", True)
