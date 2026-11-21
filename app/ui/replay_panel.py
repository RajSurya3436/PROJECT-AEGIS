from __future__ import annotations

import streamlit as st

from app.context import AppContext
from app.domain.errors import SocCopilotError
from app.ingestion.replay import DEFAULT_MAX_GAP_SECONDS, SPEEDS, ReplayState

_WAS_ACTIVE = "replay_was_active"


def render(ctx: AppContext) -> None:
    st.subheader("Timed replay of the demo dataset")
    runner = ctx.replay
    if runner is None:
        st.caption("Replay needs a file-backed database (not available for in-memory databases).")
        return
    st.write(
        "Feeds the demo events through the same ingestion and detection path, in event-time "
        "order, so alerts appear as the data arrives. Restarting is safe: events already stored "
        "are skipped and alerts are not duplicated."
    )
    c1, c2 = st.columns(2)
    speed = SPEEDS[c1.selectbox("Speed", list(SPEEDS), index=2)]
    max_gap = int(
        c2.number_input(
            "Skip idle gaps longer than (seconds of event time)",
            min_value=1,
            max_value=86_400,
            value=DEFAULT_MAX_GAP_SECONDS,
        )
    )
    if runner.progress().active:
        runner.set_speed(speed)

    @st.fragment(run_every=1.0 if runner.progress().active else None)
    def status() -> None:
        current = runner.progress()
        was_active = st.session_state.get(_WAS_ACTIVE, False)
        st.session_state[_WAS_ACTIVE] = current.active
        if was_active and not current.active:
            st.rerun()  # finished or stopped: refresh the whole page, then stop polling

        bar = st.container(horizontal=True, gap="small")
        action = None
        if bar.button(
            "Start", disabled=current.active, type="primary", icon=":material/play_arrow:"
        ):
            action = lambda: runner.start(speed=speed, max_gap_seconds=max_gap)  # noqa: E731
        if bar.button(
            "Pause", disabled=current.state is not ReplayState.RUNNING, icon=":material/pause:"
        ):
            action = runner.pause
        if bar.button(
            "Resume", disabled=current.state is not ReplayState.PAUSED, icon=":material/resume:"
        ):
            action = runner.resume
        if bar.button("Stop", disabled=not current.active, icon=":material/stop:"):
            action = runner.stop
        if bar.button("Restart", icon=":material/restart_alt:"):
            action = lambda: runner.restart(speed=speed, max_gap_seconds=max_gap)  # noqa: E731
        if action is not None:
            try:
                action()
            except SocCopilotError as exc:
                st.error(str(exc))
            else:
                st.rerun()

        st.progress(current.fraction, text=f"{current.position} / {current.total} records")
        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("State", current.state.value, border=True)
        m2.metric("Inserted", current.inserted, border=True)
        m3.metric("Already stored", current.duplicates, border=True)
        m4.metric("Quarantined", current.quarantined, border=True)
        m5.metric("Alerts", ctx.alerts.count(), border=True)
        if current.last_event_time:
            st.caption(
                f"Replay clock (event time, UTC): {current.last_event_time:%Y-%m-%d %H:%M:%S}"
            )
        if current.error:
            st.error(f"Replay problem: {current.error}")

    status()
