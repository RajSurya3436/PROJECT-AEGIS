from __future__ import annotations

from datetime import UTC, datetime, time, timedelta

import streamlit as st

from app.context import AppContext
from app.domain.errors import InvalidFilterError
from app.storage.repositories import EventFilters

PAGE_SIZE = 50


def render(ctx: AppContext) -> None:
    st.title("Events explorer")
    span = ctx.events.time_range()
    if span is None:
        st.info("No events yet. Load data from **Data sources**.")
        return

    with st.form("event_filters"):
        c1, c2, c3 = st.columns(3)
        event_type = c1.selectbox("Type", ["", "auth", "process", "network", "other"])
        user = c2.text_input("User")
        host = c3.text_input("Host")
        c4, c5, c6 = st.columns(3)
        src_ip = c4.text_input("Source IP")
        dst_ip = c5.text_input("Destination IP")
        text = c6.text_input("Message / command contains")
        d1, d2 = st.columns(2)
        start_date = d1.date_input("From (UTC)", value=span[0].date())
        end_date = d2.date_input("To (UTC)", value=span[1].date())
        st.form_submit_button("Search")

    filters = EventFilters(
        equals={
            "event_type": event_type,
            "user": user.strip(),
            "host": host.strip(),
            "src_ip": src_ip.strip(),
            "dst_ip": dst_ip.strip(),
        },
        start=datetime.combine(start_date, time.min, tzinfo=UTC),
        end=datetime.combine(end_date, time.max, tzinfo=UTC),
        text=text.strip() or None,
    )
    try:
        first = ctx.events.search(filters, 1, PAGE_SIZE)
    except InvalidFilterError as exc:
        st.error(str(exc))
        return
    pages = max(1, -(-first.total // PAGE_SIZE))
    page = st.number_input("Page", min_value=1, max_value=pages, value=1, step=1)
    result = first if page == 1 else ctx.events.search(filters, int(page), PAGE_SIZE)
    st.caption(f"{result.total:,} matching events · page {result.page} of {pages}")

    st.dataframe(
        [_summary_row(e, with_id=True) for e in result.events],
        use_container_width=True,
        hide_index=True,
    )

    if not result.events:
        return
    chosen = st.selectbox("Inspect event", [e.event_id for e in result.events])
    event = ctx.events.get(chosen)
    if event is None:
        return
    left, right = st.columns(2)
    with left:
        st.subheader("Normalized")
        st.json(event.model_dump(mode="json", exclude={"raw"}))
    with right:
        st.subheader("Raw record")
        st.json(event.raw)
    with st.expander("Related events (±10 min, same user / host / IP)"):
        related = ctx.events.related(chosen, timedelta(minutes=10))
        st.dataframe([_summary_row(e) for e in related], use_container_width=True, hide_index=True)


def _summary_row(e, with_id: bool = False) -> dict:
    row = {
        "time (UTC)": e.event_time.strftime("%Y-%m-%d %H:%M:%S"),
        "type": e.event_type.value,
        "user": e.user,
        "host": e.host,
        "src_ip": e.src_ip,
        "dst_ip": e.dst_ip,
        "outcome": e.outcome.value,
        "summary": e.command_line or e.message or e.action,
    }
    if with_id:
        row["event_id"] = e.event_id
    return row
