from __future__ import annotations

from datetime import UTC, datetime, time, timedelta

import streamlit as st

from app.context import AppContext
from app.domain.errors import InvalidFilterError
from app.storage.repositories import EventFilters
from app.ui import theme

PAGE_SIZE = 50


def render(ctx: AppContext) -> None:
    theme.page_header(
        "Events explorer",
        "Search every normalized event. Select a row to see the normalized fields, the raw "
        "record and the events around it.",
        icon="🔎",
        eyebrow="Monitor",
    )
    span = ctx.events.time_range()
    if span is None:
        theme.empty_state("No events yet. Load data from Data sources.", ":material/database:")
        return

    by_type = ctx.events.count_by_type()
    k = st.columns(len(by_type) + 1)
    k[0].metric("All events", f"{sum(by_type.values()):,}", border=True)
    for col, (name, n) in zip(k[1:], sorted(by_type.items()), strict=True):
        col.metric(name.capitalize(), f"{n:,}", border=True)

    with st.form("event_filters", border=True):
        c1, c2, c3, c4 = st.columns(4)
        event_type = c1.selectbox("Type", ["", "auth", "process", "network", "other"])
        user = c2.text_input("User")
        host = c3.text_input("Host")
        text = c4.text_input("Message / command contains")
        c5, c6, c7, c8 = st.columns(4)
        src_ip = c5.text_input("Source IP")
        dst_ip = c6.text_input("Destination IP")
        start_date = c7.date_input("From (UTC)", value=span[0].date())
        end_date = c8.date_input("To (UTC)", value=span[1].date())
        st.form_submit_button("Search", icon=":material/search:", type="primary")

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
    c1, c2 = st.columns([4, 1], vertical_alignment="bottom")
    page = c2.number_input("Page", min_value=1, max_value=pages, value=1, step=1)
    result = first if page == 1 else ctx.events.search(filters, int(page), PAGE_SIZE)
    c1.markdown(f"**{result.total:,} matching events** · page {result.page} of {pages}")

    selection = st.dataframe(
        [_summary_row(e, with_id=True) for e in result.events],
        width="stretch",
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row",
        key="event-table",
    )
    if not result.events:
        return
    rows = getattr(getattr(selection, "selection", None), "rows", None) or []
    if not rows or rows[0] >= len(result.events):
        st.caption("Select a row to inspect an event.")
        return
    event = ctx.events.get(result.events[rows[0]].event_id)
    if event is None:
        return
    with st.container(border=True):
        theme.section("Event detail")
        normalized, raw, related = st.tabs(
            [
                ":material/data_object: Normalized",
                ":material/description: Raw record",
                ":material/hub: Related (±10 min)",
            ]
        )
        with normalized:
            st.json(event.model_dump(mode="json", exclude={"raw"}))
        with raw:
            st.json(event.raw)
        with related:
            st.caption("Same user, host or IP within ten minutes.")
            near = ctx.events.related(event.event_id, timedelta(minutes=10))
            st.dataframe([_summary_row(e) for e in near], width="stretch", hide_index=True)


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
