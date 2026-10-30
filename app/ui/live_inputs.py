from __future__ import annotations

import streamlit as st

from app.config import PROJECT_ROOT
from app.context import AppContext
from app.domain.errors import SocCopilotError
from app.ingestion.adapters import ADAPTERS
from app.ingestion.http_receiver import http_source_id

SAMPLE = PROJECT_ROOT / "data" / "samples" / "wazuh_alerts.jsonl"


def render(ctx: AppContext) -> None:
    st.subheader("Live inputs")
    st.caption(
        "Both feed the same pipeline as uploads (normalise, deduplicate, detect). Nothing here "
        "reads system logs on its own: you choose the file or the sender."
    )
    tab_tail, tab_http = st.tabs(["Follow a file", "HTTP receiver"])
    with tab_tail:
        _tails(ctx)
    with tab_http:
        _receiver(ctx)


def _tails(ctx: AppContext) -> None:
    tails = ctx.tails
    st.caption(
        "Follows a growing JSONL file, e.g. Wazuh's `/var/ossec/logs/alerts/alerts.json` (shared "
        "to this PC) or any one-JSON-object-per-line log. Handles partial lines, truncation and "
        "rotation, and continues from where it stopped after a restart."
    )
    with st.form("add-tail", clear_on_submit=False):
        path = st.text_input("File path", placeholder=str(SAMPLE))
        c1, c2 = st.columns(2)
        adapter = c1.selectbox(
            "Record layout", list(ADAPTERS), format_func=lambda n: ADAPTERS[n].title, index=1
        )
        at_end = c2.checkbox(
            "Start at the end (only new lines)",
            help="Off: read the whole file first. On: skip what is already there.",
        )
        submitted = st.form_submit_button("Follow this file")
    if submitted:
        try:
            config = tails.add(path or str(SAMPLE), adapter, start_at_end=at_end)
        except SocCopilotError as exc:
            st.error(str(exc))
        else:
            st.success(f"Following {config.path} as {config.source_id}.")
    status = tails.status()
    if not status.configs:
        st.caption(f"No files followed. Try the bundled sample: `{SAMPLE}`.")
        return
    sources = {s.source_id: s for s in ctx.sources.list_all()}
    rows = []
    for config in status.configs:
        source = sources.get(config.source_id)
        last = status.last.get(config.source_id)
        rows.append(
            {
                "file": config.path,
                "layout": config.adapter,
                "read up to (bytes)": (source.cursor.get("offset") if source else None) or 0,
                "events": source.event_count if source else 0,
                "quarantined": source.error_count if source else 0,
                "last poll": (
                    f"+{last.inserted} new, {last.duplicates} dup"
                    + (f", {last.reset}" if last and last.reset else "")
                    + (", waiting for line end" if last and last.waiting_partial else "")
                )
                if last and not last.error
                else (last.error if last else ""),
                "source_id": config.source_id,
            }
        )
    st.dataframe(rows, use_container_width=True, hide_index=True)
    c1, c2, c3 = st.columns(3)
    if tails.threaded:
        if status.running:
            c1.success(f"Polling every {ctx.settings.file_tail_poll_seconds:g} s")
            if c2.button("Stop following"):
                tails.stop()
                st.rerun()
        elif c1.button("Start following", type="primary"):
            tails.start()
            st.rerun()
    else:
        c1.caption("In-memory database: use Poll now.")
    if c3.button("Poll now"):
        results = tails.poll_all()
        st.success(
            f"Read {sum(r.bytes_read for r in results):,} bytes: "
            f"{sum(r.inserted for r in results)} new event(s), "
            f"{sum(r.quarantined for r in results)} quarantined."
        )
    remove = st.selectbox(
        "Stop following a file",
        ["(none)", *[c.source_id for c in status.configs]],
        key="tail-remove",
    )
    if remove != "(none)" and st.button("Remove", key="tail-remove-btn"):
        tails.remove(remove)
        st.rerun()


def _receiver(ctx: AppContext) -> None:
    receiver = ctx.receiver
    settings = ctx.settings
    token = settings.http_receiver_token is not None and bool(
        settings.http_receiver_token.get_secret_value()
    )
    st.caption(
        f"Listens on {receiver.host} only (never the network). Browser requests are refused. "
        f"Limits: {settings.http_receiver_max_body_bytes // 1024:,} KB and "
        f"{settings.http_receiver_max_records:,} records per request, "
        f"{settings.http_receiver_requests_per_minute} requests per minute. "
        + ("A bearer token is required (HTTP_RECEIVER_TOKEN)." if token else "No token set.")
    )
    if receiver.running:
        st.success(f"Listening on {receiver.url}")
        if st.button("Stop receiver"):
            receiver.stop()
            st.rerun()
        stats = receiver.stats
        st.write(
            f"Requests {stats.requests} · accepted {stats.accepted} · rejected {stats.rejected} "
            f"· events inserted {stats.events_inserted}"
        )
        if stats.last_error:
            st.caption(f"Last rejection: {stats.last_error}")
        auth = ' -H "Authorization: Bearer $TOKEN"' if token else ""
        st.code(
            f'curl.exe -X POST "{receiver.url}/ingest?source=lab&adapter=wazuh" '
            f'-H "Content-Type: application/x-ndjson"{auth} --data-binary @"{SAMPLE}"',
            language="bash",
        )
        st.caption(f"Events land in source `{http_source_id('lab')}` (named by ?source=).")
    elif st.button("Start receiver", type="primary"):
        try:
            receiver.start()
        except SocCopilotError as exc:
            st.error(str(exc))
        else:
            st.rerun()
