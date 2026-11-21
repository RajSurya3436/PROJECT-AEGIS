from __future__ import annotations

import streamlit as st

from app.context import AppContext
from app.domain.enums import EventType, InputFormat
from app.domain.errors import SocCopilotError
from app.ingestion.adapters import ADAPTERS
from app.ingestion.demo import ingest_demo
from app.ingestion.iocs import load_demo_iocs
from app.ingestion.parsers import detect_format
from app.ingestion.upload import ingest_upload, preview_upload
from app.ui import live_inputs, replay_panel, theme

AUTO = "auto-detect"


def render(ctx: AppContext) -> None:
    theme.page_header(
        "Data sources",
        "The app only sees data you load here. It does not read Windows Event Logs, EDR alerts "
        "or system logs on its own: upload files, replay the demo, or follow a live log.",
        icon="🗄️",
        eyebrow="Configure",
    )
    sources = ctx.sources.list_all()
    k = st.columns(4)
    k[0].metric("Sources", len(sources), border=True)
    k[1].metric("Events", f"{ctx.events.count():,}", border=True)
    k[2].metric("Quarantined rows", ctx.parse_errors.count(), border=True)
    k[3].metric(
        "Sources with errors",
        sum(1 for s in sources if s.status.value == "error"),
        border=True,
    )

    load_tab, live_tab, health_tab = st.tabs(
        [
            ":material/upload_file: Load data",
            ":material/sensors: Live inputs",
            ":material/monitor_heart: Health and quarantine",
        ]
    )
    with load_tab:
        _render_load(ctx)
    with live_tab, st.container(border=True):
        live_inputs.render(ctx)
    with health_tab:
        _render_health(ctx)


def _render_load(ctx: AppContext) -> None:
    demo, upload_col = st.columns(2, gap="medium", border=True)
    with demo:
        st.subheader("Bundled demo dataset", anchor=False)
        st.write(
            "Synthetic events (RFC 5737 documentation IPs) and a small local IOC list. "
            "Loading twice adds no duplicates. Detection runs on everything loaded."
        )
        if st.button("Load demo dataset", type="primary", icon=":material/download:"):
            try:
                load_demo_iocs(ctx.iocs)  # first, so the IOC rule sees the list as events arrive
                results = ingest_demo(ctx.ingestion)
                st.success(
                    f"Inserted {sum(r.inserted for r in results)} new events "
                    f"({sum(r.duplicates for r in results)} already present, "
                    f"{sum(r.quarantined for r in results)} quarantined). "
                    f"{ctx.alerts.count()} alert(s) in the queue."
                )
            except SocCopilotError as exc:
                st.error(str(exc))
    with upload_col:
        st.subheader("Upload a file", anchor=False)
        limit_mb = ctx.settings.max_upload_bytes // (1024 * 1024)
        upload = st.file_uploader(
            f"JSONL, NDJSON, CSV or JSON (max {limit_mb} MB)",
            type=["jsonl", "ndjson", "csv", "json"],
        )
    if upload is not None:
        with st.container(border=True):
            _render_upload(ctx, upload.name, upload.getvalue())

    with st.container(border=True):
        replay_panel.render(ctx)


def _render_health(ctx: AppContext) -> None:
    with st.container(border=True):
        _render_source_table(ctx)
    with st.container(border=True):
        _render_quarantine(ctx)


def _render_source_table(ctx: AppContext) -> None:
    st.subheader("Source health", anchor=False)
    sources = ctx.sources.list_all()
    if sources:
        st.dataframe(
            [
                {
                    "source": s.name,
                    "type": s.source_type.value,
                    "status": s.status.value,
                    "events": s.event_count,
                    "quarantined": s.error_count,
                    "last seen (UTC)": s.last_seen.strftime("%Y-%m-%d %H:%M:%S")
                    if s.last_seen
                    else "",
                    "last error": s.last_error or "",
                }
                for s in sources
            ],
            width="stretch",
            hide_index=True,
        )
    else:
        st.info("No sources yet.")


def _render_quarantine(ctx: AppContext) -> None:
    st.subheader("Quarantined rows", anchor=False)
    errors = ctx.parse_errors.list_recent()
    if errors:
        st.dataframe(
            [{k: e[k] for k in ("source_id", "locator", "error", "raw_snippet")} for e in errors],
            width="stretch",
            hide_index=True,
        )
    else:
        st.caption("None.")


def _render_upload(ctx: AppContext, filename: str, content: bytes) -> None:
    detected = detect_format(filename)
    choice = st.selectbox(
        "Format", [AUTO, *[f.value for f in InputFormat]], help=f"Detected: {detected or 'unknown'}"
    )
    fmt = detected if choice == AUTO else InputFormat(choice)
    if fmt is None:
        st.error("Could not detect the format; choose one.")
        return
    type_choice = st.selectbox(
        "Default event type (used only when records have no type field)",
        ["(none)", *[t.value for t in EventType]],
    )
    default_type = None if type_choice == "(none)" else EventType(type_choice)
    adapter = ADAPTERS[
        st.selectbox(
            "Record layout",
            list(ADAPTERS),
            format_func=lambda name: ADAPTERS[name].title,
            help="Wazuh: an alerts.json export (one alert per line). Generic: field aliases.",
        )
    ]
    try:
        preview = preview_upload(
            content, fmt, ctx.settings, default_event_type=default_type, adapter=adapter
        )
    except SocCopilotError as exc:
        st.error(str(exc))
        return
    st.write(
        f"Previewed {preview.records_previewed} records · {len(preview.rows)} valid · "
        f"{len(preview.errors)} would be quarantined"
    )
    st.write("**Field mapping** (input column → canonical field)")
    st.json(preview.mapping)
    if preview.unmapped:
        st.caption("Kept as-is in `extra` (not guessed): " + ", ".join(preview.unmapped))
    if preview.rows:
        st.dataframe(preview.rows, width="stretch", hide_index=True)
    if preview.errors:
        st.dataframe(
            [e.model_dump(exclude={"source_id"}) for e in preview.errors],
            width="stretch",
            hide_index=True,
        )
    if st.button("Ingest file"):
        try:
            result = ingest_upload(
                ctx.ingestion,
                filename,
                content,
                fmt,
                default_event_type=default_type,
                adapter=adapter,
            )
        except SocCopilotError as exc:
            st.error(str(exc))
            return
        msg = (
            f"Inserted {result.inserted}, duplicates {result.duplicates}, "
            f"quarantined {result.quarantined}."
        )
        if result.truncated:
            msg += " Stopped early at the row limit."
        st.success(msg)
