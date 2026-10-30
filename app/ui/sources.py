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
from app.ui import live_inputs, replay_panel

AUTO = "auto-detect"


def render(ctx: AppContext) -> None:
    st.title("Data sources")
    st.caption(
        "The app only sees data you load here. It does not read Windows Event Logs, EDR alerts "
        "or system logs on its own."
    )

    st.subheader("Bundled demo dataset")
    st.write(
        "Synthetic events (RFC 5737 documentation IPs) and a small local IOC list. "
        "Loading twice adds no duplicates. Detection runs on everything loaded."
    )
    if st.button("Load demo dataset"):
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

    replay_panel.render(ctx)

    st.subheader("Upload a file")
    limit_mb = ctx.settings.max_upload_bytes // (1024 * 1024)
    upload = st.file_uploader(
        f"JSONL, NDJSON, CSV or JSON (max {limit_mb} MB)",
        type=["jsonl", "ndjson", "csv", "json"],
    )
    if upload is not None:
        _render_upload(ctx, upload.name, upload.getvalue())

    live_inputs.render(ctx)

    st.subheader("Source health")
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
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No sources yet.")

    st.subheader("Quarantined rows")
    errors = ctx.parse_errors.list_recent()
    if errors:
        st.dataframe(
            [{k: e[k] for k in ("source_id", "locator", "error", "raw_snippet")} for e in errors],
            use_container_width=True,
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
        st.dataframe(preview.rows, use_container_width=True, hide_index=True)
    if preview.errors:
        st.dataframe(
            [e.model_dump(exclude={"source_id"}) for e in preview.errors],
            use_container_width=True,
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
