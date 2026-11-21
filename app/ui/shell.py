"""App chrome around every page: logo, live status in the sidebar."""

from __future__ import annotations

import time
from pathlib import Path

import streamlit as st

from app.context import AppContext
from app.ollama_health import ollama_status
from app.ui import theme

ASSETS = Path(__file__).resolve().parent / "assets"
_HEALTH_TTL_SECONDS = 30


def model_status(ctx: AppContext) -> str:
    """Ollama health, cached per session for a short while so page changes stay fast."""
    cached = st.session_state.get("_ollama_health")
    now = time.monotonic()
    if cached and now - cached[0] < _HEALTH_TTL_SECONDS:
        return cached[1]
    s = ctx.settings
    status, _ = ollama_status(s.ollama_base_url, s.ollama_model)
    st.session_state["_ollama_health"] = (now, status)
    return status


def render_sidebar(ctx: AppContext) -> None:
    st.logo(str(ASSETS / "logo.svg"), size="large", icon_image=str(ASSETS / "mark.svg"))
    with st.sidebar:
        by_status = ctx.alerts.count_by("status")
        by_severity = ctx.alerts.count_by("severity")
        open_inv = ctx.investigations.repo.count_by_status().get("open", 0)
        new = by_status.get("new", 0)
        urgent = by_severity.get("critical", 0) + by_severity.get("high", 0)

        theme.section("Live status")
        theme.tiles(
            [
                ("New alerts", new, bool(new)),
                ("Open cases", open_inv, False),
                ("High / critical", urgent, bool(urgent)),
                ("Events", ctx.events.count(), False),
            ]
        )

        model = model_status(ctx)
        model_label, model_state = {
            "reachable_model_present": ("AI agents ready", "ok"),
            "reachable_model_missing": ("Model not installed", "warn"),
            "unreachable": ("AI offline", "off"),
        }[model]
        live = ctx.tails.running or ctx.receiver.running
        theme.pills(
            [
                (model_label, model_state),
                ("Live inputs on" if live else "Live inputs off", "ok" if live else "idle"),
                (
                    "Ext. reputation on" if ctx.reputation.external_enabled else "Local IOC only",
                    "warn" if ctx.reputation.external_enabled else "idle",
                ),
            ]
        )
        st.caption("Simulation-only responses · data stays on this machine")
