"""Streamlit entry point: streamlit run app/main.py"""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.context import AppContext, build_context
from app.ui import (
    alerts,
    audit,
    dashboard,
    events,
    investigations,
    rules,
    settings,
    shell,
    sources,
    theme,
)


@st.cache_resource
def get_context() -> AppContext:
    return build_context()


def main() -> None:
    st.set_page_config(
        page_title="Aegis SOC Copilot",
        page_icon=str(shell.ASSETS / "mark.svg"),
        layout="wide",
        initial_sidebar_state="expanded",
    )
    theme.inject_css()
    ctx = get_context()

    def page(render, title: str, url: str, icon: str, default: bool = False) -> st.Page:
        return st.Page(lambda: render(ctx), title=title, url_path=url, icon=icon, default=default)

    pages = {
        "Monitor": [
            page(dashboard.render, "Overview", "overview", ":material/space_dashboard:", True),
            page(alerts.render, "Alert queue", "alerts", ":material/notifications_active:"),
            page(events.render, "Events explorer", "events", ":material/manage_search:"),
        ],
        "Respond": [
            page(investigations.render, "Investigations", "investigations", ":material/biotech:"),
        ],
        "Configure": [
            page(sources.render, "Data sources", "sources", ":material/database:"),
            page(rules.render, "Detection rules", "rules", ":material/rule:"),
            page(settings.render, "Settings", "settings", ":material/tune:"),
        ],
        "Govern": [
            page(audit.render, "Audit log", "audit", ":material/policy:"),
        ],
    }
    navigation = st.navigation(pages)
    shell.render_sidebar(ctx)
    navigation.run()


main()
