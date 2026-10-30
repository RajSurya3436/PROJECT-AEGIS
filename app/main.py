"""Streamlit entry point: streamlit run app/main.py"""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.context import AppContext, build_context
from app.ui import alerts, audit, dashboard, events, investigations, rules, settings, sources


@st.cache_resource
def get_context() -> AppContext:
    return build_context()


def main() -> None:
    st.set_page_config(page_title="Agentic SOC Copilot", page_icon="🛡️", layout="wide")
    ctx = get_context()
    pages = [
        st.Page(lambda: dashboard.render(ctx), title="Overview", url_path="overview", default=True),
        st.Page(lambda: events.render(ctx), title="Events explorer", url_path="events"),
        st.Page(lambda: alerts.render(ctx), title="Alert queue", url_path="alerts"),
        st.Page(
            lambda: investigations.render(ctx), title="Investigations", url_path="investigations"
        ),
        st.Page(lambda: sources.render(ctx), title="Data sources", url_path="sources"),
        st.Page(lambda: rules.render(ctx), title="Detection rules", url_path="rules"),
        st.Page(lambda: settings.render(ctx), title="Settings", url_path="settings"),
        st.Page(lambda: audit.render(ctx), title="Audit log", url_path="audit"),
    ]
    st.navigation(pages).run()


main()
