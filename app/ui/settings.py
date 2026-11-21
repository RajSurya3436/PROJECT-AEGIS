from __future__ import annotations

import streamlit as st

from app.context import AppContext
from app.ollama_health import ollama_status
from app.ui import theme
from app.ui.reputation import render_report

OLLAMA_LABELS = {
    "reachable_model_present": "Ready ({model})",
    "reachable_model_missing": "Server up, model `{model}` not installed",
    "unreachable": "Unavailable (detection, search and reputation lookups still work)",
}


def render(ctx: AppContext) -> None:
    theme.page_header(
        "Settings and integrations",
        "Local model, threat-intel providers, the reputation cache and safe mode.",
        icon="⚙️",
        eyebrow="Configure",
    )
    s = ctx.settings
    rep = ctx.reputation

    model_col, safe_col = st.columns(2, gap="medium", border=True)
    with model_col:
        st.subheader("Local model", anchor=False)
        status, _ = ollama_status(s.ollama_base_url, s.ollama_model)
        st.write(f"**Ollama:** {OLLAMA_LABELS[status].format(model=s.ollama_model)}")
        st.caption("Used only by the agents. Never pulled automatically.")
    with safe_col:
        st.subheader("Safe mode", anchor=False)
        st.write(
            "Response actions are **simulation only**. This app never blocks IPs, disables "
            "accounts or changes any external system."
        )

    with st.container(border=True):
        st.subheader("Reputation providers", anchor=False)
        rows = [
            {
                "provider": provider.title,
                "API key": "configured" if provider.configured else "not configured",
                "requests / minute": provider.limiter.per_minute,
                "requests / day": provider.limiter.per_day,
                "timeout (s)": provider.timeout,
                "retries": provider.max_retries,
            }
            for provider in rep.providers.values()
        ]
        st.dataframe(rows, width="stretch", hide_index=True)
        if not any(p.configured for p in rep.providers.values()):
            st.info(
                "No provider keys set. Add `ABUSEIPDB_API_KEY` and/or `VIRUSTOTAL_API_KEY` to "
                "the environment or `.env` and restart. The app works fully without them, using "
                "the local IOC list."
            )
        enabled = st.toggle("Allow external reputation lookups", value=rep.external_enabled)
        if enabled != rep.external_enabled:
            rep.set_external_enabled(enabled)
            st.rerun()
        st.caption(
            "When on, a lookup you request sends **only the queried IP address** to each "
            "configured provider. Private, loopback, link-local, multicast, reserved and "
            "documentation addresses are never sent. Nothing is looked up automatically per "
            "event. Respect each provider's terms, especially free-tier limits."
        )

    cache_col, lookup_col = st.columns(2, gap="medium", border=True)
    with cache_col:
        st.subheader("Reputation cache", anchor=False)
        stats = rep.cache_stats()
        c1, c2, c3 = st.columns(3)
        c1.metric("Cached results", sum(v["total"] for v in stats.values()), border=True)
        c2.metric("Expired", sum(v["expired"] for v in stats.values()), border=True)
        c3.metric("TTL (hours)", s.reputation_cache_ttl_hours, border=True)
        if stats:
            st.dataframe(
                [{"provider": k, **v} for k, v in stats.items()],
                width="stretch",
                hide_index=True,
            )
        bar = st.container(horizontal=True, gap="small")
        purge = bar.button("Purge expired entries", icon=":material/auto_delete:")
        clear = bar.button("Clear cache", icon=":material/delete_sweep:")
        if purge:
            st.success(f"Removed {rep.purge_expired()} expired entr(ies).")
        if clear:
            st.success(f"Removed {rep.clear_cache()} entr(ies).")
        st.caption("The cache holds parsed summaries only: no raw responses and no API keys.")
    with lookup_col:
        st.subheader("Look up an IP", anchor=False)
        with st.form("ip-lookup", border=False):
            value = st.text_input("IP address", max_chars=64, placeholder="e.g. 203.0.113.80")
            refresh = st.checkbox("Bypass cache", value=False)
            submitted = st.form_submit_button("Look up", icon=":material/search:", type="primary")
        if submitted and value.strip():
            st.session_state["settings_lookup"] = rep.lookup_ip(value, force_refresh=refresh)
        report = st.session_state.get("settings_lookup")
        if report is not None:
            render_report(report)
