from __future__ import annotations

import streamlit as st

from app.context import AppContext
from app.ollama_health import ollama_status
from app.ui.reputation import render_report

OLLAMA_LABELS = {
    "reachable_model_present": "Ready ({model})",
    "reachable_model_missing": "Server up, model `{model}` not installed",
    "unreachable": "Unavailable (detection, search and reputation lookups still work)",
}


def render(ctx: AppContext) -> None:
    st.title("Settings and integrations")
    s = ctx.settings

    st.subheader("Local model")
    status, _ = ollama_status(s.ollama_base_url, s.ollama_model)
    st.write(f"**Ollama:** {OLLAMA_LABELS[status].format(model=s.ollama_model)}")
    st.caption("Needed from Phase 5 (agents). Never pulled automatically.")

    st.subheader("Reputation providers")
    rep = ctx.reputation
    rows = []
    for provider in rep.providers.values():
        rows.append(
            {
                "provider": provider.title,
                "API key": "configured" if provider.configured else "not configured",
                "requests / minute": provider.limiter.per_minute,
                "requests / day": provider.limiter.per_day,
                "timeout (s)": provider.timeout,
                "retries": provider.max_retries,
            }
        )
    st.dataframe(rows, use_container_width=True, hide_index=True)
    if not any(p.configured for p in rep.providers.values()):
        st.info(
            "No provider keys set. Add `ABUSEIPDB_API_KEY` and/or `VIRUSTOTAL_API_KEY` to the "
            "environment or `.env` and restart. The app works fully without them, using the "
            "local IOC list."
        )

    enabled = st.toggle("Allow external reputation lookups", value=rep.external_enabled)
    if enabled != rep.external_enabled:
        rep.set_external_enabled(enabled)
        st.rerun()
    st.caption(
        "When on, a lookup you request sends **only the queried IP address** to each configured "
        "provider. Private, loopback, link-local, multicast, reserved and documentation "
        "addresses are never sent. Nothing is looked up automatically per event. Respect each "
        "provider's terms, especially free-tier limits."
    )

    st.subheader("Reputation cache")
    stats = rep.cache_stats()
    total = sum(v["total"] for v in stats.values())
    expired = sum(v["expired"] for v in stats.values())
    c1, c2, c3 = st.columns(3)
    c1.metric("Cached results", total)
    c2.metric("Expired", expired)
    c3.metric("TTL (hours)", s.reputation_cache_ttl_hours)
    if stats:
        st.dataframe(
            [{"provider": k, **v} for k, v in stats.items()],
            use_container_width=True,
            hide_index=True,
        )
    b1, b2 = st.columns(2)
    if b1.button("Purge expired entries"):
        st.success(f"Removed {rep.purge_expired()} expired entr(ies).")
    if b2.button("Clear cache"):
        st.success(f"Removed {rep.clear_cache()} entr(ies).")
    st.caption("The cache holds parsed summaries only: no raw responses and no API keys.")

    st.subheader("Look up an IP")
    with st.form("ip-lookup"):
        value = st.text_input("IP address", max_chars=64)
        refresh = st.checkbox("Bypass cache", value=False)
        submitted = st.form_submit_button("Look up")
    if submitted and value.strip():
        st.session_state["settings_lookup"] = rep.lookup_ip(value, force_refresh=refresh)
    report = st.session_state.get("settings_lookup")
    if report is not None:
        render_report(report)

    st.subheader("Safe mode")
    st.write(
        "Response actions are **simulation only**. This app never blocks IPs, disables "
        "accounts or changes any external system."
    )
