"""Shared rendering of an IP reputation report (Settings page and alert detail)."""

from __future__ import annotations

import streamlit as st

from app.domain.enums import ReputationStatus
from app.domain.models import IpReputationReport

STATUS_LABELS = {
    ReputationStatus.FRESH: "fresh",
    ReputationStatus.CACHED: "cached",
    ReputationStatus.NOT_CONFIGURED: "not configured",
    ReputationStatus.DISABLED: "external lookups off",
    ReputationStatus.SKIPPED: "skipped",
    ReputationStatus.RATE_LIMITED: "rate limited",
    ReputationStatus.TIMEOUT: "timeout",
    ReputationStatus.PROVIDER_ERROR: "provider error",
}


def _time(value) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S") if value else ""


def render_report(report: IpReputationReport) -> None:
    """Provider strings and IOC descriptions are untrusted, so they go through escaping
    widgets (dataframe, json), never markdown."""
    st.write(f"Scope: **{report.scope.replace('_', '-')}**")
    if report.local_ioc:
        ioc = report.local_ioc
        st.warning("Matches the local IOC list.")
        st.dataframe(
            [
                {
                    "confidence": ioc.confidence,
                    "source": ioc.source,
                    "description": ioc.description,
                    "added": ioc.added,
                }
            ],
            use_container_width=True,
            hide_index=True,
        )
    elif report.valid:
        st.caption("No match in the local IOC list.")
    st.dataframe(
        [
            {
                "provider": r.provider,
                "status": STATUS_LABELS[r.status],
                "signal": r.signal or "",
                "known to provider": "" if r.found is None else ("yes" if r.found else "no"),
                "queried (UTC)": _time(r.queried_at),
                "cache expires (UTC)": _time(r.expires_at),
                "note": r.message,
            }
            for r in report.results
        ],
        use_container_width=True,
        hide_index=True,
    )
    for r in report.results:
        if r.has_data and r.summary:
            with st.expander(f"{r.provider} details"):
                st.json(r.summary)
    st.caption(
        "Signals use fixed thresholds (AbuseIPDB score ≥75 high, ≥25 medium; VirusTotal "
        "≥3 malicious engines high, ≥1 malicious or ≥2 suspicious medium). They are evidence, "
        "not a verdict."
    )
