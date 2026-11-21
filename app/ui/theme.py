"""Shared look and feel: colors, CSS, page headers, badges and small chart helpers.

Safety rule kept from the original pages: values that come from logs or models (titles,
explanations, user names, command lines) are never passed to Markdown or HTML here. Only fixed
strings and enum values are styled; untrusted text goes through ``st.text``/dataframes.
"""

from __future__ import annotations

import html
from collections.abc import Iterable, Mapping

import altair as alt
import streamlit as st

from app.domain.enums import AlertStatus, Severity

# --- palette --------------------------------------------------------------------------------

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
SEVERITY_HEX = {
    Severity.CRITICAL: "#f43f5e",
    Severity.HIGH: "#fb923c",
    Severity.MEDIUM: "#facc15",
    Severity.LOW: "#38bdf8",
}
# st.badge colours
SEVERITY_BADGE = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "orange",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
}
SEVERITY_DOT = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
}
SEVERITY_ICON = {
    Severity.CRITICAL: ":material/crisis_alert:",
    Severity.HIGH: ":material/priority_high:",
    Severity.MEDIUM: ":material/warning:",
    Severity.LOW: ":material/info:",
}
STATUS_BADGE = {
    AlertStatus.NEW: ("blue", ":material/fiber_new:"),
    AlertStatus.ACKNOWLEDGED: ("violet", ":material/visibility:"),
    AlertStatus.INVESTIGATING: ("orange", ":material/manage_search:"),
    AlertStatus.RESOLVED: ("green", ":material/task_alt:"),
    AlertStatus.FALSE_POSITIVE: ("gray", ":material/block:"),
}
EVENT_TYPE_HEX = {
    "auth": "#818cf8",
    "process": "#34d399",
    "network": "#38bdf8",
    "other": "#94a3b8",
}

_CSS = """
<style>
/* layout: clear the fixed top bar so page headers are never hidden under it */
.block-container {padding-top: 4rem; padding-bottom: 3rem; max-width: 1500px;}
[data-testid="stSidebarHeader"] {padding-bottom: 0.25rem;}
[data-testid="stSidebarContent"] {overflow-x: hidden;}
[data-testid="stSidebarUserContent"] {padding-top: 0.5rem;}

/* one heading scale across pages: st.subheader is a card title, not a page title */
[data-testid="stMain"] h3 {font-size: 1.12rem; font-weight: 650; padding: 0.1rem 0 0.4rem 0;}
[data-testid="stMain"] h2 {font-size: 1.3rem; font-weight: 650;}

/* sidebar stat tiles */
.soc-tiles {display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; margin: 0.2rem 0 0.4rem;}
.soc-tile {border: 1px solid rgba(148,163,184,0.22); border-radius: 0.7rem;
  padding: 0.55rem 0.7rem; background: rgba(148,163,184,0.05); min-width: 0;}
.soc-tile .n {font-size: 1.5rem; font-weight: 700; line-height: 1.15;}
.soc-tile .l {font-size: 0.74rem; opacity: 0.7; white-space: nowrap; overflow: hidden;
  text-overflow: ellipsis;}
.soc-tile.hot .n {color: #fb923c;}

/* page header */
.soc-header {display: flex; align-items: center; gap: 0.9rem; margin: 0 0 0.35rem 0;}
.soc-header .soc-icon {
  width: 2.6rem; height: 2.6rem; border-radius: 0.75rem; display: grid; place-items: center;
  background: linear-gradient(135deg, rgba(79,140,255,0.28), rgba(56,189,248,0.10));
  border: 1px solid rgba(79,140,255,0.35); font-size: 1.35rem;
}
.soc-header h1 {font-size: 1.65rem; line-height: 1.2; margin: 0; padding: 0; font-weight: 700;}
.soc-header .soc-eyebrow {
  font-size: 0.72rem; letter-spacing: 0.12em; text-transform: uppercase; opacity: 0.6;
  margin-bottom: 0.1rem;
}
.soc-sub {opacity: 0.72; margin: 0 0 1.1rem 0; font-size: 0.93rem; max-width: 70rem;}

/* section titles */
.soc-section {
  font-size: 0.78rem; letter-spacing: 0.1em; text-transform: uppercase; opacity: 0.65;
  font-weight: 600; margin: 0.4rem 0 0.35rem 0;
}

/* metric cards */
[data-testid="stMetric"] {
  background: var(--soc-card, rgba(255,255,255,0.025));
  border-radius: 0.8rem;
}
[data-testid="stMetricLabel"] p {font-size: 0.8rem; opacity: 0.75;}
[data-testid="stMetricValue"] {font-weight: 700;}

/* bordered containers read as cards */
[data-testid="stVerticalBlockBorderWrapper"] {border-radius: 0.85rem;}

/* untrusted titles shown with st.text inside keyed containers */
[class*="st-key-title-"] [data-testid="stText"] {
  font-size: 1.2rem; font-weight: 650; line-height: 1.35; white-space: pre-wrap;
}
[class*="st-key-explain-"] [data-testid="stText"] {
  white-space: pre-wrap; font-size: 0.92rem; line-height: 1.5;
}

/* tabs */
.stTabs [data-baseweb="tab-list"] {gap: 0.25rem;}
.stTabs [data-baseweb="tab"] {padding: 0.45rem 0.9rem; border-radius: 0.5rem 0.5rem 0 0;}

/* status pill used in the sidebar and integration cards */
.soc-pill {display: inline-flex; align-items: center; gap: 0.45rem; font-size: 0.84rem;
  padding: 0.18rem 0.6rem; border-radius: 999px; border: 1px solid rgba(148,163,184,0.25);
  background: rgba(148,163,184,0.08); margin: 0.12rem 0;}
.soc-dot {width: 0.55rem; height: 0.55rem; border-radius: 50%; display: inline-block;}
.soc-dot.ok {background: #34d399; box-shadow: 0 0 6px #34d399;}
.soc-dot.warn {background: #facc15; box-shadow: 0 0 6px #facc15;}
.soc-dot.off {background: #f43f5e; box-shadow: 0 0 6px #f43f5e;}
.soc-dot.idle {background: #94a3b8;}

/* severity strip on the alert queue */
.soc-sev {border-left: 4px solid var(--c); padding: 0.35rem 0.7rem; border-radius: 0.5rem;
  background: rgba(148,163,184,0.06);}
.soc-sev .n {font-size: 1.45rem; font-weight: 700; line-height: 1.1;}
.soc-sev .l {font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.08em; opacity: 0.7;}
</style>
"""


def inject_css() -> None:
    st.html(_CSS)


# --- building blocks ------------------------------------------------------------------------


def page_header(title: str, subtitle: str = "", icon: str = "🛡️", eyebrow: str = "") -> None:
    """Page title block. ``title``, ``subtitle`` and ``eyebrow`` must be fixed strings."""
    eyebrow_html = f'<div class="soc-eyebrow">{html.escape(eyebrow)}</div>' if eyebrow else ""
    st.html(
        f'<div class="soc-header"><div class="soc-icon">{html.escape(icon)}</div>'
        f"<div>{eyebrow_html}<h1>{html.escape(title)}</h1></div></div>"
        + (f'<p class="soc-sub">{html.escape(subtitle)}</p>' if subtitle else "")
    )


def section(label: str) -> None:
    st.html(f'<div class="soc-section">{html.escape(label)}</div>')


def pill(label: str, state: str) -> str:
    """HTML for a status pill. ``state``: ok, warn, off or idle. ``label`` must be fixed text."""
    return (
        f'<span class="soc-pill"><span class="soc-dot {state}"></span>{html.escape(label)}</span>'
    )


def pills(items: Iterable[tuple[str, str]]) -> None:
    st.html("<div>" + " ".join(pill(label, state) for label, state in items) + "</div>")


def tiles(items: Iterable[tuple[str, int, bool]]) -> None:
    """Compact number tiles (label, count, highlight). Labels must be fixed text."""
    st.html(
        '<div class="soc-tiles">'
        + "".join(
            f'<div class="soc-tile{" hot" if hot else ""}"><div class="n">{int(n)}</div>'
            f'<div class="l">{html.escape(label)}</div></div>'
            for label, n, hot in items
        )
        + "</div>"
    )


def severity_badge(severity: Severity) -> None:
    st.badge(severity.value.upper(), icon=SEVERITY_ICON[severity], color=SEVERITY_BADGE[severity])


def status_badge(status: AlertStatus) -> None:
    color, icon = STATUS_BADGE[status]
    st.badge(status.value.replace("_", " "), icon=icon, color=color)


def sev_label(severity: Severity) -> str:
    """Severity for dataframe cells."""
    return f"{SEVERITY_DOT[severity]} {severity.value}"


def mitre_url(technique: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique.replace(".", "/") + "/"


def mitre_markdown(techniques: Iterable[str]) -> str:
    """Markdown links for MITRE IDs (fixed rule metadata, never log values)."""
    return " ".join(f"[`{t}`]({mitre_url(t)})" for t in techniques)


def severity_strip(counts: Mapping[str, int]) -> None:
    cols = st.columns(len(SEVERITY_ORDER))
    for col, sev in zip(cols, SEVERITY_ORDER, strict=True):
        col.html(
            f'<div class="soc-sev" style="--c:{SEVERITY_HEX[sev]}">'
            f'<div class="n">{int(counts.get(sev.value, 0))}</div>'
            f'<div class="l">{sev.value}</div></div>'
        )


def empty_state(message: str, icon: str = ":material/inbox:") -> None:
    st.info(message, icon=icon)


# --- charts ---------------------------------------------------------------------------------


def severity_donut(counts: Mapping[str, int]) -> alt.Chart:
    data = [
        {"severity": s.value, "alerts": counts.get(s.value, 0), "order": i}
        for i, s in enumerate(SEVERITY_ORDER)
        if counts.get(s.value, 0)
    ]
    return (
        alt.Chart(alt.Data(values=data))
        .mark_arc(innerRadius=58, outerRadius=92, cornerRadius=4, padAngle=0.02)
        .encode(
            theta=alt.Theta("alerts:Q", stack=True),
            order=alt.Order("order:Q"),
            color=alt.Color(
                "severity:N",
                scale=alt.Scale(
                    domain=[s.value for s in SEVERITY_ORDER],
                    range=[SEVERITY_HEX[s] for s in SEVERITY_ORDER],
                ),
                legend=alt.Legend(orient="right", title=None),
            ),
            tooltip=["severity:N", "alerts:Q"],
        )
        .properties(height=220)
    )


def activity_chart(rows: list[tuple[str, str, int]]) -> alt.Chart:
    data = [{"hour": f"{h}:00:00Z", "type": t, "events": n} for h, t, n in rows]
    types = sorted({t for _, t, _ in rows})
    return (
        alt.Chart(alt.Data(values=data))
        .mark_bar(cornerRadiusTopLeft=2, cornerRadiusTopRight=2)
        .encode(
            x=alt.X("hour:T", title=None, axis=alt.Axis(format="%b %d %H:%M", labelAngle=0)),
            y=alt.Y("sum(events):Q", title="events"),
            color=alt.Color(
                "type:N",
                scale=alt.Scale(
                    domain=types, range=[EVENT_TYPE_HEX.get(t, "#94a3b8") for t in types]
                ),
                legend=alt.Legend(orient="top", title=None),
            ),
            tooltip=[
                alt.Tooltip("hour:T", format="%Y-%m-%d %H:00 UTC"),
                "type:N",
                alt.Tooltip("sum(events):Q", title="events"),
            ],
        )
        .properties(height=240)
    )


def bar_chart(counts: Mapping[str, int], label: str, value: str, color: str = "#4f8cff"):
    data = [{label: k, value: v} for k, v in counts.items() if v]
    return (
        alt.Chart(alt.Data(values=data))
        .mark_bar(cornerRadiusTopRight=3, cornerRadiusBottomRight=3, color=color)
        .encode(
            x=alt.X(f"{value}:Q", title=None, axis=alt.Axis(format="d", tickMinStep=1)),
            y=alt.Y(f"{label}:N", sort="-x", title=None, axis=alt.Axis(labelLimit=260)),
            tooltip=[f"{label}:N", f"{value}:Q"],
        )
        .properties(height=max(120, 28 * len(data)))
    )
