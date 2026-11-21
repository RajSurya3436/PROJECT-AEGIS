from __future__ import annotations

import streamlit as st

from app.context import AppContext
from app.detection.registry import CATEGORIES
from app.domain.enums import ALLOWED_TRANSITIONS, AlertStatus, Severity
from app.domain.errors import SocCopilotError
from app.domain.models import Alert
from app.ui import theme
from app.ui.reputation import render_report

ALL = "all"
SELECTED = "alert_id"
STATUS_LABELS = {
    AlertStatus.ACKNOWLEDGED: "Acknowledge",
    AlertStatus.INVESTIGATING: "Mark investigating",
    AlertStatus.RESOLVED: "Resolve",
    AlertStatus.FALSE_POSITIVE: "False positive",
    AlertStatus.NEW: "Reopen",
}
STATUS_ICONS = {
    AlertStatus.ACKNOWLEDGED: ":material/visibility:",
    AlertStatus.INVESTIGATING: ":material/manage_search:",
    AlertStatus.RESOLVED: ":material/task_alt:",
    AlertStatus.FALSE_POSITIVE: ":material/block:",
    AlertStatus.NEW: ":material/undo:",
}


def _summary_rows(alerts: list[Alert], ctx: AppContext) -> list[dict]:
    rows = []
    for a in alerts:
        rule = ctx.detection.rules.get(a.rule_id)
        rows.append(
            {
                "severity": theme.sev_label(a.severity),
                "status": a.status.value.replace("_", " "),
                "title": a.title,
                "tactic": CATEGORIES.get(rule.category, "Other") if rule else "",
                "rule": a.rule_id,
                "events": a.event_count,
                "first seen (UTC)": a.first_seen.strftime("%Y-%m-%d %H:%M"),
            }
        )
    return rows


def render(ctx: AppContext) -> None:
    theme.page_header(
        "Alert queue",
        "Alerts come from deterministic rules over stored events; no model is involved. "
        "Pick a row to see why it fired, triage it, or open an investigation.",
        icon="🚨",
        eyebrow="Monitor",
    )
    if ctx.alerts.count() == 0:
        theme.empty_state(
            "No alerts yet. Load the demo data or start a replay from Data sources.",
            icon=":material/notifications_off:",
        )
        return

    theme.severity_strip(ctx.alerts.count_by("severity"))
    st.space("small")

    with st.container(border=True):
        c1, c2, c3, c4 = st.columns([1, 1, 1.6, 1.6])
        status = c1.selectbox("Status", [ALL, *[s.value for s in AlertStatus]])
        severity = c2.selectbox("Severity", [ALL, *[s.value for s in Severity]])
        rule_id = c3.selectbox("Rule", [ALL, *sorted(ctx.detection.rules)])
        query = c4.text_input(
            "Search titles", placeholder="user, host, IP…", key="alert-search"
        ).strip()
    alerts = ctx.alerts.list(
        status=None if status == ALL else AlertStatus(status),
        severity=None if severity == ALL else Severity(severity),
        rule_id=None if rule_id == ALL else rule_id,
    )
    if query:
        needle = query.lower()
        alerts = [a for a in alerts if needle in a.title.lower() or needle in a.rule_id]
    st.markdown(f"**{len(alerts)} alert(s)**, highest severity first")
    if not alerts:
        return

    selection = st.dataframe(
        _summary_rows(alerts, ctx),
        width="stretch",
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row",
        key="alert-table",
        height=min(38 + 35 * len(alerts), 420),
        column_config={
            "severity": st.column_config.TextColumn(width=95),
            "status": st.column_config.TextColumn(width=110),
            "title": st.column_config.TextColumn(width="large"),
            "events": st.column_config.NumberColumn(width="small"),
        },
    )
    rows = getattr(getattr(selection, "selection", None), "rows", None) or []
    by_id = {a.alert_id: a for a in alerts}
    if rows and rows[0] < len(alerts):
        chosen = alerts[rows[0]]
    else:
        chosen = by_id.get(st.session_state.get(SELECTED, ""), alerts[0])
    st.session_state[SELECTED] = chosen.alert_id
    _render_detail(ctx, chosen)


def _render_detail(ctx: AppContext, alert: Alert) -> None:
    rule = ctx.detection.rules.get(alert.rule_id)
    # Bordered columns stretch to the same height, so the two cards line up.
    main, side = st.columns([2.3, 1], gap="medium", border=True)

    with main:
        with st.container(horizontal=True, gap="small"):
            theme.severity_badge(alert.severity)
            theme.status_badge(alert.status)
            if rule:
                st.badge(CATEGORIES.get(rule.category, "Other"), color="violet")
            st.badge(f"{alert.event_count} event(s)", icon=":material/list:", color="gray")
        with st.container(key=f"title-{alert.alert_id}"):
            st.text(alert.title)
        st.markdown(
            f"**Rule** `{alert.rule_id}` v{alert.rule_version}"
            + (f" — {rule.title}" if rule else "")
        )
        if rule and rule.mitre:
            st.markdown("**MITRE ATT&CK** " + theme.mitre_markdown(rule.mitre))
        if rule:
            st.caption(rule.description)

        st.markdown("**Why it fired**")
        with st.container(key=f"explain-{alert.alert_id}"):
            st.text(alert.explanation)
        # The dedup key holds log values, so it is not put into Markdown.
        st.caption(
            f"First seen {alert.first_seen:%Y-%m-%d %H:%M:%S} · last seen "
            f"{alert.last_seen:%Y-%m-%d %H:%M:%S} UTC · alert {alert.alert_id}"
        )

    links = ctx.alerts.events_for(alert.alert_id)
    events = {e.event_id: e for e in ctx.events.get_many([link.event_id for link in links])}

    with side:
        theme.section("Triage")
        for target in sorted(ALLOWED_TRANSITIONS[alert.status]):
            if st.button(
                STATUS_LABELS[target],
                key=f"{alert.alert_id}-{target.value}",
                icon=STATUS_ICONS[target],
                width="stretch",
            ):
                try:
                    ctx.detection.transition(alert.alert_id, target)
                except SocCopilotError as exc:
                    st.error(str(exc))
                else:
                    st.rerun()
        if st.button(
            "Investigate",
            key=f"{alert.alert_id}-investigate",
            help="Open (or reuse) an investigation and collect related events and evidence.",
            type="primary",
            icon=":material/biotech:",
            width="stretch",
        ):
            try:
                investigation = ctx.investigations.start_from_alert(alert.alert_id)
            except SocCopilotError as exc:
                st.error(str(exc))
            else:
                st.session_state["investigation_id"] = investigation.investigation_id
                st.success(
                    f"Investigation {investigation.investigation_id} is ready. "
                    "Open **Investigations** to continue."
                )

    ips = sorted({ip for e in events.values() for ip in (e.src_ip, e.dst_ip) if ip})
    if ips:
        with side:
            st.divider()
            _render_reputation(ctx, alert, ips)

    with st.container(border=True):
        theme.section(f"Matched events · {len(links)}")
        rows = []
        for link in links:
            event = events.get(link.event_id)
            if event is None:
                continue
            rows.append(
                {
                    "time (UTC)": event.event_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "type": event.event_type.value,
                    "user": event.user or "",
                    "host": event.host or "",
                    "src_ip": event.src_ip or "",
                    "dst_ip": event.dst_ip or "",
                    "outcome": event.outcome.value,
                    "command / message": event.command_line or event.message or "",
                    "why matched": link.reason,
                    "event_id": link.event_id,
                }
            )
        st.dataframe(rows, width="stretch", hide_index=True, height=min(38 + 35 * len(rows), 460))


def _render_reputation(ctx: AppContext, alert: Alert, ips: list[str]) -> None:
    st.markdown("**IP reputation**")
    st.caption(
        "Local IOC list, plus each configured provider if allowed in Settings. Runs only when "
        "you press the button."
    )
    ip = st.selectbox("IP from matched events", ips, key=f"{alert.alert_id}-rep-ip")
    state_key = f"rep-{alert.alert_id}-{ip}"
    if st.button(
        "Check reputation",
        key=f"{alert.alert_id}-rep-check",
        icon=":material/travel_explore:",
        width="stretch",
    ):
        st.session_state[state_key] = ctx.reputation.lookup_ip(ip)
    report = st.session_state.get(state_key)
    if report is not None:
        render_report(report)
