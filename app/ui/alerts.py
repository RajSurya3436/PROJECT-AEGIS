from __future__ import annotations

import streamlit as st

from app.context import AppContext
from app.domain.enums import ALLOWED_TRANSITIONS, AlertStatus, Severity
from app.domain.errors import SocCopilotError
from app.domain.models import Alert
from app.ui.reputation import render_report

ALL = "all"
STATUS_LABELS = {
    AlertStatus.ACKNOWLEDGED: "Acknowledge",
    AlertStatus.INVESTIGATING: "Mark investigating",
    AlertStatus.RESOLVED: "Resolve",
    AlertStatus.FALSE_POSITIVE: "False positive",
    AlertStatus.NEW: "Reopen",
}


def _summary_rows(alerts: list[Alert]) -> list[dict]:
    return [
        {
            "severity": a.severity.value,
            "status": a.status.value,
            "title": a.title,
            "rule": f"{a.rule_id} v{a.rule_version}",
            "events": a.event_count,
            "first seen (UTC)": a.first_seen.strftime("%Y-%m-%d %H:%M:%S"),
            "last seen (UTC)": a.last_seen.strftime("%Y-%m-%d %H:%M:%S"),
        }
        for a in alerts
    ]


def render(ctx: AppContext) -> None:
    st.title("Alert queue")
    st.caption(
        "Alerts come from deterministic rules over stored events. No model is involved. "
        "Alert text includes values from the logs, so it is shown as plain text."
    )
    if ctx.alerts.count() == 0:
        st.info("No alerts yet. Load the demo data or start a replay from **Data sources**.")
        return

    c1, c2, c3 = st.columns(3)
    status = c1.selectbox("Status", [ALL, *[s.value for s in AlertStatus]])
    severity = c2.selectbox("Severity", [ALL, *[s.value for s in Severity]])
    rule_id = c3.selectbox("Rule", [ALL, *sorted(ctx.detection.rules)])
    alerts = ctx.alerts.list(
        status=None if status == ALL else AlertStatus(status),
        severity=None if severity == ALL else Severity(severity),
        rule_id=None if rule_id == ALL else rule_id,
    )
    st.write(f"{len(alerts)} alert(s), highest severity first")
    if not alerts:
        return
    st.dataframe(_summary_rows(alerts), use_container_width=True, hide_index=True)

    by_id = {a.alert_id: a for a in alerts}
    chosen = st.selectbox(
        "Open alert",
        list(by_id),
        format_func=lambda i: f"[{by_id[i].severity.value}] {by_id[i].title}",
    )
    _render_detail(ctx, by_id[chosen])


def _render_detail(ctx: AppContext, alert: Alert) -> None:
    st.subheader("Alert detail")
    st.text(alert.title)
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Severity", alert.severity.value)
    m2.metric("Status", alert.status.value)
    m3.metric("Linked events", alert.event_count)
    m4.metric("Rule version", f"v{alert.rule_version}")

    rule = ctx.detection.rules.get(alert.rule_id)
    st.write(f"**Rule:** `{alert.rule_id}`" + (f" — {rule.title}" if rule else ""))
    if rule:
        st.caption(rule.description)
    st.write("**Why it fired**")
    st.text(alert.explanation)
    st.caption(f"Dedup key: {alert.dedup_key}")

    links = ctx.alerts.events_for(alert.alert_id)
    events = {e.event_id: e for e in ctx.events.get_many([link.event_id for link in links])}
    st.write("**Matched events**")
    rows = []
    for link in links:
        event = events.get(link.event_id)
        if event is None:
            continue
        rows.append(
            {
                "time (UTC)": event.event_time.strftime("%Y-%m-%d %H:%M:%S"),
                "type": event.event_type.value,
                "user": event.user,
                "host": event.host,
                "src_ip": event.src_ip,
                "dst_ip": event.dst_ip,
                "outcome": event.outcome.value,
                "command / message": event.command_line or event.message,
                "why matched": link.reason,
                "event_id": link.event_id,
            }
        )
    st.dataframe(rows, use_container_width=True, hide_index=True)

    ips = sorted({ip for e in events.values() for ip in (e.src_ip, e.dst_ip) if ip})
    if ips:
        _render_reputation(ctx, alert, ips)

    st.write("**Actions**")
    targets = sorted(ALLOWED_TRANSITIONS[alert.status])
    cols = st.columns(len(targets) + 1)
    for col, target in zip(cols, targets, strict=False):
        if col.button(STATUS_LABELS[target], key=f"{alert.alert_id}-{target.value}"):
            try:
                ctx.detection.transition(alert.alert_id, target)
            except SocCopilotError as exc:
                st.error(str(exc))
            else:
                st.rerun()
    if cols[-1].button(
        "Investigate",
        key=f"{alert.alert_id}-investigate",
        help="Open (or reuse) an investigation and collect related events and evidence.",
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


def _render_reputation(ctx: AppContext, alert: Alert, ips: list[str]) -> None:
    st.write("**IP reputation**")
    st.caption(
        "Checks the local IOC list and, if allowed on the Settings page, each configured "
        "provider. Runs only when you press the button."
    )
    c1, c2 = st.columns([3, 1])
    ip = c1.selectbox("IP from matched events", ips, key=f"{alert.alert_id}-rep-ip")
    state_key = f"rep-{alert.alert_id}-{ip}"
    if c2.button("Check reputation", key=f"{alert.alert_id}-rep-check"):
        st.session_state[state_key] = ctx.reputation.lookup_ip(ip)
    report = st.session_state.get(state_key)
    if report is not None:
        render_report(report)
