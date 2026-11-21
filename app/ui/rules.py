from __future__ import annotations

import streamlit as st

from app.context import AppContext
from app.detection.registry import CATEGORIES
from app.domain.errors import SocCopilotError
from app.ui import theme

ALL = "All tactics"


def render(ctx: AppContext) -> None:
    theme.page_header(
        "Detection rules",
        "Fixed, versioned rules written in Python: pure functions over stored events, so the "
        "same data always gives the same alerts. Switch rules on or off and tune thresholds; "
        "changes apply to new events, and re-running applies them to stored events.",
        icon="🧬",
        eyebrow="Configure",
    )
    listed = ctx.detection.list_rules()
    alerts_by_rule = ctx.alerts.count_by("rule_id")
    techniques = {t for rule, _ in listed for t in rule.mitre}
    enabled = sum(s.enabled for _, s in listed)

    k = st.columns(4)
    k[0].metric("Rules", len(listed), border=True)
    k[1].metric("Enabled", enabled, border=True)
    k[2].metric("ATT&CK techniques", len(techniques), border=True)
    k[3].metric("Local IOC entries", ctx.iocs.count(), border=True)

    categories = [c for c in CATEGORIES if any(r.category == c for r, _ in listed)]
    with st.container(border=True):
        picked = st.pills(
            "Tactic",
            [ALL, *categories],
            default=ALL,
            format_func=lambda c: c if c == ALL else CATEGORIES[c],
            key="rule-tactic",
        )
        query = st.text_input(
            "Search",
            placeholder="rule ID, title or ATT&CK technique (e.g. T1003)",
            key="rule-search",
        )
    picked = picked or ALL
    needle = query.strip().lower()

    for category in categories:
        if picked not in (ALL, category):
            continue
        rows = [
            (rule, settings)
            for rule, settings in listed
            if rule.category == category
            and (
                not needle
                or needle in rule.rule_id
                or needle in rule.title.lower()
                or any(needle in t.lower() for t in rule.mitre)
            )
        ]
        if not rows:
            continue
        theme.section(f"{CATEGORIES[category]} · {len(rows)}")
        for rule, settings in rows:
            fired = alerts_by_rule.get(rule.rule_id, 0)
            state = ":green[●]" if settings.enabled else ":gray[○]"
            label = (
                f"{state} **{rule.title}**  ·  `{rule.rule_id}` v{settings.version}"
                f"  ·  {theme.SEVERITY_DOT[rule.severity]} {rule.severity.value}"
                + (f"  ·  {fired} alert(s)" if fired else "")
            )
            with st.expander(label):
                left, right = st.columns([1.5, 1], gap="medium")
                with left:
                    st.write(rule.description)
                    if rule.mitre:
                        st.markdown("**MITRE ATT&CK** " + theme.mitre_markdown(rule.mitre))
                    st.caption(
                        f"Default severity {rule.severity.value} · {fired} alert(s) produced so far"
                    )
                with right, st.form(f"rule-{rule.rule_id}", border=False):
                    on = st.toggle("Enabled", value=settings.enabled)
                    config = {
                        key: int(
                            st.number_input(
                                rule.config_help.get(key, key),
                                min_value=1,
                                value=settings.config.get(key, default),
                                step=1,
                                help=f"Setting `{key}`, default {default}",
                            )
                        )
                        for key, default in rule.default_config.items()
                    }
                    if st.form_submit_button("Save", icon=":material/save:", type="primary"):
                        try:
                            ctx.detection.configure(rule.rule_id, enabled=on, config=config)
                        except SocCopilotError as exc:
                            st.error(str(exc))
                        else:
                            st.rerun()

    st.space("small")
    with st.container(border=True):
        theme.section("Re-run on stored events")
        c1, c2 = st.columns([3, 1], vertical_alignment="center")
        c1.write(
            "Apply the current rules and thresholds to every stored event. Existing alerts are "
            "kept and never duplicated."
        )
        if c2.button("Re-run detection", icon=":material/replay:", width="stretch"):
            try:
                outcome = ctx.detection.rescan()
            except RuntimeError as exc:
                st.error(f"Some rules failed: {exc}")
            else:
                st.success(
                    f"{outcome['created']} alert(s) created, {outcome['updated']} extended, "
                    f"{ctx.alerts.count()} in total."
                )
