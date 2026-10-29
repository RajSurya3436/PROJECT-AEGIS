from __future__ import annotations

import streamlit as st

from app.context import AppContext
from app.domain.errors import SocCopilotError


def render(ctx: AppContext) -> None:
    st.title("Detection rules")
    st.caption(
        "Fixed, versioned rules. You can switch them on or off and tune thresholds; "
        "changes apply to events ingested from now on. Use re-run to apply them to stored events."
    )
    st.write(
        f"Local IOC entries loaded: **{ctx.iocs.count()}** (the demo dataset loads its own list)."
    )

    for rule, settings in ctx.detection.list_rules():
        label = f"{rule.rule_id} · v{settings.version} · {'on' if settings.enabled else 'off'}"
        with st.expander(label), st.form(f"rule-{rule.rule_id}"):
            st.write(rule.title)
            st.caption(rule.description)
            enabled = st.checkbox("Enabled", value=settings.enabled)
            config = {
                key: int(
                    st.number_input(
                        f"{key} — {rule.config_help.get(key, '')}",
                        min_value=1,
                        value=settings.config.get(key, default),
                        step=1,
                    )
                )
                for key, default in rule.default_config.items()
            }
            if st.form_submit_button("Save"):
                try:
                    ctx.detection.configure(rule.rule_id, enabled=enabled, config=config)
                except SocCopilotError as exc:
                    st.error(str(exc))
                else:
                    st.rerun()

    st.subheader("Re-run on stored events")
    st.write("Existing alerts are kept and never duplicated.")
    if st.button("Re-run detection"):
        try:
            outcome = ctx.detection.rescan()
        except RuntimeError as exc:
            st.error(f"Some rules failed: {exc}")
        else:
            st.success(
                f"{outcome['created']} alert(s) created, {outcome['updated']} extended, "
                f"{ctx.alerts.count()} in total."
            )
