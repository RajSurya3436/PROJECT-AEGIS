from __future__ import annotations

from streamlit.testing.v1 import AppTest

from app.context import build_context
from app.domain.enums import AlertStatus
from app.ingestion.demo import ingest_demo
from app.ingestion.iocs import load_demo_iocs
from app.ui import alerts, dashboard, events, investigations, rules, settings, sources

PAGES = (
    dashboard.render,
    events.render,
    sources.render,
    alerts.render,
    rules.render,
    settings.render,
    investigations.render,
)


def _page(render, ctx):
    render(ctx)


def _run(render, ctx):
    at = AppTest.from_function(_page, kwargs={"render": render, "ctx": ctx})
    return at.run(timeout=30)


def test_pages_render_empty_without_exceptions(ctx):
    for render in PAGES:
        at = _run(render, ctx)
        assert not at.exception, (render, at.exception)


def test_pages_render_with_demo_data(ctx):
    load_demo_iocs(ctx.iocs)
    ingest_demo(ctx.ingestion)
    for render in PAGES:
        at = _run(render, ctx)
        assert not at.exception, (render, at.exception)
    at = _run(dashboard.render, ctx)
    assert any("136" in m.value for m in at.metric)
    assert any(m.label == "Alerts" and m.value == "5" for m in at.metric)


def test_alert_queue_shows_detail_and_changes_status(ctx):
    load_demo_iocs(ctx.iocs)
    ingest_demo(ctx.ingestion)
    at = _run(alerts.render, ctx)
    assert any("Why it fired" in m.value for m in at.markdown)
    ack = next(b for b in at.button if b.label == "Acknowledge")
    ack.click().run()
    assert not at.exception
    assert sum(a.status is AlertStatus.ACKNOWLEDGED for a in ctx.alerts.list()) == 1


def test_alert_queue_filters(ctx):
    load_demo_iocs(ctx.iocs)
    ingest_demo(ctx.ingestion)
    at = _run(alerts.render, ctx)
    at.selectbox[1].select("high").run()
    assert not at.exception
    assert any("3 alert(s)" in m.value for m in at.markdown)


def test_rules_page_saves_settings_and_reruns_detection(ctx):
    ingest_demo(ctx.ingestion)
    at = _run(rules.render, ctx)
    assert at.expander
    next(b for b in at.button if b.label == "Re-run detection").click().run()
    assert not at.exception and any("created" in s.value for s in at.success)


def test_sources_page_with_file_database_shows_replay_controls(tmp_path, settings):
    ctx = build_context(settings, str(tmp_path / "ui.db"))
    at = _run(sources.render, ctx)
    assert not at.exception
    labels = {b.label for b in at.button}
    assert {"Start", "Pause", "Resume", "Stop", "Restart"} <= labels
    next(b for b in at.button if b.label == "Load demo dataset").click().run()
    assert not at.exception and ctx.alerts.count() == 5


def test_settings_page_toggle_and_lookup(ctx):
    load_demo_iocs(ctx.iocs)
    at = _run(settings.render, ctx)
    assert any("No provider keys set" in i.value for i in at.info)
    assert at.toggle[0].value is False
    at.toggle[0].set_value(True).run()
    assert not at.exception and ctx.reputation.external_enabled is True
    at.text_input[0].input("203.0.113.80")
    next(b for b in at.button if b.label == "Look up").click().run()
    assert not at.exception
    assert any("local IOC" in w.value for w in at.warning)
    next(b for b in at.button if b.label == "Clear cache").click().run()
    assert not at.exception


def test_alert_detail_checks_reputation_on_request(ctx):
    load_demo_iocs(ctx.iocs)
    ingest_demo(ctx.ingestion)
    at = _run(alerts.render, ctx)
    assert not at.warning  # nothing is looked up until the button is pressed
    next(b for b in at.button if b.label == "Check reputation").click().run()
    assert not at.exception
    assert any("IP reputation" in m.value for m in at.markdown)


def test_investigate_button_opens_investigation_and_workspace_renders(ctx):
    load_demo_iocs(ctx.iocs)
    ingest_demo(ctx.ingestion)
    at = _run(alerts.render, ctx)
    next(b for b in at.button if b.label == "Investigate").click().run()
    assert not at.exception
    assert any("is ready" in s.value for s in at.success)
    (inv,) = ctx.investigations.repo.list()

    at = _run(investigations.render, ctx)
    assert not at.exception
    assert any(m.label == "Events in scope" and int(m.value) > 0 for m in at.metric)
    assert {"Download Markdown", "Download JSON"} <= {b.label for b in at.get("download_button")}

    at.text_area[0].input("Repeated failures came from an IOC-listed address.")
    next(b for b in at.button if b.label == "Add evidence").click().run()
    assert not at.exception
    assert any(
        e.source_type.value == "analyst" for e in ctx.investigations.evidence(inv.investigation_id)
    )

    next(b for b in at.button if b.label == "Add events to scope").click().run()
    assert not at.exception
    next(b for b in at.button if b.label == "Check reputation and record").click().run()
    assert not at.exception


def test_verdict_form_shows_validation_error(ctx):
    load_demo_iocs(ctx.iocs)
    ingest_demo(ctx.ingestion)
    ctx.investigations.start_from_alert(ctx.alerts.list()[0].alert_id)
    at = _run(investigations.render, ctx)
    next(b for b in at.button if b.label == "Close investigation").click().run()
    assert not at.exception
    assert any("explain" in e.value for e in at.error)
