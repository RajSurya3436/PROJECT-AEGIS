from __future__ import annotations

import time

import pytest

from app.context import build_context
from app.ingestion.demo import load_manifest
from app.ingestion.iocs import load_demo_iocs
from app.ingestion.replay import (
    ReplayEngine,
    ReplayRunner,
    ReplayState,
    ReplayStateError,
    build_plan,
)


def shape(ctx):
    return sorted((a.dedup_key, a.event_count) for a in ctx.alerts.list())


def new_engine(ctx, **kwargs) -> ReplayEngine:
    load_demo_iocs(ctx.iocs)
    return ReplayEngine(ctx.ingestion, build_plan(), speed=None, **kwargs)


def test_plan_is_time_ordered_complete_and_stable():
    plan = build_plan()
    assert len(plan) == sum(f["expected_records"] for f in load_manifest()["files"])
    times = [p.event_time for p in plan if p.event_time]
    assert times == sorted(times)
    assert {p.source.source_id for p in plan} == {"demo-auth", "demo-endpoint", "demo-network"}
    assert [p.item for p in build_plan()] == [p.item for p in plan]


def test_replay_matches_bulk_load_and_inserts_every_event_once(ctx, settings):
    engine = new_engine(ctx)
    engine.run_all()
    assert engine.done
    assert (engine.inserted, engine.duplicates, engine.quarantined) == (136, 0, 0)
    assert ctx.events.count() == 136

    from app.ingestion.demo import ingest_demo

    bulk = build_context(settings, ":memory:")
    load_demo_iocs(bulk.iocs)
    ingest_demo(bulk.ingestion)
    assert shape(ctx) == shape(bulk)
    assert len(shape(ctx)) == 5


def test_alerts_appear_as_events_arrive_and_grow(ctx):
    engine = new_engine(ctx)
    seen = []
    while not engine.done:
        engine.step()
        seen.append(ctx.alerts.count())
    assert seen[0] == 0
    assert seen == sorted(seen)  # alerts are never removed while replaying
    assert seen[-1] == 5 and len(set(seen)) > 3  # they appear gradually, not all at the end
    failures = ctx.alerts.list(rule_id="auth.repeated_failures")[0]
    assert failures.event_count == 12


def test_restart_is_duplicate_safe(ctx):
    first = new_engine(ctx)
    first.run_all()
    before = shape(ctx)
    again = ReplayEngine(ctx.ingestion, build_plan(), speed=None)
    again.run_all()
    assert (again.inserted, again.duplicates) == (0, 136)
    assert ctx.events.count() == 136
    assert shape(ctx) == before


def test_partial_replay_then_restart_ends_in_the_same_state(ctx, settings):
    partial = new_engine(ctx)
    for _ in range(70):
        partial.step()
    assert 0 < ctx.events.count() < 136
    full = ReplayEngine(ctx.ingestion, build_plan(), speed=None)
    full.run_all()
    assert ctx.events.count() == 136
    assert full.duplicates == 70

    clean = build_context(settings, ":memory:")
    new_engine(clean).run_all()
    assert shape(ctx) == shape(clean)


def test_delay_scales_with_speed_and_caps_idle_gaps(ctx):
    plan = build_plan()
    engine = ReplayEngine(ctx.ingestion, plan, speed=10.0, max_gap_seconds=300)
    delays = []
    gaps = []
    for index in range(len(plan) - 1):
        start, end = plan[index].event_time, plan[index + 1].event_time
        assert start and end
        gaps.append((end - start).total_seconds())
        delays.append(engine.step())
    for gap, delay in zip(gaps, delays, strict=True):
        assert delay == pytest.approx(min(max(gap, 0), 300) / 10)
    assert max(gaps) > 300  # the dataset has idle hours that get skipped
    assert max(delays) <= 30
    fast = ReplayEngine(ctx.ingestion, plan, speed=None)
    assert fast.step() == 0.0
    assert engine.step() == 0.0  # the final record has nothing after it


def test_replay_goes_through_the_shared_ingestion_service(ctx):
    engine = new_engine(ctx)
    engine.run_all()
    source = ctx.sources.get("demo-auth")
    assert source.event_count == 65 and source.source_type.value == "demo_replay"
    assert source.last_error is None


# --- runner (thread) -----------------------------------------------------------------------


@pytest.fixture
def file_ctx(tmp_path, settings):
    return build_context(settings, str(tmp_path / "soc.db"))


def wait_for(runner: ReplayRunner, state: ReplayState, timeout: float = 15.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        progress = runner.progress()
        if progress.state is state:
            return progress
        time.sleep(0.02)
    raise AssertionError(f"never reached {state}: {runner.progress()}")


def test_in_memory_database_has_no_runner(ctx):
    assert ctx.replay is None


def test_runner_replays_to_completion(file_ctx):
    runner = file_ctx.replay
    assert runner.progress().state is ReplayState.IDLE
    runner.start(speed=None)
    done = wait_for(runner, ReplayState.COMPLETED)
    assert (done.position, done.total, done.inserted) == (136, 136, 136)
    assert done.fraction == 1.0 and not done.active
    assert file_ctx.events.count() == 136
    assert file_ctx.alerts.count() == 5  # visible from the UI's own connection


def test_runner_pause_resume(file_ctx):
    runner = file_ctx.replay
    runner.start(speed=None, paused=True)
    time.sleep(0.2)
    paused = runner.progress()
    assert paused.state is ReplayState.PAUSED and paused.position == 0
    assert file_ctx.events.count() == 0
    runner.resume()
    wait_for(runner, ReplayState.COMPLETED)
    assert file_ctx.events.count() == 136


def test_runner_pause_mid_run_holds_position(file_ctx):
    runner = file_ctx.replay
    runner.start(speed=1.0, max_gap_seconds=3600)  # real time: waits long between events
    deadline = time.monotonic() + 10
    while runner.progress().position < 1 and time.monotonic() < deadline:
        time.sleep(0.01)
    runner.pause()
    held = runner.progress().position
    time.sleep(0.3)
    assert runner.progress().position == held and runner.progress().state is ReplayState.PAUSED
    runner.stop()
    assert runner.progress().state is ReplayState.STOPPED
    assert runner.progress().position == held


def test_runner_stop_interrupts_a_long_wait_and_restart_is_duplicate_safe(file_ctx):
    runner = file_ctx.replay
    runner.start(speed=1.0, max_gap_seconds=3600)
    deadline = time.monotonic() + 10
    while runner.progress().position < 3 and time.monotonic() < deadline:
        time.sleep(0.01)
    started = time.monotonic()
    runner.stop()
    assert time.monotonic() - started < 5
    stopped = runner.progress()
    assert stopped.state is ReplayState.STOPPED and 0 < stopped.position < 136
    stored = file_ctx.events.count()

    runner.restart(speed=None)
    done = wait_for(runner, ReplayState.COMPLETED)
    assert done.duplicates == stored and done.inserted == 136 - stored
    assert file_ctx.events.count() == 136
    assert file_ctx.alerts.count() == 5

    runner.restart(speed=None)
    again = wait_for(runner, ReplayState.COMPLETED)
    assert (again.inserted, again.duplicates) == (0, 136)
    assert file_ctx.alerts.count() == 5


def test_runner_rejects_invalid_controls(file_ctx):
    runner = file_ctx.replay
    with pytest.raises(ReplayStateError):
        runner.pause()
    with pytest.raises(ReplayStateError):
        runner.resume()
    runner.stop()  # safe when idle
    runner.start(speed=1.0, max_gap_seconds=3600)
    with pytest.raises(ReplayStateError):
        runner.start(speed=None)
    runner.stop()


def test_runner_reports_worker_errors(settings, tmp_path):
    ctx = build_context(settings, str(tmp_path / "e.db"))

    def broken():
        engine = ReplayEngine(ctx.ingestion, build_plan(), speed=None)

        def explode(*args, **kwargs):
            raise RuntimeError("disk on fire")

        engine.service.ingest_items = explode
        return engine

    runner = ReplayRunner(broken)
    runner.start(speed=None)
    failed = wait_for(runner, ReplayState.ERROR)
    assert failed.error and "disk on fire" in failed.error
    runner.start(speed=None)  # can be started again after an error
    wait_for(runner, ReplayState.ERROR)
