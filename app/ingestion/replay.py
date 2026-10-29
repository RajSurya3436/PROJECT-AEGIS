"""Timed replay of the bundled demo dataset through the shared ingestion service.

``ReplayEngine`` is synchronous and deterministic: each ``step`` ingests one record (so rules fire
as the data "arrives") and says how long to wait before the next. ``ReplayRunner`` drives an
engine on a background thread with pause / resume / stop / restart. Restarting is duplicate-safe
because event IDs are stable: a second pass inserts nothing and creates no new alerts.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from app.config import DEMO_DATA_DIR
from app.domain.enums import EventType, InputFormat, SourceType
from app.domain.errors import NormalizationError, SocCopilotError
from app.ingestion.demo import load_manifest
from app.ingestion.normalizer import flatten, map_fields, parse_timestamp
from app.ingestion.parsers import ParsedItem, RawRecord, decode_bytes, parse_text
from app.ingestion.service import IngestionService

logger = logging.getLogger(__name__)

# Speed multipliers offered in the UI; ``None`` means as fast as possible.
SPEEDS: dict[str, float | None] = {
    "1x (real time)": 1.0,
    "10x": 10.0,
    "60x": 60.0,
    "600x": 600.0,
    "Maximum": None,
}
DEFAULT_MAX_GAP_SECONDS = 300
_EARLIEST = datetime.min.replace(tzinfo=UTC)


class ReplayStateError(SocCopilotError):
    """A replay control was used in a state where it does not apply."""


class ReplayState(StrEnum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"
    COMPLETED = "completed"
    ERROR = "error"


@dataclass(frozen=True)
class ReplaySource:
    source_id: str
    name: str
    default_event_type: EventType


@dataclass(frozen=True)
class PlannedRecord:
    event_time: datetime | None  # None: unparseable, replayed first so it is quarantined early
    source: ReplaySource
    item: ParsedItem


@dataclass(frozen=True)
class ReplayProgress:
    state: ReplayState
    position: int
    total: int
    speed: float | None
    inserted: int
    duplicates: int
    quarantined: int
    last_event_time: datetime | None
    error: str | None = None

    @property
    def fraction(self) -> float:
        return self.position / self.total if self.total else 0.0

    @property
    def active(self) -> bool:
        return self.state in (ReplayState.RUNNING, ReplayState.PAUSED)


def _record_time(item: ParsedItem) -> datetime | None:
    if not isinstance(item, RawRecord):
        return None
    mapped, _, _ = map_fields(flatten(item.data))
    try:
        return parse_timestamp(mapped.get("timestamp"))[0]
    except NormalizationError:
        return None


def build_plan(demo_dir: Path = DEMO_DATA_DIR, snippet_chars: int = 500) -> list[PlannedRecord]:
    """Every demo record from every file, merged into event-time order. Ties keep manifest and
    file order, so the plan is identical on every run."""
    keyed: list[tuple[datetime, int, int, PlannedRecord]] = []
    for order, entry in enumerate(load_manifest(demo_dir)["files"]):
        source = ReplaySource(
            entry["source_id"], entry["name"], EventType(entry["default_event_type"])
        )
        text = decode_bytes((demo_dir / entry["path"]).read_bytes())
        for seq, item in enumerate(
            parse_text(text, InputFormat(entry["format"]), source.source_id, snippet_chars)
        ):
            when = _record_time(item)
            keyed.append((when or _EARLIEST, order, seq, PlannedRecord(when, source, item)))
    keyed.sort(key=lambda k: k[:3])
    return [k[3] for k in keyed]


class ReplayEngine:
    def __init__(
        self,
        service: IngestionService,
        plan: list[PlannedRecord],
        *,
        speed: float | None = 60.0,
        max_gap_seconds: int = DEFAULT_MAX_GAP_SECONDS,
        close: Callable[[], None] | None = None,
    ) -> None:
        self.service = service
        self.plan = plan
        self.speed = speed
        self.max_gap_seconds = max_gap_seconds
        self.position = 0
        self.inserted = 0
        self.duplicates = 0
        self.quarantined = 0
        self.errors: list[str] = []
        self.last_event_time: datetime | None = None
        self._close = close

    @property
    def total(self) -> int:
        return len(self.plan)

    @property
    def done(self) -> bool:
        return self.position >= len(self.plan)

    def step(self) -> float:
        """Ingest the next record. Returns the wall-clock seconds to wait before the following
        one: event-time gap (capped at ``max_gap_seconds`` so idle hours are skipped) / speed."""
        record = self.plan[self.position]
        result = self.service.ingest_items(
            [record.item],
            source_id=record.source.source_id,
            source_type=SourceType.DEMO_REPLAY,
            source_name=record.source.name,
            default_event_type=record.source.default_event_type,
        )
        self.position += 1
        self.inserted += result.inserted
        self.duplicates += result.duplicates
        self.quarantined += result.quarantined
        self.errors.extend(e for e in result.hook_errors if e not in self.errors)
        if record.event_time:
            self.last_event_time = record.event_time
        return self._delay_after(record)

    def run_all(self) -> None:
        """Ingest everything that is left without waiting."""
        while not self.done:
            self.step()

    def close(self) -> None:
        if self._close:
            self._close()
            self._close = None

    def _delay_after(self, record: PlannedRecord) -> float:
        if self.done or self.speed is None or record.event_time is None:
            return 0.0
        following = self.plan[self.position].event_time
        if following is None:
            return 0.0
        gap = max((following - record.event_time).total_seconds(), 0.0)
        return min(gap, self.max_gap_seconds) / self.speed


class ReplayRunner:
    """Runs a ``ReplayEngine`` on a background thread. The factory builds a fresh engine (with
    its own database connection) for every start, which is also how restart works."""

    def __init__(self, engine_factory: Callable[[], ReplayEngine]) -> None:
        self._factory = engine_factory
        self._lock = threading.RLock()
        self._engine: ReplayEngine | None = None
        self._thread: threading.Thread | None = None
        self._state = ReplayState.IDLE
        self._error: str | None = None
        self._gate = threading.Event()  # set while the replay may proceed
        self._stop = threading.Event()

    def start(
        self,
        *,
        speed: float | None = 60.0,
        max_gap_seconds: int = DEFAULT_MAX_GAP_SECONDS,
        paused: bool = False,
    ) -> None:
        """Begin from the first record. Needs the previous run to be finished or stopped."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                raise ReplayStateError("a replay is already running; stop it first")
            engine = self._factory()
            engine.speed = speed
            engine.max_gap_seconds = max_gap_seconds
            self._engine = engine
            self._error = None
            self._stop.clear()
            if paused:
                self._gate.clear()
                self._state = ReplayState.PAUSED
            else:
                self._gate.set()
                self._state = ReplayState.RUNNING
            self._thread = threading.Thread(
                target=self._loop, args=(engine,), name="replay", daemon=True
            )
            self._thread.start()

    def restart(
        self, *, speed: float | None = 60.0, max_gap_seconds: int = DEFAULT_MAX_GAP_SECONDS
    ) -> None:
        self.stop()
        self.start(speed=speed, max_gap_seconds=max_gap_seconds)

    def pause(self) -> None:
        with self._lock:
            if self._state is not ReplayState.RUNNING:
                raise ReplayStateError("replay is not running")
            self._gate.clear()
            self._state = ReplayState.PAUSED

    def resume(self) -> None:
        with self._lock:
            if self._state is not ReplayState.PAUSED:
                raise ReplayStateError("replay is not paused")
            self._state = ReplayState.RUNNING
            self._gate.set()

    def stop(self) -> None:
        """Stop and wait for the worker to finish its current record. Safe when idle."""
        with self._lock:
            thread = self._thread
            if thread is None or not thread.is_alive():
                return
            self._stop.set()
            self._gate.set()
        thread.join(timeout=10)

    def set_speed(self, speed: float | None) -> None:
        with self._lock:
            if self._engine is not None:
                self._engine.speed = speed

    def progress(self) -> ReplayProgress:
        with self._lock:
            engine, state, error = self._engine, self._state, self._error
        if engine is None:
            return ReplayProgress(ReplayState.IDLE, 0, 0, None, 0, 0, 0, None)
        return ReplayProgress(
            state=state,
            position=engine.position,
            total=engine.total,
            speed=engine.speed,
            inserted=engine.inserted,
            duplicates=engine.duplicates,
            quarantined=engine.quarantined,
            last_event_time=engine.last_event_time,
            error=error or (engine.errors[0] if engine.errors else None),
        )

    def _loop(self, engine: ReplayEngine) -> None:
        final = ReplayState.COMPLETED
        error: str | None = None
        try:
            while not engine.done:
                self._gate.wait()
                if self._stop.is_set():
                    final = ReplayState.STOPPED
                    break
                delay = engine.step()
                if delay > 0 and self._stop.wait(delay):
                    final = ReplayState.STOPPED
                    break
        except Exception as exc:
            logger.exception("replay failed")
            final, error = ReplayState.ERROR, f"{type(exc).__name__}: {exc}"
        finally:
            engine.close()
            with self._lock:
                if self._engine is engine:
                    self._state, self._error = final, error
