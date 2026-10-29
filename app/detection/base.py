"""Rule interface and the helpers shared by rules.

Rules are pure functions of stored events plus configuration: given the newly inserted events
they work out which entities are affected, re-read those entities' history from the database
and report findings. Because findings depend on stored data rather than arrival order, replaying
or re-ingesting the same data always produces the same alerts.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar

from app.domain.enums import Severity
from app.domain.models import NormalizedEvent
from app.storage.alerts import Finding, IocRepository, Match
from app.storage.repositories import EventRepository


@dataclass(frozen=True)
class DetectionContext:
    events: EventRepository
    iocs: IocRepository


def fmt_ts(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%SZ")


class Rule(ABC):
    rule_id: ClassVar[str]
    version: ClassVar[int]
    title: ClassVar[str]
    description: ClassVar[str]
    severity: ClassVar[Severity]
    default_config: ClassVar[dict[str, int]]
    config_help: ClassVar[dict[str, str]]

    @abstractmethod
    def evaluate(
        self, new_events: Sequence[NormalizedEvent], ctx: DetectionContext, config: dict[str, int]
    ) -> list[Finding]:
        """Findings for the entities touched by ``new_events``."""

    def setting(self, config: dict[str, int], key: str) -> int:
        return config.get(key, self.default_config[key])

    def finding(
        self,
        *,
        key_parts: Sequence[str],
        title: str,
        explanation: str,
        matched: Sequence[tuple[NormalizedEvent, str]],
        severity: Severity | None = None,
        identity: Sequence[NormalizedEvent] | None = None,
    ) -> Finding:
        """Build a finding. The dedup key is the rule ID, the identifying key parts, and the
        time of the earliest matched event, so each separate burst gets its own alert."""
        times = [event.event_time for event, _ in matched]
        first = min(times)
        return Finding(
            rule_id=self.rule_id,
            rule_version=self.version,
            severity=severity or self.severity,
            title=title,
            explanation=explanation,
            dedup_key="|".join([self.rule_id, *key_parts, first.isoformat()]),
            matches=tuple(Match(event.event_id, reason) for event, reason in matched),
            first_seen=first,
            last_seen=max(times),
            identity_event_ids=tuple(e.event_id for e in identity) if identity else None,
        )


def qualifying_runs(
    events: Sequence[NormalizedEvent],
    window_seconds: int,
    qualifies: Callable[[Sequence[NormalizedEvent]], bool],
) -> list[list[NormalizedEvent]]:
    """Sliding-window grouping over time-ordered ``events``.

    Every window that starts at an event and spans at most ``window_seconds`` (inclusive) is
    tested with ``qualifies``; events in any qualifying window are kept, and kept events that are
    adjacent in the input form one run (one future alert).
    """
    count = len(events)
    kept: set[int] = set()
    end = 0
    for start in range(count):
        end = max(end, start + 1)
        origin = events[start].event_time
        while end < count and (events[end].event_time - origin).total_seconds() <= window_seconds:
            end += 1
        if qualifies(events[start:end]):
            kept.update(range(start, end))
    runs: list[list[NormalizedEvent]] = []
    previous = -2
    for index in sorted(kept):
        # A new run starts at a gap in the kept events, or when neighbouring kept events are
        # further apart than one window (separate bursts with nothing in between).
        if (
            index != previous + 1
            or (events[index].event_time - events[previous].event_time).total_seconds()
            > window_seconds
        ):
            runs.append([])
        runs[-1].append(events[index])
        previous = index
    return runs


def sessions(events: Sequence[NormalizedEvent], gap_seconds: int) -> list[list[NormalizedEvent]]:
    """Split time-ordered events where the gap to the previous event exceeds ``gap_seconds``."""
    groups: list[list[NormalizedEvent]] = []
    for event in events:
        if groups and (event.event_time - groups[-1][-1].event_time).total_seconds() <= gap_seconds:
            groups[-1].append(event)
        else:
            groups.append([event])
    return groups
