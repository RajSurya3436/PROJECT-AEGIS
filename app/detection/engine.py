"""Runs enabled rules over newly stored events and records the findings as alerts.

``DetectionEngine.detect`` is the post-persist hook of the shared ingestion service, so uploads,
replay and (later) file tail and HTTP all get identical detection. It needs no model or network.
"""

from __future__ import annotations

import logging
import sqlite3
from collections import Counter
from collections.abc import Sequence

from app.detection.base import DetectionContext, Rule
from app.detection.registry import default_rules
from app.domain.enums import ALLOWED_TRANSITIONS, AlertStatus
from app.domain.errors import InvalidRuleConfigError, InvalidTransitionError, NotFoundError
from app.domain.models import NormalizedEvent, RuleSettings
from app.storage.alerts import AlertRepository, IocRepository, RuleRepository
from app.storage.repositories import EventRepository

logger = logging.getLogger(__name__)

MAX_CONFIG_VALUE = 10_000_000


class DetectionEngine:
    def __init__(self, conn: sqlite3.Connection, rules: Sequence[Rule] | None = None) -> None:
        self.rules: dict[str, Rule] = {r.rule_id: r for r in (rules or default_rules())}
        self.rule_settings = RuleRepository(conn)
        self.alerts = AlertRepository(conn)
        self.events = EventRepository(conn)
        self.ctx = DetectionContext(self.events, IocRepository(conn))
        self.rule_settings.sync(
            [(r.rule_id, r.version, r.default_config) for r in self.rules.values()]
        )

    # --- detection -------------------------------------------------------------------------

    def detect(self, new_events: list[NormalizedEvent]) -> None:
        """Post-persist hook. A failing rule never stops the others or loses events; failures
        are reported together so the ingestion service records them on the source."""
        _, failures = self._run(new_events)
        if failures:
            raise RuntimeError("; ".join(failures))

    def rescan(self) -> Counter[str]:
        """Re-evaluate every stored event, e.g. after enabling a rule, changing a threshold or
        loading IOCs. Alerts are deduplicated, so this never duplicates existing ones."""
        total: Counter[str] = Counter()
        failures: list[str] = []
        for batch in self.events.iter_batches():
            outcomes, failed = self._run(batch)
            total.update(outcomes)
            failures.extend(f for f in failed if f not in failures)
        if failures:
            raise RuntimeError("; ".join(failures))
        return total

    def _run(self, events: Sequence[NormalizedEvent]) -> tuple[Counter[str], list[str]]:
        outcomes: Counter[str] = Counter()
        failures: list[str] = []
        if not events:
            return outcomes, failures
        for rule in self.rules.values():
            settings = self.rule_settings.get(rule.rule_id)
            if settings is None or not settings.enabled:
                continue
            try:
                for finding in rule.evaluate(events, self.ctx, settings.config):
                    outcomes[self.alerts.upsert_finding(finding)] += 1
            except Exception as exc:
                logger.exception("rule %s failed", rule.rule_id)
                failures.append(f"{rule.rule_id}: {exc}")
        return outcomes, failures

    # --- rule settings ---------------------------------------------------------------------

    def list_rules(self) -> list[tuple[Rule, RuleSettings]]:
        out = []
        for settings in self.rule_settings.list_all():
            rule = self.rules.get(settings.rule_id)
            if rule is not None:
                out.append((rule, settings))
        return out

    def configure(self, rule_id: str, *, enabled: bool, config: dict[str, int]) -> None:
        rule = self.rules.get(rule_id)
        if rule is None:
            raise NotFoundError(f"unknown rule: {rule_id}")
        unknown = set(config) - set(rule.default_config)
        if unknown:
            raise InvalidRuleConfigError(f"unknown setting(s) for {rule_id}: {sorted(unknown)}")
        for key, value in config.items():
            if isinstance(value, bool) or not isinstance(value, int):
                raise InvalidRuleConfigError(f"{key} must be an integer")
            if not 1 <= value <= MAX_CONFIG_VALUE:
                raise InvalidRuleConfigError(f"{key} must be between 1 and {MAX_CONFIG_VALUE:,}")
        current = self.rule_settings.get(rule_id)
        base = current.config if current else rule.default_config
        self.rule_settings.update(rule_id, enabled, {**base, **config})

    # --- alert lifecycle -------------------------------------------------------------------

    def transition(self, alert_id: str, status: AlertStatus) -> None:
        alert = self.alerts.get(alert_id)
        if alert is None:
            raise NotFoundError(f"unknown alert: {alert_id}")
        if status not in ALLOWED_TRANSITIONS[alert.status]:
            raise InvalidTransitionError(f"cannot move an alert from {alert.status} to {status}")
        self.alerts.set_status(alert_id, status)
