"""Authentication rules: repeated failures, failures followed by success, password spray."""

from __future__ import annotations

from collections.abc import Sequence
from typing import ClassVar

from app.detection.base import DetectionContext, Rule, fmt_ts, qualifying_runs
from app.domain.enums import EventType, Outcome, Severity
from app.domain.models import NormalizedEvent
from app.storage.alerts import Finding
from app.storage.repositories import EventFilters


def _scopes(events: Sequence[NormalizedEvent], outcome: Outcome | None) -> list[tuple[str, str]]:
    """Distinct (user, src_ip) pairs of auth events. Events missing either field are skipped:
    without both there is no entity to count failures against."""
    return sorted(
        {
            (e.user, e.src_ip)
            for e in events
            if e.event_type is EventType.AUTH
            and e.user
            and e.src_ip
            and (outcome is None or e.outcome is outcome)
        }
    )


def _history(ctx: DetectionContext, user: str, src_ip: str) -> list[NormalizedEvent]:
    return ctx.events.query(
        EventFilters(equals={"event_type": EventType.AUTH, "user": user, "src_ip": src_ip})
    )


def _failure_runs(
    history: Sequence[NormalizedEvent], threshold: int, window: int
) -> list[list[NormalizedEvent]]:
    failures = [e for e in history if e.outcome is Outcome.FAILURE]
    return qualifying_runs(failures, window, lambda w: len(w) >= threshold)


class RepeatedFailedLogins(Rule):
    rule_id: ClassVar[str] = "auth.repeated_failures"
    version: ClassVar[int] = 1
    title: ClassVar[str] = "Repeated failed logons"
    description: ClassVar[str] = (
        "Many failed authentications for the same user from the same source IP in a short time."
    )
    severity: ClassVar[Severity] = Severity.MEDIUM
    default_config: ClassVar[dict[str, int]] = {"threshold": 5, "window_seconds": 300}
    config_help: ClassVar[dict[str, str]] = {
        "threshold": "Failures needed to alert",
        "window_seconds": "Window the failures must fall in (inclusive)",
    }

    def evaluate(
        self, new_events: Sequence[NormalizedEvent], ctx: DetectionContext, config: dict[str, int]
    ) -> list[Finding]:
        threshold = self.setting(config, "threshold")
        window = self.setting(config, "window_seconds")
        findings: list[Finding] = []
        for user, src_ip in _scopes(new_events, Outcome.FAILURE):
            for run in _failure_runs(_history(ctx, user, src_ip), threshold, window):
                findings.append(
                    self.finding(
                        key_parts=[user, src_ip],
                        title=f"{len(run)} failed logons for {user} from {src_ip}",
                        explanation=(
                            f"{len(run)} failed logons for user '{user}' from {src_ip} between "
                            f"{fmt_ts(run[0].event_time)} and {fmt_ts(run[-1].event_time)}. "
                            f"Rule: at least {threshold} failures within {window}s."
                        ),
                        matched=[(e, "failed logon in burst") for e in run],
                    )
                )
        return findings


class FailuresThenSuccess(Rule):
    rule_id: ClassVar[str] = "auth.failures_then_success"
    version: ClassVar[int] = 1
    title: ClassVar[str] = "Failed logons followed by a success"
    description: ClassVar[str] = (
        "A burst of failed logons for a user from one source IP, then a successful logon for the "
        "same user from the same IP shortly after: possible guessed or stolen credentials."
    )
    severity: ClassVar[Severity] = Severity.HIGH
    default_config: ClassVar[dict[str, int]] = {
        "failure_threshold": 3,
        "failure_window_seconds": 600,
        "success_within_seconds": 900,
    }
    config_help: ClassVar[dict[str, str]] = {
        "failure_threshold": "Failures needed before a success is suspicious",
        "failure_window_seconds": "Window the failures must fall in (inclusive)",
        "success_within_seconds": "Max time from the last failure to the success (inclusive)",
    }

    def evaluate(
        self, new_events: Sequence[NormalizedEvent], ctx: DetectionContext, config: dict[str, int]
    ) -> list[Finding]:
        threshold = self.setting(config, "failure_threshold")
        window = self.setting(config, "failure_window_seconds")
        within = self.setting(config, "success_within_seconds")
        findings: list[Finding] = []
        for user, src_ip in _scopes(new_events, None):
            history = _history(ctx, user, src_ip)
            successes = [e for e in history if e.outcome is Outcome.SUCCESS]
            for run in _failure_runs(history, threshold, window):
                last_failure = run[-1].event_time
                success = next(
                    (
                        s
                        for s in successes
                        if 0 <= (s.event_time - last_failure).total_seconds() <= within
                    ),
                    None,
                )
                if success is None:
                    continue
                findings.append(
                    self.finding(
                        key_parts=[user, src_ip],
                        title=f"Successful logon for {user} from {src_ip} after {len(run)} fails",
                        explanation=(
                            f"{len(run)} failed logons for user '{user}' from {src_ip} "
                            f"({fmt_ts(run[0].event_time)} to {fmt_ts(last_failure)}), then a "
                            f"successful logon at {fmt_ts(success.event_time)}. Rule: at least "
                            f"{threshold} failures within {window}s followed by a success within "
                            f"{within}s of the last failure."
                        ),
                        matched=[(e, "failed logon in burst") for e in run]
                        + [(success, "successful logon after the burst")],
                        identity=run,
                    )
                )
        return findings


class PasswordSpray(Rule):
    rule_id: ClassVar[str] = "auth.password_spray"
    version: ClassVar[int] = 1
    title: ClassVar[str] = "Password spray"
    description: ClassVar[str] = (
        "Failed logons for many different users from one source IP in a short time. "
        "A failure count per user stays low, so this needs its own rule."
    )
    severity: ClassVar[Severity] = Severity.MEDIUM
    default_config: ClassVar[dict[str, int]] = {"distinct_users": 5, "window_seconds": 600}
    config_help: ClassVar[dict[str, str]] = {
        "distinct_users": "Distinct users failing from one IP to alert",
        "window_seconds": "Window the failures must fall in (inclusive)",
    }

    def evaluate(
        self, new_events: Sequence[NormalizedEvent], ctx: DetectionContext, config: dict[str, int]
    ) -> list[Finding]:
        needed = self.setting(config, "distinct_users")
        window = self.setting(config, "window_seconds")
        sources = sorted(
            {
                e.src_ip
                for e in new_events
                if e.event_type is EventType.AUTH
                and e.outcome is Outcome.FAILURE
                and e.user
                and e.src_ip
            }
        )
        findings: list[Finding] = []
        for src_ip in sources:
            history = ctx.events.query(
                EventFilters(
                    equals={
                        "event_type": EventType.AUTH,
                        "outcome": Outcome.FAILURE,
                        "src_ip": src_ip,
                    }
                )
            )
            failures = [e for e in history if e.user]
            runs = qualifying_runs(failures, window, lambda w: len({e.user for e in w}) >= needed)
            for run in runs:
                users = sorted({e.user for e in run if e.user})
                findings.append(
                    self.finding(
                        key_parts=[src_ip],
                        title=f"Failed logons for {len(users)} users from {src_ip}",
                        explanation=(
                            f"{len(run)} failed logons from {src_ip} targeting {len(users)} "
                            f"distinct users ({', '.join(users)}) between "
                            f"{fmt_ts(run[0].event_time)} and {fmt_ts(run[-1].event_time)}. "
                            f"Rule: at least {needed} distinct users within {window}s. "
                            "No success is implied; check later logons from this IP."
                        ),
                        matched=[(e, "failed logon in spray") for e in run],
                    )
                )
        return findings
