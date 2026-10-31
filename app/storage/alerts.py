"""Repositories for detection state: rule settings, alerts and their event links, local IOCs.
Like ``repositories.py``, all SQL is parameterised; interpolated fragments are fixed strings."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime

from app.domain.enums import SEVERITY_RANK, AlertStatus, Severity
from app.domain.models import Alert, AlertEventLink, Ioc, RuleSettings
from app.storage.db import transaction, utc_now_iso

_SEVERITY_ORDER_SQL = (
    "CASE a.severity "
    + " ".join(f"WHEN '{sev.value}' THEN {rank}" for sev, rank in SEVERITY_RANK.items())
    + " ELSE 0 END"
)
_ALERT_SELECT = (
    "SELECT a.*, (SELECT COUNT(*) FROM alert_events ae WHERE ae.alert_id = a.alert_id)"
    " AS event_count FROM alerts a"
)
MAX_ALERT_ROWS = 1_000


@dataclass(frozen=True)
class Match:
    event_id: str
    reason: str


@dataclass(frozen=True)
class Finding:
    """What a rule reports: one alert-worthy group of events, before it is stored."""

    rule_id: str
    rule_version: int
    severity: Severity
    title: str
    explanation: str
    dedup_key: str
    matches: tuple[Match, ...]
    first_seen: datetime
    last_seen: datetime
    # Events that define which alert this is. Defaults to every match; a rule sets it when
    # some matches (a shared success) must not tie two separate alerts together.
    identity_event_ids: tuple[str, ...] | None = None


def alert_id_for(dedup_key: str) -> str:
    return hashlib.sha256(dedup_key.encode("utf-8")).hexdigest()[:16]


class RuleRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def sync(self, rules: list[tuple[str, int, dict[str, int]]]) -> None:
        """Make sure each (rule_id, version, default_config) has a row. Existing enabled flags
        and thresholds survive version bumps; keys no longer in the defaults are dropped."""
        with transaction(self.conn):
            for rule_id, version, defaults in rules:
                current = self.get(rule_id)
                if current is None:
                    self.conn.execute(
                        "INSERT INTO detection_rules (rule_id, version, enabled, config_json,"
                        " updated_at) VALUES (?, ?, 1, ?, ?)",
                        (rule_id, version, json.dumps(defaults, sort_keys=True), utc_now_iso()),
                    )
                    continue
                merged = {k: current.config.get(k, v) for k, v in defaults.items()}
                if current.version != version or merged != current.config:
                    self.conn.execute(
                        "UPDATE detection_rules SET version = ?, config_json = ?, updated_at = ?"
                        " WHERE rule_id = ?",
                        (version, json.dumps(merged, sort_keys=True), utc_now_iso(), rule_id),
                    )

    def get(self, rule_id: str) -> RuleSettings | None:
        row = self.conn.execute(
            "SELECT * FROM detection_rules WHERE rule_id = ?", (rule_id,)
        ).fetchone()
        return self._row(row) if row else None

    def list_all(self) -> list[RuleSettings]:
        rows = self.conn.execute("SELECT * FROM detection_rules ORDER BY rule_id").fetchall()
        return [self._row(r) for r in rows]

    def update(self, rule_id: str, enabled: bool, config: dict[str, int]) -> None:
        self.conn.execute(
            "UPDATE detection_rules SET enabled = ?, config_json = ?, updated_at = ?"
            " WHERE rule_id = ?",
            (int(enabled), json.dumps(config, sort_keys=True), utc_now_iso(), rule_id),
        )

    @staticmethod
    def _row(row: sqlite3.Row) -> RuleSettings:
        return RuleSettings(
            rule_id=row["rule_id"],
            version=row["version"],
            enabled=bool(row["enabled"]),
            config=json.loads(row["config_json"]),
        )


class AlertRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def upsert_finding(self, finding: Finding) -> str:
        """Store a finding. Returns ``created``, ``updated`` or ``unchanged``.

        A finding joins an existing alert when it has the same dedup key, or when it shares
        any event with an alert of the same rule (so late-arriving events that shift a group's
        anchor still extend the original alert). Joining never changes the analyst's status:
        a closed alert absorbs recurrences instead of reopening.
        """
        with transaction(self.conn):
            alert_id = self._find_existing(finding)
            if alert_id is None:
                return self._create(finding)
            return self._extend(alert_id, finding)

    def _find_existing(self, finding: Finding) -> str | None:
        row = self.conn.execute(
            "SELECT alert_id FROM alerts WHERE dedup_key = ?", (finding.dedup_key,)
        ).fetchone()
        if row:
            return row["alert_id"]
        event_ids = list(finding.identity_event_ids or [m.event_id for m in finding.matches])
        if not event_ids:
            return None
        placeholders = ",".join("?" for _ in event_ids)
        row = self.conn.execute(
            "SELECT a.alert_id FROM alerts a JOIN alert_events ae ON ae.alert_id = a.alert_id"  # noqa: S608
            f" WHERE a.rule_id = ? AND ae.event_id IN ({placeholders})"
            " ORDER BY a.first_seen, a.alert_id LIMIT 1",
            [finding.rule_id, *event_ids],
        ).fetchone()
        return row["alert_id"] if row else None

    def _create(self, finding: Finding) -> str:
        now = utc_now_iso()
        alert_id = alert_id_for(finding.dedup_key)
        self.conn.execute(
            "INSERT INTO alerts (alert_id, rule_id, rule_version, severity, status, title,"
            " explanation, dedup_key, first_seen, last_seen, created_at, updated_at)"
            " VALUES (?, ?, ?, ?, 'new', ?, ?, ?, ?, ?, ?, ?)",
            (
                alert_id,
                finding.rule_id,
                finding.rule_version,
                finding.severity.value,
                finding.title,
                finding.explanation,
                finding.dedup_key,
                finding.first_seen.isoformat(),
                finding.last_seen.isoformat(),
                now,
                now,
            ),
        )
        self._link(alert_id, finding)
        return "created"

    def _extend(self, alert_id: str, finding: Finding) -> str:
        current = self.get(alert_id)
        assert current is not None
        linked = self._link(alert_id, finding)
        first_seen = min(current.first_seen, finding.first_seen)
        last_seen = max(current.last_seen, finding.last_seen)
        unchanged = (
            linked == 0
            and first_seen == current.first_seen
            and last_seen == current.last_seen
            and finding.severity == current.severity
            and finding.title == current.title
            and finding.explanation == current.explanation
            and finding.rule_version == current.rule_version
        )
        if unchanged:
            return "unchanged"
        self.conn.execute(
            "UPDATE alerts SET rule_version = ?, severity = ?, title = ?, explanation = ?,"
            " first_seen = ?, last_seen = ?, updated_at = ? WHERE alert_id = ?",
            (
                finding.rule_version,
                finding.severity.value,
                finding.title,
                finding.explanation,
                first_seen.isoformat(),
                last_seen.isoformat(),
                utc_now_iso(),
                alert_id,
            ),
        )
        return "updated"

    def _link(self, alert_id: str, finding: Finding) -> int:
        added = 0
        for match in finding.matches:
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO alert_events (alert_id, event_id, reason) VALUES (?, ?, ?)",
                (alert_id, match.event_id, match.reason),
            )
            added += cur.rowcount
        return added

    def get(self, alert_id: str) -> Alert | None:
        row = self.conn.execute(
            f"{_ALERT_SELECT} WHERE a.alert_id = ?",
            (alert_id,),
        ).fetchone()
        return self._row(row) if row else None

    def list(
        self,
        status: AlertStatus | None = None,
        severity: Severity | None = None,
        rule_id: str | None = None,
        limit: int = 500,
    ) -> list[Alert]:
        clauses: list[str] = []
        params: list[str | int] = []
        for column, value in (("status", status), ("severity", severity), ("rule_id", rule_id)):
            if value:
                clauses.append(f"a.{column} = ?")
                params.append(getattr(value, "value", value))
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        rows = self.conn.execute(
            f"{_ALERT_SELECT}{where}"
            f" ORDER BY {_SEVERITY_ORDER_SQL} DESC, a.first_seen, a.alert_id LIMIT ?",
            [*params, min(max(limit, 1), MAX_ALERT_ROWS)],
        ).fetchall()
        return [self._row(r) for r in rows]

    def events_for(self, alert_id: str) -> list[AlertEventLink]:
        rows = self.conn.execute(
            "SELECT ae.event_id, ae.reason FROM alert_events ae JOIN events e"
            " ON e.event_id = ae.event_id WHERE ae.alert_id = ? ORDER BY e.event_time, e.event_id",
            (alert_id,),
        ).fetchall()
        return [AlertEventLink(event_id=r["event_id"], reason=r["reason"]) for r in rows]

    def alerts_for_event(self, event_id: str) -> list[Alert]:
        rows = self.conn.execute(
            f"{_ALERT_SELECT} WHERE a.alert_id IN"  # noqa: S608 - fixed fragments
            " (SELECT alert_id FROM alert_events WHERE event_id = ?) ORDER BY a.first_seen",
            (event_id,),
        ).fetchall()
        return [self._row(r) for r in rows]

    def links_for_events(self, event_ids: list[str]) -> dict[str, list[str]]:
        """alert_id -> the given events it is linked to (batched; for related-alert checks)."""
        links: dict[str, list[str]] = {}
        for start in range(0, len(event_ids), 500):
            chunk = event_ids[start : start + 500]
            marks = ",".join("?" * len(chunk))
            rows = self.conn.execute(
                f"SELECT alert_id, event_id FROM alert_events WHERE event_id IN ({marks})"  # noqa: S608
                " ORDER BY alert_id, event_id",
                chunk,
            ).fetchall()
            for row in rows:
                links.setdefault(row["alert_id"], []).append(row["event_id"])
        return links

    def set_status(self, alert_id: str, status: AlertStatus) -> None:
        self.conn.execute(
            "UPDATE alerts SET status = ?, updated_at = ? WHERE alert_id = ?",
            (status.value, utc_now_iso(), alert_id),
        )

    def count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()["n"]

    def count_by(self, column: str) -> dict[str, int]:
        if column not in ("status", "severity", "rule_id"):
            raise ValueError(f"cannot group alerts by {column!r}")
        rows = self.conn.execute(
            f"SELECT {column} AS k, COUNT(*) AS n FROM alerts GROUP BY {column} ORDER BY {column}"  # noqa: S608
        ).fetchall()
        return {r["k"]: r["n"] for r in rows}

    @staticmethod
    def _row(row: sqlite3.Row) -> Alert:
        return Alert(
            alert_id=row["alert_id"],
            rule_id=row["rule_id"],
            rule_version=row["rule_version"],
            severity=Severity(row["severity"]),
            status=AlertStatus(row["status"]),
            title=row["title"],
            explanation=row["explanation"],
            dedup_key=row["dedup_key"],
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_seen=datetime.fromisoformat(row["last_seen"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            event_count=row["event_count"],
        )


class IocRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def upsert_many(self, iocs: list[Ioc]) -> int:
        with transaction(self.conn):
            for ioc in iocs:
                self.conn.execute(
                    "INSERT INTO local_iocs (indicator, ioc_type, source, confidence, description,"
                    " added) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (indicator, ioc_type) DO UPDATE"
                    " SET source = excluded.source, confidence = excluded.confidence,"
                    " description = excluded.description, added = excluded.added",
                    (
                        ioc.indicator,
                        ioc.ioc_type,
                        ioc.source,
                        ioc.confidence,
                        ioc.description,
                        ioc.added,
                    ),
                )
        return len(iocs)

    def list_all(self, ioc_type: str | None = None) -> list[Ioc]:
        if ioc_type:
            rows = self.conn.execute(
                "SELECT * FROM local_iocs WHERE ioc_type = ? ORDER BY indicator", (ioc_type,)
            ).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM local_iocs ORDER BY indicator").fetchall()
        return [Ioc(**dict(r)) for r in rows]

    def get(self, indicator: str, ioc_type: str) -> Ioc | None:
        row = self.conn.execute(
            "SELECT * FROM local_iocs WHERE indicator = ? AND ioc_type = ?", (indicator, ioc_type)
        ).fetchone()
        return Ioc(**dict(row)) if row else None

    def ip_map(self) -> dict[str, Ioc]:
        return {i.indicator: i for i in self.list_all("ip")}

    def count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) AS n FROM local_iocs").fetchone()["n"]
