"""Deterministic context recorded when an investigation starts, so the decisive facts reach the
evidence list instead of hiding in a long timeline:

- **related alerts**: other alerts linked to events in the scope (same user, host or IP in the
  window), e.g. the PowerShell alert on the workstation of a user whose logon is investigated;
- **upstream SIEM detections**: events in the scope that a SIEM (Wazuh) rated at
  ``SIEM_NOTABLE_LEVEL`` or above, with its rule, level and MITRE IDs;
- **history ("seen before")** over the ``HISTORY_DAYS`` before the alert window: did this user
  log on from this address before, did this exact command run on this host before, did this
  client connect to this address before. "First time" and "every day for a month" are both
  facts an analyst checks by hand.

Every claim is built from stored events by code. History looks at events outside the scope, so
it cites none; the sample event IDs it used are kept in provenance.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from app.domain.enums import EventType, Outcome
from app.domain.models import Alert, NormalizedEvent
from app.storage.alerts import AlertRepository
from app.storage.repositories import EventFilters, EventRepository

HISTORY_DAYS = 30
SIEM_NOTABLE_LEVEL = 7
MAX_RELATED_ALERTS = 10
MAX_SIEM_ITEMS = 10
MAX_HISTORY_ITEMS = 6
MAX_LISTED = 5
MAX_USERS_ITEMISED = 3  # more accounts than this get one summary line
HISTORY_QUERY_LIMIT = 5_000
# Every history line starts with one of these, computed by code, so the verifier does not have to
# infer "is this normal?" from a long sentence: it is about the alert's own source, command or
# connection.
SEEN_BEFORE, FIRST_SEEN, NO_BASELINE = "seen before", "first seen", "no baseline"


@dataclass
class ContextItem:
    kind: str  # related_alert | siem | history
    ref: str
    claim: str
    event_ids: list[str] = field(default_factory=list)
    provenance: dict[str, object] = field(default_factory=dict)


def _labelled(label: str, ref: str, claim: str, sample: list[str]) -> ContextItem:
    return ContextItem(
        "history",
        ref,
        f"[{label}] {claim}",
        provenance={"days": HISTORY_DAYS, "baseline": label, "sample": sample},
    )


def _day(value: datetime) -> str:
    return value.strftime("%Y-%m-%d")


def _clip(text: str, n: int = 300) -> str:
    text = " ".join(text.split())
    return text if len(text) <= n else text[: n - 1] + "…"


def related_alerts(alerts: AlertRepository, alert: Alert, scope_ids: set[str]) -> list[ContextItem]:
    items = []
    for alert_id, linked in alerts.links_for_events(sorted(scope_ids)).items():
        if alert_id == alert.alert_id:
            continue
        other = alerts.get(alert_id)
        if other is None:
            continue
        items.append(
            ContextItem(
                "related_alert",
                f"alert:{alert_id}",
                f"Related alert on the same entities: {other.title} (rule {other.rule_id}, "
                f"{other.severity.value}): {_clip(other.explanation)}",
                linked[:50],
                {"alert_id": alert_id, "rule_id": other.rule_id},
            )
        )
    items.sort(key=lambda i: (str(i.provenance["rule_id"]), i.ref))
    return items[:MAX_RELATED_ALERTS]


def siem_detections(scope: list[NormalizedEvent], alerted_event_ids: set[str]) -> list[ContextItem]:
    """``alerted_event_ids``: events already behind an alert (this one or a related one),
    which are reported through the alert instead."""
    notable = []
    for event in scope:
        level = event.extra.get("siem.rule_level")
        if (
            event.event_id in alerted_event_ids
            or not isinstance(level, int)
            or isinstance(level, bool)
            or level < SIEM_NOTABLE_LEVEL
        ):
            continue
        notable.append((level, event))
    notable.sort(key=lambda pair: (-pair[0], pair[1].event_time, pair[1].event_id))
    items = []
    for level, event in notable[:MAX_SIEM_ITEMS]:
        vendor = str(event.extra.get("siem.vendor") or "siem").capitalize()
        rule = event.extra.get("siem.rule_id") or "?"
        mitre = event.extra.get("siem.mitre_ids") or []
        mitre_text = f", MITRE {', '.join(map(str, mitre))}" if mitre else ""
        who = f" for user {event.user}" if event.user else ""
        where = f" on {event.host}" if event.host else ""
        items.append(
            ContextItem(
                "siem",
                f"siem:{event.event_id}",
                f"{vendor} rule {rule} (level {level}{mitre_text}){where}{who} at "
                f"{event.event_time:%Y-%m-%d %H:%M:%S}Z: {_clip(event.message or '')}",
                [event.event_id],
                {"vendor": vendor.lower(), "rule_id": rule, "level": level},
            )
        )
    return items


def _prior_logons(
    events: EventRepository, user: str, since: datetime, until: datetime
) -> tuple[dict[str, set[str]], list[str]]:
    """Source address -> days with a successful logon by ``user``, plus sample event IDs."""
    prior = events.query(
        EventFilters(
            equals={"event_type": EventType.AUTH, "user": user, "outcome": Outcome.SUCCESS},
            start=since,
            end=until,
        ),
        limit=HISTORY_QUERY_LIMIT,
    )
    days_by_ip: dict[str, set[str]] = defaultdict(set)
    for e in prior:
        days_by_ip[e.src_ip or "unknown address"].add(_day(e.event_time))
    return days_by_ip, [e.event_id for e in prior[:5]]


def _accounts_summary(
    users: list[str],
    logons: dict[str, tuple[dict[str, set[str]], list[str]]],
    auth: list[NormalizedEvent],
    span: str,
) -> ContextItem:
    """One line for alerts over many accounts (e.g. a spray), instead of one per account."""
    known = [u for u in users if logons[u][0]]
    sources = sorted({e.src_ip for e in auth if e.src_ip})
    used_by = {ip: [u for u in users if ip in logons[u][0]] for ip in sources}
    source_text = "; ".join(
        f"{ip} had been used by {', '.join(who[:MAX_LISTED])}"
        if who
        else f"{ip} had been used by none of them"
        for ip, who in used_by.items()
    )
    claim = (
        f"Logon history for the {len(users)} accounts in this alert {span}: {len(known)} had "
        f"successful logons before"
        + (f" ({', '.join(known[:MAX_LISTED])})" if known else "")
        + (f". This alert's source: {source_text}." if source_text else ".")
    )
    sample = [i for u in known for i in logons[u][1]][:5]
    if not known or not sources:
        label = NO_BASELINE
    else:
        label = SEEN_BEFORE if all(used_by.values()) else FIRST_SEEN
    return _labelled(label, "history:accounts", claim, sample)


def history(
    events: EventRepository, alert_events: list[NormalizedEvent], window_start: datetime
) -> list[ContextItem]:
    since = window_start - timedelta(days=HISTORY_DAYS)
    items: list[ContextItem] = []
    span = f"in the {HISTORY_DAYS} days before {_day(window_start)}"

    auth = [e for e in alert_events if e.event_type is EventType.AUTH and e.user]
    users = sorted({e.user for e in auth if e.user})
    logons = {u: _prior_logons(events, u, since, window_start) for u in users}
    if len(users) > MAX_USERS_ITEMISED:
        items.append(_accounts_summary(users, logons, auth, span))
    for user in users if len(users) <= MAX_USERS_ITEMISED else []:
        sources = sorted({e.src_ip for e in auth if e.user == user and e.src_ip})
        days_by_ip, sample = logons[user]
        if not days_by_ip or not sources:
            label = NO_BASELINE
        else:
            label = SEEN_BEFORE if all(ip in days_by_ip for ip in sources) else FIRST_SEEN
        if not days_by_ip:
            claim = f"No successful logons for {user} {span}: no baseline to compare with."
        else:
            usual = sorted(days_by_ip.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:MAX_LISTED]
            listed = ", ".join(f"{ip} ({len(days)} day(s))" for ip, days in usual)
            seen = [
                f"{ip} was used on {len(days_by_ip[ip])} of those days"
                if ip in days_by_ip
                else f"{ip} had never been used"
                for ip in sources
            ]
            claim = (
                f"Logon history for {user} {span}: successful logons on "
                f"{len({d for days in days_by_ip.values() for d in days})} day(s), from {listed}. "
                + ("This alert's source " + "; ".join(seen) + "." if seen else "")
            )
        items.append(_labelled(label, f"history:user:{user}", claim, sample))

    commands = sorted(
        {
            (e.host, e.process_name, e.command_line)
            for e in alert_events
            if e.event_type is EventType.PROCESS and e.host and e.process_name and e.command_line
        }
    )
    for host, name, command in commands:
        prior = [
            e
            for e in events.query(
                EventFilters(
                    equals={"event_type": EventType.PROCESS, "host": host, "process_name": name},
                    start=since,
                    end=window_start,
                ),
                limit=HISTORY_QUERY_LIMIT,
            )
            if e.command_line == command
        ]
        if prior:
            users = sorted({e.user for e in prior if e.user})[:MAX_LISTED]
            parents = sorted({e.parent_process for e in prior if e.parent_process})[:MAX_LISTED]
            days = sorted({_day(e.event_time) for e in prior})
            claim = (
                f"The same {name} command line ran on {host} on {len(days)} earlier day(s) {span} "
                f"(first {days[0]}, last {days[-1]}"
                + (f"; user {', '.join(users)}" if users else "")
                + (f"; parent {', '.join(parents)}" if parents else "")
                + ")."
            )
        else:
            claim = f"This {name} command line had not run on {host} {span}."
        items.append(
            _labelled(
                SEEN_BEFORE if prior else FIRST_SEEN,
                f"history:command:{host}:{name}",
                claim,
                [e.event_id for e in prior[:5]],
            )
        )

    flows = sorted(
        {
            (e.host or e.src_ip or "", e.dst_ip)
            for e in alert_events
            if e.event_type is EventType.NETWORK and e.dst_ip and (e.host or e.src_ip)
        }
    )
    for client, dst in flows:
        field_name = "host" if any(e.host == client for e in alert_events) else "src_ip"
        prior = events.query(
            EventFilters(
                equals={"event_type": EventType.NETWORK, field_name: client, "dst_ip": dst},
                start=since,
                end=window_start,
            ),
            limit=HISTORY_QUERY_LIMIT,
        )
        days = sorted({_day(e.event_time) for e in prior})
        claim = (
            f"{client} had connected to {dst} on {len(days)} earlier day(s) {span}."
            if days
            else f"{client} had not connected to {dst} {span}: first seen in this alert."
        )
        items.append(
            _labelled(
                SEEN_BEFORE if days else FIRST_SEEN,
                f"history:flow:{client}:{dst}",
                claim,
                [e.event_id for e in prior[:5]],
            )
        )
    return items[:MAX_HISTORY_ITEMS]
