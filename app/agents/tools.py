"""The allowlisted agent tools.

A model can only *name* a tool and supply JSON arguments. This module decides everything else:
whether the name exists, whether the calling role may use it, whether the arguments validate
(strict schemas, unknown keys rejected, sizes capped), and what the result looks like. Handlers
call the same services the UI uses, so the Phase 4 evidence rules apply unchanged. There is no
eval, no dynamic import, no SQL from the model: filters go through the allowlisted repository.

``propose_response`` only stores a proposal; ``app/policy`` decides whether it stands, and
nothing is ever executed. Every call, accepted or refused, is written to the audit log.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError
from pydantic import field_validator as validator

from app.agents.schemas import json_schema
from app.audit.log import OK, REJECTED, AuditLog
from app.domain.enums import (
    AgentRole,
    EventType,
    EvidenceCategory,
    EvidenceSource,
    Outcome,
    ResponseAction,
)
from app.domain.errors import SocCopilotError
from app.domain.models import Evidence, NormalizedEvent
from app.investigations.service import InvestigationService
from app.investigations.timeline import describe_event
from app.policy.service import ResponseService
from app.storage.repositories import EventFilters
from app.tools.local_ioc import lookup_local_ioc

MAX_RESULT_CHARS = 8_000
MAX_FIELD_CHARS = 200
MAX_EVENTS_PER_RESULT = 50
MAX_OPEN_QUESTIONS = 5
MAX_RETURNED_IDS = 5_000

Id = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)]
ShortText = Annotated[str, StringConstraints(strip_whitespace=True, max_length=MAX_FIELD_CHARS)]
CorrelationField = Literal["user", "host", "src_ip", "dst_ip"]


class ToolArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class SearchEventsArgs(ToolArgs):
    event_type: EventType | None = None
    user: ShortText | None = None
    host: ShortText | None = None
    src_ip: ShortText | None = None
    dst_ip: ShortText | None = None
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    process_name: ShortText | None = None
    outcome: Outcome | None = None
    action: ShortText | None = None
    start: datetime | None = None
    end: datetime | None = None
    text: ShortText | None = None
    limit: int = Field(default=20, ge=1, le=MAX_EVENTS_PER_RESULT)

    _utc_times = validator("start", "end")(_utc)


class GetEventArgs(ToolArgs):
    event_id: Id


class GetRelatedEventsArgs(ToolArgs):
    seed_event_id: Id
    window_minutes: int = Field(default=30, ge=1, le=24 * 60)
    fields: list[CorrelationField] | None = Field(default=None, max_length=4)
    limit: int = Field(default=20, ge=1, le=MAX_EVENTS_PER_RESULT)


class BuildTimelineArgs(ToolArgs):
    event_ids: list[Id] | None = Field(default=None, max_length=MAX_EVENTS_PER_RESULT)


class AlertExplanationArgs(ToolArgs):
    alert_id: Id


class LocalIocArgs(ToolArgs):
    indicator: Annotated[
        str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)
    ]
    ioc_type: Literal["ip", "domain", "sha256"] = "ip"


class IpArgs(ToolArgs):
    ip: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)]


class AddEvidenceArgs(ToolArgs):
    category: Literal["observation", "inference", "contradiction", "missing_telemetry"]
    claim: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=1000)]
    event_ids: list[Id] = Field(default_factory=list, max_length=20)
    based_on_evidence_ids: list[Id] = Field(default_factory=list, max_length=20)


class ProposeResponseArgs(ToolArgs):
    action: ResponseAction
    target: Annotated[str, StringConstraints(strip_whitespace=True, max_length=256)] = ""
    rationale: Annotated[
        str, StringConstraints(strip_whitespace=True, min_length=1, max_length=1000)
    ]
    evidence_ids: list[Id] = Field(min_length=1, max_length=10)


class RequestAnalystInputArgs(ToolArgs):
    question: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=500)]


@dataclass
class ToolContext:
    """What a handler may touch. ``returned_event_ids`` is every event ID a tool (or the case
    file, which is built by code) has shown to the agents in this run: the only IDs they may
    cite."""

    investigations: InvestigationService
    investigation_id: str
    run_id: str
    role: AgentRole
    model_name: str
    returned_event_ids: set[str] = field(default_factory=set)
    open_questions: list[str] = field(default_factory=list)
    read_only: bool = False  # Ask mode: tools that write or contact providers are refused
    waiting_question: str | None = None  # set by request_analyst_input: the run must wait

    @property
    def actor(self) -> str:
        return f"agent:{self.role.value}"

    def saw(self, events: list[NormalizedEvent]) -> None:
        for event in events:
            if len(self.returned_event_ids) >= MAX_RETURNED_IDS:
                return
            self.returned_event_ids.add(event.event_id)


@dataclass(frozen=True)
class ToolOutcome:
    ok: bool
    result: dict[str, Any]
    summary: str  # one line for the activity log

    def as_text(self) -> str:
        return json.dumps(self.result, sort_keys=True, default=str)


class ToolRejected(SocCopilotError):
    """A tool call was refused before or during execution; the message goes back to the model."""


Handler = Callable[[ToolContext, Any], tuple[dict[str, Any], str]]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    args: type[ToolArgs]
    roles: frozenset[AgentRole]
    handler: Handler

    def signature(self) -> dict[str, Any]:
        schema = json_schema(self.args)
        required = set(schema.get("required", []))
        return {
            "name": self.name,
            "description": self.description,
            "arguments": {
                k: _describe_property(v, k in required)
                for k, v in schema.get("properties", {}).items()
            },
        }


def _describe_property(schema: dict[str, Any], required: bool) -> str:
    """Compact argument description for prompts (the full JSON schema is too long for an 8B
    model's context and adds nothing the validator does not enforce)."""
    kinds = []
    for option in schema.get("anyOf") or [schema]:
        if "enum" in option:
            kinds.append("|".join(map(str, option["enum"])))
        elif option.get("type") == "array":
            item = option.get("items", {})
            kinds.append(f"list of {'|'.join(item['enum']) if 'enum' in item else 'string'}")
        elif option.get("type") and option["type"] != "null":
            kinds.append(option["type"] + (" (ISO-8601 UTC)" if option.get("format") else ""))
    if required:
        return f"{' or '.join(kinds)}, required"
    default = schema.get("default")
    return f"{' or '.join(kinds)}" + (f", default {default}" if default is not None else "")


# --- results -------------------------------------------------------------------------------


def _clip(value: Any) -> Any:
    if isinstance(value, str) and len(value) > MAX_FIELD_CHARS:
        return value[: MAX_FIELD_CHARS - 1] + "…"
    return value


def compact_event(event: NormalizedEvent) -> dict[str, Any]:
    fields = {
        "event_id": event.event_id,
        "time": event.event_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "type": event.event_type.value,
        "summary": describe_event(event),
        "outcome": event.outcome.value,
        "user": event.user,
        "host": event.host,
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "dst_port": event.dst_port,
        "process_name": event.process_name,
        "command_line": event.command_line,
        "action": event.action,
    }
    if event.parse_status != "ok":
        fields["parse_status"] = event.parse_status
    return {k: _clip(v) for k, v in fields.items() if v is not None}


def compact_evidence(item: Evidence) -> dict[str, Any]:
    return {
        "evidence_id": item.evidence_id,
        "category": item.category.value,
        "source": item.source_type.value,
        "claim": _clip(item.claim) if len(item.claim) <= 600 else item.claim[:599] + "…",
        "event_ids": item.event_ids[:10],
        "collected_by": item.collected_by,
    }


def _event_result(
    ctx: ToolContext, events: list[NormalizedEvent], total: int | None = None
) -> dict[str, Any]:
    """Return as many events as fit in the result budget; only those count as returned."""
    shown = [compact_event(e) for e in events[:MAX_EVENTS_PER_RESULT]]
    while shown and len(json.dumps(shown, default=str)) > MAX_RESULT_CHARS - 300:
        shown.pop()
    ctx.saw([e for e in events if e.event_id in {s["event_id"] for s in shown}])
    result: dict[str, Any] = {"events": shown, "returned": len(shown)}
    matched = total if total is not None else len(events)
    if matched > len(shown):
        result["note"] = f"{matched} matched; narrow the filters to see the rest"
    result["matched"] = matched
    return result


# --- handlers ------------------------------------------------------------------------------


def _search_events(ctx: ToolContext, args: SearchEventsArgs) -> tuple[dict[str, Any], str]:
    equals = {
        k: v
        for k, v in args.model_dump(exclude={"start", "end", "text", "limit"}).items()
        if v is not None
    }
    if not equals and args.start is None and args.end is None and not args.text:
        raise ToolRejected("give at least one filter (a field, a time range or text)")
    page = ctx.investigations.events.search(
        EventFilters(equals=equals, start=args.start, end=args.end, text=args.text),
        page=1,
        page_size=args.limit,
    )
    return _event_result(ctx, page.events, page.total), f"{page.total} event(s) matched"


def _get_event(ctx: ToolContext, args: GetEventArgs) -> tuple[dict[str, Any], str]:
    event = ctx.investigations.events.get(args.event_id)
    if event is None:
        raise ToolRejected(f"no event with id {args.event_id}")
    ctx.saw([event])
    detail = compact_event(event)
    detail["message"] = _clip(event.message) if event.message else None
    detail["parent_process"] = event.parent_process
    alerts = ctx.investigations.alerts.alerts_for_event(event.event_id)
    detail["alert_ids"] = [a.alert_id for a in alerts][:10]
    return {"event": {k: v for k, v in detail.items() if v is not None}}, "1 event"


def _get_related_events(ctx: ToolContext, args: GetRelatedEventsArgs) -> tuple[dict[str, Any], str]:
    if ctx.investigations.events.get(args.seed_event_id) is None:
        raise ToolRejected(f"no event with id {args.seed_event_id}")
    events = ctx.investigations.events.related(
        args.seed_event_id,
        timedelta(minutes=args.window_minutes),
        list(args.fields) if args.fields else None,
        limit=args.limit,
    )
    return _event_result(ctx, events), f"{len(events)} related event(s)"


def build_timeline(ctx: ToolContext, args: BuildTimelineArgs) -> tuple[dict[str, Any], str]:
    entries = ctx.investigations.timeline(ctx.investigation_id)
    if args.event_ids:
        wanted = set(args.event_ids)
        entries = [t for t in entries if t.event_id in wanted]
    total = len(entries)
    # Alert-matched events first, so a capped timeline still shows what fired.
    picked = sorted(entries, key=lambda t: (not t.alert_match, t.event_time))
    picked = sorted(picked[:MAX_EVENTS_PER_RESULT], key=lambda t: (t.event_time, t.event_id))
    rows = [
        {
            "event_id": t.event_id,
            "time": t.event_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "summary": _clip(t.summary),
            "alert_match": t.alert_match,
            "cited_by": t.cited_by[:5],
        }
        for t in picked
    ]
    while rows and len(json.dumps(rows)) > MAX_RESULT_CHARS - 300:
        rows.pop()
    ctx.returned_event_ids.update(r["event_id"] for r in rows)
    result: dict[str, Any] = {"timeline": rows, "events_in_scope": total}
    if total > len(rows):
        result["note"] = f"showing {len(rows)} of {total}; alert-matched events first"
    return result, f"{len(rows)} of {total} timeline entries"


def _alert_explanation(ctx: ToolContext, args: AlertExplanationArgs) -> tuple[dict[str, Any], str]:
    investigation = ctx.investigations.get(ctx.investigation_id)
    if args.alert_id not in investigation.alert_ids:
        raise ToolRejected("that alert is not part of this investigation")
    alert = ctx.investigations.alerts.get(args.alert_id)
    if alert is None:
        raise ToolRejected(f"no alert with id {args.alert_id}")
    rule = ctx.investigations.detection.rules.get(alert.rule_id)
    event_ids = [link.event_id for link in ctx.investigations.alerts.events_for(alert.alert_id)]
    ctx.returned_event_ids.update(event_ids[:MAX_EVENTS_PER_RESULT])
    return {
        "alert_id": alert.alert_id,
        "rule_id": alert.rule_id,
        "rule_version": alert.rule_version,
        "rule_title": rule.title if rule else None,
        "rule_description": _clip(rule.description) if rule else None,
        "severity": alert.severity.value,
        "explanation": alert.explanation,
        "first_seen": alert.first_seen.isoformat(),
        "last_seen": alert.last_seen.isoformat(),
        "matched_event_ids": event_ids[:MAX_EVENTS_PER_RESULT],
    }, f"rule {alert.rule_id}"


def _lookup_local_ioc(ctx: ToolContext, args: LocalIocArgs) -> tuple[dict[str, Any], str]:
    ioc = lookup_local_ioc(ctx.investigations.reputation.iocs, args.indicator, args.ioc_type)
    if ioc is None:
        return {"indicator": args.indicator, "match": False}, "no local IOC match"
    return {
        "indicator": ioc.indicator,
        "match": True,
        "ioc_type": ioc.ioc_type,
        "confidence": ioc.confidence,
        "source": ioc.source,
        "description": _clip(ioc.description),
        "added": ioc.added,
    }, "local IOC match"


def _reputation(provider: str) -> Handler:
    def handler(ctx: ToolContext, args: IpArgs) -> tuple[dict[str, Any], str]:
        service = ctx.investigations
        scope = service.scope_events(ctx.investigation_id)
        if not any(args.ip in (e.src_ip, e.dst_ip) for e in scope):
            # An IP the agents found through a search: bring the events that show it into the
            # scope first, so the recorded evidence cites real events.
            shown = [
                e
                for e in service.events.get_many(sorted(ctx.returned_event_ids))
                if args.ip in (e.src_ip, e.dst_ip)
            ]
            if not shown:
                raise ToolRejected(
                    f"{args.ip} is not in any event returned so far; find an event with it first"
                )
            service.add_to_scope(
                ctx.investigation_id,
                [e.event_id for e in shown][:50],
                f"contains {args.ip}; looked up by {ctx.role.value}",
                ctx.actor,
            )
        recorded = service.check_reputation(
            ctx.investigation_id, args.ip, ctx.actor, providers=[provider]
        )
        items = [compact_evidence(e) for e in recorded]
        return (
            {"ip": args.ip, "provider": provider, "recorded_evidence": items},
            f"{provider}: {len(items)} evidence item(s) recorded",
        )

    return handler


def _add_evidence(ctx: ToolContext, args: AddEvidenceArgs) -> tuple[dict[str, Any], str]:
    cited = list(dict.fromkeys(args.event_ids))
    unseen = [e for e in cited if e not in ctx.returned_event_ids]
    if unseen:
        raise ToolRejected(
            "only cite event IDs a tool returned in this run; not returned: " + ", ".join(unseen)
        )
    if args.category == "observation" and not cited:
        raise ToolRejected("an observation must cite at least one event")
    known = {e.evidence_id for e in ctx.investigations.evidence(ctx.investigation_id)}
    unknown = [e for e in args.based_on_evidence_ids if e not in known]
    if unknown:
        raise ToolRejected("unknown evidence id(s): " + ", ".join(unknown))
    service = ctx.investigations
    service.add_to_scope(ctx.investigation_id, cited, f"cited by {ctx.role.value} agent", ctx.actor)
    item = service.add_evidence(
        ctx.investigation_id,
        category=EvidenceCategory(args.category),
        claim=args.claim,
        source_type=EvidenceSource.AGENT,
        source_ref=f"{ctx.run_id}:{ctx.role.value}",
        collected_by=ctx.actor,
        event_ids=cited,
        provenance={
            "tool": "add_evidence",
            "run_id": ctx.run_id,
            "role": ctx.role.value,
            "model": ctx.model_name,
            "based_on_evidence_ids": list(dict.fromkeys(args.based_on_evidence_ids)),
        },
        reliability=(
            f"Written by the {ctx.role.value} agent ({ctx.model_name}). Model-generated; check "
            "the cited events and evidence."
        ),
    )
    return {"evidence_id": item.evidence_id, "recorded": True}, f"recorded {item.evidence_id}"


def _request_analyst_input(
    ctx: ToolContext, args: RequestAnalystInputArgs
) -> tuple[dict[str, Any], str]:
    if len(ctx.open_questions) >= MAX_OPEN_QUESTIONS:
        raise ToolRejected(f"at most {MAX_OPEN_QUESTIONS} questions per run")
    if args.question not in ctx.open_questions:
        ctx.open_questions.append(args.question)
    ctx.waiting_question = args.question
    return {
        "recorded": True,
        "note": "The run pauses until the analyst answers in chat. Their reply will appear "
        "under analyst messages; then continue your turn.",
    }, "waiting for the analyst"


def _propose_response(ctx: ToolContext, args: ProposeResponseArgs) -> tuple[dict[str, Any], str]:
    rec = ResponseService(ctx.investigations).propose(
        ctx.investigation_id,
        args.action,
        args.target,
        args.rationale,
        args.evidence_ids,
        ctx.actor,
    )
    result = {
        "recommendation_id": rec.recommendation_id,
        "action": rec.action.value,
        "target": rec.target,
        "status": rec.status.value,
        "risk": rec.risk.value,
        "policy_notes": rec.policy_notes,
    }
    return result, f"{rec.action.value} {rec.target}: {rec.status.value}"


_INVESTIGATORS = frozenset({AgentRole.LOG_INVESTIGATOR, AgentRole.THREAT_INTEL})
# Tools that change state or send data out. Ask mode (read-only) cannot use them.
WRITING_TOOLS = frozenset(
    {
        "add_evidence",
        "request_analyst_input",
        "lookup_abuseipdb",
        "lookup_virustotal_ip",
        "propose_response",
    }
)

TOOLS: dict[str, ToolSpec] = {
    spec.name: spec
    for spec in (
        ToolSpec(
            "search_events",
            "Find stored events by exact field values, a UTC time range and/or text in the "
            "message or command line.",
            SearchEventsArgs,
            frozenset({AgentRole.LOG_INVESTIGATOR}),
            _search_events,
        ),
        ToolSpec(
            "get_event",
            "Full detail of one event, including the alerts it is linked to.",
            GetEventArgs,
            _INVESTIGATORS,
            _get_event,
        ),
        ToolSpec(
            "get_related_events",
            "Events sharing user/host/src_ip/dst_ip with a seed event within +/- a window.",
            GetRelatedEventsArgs,
            frozenset({AgentRole.LOG_INVESTIGATOR}),
            _get_related_events,
        ),
        ToolSpec(
            "build_timeline",
            "The investigation's events in time order (optionally only the given IDs).",
            BuildTimelineArgs,
            _INVESTIGATORS,
            build_timeline,
        ),
        ToolSpec(
            "get_alert_rule_explanation",
            "Why an alert of this investigation fired: rule, thresholds, matched events.",
            AlertExplanationArgs,
            _INVESTIGATORS,
            _alert_explanation,
        ),
        ToolSpec(
            "lookup_local_ioc",
            "Check an IP, domain or sha256 against the local IOC list (offline).",
            LocalIocArgs,
            frozenset({AgentRole.THREAT_INTEL}),
            _lookup_local_ioc,
        ),
        ToolSpec(
            "lookup_abuseipdb",
            "AbuseIPDB reputation of an IP seen in the events; the result is recorded as "
            "evidence. Private and documentation addresses are never sent.",
            IpArgs,
            frozenset({AgentRole.THREAT_INTEL}),
            _reputation("abuseipdb"),
        ),
        ToolSpec(
            "lookup_virustotal_ip",
            "VirusTotal reputation of an IP seen in the events; the result is recorded as "
            "evidence. Private and documentation addresses are never sent.",
            IpArgs,
            frozenset({AgentRole.THREAT_INTEL}),
            _reputation("virustotal"),
        ),
        ToolSpec(
            "add_evidence",
            "Record a finding. Cite only event IDs that a tool returned in this run. Use "
            "contradiction for evidence against compromise and missing_telemetry for gaps.",
            AddEvidenceArgs,
            _INVESTIGATORS,
            _add_evidence,
        ),
        ToolSpec(
            "request_analyst_input",
            "Ask the analyst a question. The run waits for the answer, so only ask when the "
            "answer would change what you do next.",
            RequestAnalystInputArgs,
            _INVESTIGATORS,
            _request_analyst_input,
        ),
        ToolSpec(
            "propose_response",
            "Propose one response action from the catalogue for a target seen in the events, "
            "citing evidence IDs. It is only a proposal: policy may block it, the analyst "
            "decides, and every action is simulated.",
            ProposeResponseArgs,
            frozenset({AgentRole.RESPONSE_PLANNER}),
            _propose_response,
        ),
    )
}


def tools_for(role: AgentRole, read_only: bool = False) -> list[ToolSpec]:
    return [
        spec
        for spec in TOOLS.values()
        if role in spec.roles and not (read_only and spec.name in WRITING_TOOLS)
    ]


def execute(ctx: ToolContext, name: str, arguments: Any) -> ToolOutcome:
    """Validate and run one tool call. Never raises for a bad call: the refusal is the
    outcome, and it is returned to the model so it can correct itself. Every call is audited."""
    outcome = _execute(ctx, name, arguments)
    AuditLog(ctx.investigations.conn).record(
        ctx.actor,
        f"tool.{name}" if name in TOOLS else "tool.unknown",
        "tool",
        str(name)[:64],
        investigation_id=ctx.investigation_id,
        outcome=OK if outcome.ok else REJECTED,
        details={
            "run_id": ctx.run_id,
            "arguments": arguments if isinstance(arguments, dict) else str(arguments)[:200],
            "summary": outcome.summary,
            "read_only": ctx.read_only,
        },
    )
    return outcome


def _execute(ctx: ToolContext, name: str, arguments: Any) -> ToolOutcome:
    spec = TOOLS.get(name)
    if spec is None:
        allowed = ", ".join(s.name for s in tools_for(ctx.role, ctx.read_only))
        return _refused(f"unknown tool {name!r}; available: {allowed}")
    if ctx.role not in spec.roles:
        return _refused(f"the {ctx.role.value} role may not use {name}")
    if ctx.read_only and name in WRITING_TOOLS:
        return _refused(f"{name} is not available in read-only Ask mode")
    if not isinstance(arguments, dict):
        return _refused("arguments must be a JSON object")
    try:
        args = spec.args.model_validate(arguments)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(map(str, err['loc'])) or 'arguments'}: {err['msg']}"
            for err in exc.errors()[:5]
        )
        return _refused(f"invalid arguments for {name}: {problems}")
    try:
        result, summary = spec.handler(ctx, args)
    except SocCopilotError as exc:
        return _refused(str(exc))
    return ToolOutcome(True, result, summary)


def _refused(message: str) -> ToolOutcome:
    return ToolOutcome(False, {"error": message[:500]}, message[:200])
