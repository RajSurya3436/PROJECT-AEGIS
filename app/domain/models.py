"""Core domain models for ingested security events."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.domain.enums import (
    AgentRole,
    AgentRunStatus,
    AlertStatus,
    Confidence,
    Disposition,
    EventType,
    EvidenceCategory,
    EvidenceSource,
    InvestigationStatus,
    Outcome,
    ReputationStatus,
    Severity,
    SourceStatus,
    SourceType,
)

EVENT_SCHEMA_VERSION = 1


def _require_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None or value.utcoffset().total_seconds() != 0:
        raise ValueError("timestamps must be timezone-aware UTC")
    return value


class NormalizedEvent(BaseModel):
    """A validated event. Fields not covered by an explicit alias stay in ``extra``."""

    model_config = ConfigDict(frozen=True)

    event_id: str
    source_id: str
    source_locator: str
    event_time: datetime
    ingest_time: datetime
    event_type: EventType = EventType.OTHER
    user: str | None = None
    host: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    process_name: str | None = None
    command_line: str | None = None
    parent_process: str | None = None
    outcome: Outcome = Outcome.UNKNOWN
    action: str | None = None
    message: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)
    raw: dict[str, Any]
    parse_status: str = "ok"
    schema_version: int = EVENT_SCHEMA_VERSION

    _check_event_time = field_validator("event_time", "ingest_time")(_require_utc)


class ParseErrorRecord(BaseModel):
    """A malformed input row, kept for analyst review instead of being silently dropped."""

    source_id: str
    locator: str
    error: str
    raw_snippet: str


class IngestResult(BaseModel):
    source_id: str
    received: int = 0
    inserted: int = 0
    duplicates: int = 0
    quarantined: int = 0
    truncated: bool = False
    hook_errors: list[str] = Field(default_factory=list)
    inserted_event_ids: list[str] = Field(default_factory=list)


class DataSource(BaseModel):
    source_id: str
    source_type: SourceType
    name: str
    enabled: bool = True
    status: SourceStatus = SourceStatus.IDLE
    last_seen: datetime | None = None
    cursor: dict[str, Any] = Field(default_factory=dict)
    event_count: int = 0
    error_count: int = 0
    last_error: str | None = None


class Alert(BaseModel):
    """A deterministic rule match. ``event_count`` is the number of linked events."""

    alert_id: str
    rule_id: str
    rule_version: int
    severity: Severity
    status: AlertStatus
    title: str
    explanation: str
    dedup_key: str
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime
    event_count: int = 0


class AlertEventLink(BaseModel):
    event_id: str
    reason: str


class RuleSettings(BaseModel):
    """Stored per-rule state: enabled flag and integer thresholds."""

    rule_id: str
    version: int
    enabled: bool
    config: dict[str, int]


class Ioc(BaseModel):
    indicator: str
    ioc_type: str
    source: str
    confidence: str = "medium"
    description: str = ""
    added: str | None = None


class ReputationResult(BaseModel):
    """One provider's answer for one indicator. ``summary`` holds only allowlisted, typed and
    length-capped fields parsed from the provider response; raw responses are never kept.
    Provider-supplied strings in it are untrusted data."""

    provider: str
    indicator: str
    status: ReputationStatus
    found: bool | None = None  # False: the provider has no record of the indicator
    signal: str | None = None  # low / medium / high, from fixed per-provider thresholds
    summary: dict[str, Any] = Field(default_factory=dict)
    queried_at: datetime | None = None
    expires_at: datetime | None = None
    message: str = ""
    retry_after_seconds: int | None = None

    @property
    def has_data(self) -> bool:
        return self.status in (ReputationStatus.FRESH, ReputationStatus.CACHED)


class IpReputationReport(BaseModel):
    """Everything known about one IP: local IOC match plus each provider's result."""

    indicator: str
    valid: bool
    scope: str  # public, private, loopback, link_local, multicast, reserved, ... or invalid
    local_ioc: Ioc | None = None
    results: list[ReputationResult] = Field(default_factory=list)


class Investigation(BaseModel):
    investigation_id: str
    title: str
    objective: str
    status: InvestigationStatus
    disposition: Disposition | None = None
    confidence: Confidence | None = None
    disposition_reason: str | None = None
    disposition_evidence_ids: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None = None
    alert_ids: list[str] = Field(default_factory=list)


class ScopeEvent(BaseModel):
    """An event brought into an investigation, with the reason it was added."""

    event_id: str
    reason: str
    added_by: str
    added_at: datetime


class Evidence(BaseModel):
    """One sourced statement. ``event_ids`` must be in the investigation's scope; ``provenance``
    records the tool and arguments (or analyst action) that produced it."""

    evidence_id: str
    investigation_id: str
    category: EvidenceCategory
    source_type: EvidenceSource
    source_ref: str
    claim: str
    event_ids: list[str] = Field(default_factory=list)
    observed_at: datetime | None = None
    collected_at: datetime
    collected_by: str
    provenance: dict[str, Any] = Field(default_factory=dict)
    reliability: str = ""


class TimelineEntry(BaseModel):
    event_id: str
    event_time: datetime
    event_type: EventType
    summary: str
    user: str | None = None
    host: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    scope_reason: str
    alert_match: bool = False  # linked to one of the investigation's alerts
    cited_by: list[str] = Field(default_factory=list)  # evidence IDs citing this event


class Assessment(BaseModel):
    """The verifier's proposal. Advisory: only an analyst closes an investigation, and closing
    applies the usual evidence rules again. Every ID here was checked against stored evidence."""

    disposition: Disposition
    confidence: Confidence
    rationale: str
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    contradicting_evidence_ids: list[str] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)
    unsupported_claims: list[str] = Field(default_factory=list)
    adjustments: list[str] = Field(default_factory=list)  # changes made by deterministic checks
    open_questions: list[str] = Field(default_factory=list)  # from request_analyst_input


class AgentRun(BaseModel):
    run_id: str
    investigation_id: str
    status: AgentRunStatus
    model: str
    model_calls: int = 0
    tool_calls: int = 0
    checkpoint: dict[str, Any] = Field(default_factory=dict)
    assessment: Assessment | None = None
    error: str | None = None
    created_at: datetime
    updated_at: datetime
    finished_at: datetime | None = None


class AgentStep(BaseModel):
    """One entry of a run's activity log. ``payload`` holds validated, capped data."""

    run_id: str
    seq: int
    role: AgentRole
    kind: str  # route, model_output, tool_call, tool_result, tool_rejected, error, assessment
    summary: str
    payload: dict[str, Any] = Field(default_factory=dict)
    duration_ms: int | None = None
    created_at: datetime
