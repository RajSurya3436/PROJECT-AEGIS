from __future__ import annotations

from enum import StrEnum


class EventType(StrEnum):
    AUTH = "auth"
    PROCESS = "process"
    NETWORK = "network"
    OTHER = "other"


class Outcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class SourceType(StrEnum):
    DEMO_REPLAY = "demo_replay"
    UPLOAD = "upload"
    FILE_TAIL = "file_tail"
    HTTP = "http"


class SourceStatus(StrEnum):
    IDLE = "idle"
    INGESTING = "ingesting"
    OK = "ok"
    ERROR = "error"


class InputFormat(StrEnum):
    JSONL = "jsonl"
    NDJSON = "ndjson"
    CSV = "csv"
    JSON = "json"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_RANK: dict[Severity, int] = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class AlertStatus(StrEnum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


# Analyst-driven lifecycle. Closed alerts can only be reopened to ``new``.
ALLOWED_TRANSITIONS: dict[AlertStatus, frozenset[AlertStatus]] = {
    AlertStatus.NEW: frozenset(
        {
            AlertStatus.ACKNOWLEDGED,
            AlertStatus.INVESTIGATING,
            AlertStatus.RESOLVED,
            AlertStatus.FALSE_POSITIVE,
        }
    ),
    AlertStatus.ACKNOWLEDGED: frozenset(
        {AlertStatus.INVESTIGATING, AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE}
    ),
    AlertStatus.INVESTIGATING: frozenset({AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE}),
    AlertStatus.RESOLVED: frozenset({AlertStatus.NEW}),
    AlertStatus.FALSE_POSITIVE: frozenset({AlertStatus.NEW}),
}


class ReputationStatus(StrEnum):
    """Outcome of one provider lookup. Only ``fresh`` and ``cached`` carry provider data."""

    FRESH = "fresh"
    CACHED = "cached"
    NOT_CONFIGURED = "not_configured"
    DISABLED = "disabled"
    SKIPPED = "skipped"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    PROVIDER_ERROR = "provider_error"


class InvestigationStatus(StrEnum):
    OPEN = "open"
    CLOSED = "closed"


class Disposition(StrEnum):
    CONFIRMED_MALICIOUS = "confirmed_malicious"
    LIKELY_MALICIOUS = "likely_malicious"
    SUSPICIOUS_INCONCLUSIVE = "suspicious_inconclusive"
    BENIGN_OR_EXPECTED = "benign_or_expected"
    INSUFFICIENT_DATA = "insufficient_data"


class Confidence(StrEnum):
    """Qualitative only: the blueprint forbids invented numerical calibration."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class EvidenceCategory(StrEnum):
    OBSERVATION = "observation"  # directly seen in stored events or tool results
    INFERENCE = "inference"  # a conclusion drawn from observations
    CONTRADICTION = "contradiction"  # evidence that argues against another claim
    MISSING_TELEMETRY = "missing_telemetry"  # data that would help but is absent


class EvidenceSource(StrEnum):
    ALERT = "alert"
    EVENT = "event"
    LOCAL_IOC = "local_ioc"
    REPUTATION = "reputation"
    COVERAGE_CHECK = "coverage_check"
    ANALYST = "analyst"
    AGENT = "agent"  # written by an agent through the add_evidence tool


class AgentRole(StrEnum):
    """One local model serves every role; only the prompt and the allowed tools differ."""

    ORCHESTRATOR = "orchestrator"
    LOG_INVESTIGATOR = "log_investigator"
    THREAT_INTEL = "threat_intel"
    VERIFIER = "verifier"


SPECIALISTS: tuple[AgentRole, ...] = (AgentRole.LOG_INVESTIGATOR, AgentRole.THREAT_INTEL)


class AgentRunStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"  # the verifier produced an assessment
    STOPPED = "stopped"  # an analyst asked it to stop
    LIMIT_REACHED = "limit_reached"  # a step, tool-call or time limit ended it early
    FAILED = "failed"  # model unavailable or repeatedly invalid output
    INTERRUPTED = "interrupted"  # the process ended mid-run; resumable from its checkpoint


ACTIVE_RUN_STATUSES = frozenset({AgentRunStatus.QUEUED, AgentRunStatus.RUNNING})
