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
    RESPONSE_PLANNER = "response_planner"  # proposes simulated responses; never part of a run


SPECIALISTS: tuple[AgentRole, ...] = (AgentRole.LOG_INVESTIGATOR, AgentRole.THREAT_INTEL)


class AgentRunStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"  # the analyst paused it; resumable from its checkpoint
    WAITING = "waiting"  # an agent asked the analyst a question; resumes once answered
    COMPLETED = "completed"  # the verifier produced an assessment
    STOPPED = "stopped"  # the analyst stopped it, or the investigation was closed (final)
    LIMIT_REACHED = "limit_reached"  # a step, tool-call or time limit ended it early
    FAILED = "failed"  # model unavailable or repeatedly invalid output
    INTERRUPTED = "interrupted"  # the process ended mid-run; resumable from its checkpoint


# Executing on a worker (or about to). Only these can still change on their own.
ACTIVE_RUN_STATUSES = frozenset({AgentRunStatus.QUEUED, AgentRunStatus.RUNNING})
# Holding the investigation: at most one run per investigation may be in one of these.
OPEN_RUN_STATUSES = ACTIVE_RUN_STATUSES | {AgentRunStatus.PAUSED, AgentRunStatus.WAITING}
RESUMABLE_RUN_STATUSES = frozenset(
    {
        AgentRunStatus.QUEUED,
        AgentRunStatus.PAUSED,
        AgentRunStatus.WAITING,
        AgentRunStatus.INTERRUPTED,
    }
)


class ChatMode(StrEnum):
    ASK = "ask"  # read-only question; no evidence written, no external lookups
    INVESTIGATE = "investigate"  # instruct the agents (starts or redirects a run)
    CONTROL = "control"  # pause, resume, stop, redirect


class ChatKind(StrEnum):
    QUESTION = "question"  # analyst, Ask mode
    ANSWER = "answer"  # agent reply in Ask mode
    INSTRUCTION = "instruction"  # analyst, Investigate mode
    REDIRECT = "redirect"  # analyst, Control mode
    REPLY = "reply"  # analyst answering an agent's question (resumes a waiting run)
    PAUSE = "pause"
    RESUME = "resume"
    STOP = "stop"
    AGENT_QUESTION = "agent_question"  # request_analyst_input
    NOTICE = "notice"  # run started, finished, failed, ...


# Analyst messages the agent graph acts on, in order, at its next step boundary.
DIRECTIVE_KINDS = frozenset({ChatKind.INSTRUCTION, ChatKind.REDIRECT, ChatKind.REPLY})


class ResponseAction(StrEnum):
    """The only response actions that can be proposed. All are simulated: there is no firewall,
    EDR or identity integration, and nothing outside this app is changed."""

    BLOCK_IP = "block_ip"
    ISOLATE_HOST = "isolate_host"
    DISABLE_ACCOUNT = "disable_account"
    RESET_CREDENTIALS = "reset_credentials"
    REVOKE_SESSIONS = "revoke_sessions"
    COLLECT_TRIAGE = "collect_triage"
    WATCHLIST = "watchlist"
    ESCALATE = "escalate"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RecommendationStatus(StrEnum):
    PROPOSED = "proposed"  # awaiting the analyst (approval first if required)
    APPROVED = "approved"  # approved; can be simulated
    SIMULATED = "simulated"  # simulation recorded (final)
    REJECTED = "rejected"  # the analyst declined it (final)
    BLOCKED = "blocked"  # refused by policy when proposed (final); kept so it stays visible


OPEN_RECOMMENDATION_STATUSES = frozenset(
    {RecommendationStatus.PROPOSED, RecommendationStatus.APPROVED}
)
