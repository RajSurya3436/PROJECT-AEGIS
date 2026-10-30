from __future__ import annotations


class SocCopilotError(Exception):
    """Base class for application errors."""


class NormalizationError(SocCopilotError):
    """A record could not be normalized; it is quarantined, not stored as an event."""


class IngestLimitError(SocCopilotError):
    """Input exceeds a configured size or row limit."""


class InvalidFilterError(SocCopilotError):
    """A search filter names a field or value that is not allowed."""


class UnsupportedInputError(SocCopilotError):
    """Input cannot be decoded or is in an unsupported format."""


class NotFoundError(SocCopilotError):
    """A referenced alert, rule or other record does not exist."""


class InvalidTransitionError(SocCopilotError):
    """An alert status change is not allowed by the lifecycle."""


class InvalidRuleConfigError(SocCopilotError):
    """A detection rule configuration names an unknown key or an invalid value."""


class InvestigationError(SocCopilotError):
    """An investigation action is invalid (closed investigation, uncited events, bad verdict)."""


class ResponseError(SocCopilotError):
    """A response proposal or decision is invalid (unknown action, wrong status, closed case)."""
