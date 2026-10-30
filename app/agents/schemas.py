"""Strict schemas for everything a model may return. A reply that does not validate is
rejected and never acted on; the same schema is sent to Ollama as the ``format`` constraint."""

from __future__ import annotations

import json
from typing import Annotated, Any, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

from app.domain.enums import Confidence, Disposition, ResponseAction

Text = Annotated[str, StringConstraints(strip_whitespace=True, max_length=1_500)]
Short = Annotated[str, StringConstraints(strip_whitespace=True, max_length=500)]
Id = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)]


class ModelOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RouteDecision(ModelOutput):
    """Orchestrator: which specialist works next, or hand over to the verifier."""

    next: Literal["log_investigator", "threat_intel", "verifier"]
    instruction: Short = ""
    rationale: Short = ""


class SpecialistAction(ModelOutput):
    """One specialist step: call a tool, or finish the turn with a summary."""

    action: Literal["tool_call", "finish"]
    tool: Annotated[str, StringConstraints(strip_whitespace=True, max_length=64)] | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    rationale: Short = ""
    summary: Text = ""


class VerifierReport(ModelOutput):
    disposition: Disposition
    confidence: Confidence
    rationale: Text
    supporting_evidence_ids: list[Id] = Field(default_factory=list, max_length=30)
    contradicting_evidence_ids: list[Id] = Field(default_factory=list, max_length=30)
    gaps: list[Short] = Field(default_factory=list, max_length=10)
    unsupported_claims: list[Short] = Field(default_factory=list, max_length=10)


class ProposalItem(ModelOutput):
    action: ResponseAction
    target: Annotated[str, StringConstraints(strip_whitespace=True, max_length=256)] = ""
    rationale: Short
    evidence_ids: list[Id] = Field(default_factory=list, max_length=10)


class ResponsePlan(ModelOutput):
    """Response planner: a short plan and at most five proposals. Each proposal still goes
    through the propose_response tool and the policy gate."""

    summary: Text
    proposals: list[ProposalItem] = Field(default_factory=list, max_length=5)


def json_schema(model: type[BaseModel]) -> dict[str, Any]:
    """The model's JSON schema with ``$ref``s inlined (simpler for constrained decoding)."""
    schema = model.model_json_schema()
    defs = schema.pop("$defs", {})

    def resolve(node: Any) -> Any:
        if isinstance(node, dict):
            if "$ref" in node:
                return resolve(defs[node["$ref"].rsplit("/", 1)[-1]])
            return {k: resolve(v) for k, v in node.items()}
        if isinstance(node, list):
            return [resolve(v) for v in node]
        return node

    return resolve(schema)


T = TypeVar("T", bound=ModelOutput)


class InvalidOutputError(ValueError):
    """A model reply was not valid JSON for the expected schema."""


def parse_output(model: type[T], text: str) -> T:
    """Parse one JSON object. Tolerates a fenced code block around it (common with small
    models), nothing else: no partial objects, no extra keys."""
    candidate = text.strip()
    if candidate.startswith("```"):
        candidate = candidate.strip("`").removeprefix("json").strip()
    try:
        data = json.loads(candidate)
    except json.JSONDecodeError as exc:
        raise InvalidOutputError(f"reply is not valid JSON ({exc.msg})") from None
    if not isinstance(data, dict):
        raise InvalidOutputError("reply must be a JSON object")
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(map(str, e['loc'])) or 'reply'}: {e['msg']}" for e in exc.errors()[:5]
        )
        raise InvalidOutputError(problems) from None
