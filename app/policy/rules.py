"""Deterministic response policy. The model may only *name* an action from the catalogue, a
target and the evidence; everything that decides whether the proposal stands is here.

- Only catalogued actions exist, and every one is simulated (no integration is implemented).
- The target must be of the right kind and appear in the investigation's own events, so text
  in a log or a provider reply cannot steer an action at some other system.
- ``block_ip`` is for external addresses only (public, or documentation ranges standing in
  for public ones in demo data); internal hosts are isolated instead.
- Every proposal cites evidence from the investigation.
- Agent proposals are proportionate to the verifier's latest assessment: high-impact actions
  need likely/confirmed malicious, medium ones at least suspicious_inconclusive.
- Analyst proposals of medium or high impact must cite at least one observation.
- Medium and high-impact actions need the analyst's approval before they can be simulated.
See ``docs/decisions/0003-response-policy-and-audit.md``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

from app.domain.enums import Disposition, EvidenceCategory, ResponseAction, RiskLevel
from app.domain.models import Evidence
from app.tools.reputation.base import classify_ip

TargetKind = Literal["ip", "host", "user", "entity", "none"]
NO_TARGET = "incident-response"
BLOCKABLE_SCOPES = ("public", "documentation")
MALICIOUS = (Disposition.CONFIRMED_MALICIOUS, Disposition.LIKELY_MALICIOUS)
SUSPICIOUS_OR_WORSE = (*MALICIOUS, Disposition.SUSPICIOUS_INCONCLUSIVE)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
KIND_NAMES = {"ip": "an IP", "host": "a host", "user": "a user", "entity": "an IP, host or user"}


@dataclass(frozen=True)
class ActionSpec:
    title: str
    target_kind: TargetKind
    risk: RiskLevel
    reversible: bool
    would: str  # what a real integration would do; {target} is filled in
    undo: str

    @property
    def requires_approval(self) -> bool:
        return self.risk is not RiskLevel.LOW


CATALOGUE: dict[ResponseAction, ActionSpec] = {
    ResponseAction.BLOCK_IP: ActionSpec(
        "Block an external IP at the perimeter",
        "ip",
        RiskLevel.HIGH,
        True,
        "add an inbound and outbound deny rule for {target} on the perimeter firewall",
        "remove the deny rule",
    ),
    ResponseAction.ISOLATE_HOST: ActionSpec(
        "Network-isolate a host",
        "host",
        RiskLevel.HIGH,
        True,
        "isolate {target} from the network through the EDR, keeping only the EDR channel",
        "release the host from isolation",
    ),
    ResponseAction.DISABLE_ACCOUNT: ActionSpec(
        "Disable a user account",
        "user",
        RiskLevel.HIGH,
        True,
        "disable the account {target} in the identity provider",
        "re-enable the account",
    ),
    ResponseAction.RESET_CREDENTIALS: ActionSpec(
        "Force a credential reset",
        "user",
        RiskLevel.MEDIUM,
        False,
        "force a password reset (and MFA re-registration) for {target}",
        "not reversible: the old credentials are gone",
    ),
    ResponseAction.REVOKE_SESSIONS: ActionSpec(
        "Revoke active sessions and tokens",
        "user",
        RiskLevel.MEDIUM,
        False,
        "revoke every active session and refresh token of {target}",
        "not reversible: the user signs in again",
    ),
    ResponseAction.COLLECT_TRIAGE: ActionSpec(
        "Collect a forensic triage package",
        "host",
        RiskLevel.LOW,
        True,
        "collect a read-only triage package (processes, autoruns, recent files, logs) "
        "from {target}",
        "nothing to undo: collection is read-only",
    ),
    ResponseAction.WATCHLIST: ActionSpec(
        "Add to a monitoring watchlist",
        "entity",
        RiskLevel.LOW,
        True,
        "add {target} to the SOC watchlist for heightened monitoring",
        "remove it from the watchlist",
    ),
    ResponseAction.ESCALATE: ActionSpec(
        "Escalate to incident response",
        "none",
        RiskLevel.LOW,
        True,
        "open an incident and page the incident response on-call",
        "close the incident",
    ),
}


@dataclass(frozen=True)
class PolicyContext:
    """What the policy may consult, built by code from stored state."""

    scope: dict[str, set[str]]  # "ip" / "host" / "user" -> values in the investigation's events
    evidence: dict[str, Evidence]
    assessment: Disposition | None  # the verifier's latest, for agent proposals
    by_agent: bool


@dataclass
class PolicyDecision:
    target: str
    allowed: bool = True
    notes: list[str] = field(default_factory=list)

    def refuse(self, reason: str) -> None:
        self.allowed = False
        self.notes.append(f"Blocked: {reason}")


def normalise_target(action: ResponseAction, target: str) -> str:
    spec = CATALOGUE[action]
    target = (target or "").strip()
    if spec.target_kind == "none":
        return NO_TARGET
    if spec.target_kind == "ip":
        ip, _ = classify_ip(target)
        return ip or target[:256]
    return target[:256]


def evaluate(
    action: ResponseAction, target: str, evidence_ids: list[str], ctx: PolicyContext
) -> PolicyDecision:
    spec = CATALOGUE[action]
    decision = PolicyDecision(normalise_target(action, target))
    _check_target(spec, action, decision, ctx)
    _check_evidence(spec, evidence_ids, decision, ctx)
    _check_proportionality(spec, action, decision, ctx)
    if decision.allowed:
        if spec.requires_approval:
            decision.notes.append(
                f"{spec.risk.value.capitalize()} impact: needs analyst approval before it can be "
                "simulated."
            )
        if not spec.reversible:
            decision.notes.append(f"Not reversible ({spec.undo}).")
    return decision


def _check_target(
    spec: ActionSpec, action: ResponseAction, decision: PolicyDecision, ctx: PolicyContext
) -> None:
    target = decision.target
    if spec.target_kind == "none":
        return
    if not target or _CONTROL.search(target):
        decision.refuse(
            f"{action.value} needs {KIND_NAMES[spec.target_kind]} from the investigation"
        )
        return
    if spec.target_kind == "ip":
        ip, scope = classify_ip(target)
        if ip is None:
            decision.refuse(f"{target!r} is not an IP address")
            return
        if scope not in BLOCKABLE_SCOPES:
            decision.refuse(
                f"{ip} is a {scope.replace('_', '-')} address; block_ip is for external "
                "addresses (isolate an internal host instead)"
            )
            return
    kinds = ("ip", "host", "user") if spec.target_kind == "entity" else (spec.target_kind,)
    known = {v.casefold(): v for kind in kinds for v in sorted(ctx.scope.get(kind, set()))}
    if target.casefold() not in known:
        wanted = KIND_NAMES[spec.target_kind]
        decision.refuse(f"{target!r} is not {wanted} seen in this investigation's events")
        return
    decision.target = known[target.casefold()]  # as spelled in the events


def _check_evidence(
    spec: ActionSpec, evidence_ids: list[str], decision: PolicyDecision, ctx: PolicyContext
) -> None:
    cited = list(dict.fromkeys(evidence_ids))
    if not cited:
        decision.refuse("cite the evidence that supports the action")
        return
    unknown = [e for e in cited if e not in ctx.evidence]
    if unknown:
        decision.refuse(f"evidence not in this investigation: {', '.join(unknown)}")
        return
    if (
        not ctx.by_agent
        and spec.risk is not RiskLevel.LOW
        and not any(ctx.evidence[e].category is EvidenceCategory.OBSERVATION for e in cited)
    ):
        decision.refuse(f"a {spec.risk.value}-impact action must cite at least one observation")


def _check_proportionality(
    spec: ActionSpec, action: ResponseAction, decision: PolicyDecision, ctx: PolicyContext
) -> None:
    if not ctx.by_agent or spec.risk is RiskLevel.LOW:
        return
    needed = MALICIOUS if spec.risk is RiskLevel.HIGH else SUSPICIOUS_OR_WORSE
    if ctx.assessment not in needed:
        current = ctx.assessment.value if ctx.assessment else "no assessment"
        decision.refuse(
            f"{action.value} is {spec.risk.value} impact; an agent may only propose it when the "
            f"assessment is {' or '.join(d.value for d in needed)} (it is {current})"
        )


def simulate(action: ResponseAction, target: str) -> dict[str, str | bool]:
    """What would happen. Nothing is executed and no external system exists to contact."""
    spec = CATALOGUE[action]
    return {
        "mode": "simulation",
        "executed": False,
        "would": "Would " + spec.would.format(target=target) + ".",
        "undo": spec.undo,
        "integration": "none: this app has no firewall, EDR or identity integration",
    }
