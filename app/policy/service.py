"""Response recommendations: propose (through the policy gate), approve, reject, simulate.

Every proposal is stored, including ones the policy blocks, so the analyst sees what was
suggested and why it was refused. Nothing here touches anything outside this app: "simulate"
records what a real integration would have done.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime

from app.audit.log import OK, REJECTED, AuditLog
from app.domain.enums import (
    AgentRunStatus,
    InvestigationStatus,
    RecommendationStatus,
    ResponseAction,
)
from app.domain.errors import NotFoundError, ResponseError
from app.domain.models import Assessment, Recommendation
from app.investigations.service import InvestigationService
from app.policy.rules import CATALOGUE, PolicyContext, evaluate, simulate
from app.storage.agents import AgentRunRepository
from app.storage.db import transaction
from app.storage.responses import RecommendationRepository

MAX_RATIONALE_CHARS = 1_000
MAX_NOTE_CHARS = 500
MAX_CITED = 20


class ResponseService:
    def __init__(
        self,
        investigations: InvestigationService,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        conn = investigations.conn
        self.investigations = investigations
        self.repo = RecommendationRepository(conn)
        self.runs = AgentRunRepository(conn)
        self.audit = AuditLog(conn)
        self._clock = clock

    # --- reading ---------------------------------------------------------------------------

    def list(self, investigation_id: str) -> list[Recommendation]:
        return self.repo.for_investigation(investigation_id)

    def get(self, recommendation_id: str) -> Recommendation:
        rec = self.repo.get(recommendation_id)
        if rec is None:
            raise NotFoundError(f"unknown recommendation: {recommendation_id}")
        return rec

    def latest_assessment(self, investigation_id: str) -> Assessment | None:
        """The verifier's assessment from the most recent completed run, if any."""
        for run in self.runs.for_investigation(investigation_id):
            if run.status is AgentRunStatus.COMPLETED and run.assessment is not None:
                return run.assessment
        return None

    def scope_entities(self, investigation_id: str) -> dict[str, set[str]]:
        entities: dict[str, set[str]] = {"ip": set(), "host": set(), "user": set()}
        for event in self.investigations.scope_events(investigation_id):
            entities["ip"].update(ip for ip in (event.src_ip, event.dst_ip) if ip)
            if event.host:
                entities["host"].add(event.host)
            if event.user:
                entities["user"].add(event.user)
        return entities

    # --- proposing -------------------------------------------------------------------------

    def propose(
        self,
        investigation_id: str,
        action: ResponseAction | str,
        target: str,
        rationale: str,
        evidence_ids: list[str],
        actor: str,
    ) -> Recommendation:
        """Store a proposal with the policy's verdict on it. Returns the existing undecided
        recommendation when the same action and target is already waiting for a decision."""
        self.require_open(investigation_id)
        try:
            action = ResponseAction(action)
        except ValueError:
            known = ", ".join(a.value for a in ResponseAction)
            raise ResponseError(f"unknown response action {action!r}; known: {known}") from None
        rationale = (rationale or "").strip()
        if not rationale:
            raise ResponseError("explain why the action is needed")
        if len(rationale) > MAX_RATIONALE_CHARS:
            raise ResponseError(f"rationale is longer than {MAX_RATIONALE_CHARS} characters")
        cited = list(dict.fromkeys(evidence_ids))[:MAX_CITED]
        by_agent = actor.startswith("agent:")
        assessment = self.latest_assessment(investigation_id) if by_agent else None
        context = PolicyContext(
            scope=self.scope_entities(investigation_id),
            evidence={e.evidence_id: e for e in self.investigations.evidence(investigation_id)},
            assessment=assessment.disposition if assessment else None,
            by_agent=by_agent,
        )
        decision = evaluate(action, target, cited, context)
        existing = self.repo.open_for(investigation_id, action, decision.target)
        if existing is not None:
            return existing
        spec = CATALOGUE[action]
        rec = Recommendation(
            recommendation_id="rec-" + uuid.uuid4().hex[:12],
            investigation_id=investigation_id,
            action=action,
            target=decision.target,
            rationale=rationale,
            evidence_ids=cited,
            risk=spec.risk,
            reversible=spec.reversible,
            requires_approval=spec.requires_approval,
            status=RecommendationStatus.PROPOSED
            if decision.allowed
            else RecommendationStatus.BLOCKED,
            policy_notes=decision.notes,
            proposed_by=actor,
            proposed_at=self._clock(),
        )
        with transaction(self.repo.conn):  # the proposal and its audit row, or neither
            self._add_and_audit(rec, actor, decision.allowed, decision.notes, context)
        return rec

    def _add_and_audit(
        self,
        rec: Recommendation,
        actor: str,
        allowed: bool,
        notes: list[str],
        context: PolicyContext,
    ) -> None:
        self.repo.add(rec)
        self.audit.record(
            actor,
            "response.proposed" if allowed else "response.blocked_by_policy",
            "recommendation",
            rec.recommendation_id,
            investigation_id=rec.investigation_id,
            outcome=OK if allowed else REJECTED,
            details={
                "action": rec.action.value,
                "target": rec.target,
                "risk": rec.risk.value,
                "evidence_ids": rec.evidence_ids,
                "policy_notes": notes,
                "assessment": context.assessment.value if context.assessment else None,
            },
        )

    # --- deciding --------------------------------------------------------------------------

    def approve(self, recommendation_id: str, actor: str, note: str = "") -> Recommendation:
        rec = self._decidable(recommendation_id)
        if rec.status is not RecommendationStatus.PROPOSED:
            raise ResponseError(f"recommendation is {rec.status.value}; only proposed ones")
        if not rec.requires_approval:
            raise ResponseError("low-impact action: no approval needed, simulate it directly")
        self._move(rec, RecommendationStatus.APPROVED, actor, note, "response.approved")
        return self.get(recommendation_id)

    def reject(self, recommendation_id: str, actor: str, note: str = "") -> Recommendation:
        rec = self._decidable(recommendation_id)
        self._move(rec, RecommendationStatus.REJECTED, actor, note, "response.rejected")
        return self.get(recommendation_id)

    def simulate(self, recommendation_id: str, actor: str) -> Recommendation:
        rec = self._decidable(recommendation_id)
        if rec.requires_approval and rec.status is not RecommendationStatus.APPROVED:
            raise ResponseError(f"{rec.risk.value}-impact action: approve it before simulating")
        simulation = {**simulate(rec.action, rec.target), "simulated_by": actor}
        with transaction(self.repo.conn):
            if not self.repo.record_simulation(recommendation_id, rec.status, simulation):
                raise ResponseError("the recommendation changed meanwhile; reload and try again")
            self.audit.record(
                actor,
                "response.simulated",
                "recommendation",
                recommendation_id,
                investigation_id=rec.investigation_id,
                details={"action": rec.action.value, "target": rec.target, **simulation},
            )
        return self.get(recommendation_id)

    def _decidable(self, recommendation_id: str) -> Recommendation:
        rec = self.get(recommendation_id)
        self.require_open(rec.investigation_id)
        if rec.status not in (RecommendationStatus.PROPOSED, RecommendationStatus.APPROVED):
            raise ResponseError(f"recommendation is {rec.status.value}; nothing left to decide")
        return rec

    def _move(
        self,
        rec: Recommendation,
        status: RecommendationStatus,
        actor: str,
        note: str,
        action: str,
    ) -> None:
        note = (note or "").strip()[:MAX_NOTE_CHARS]
        with transaction(self.repo.conn):
            if not self.repo.decide(rec.recommendation_id, rec.status, status, actor, note):
                raise ResponseError("the recommendation changed meanwhile; reload and try again")
            self.audit.record(
                actor,
                action,
                "recommendation",
                rec.recommendation_id,
                investigation_id=rec.investigation_id,
                details={"action": rec.action.value, "target": rec.target, "note": note},
            )

    def require_open(self, investigation_id: str) -> None:
        if self.investigations.get(investigation_id).status is not InvestigationStatus.OPEN:
            raise ResponseError("investigation is closed; reopen it to change its response")
