"""Response planner: one model call that turns the verifier's latest assessment into proposed
response steps. It is not part of an agent run (it does not use the run's budget) and only
runs when the analyst asks. Each proposal goes through the allowlisted ``propose_response``
tool, so the role check, argument schema, policy gate and audit apply exactly as for any tool.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from app.agents import prompts
from app.agents.graph import build_case_file
from app.agents.llm import ChatMessage, ModelError, ModelUnavailableError
from app.agents.schemas import InvalidOutputError, ResponsePlan, json_schema, parse_output
from app.agents.service import AgentService
from app.agents.tools import ToolContext, execute
from app.audit.log import FAILED, OK, AuditLog
from app.domain.enums import AgentRole, ChatKind, ChatMode, RecommendationStatus
from app.domain.errors import ResponseError
from app.domain.models import Recommendation
from app.policy.rules import CATALOGUE
from app.policy.service import ResponseService

CASE_EVIDENCE = 40


@dataclass
class PlanResult:
    summary: str
    recommendations: list[Recommendation] = field(default_factory=list)
    refused: list[str] = field(default_factory=list)  # proposals the tool layer rejected


class ResponsePlanner:
    def __init__(self, agents: AgentService, responses: ResponseService) -> None:
        self.agents = agents
        self.responses = responses
        self.audit = AuditLog(responses.investigations.conn)

    def plan(self, investigation_id: str, actor: str = "analyst") -> PlanResult:
        """Raises ``ResponseError`` when there is nothing to plan from or the model fails;
        the failure is audited and posted to the chat either way."""
        self.responses.require_open(investigation_id)
        assessment = self.responses.latest_assessment(investigation_id)
        if assessment is None:
            raise ResponseError(
                "run the agents first: the planner works from the verifier's assessment"
            )
        try:
            model = self.agents.model()
            ctx = ToolContext(
                investigations=self.responses.investigations,
                investigation_id=investigation_id,
                run_id=f"plan:{uuid.uuid4().hex[:12]}",
                role=AgentRole.RESPONSE_PLANNER,
                model_name=model.name,
            )
            plan = self._ask(model, ctx, investigation_id, assessment.model_dump(mode="json"))
        except (ModelUnavailableError, ModelError, InvalidOutputError) as exc:
            prefix = "AI unavailable" if isinstance(exc, ModelUnavailableError) else "No plan"
            message = f"{prefix}: {exc}"
            self.audit.record(
                actor,
                "response.plan",
                "investigation",
                investigation_id,
                investigation_id=investigation_id,
                outcome=FAILED,
                details={"error": message[:500]},
            )
            self._notice(investigation_id, f"Response planner failed. {message}")
            raise ResponseError(message) from exc

        result = PlanResult(summary=plan.summary)
        for proposal in plan.proposals:
            outcome = execute(ctx, "propose_response", proposal.model_dump(mode="json"))
            if outcome.ok:
                result.recommendations.append(
                    self.responses.get(outcome.result["recommendation_id"])
                )
            else:
                result.refused.append(outcome.summary)
        blocked = sum(r.status is RecommendationStatus.BLOCKED for r in result.recommendations)
        self.audit.record(
            actor,
            "response.plan",
            "investigation",
            investigation_id,
            investigation_id=investigation_id,
            outcome=OK,
            details={
                "run_id": ctx.run_id,
                "model": model.name,
                "assessment": assessment.disposition.value,
                "summary": plan.summary,
                "recommendations": [r.recommendation_id for r in result.recommendations],
                "refused": result.refused,
            },
        )
        self._notice(
            investigation_id,
            f"Response plan: {len(result.recommendations) - blocked} proposed, {blocked} "
            f"blocked by policy, {len(result.refused)} refused. {plan.summary} "
            "Review them on the Response tab; every action is simulated.",
            author=AgentRole.RESPONSE_PLANNER.value,
        )
        return result

    def _ask(
        self, model, ctx: ToolContext, investigation_id: str, assessment: dict
    ) -> ResponsePlan:
        settings = self.agents.settings
        entities = {
            kind: sorted(values)
            for kind, values in self.responses.scope_entities(investigation_id).items()
        }
        base = "\n\n".join(
            [
                build_case_file(self.responses.investigations, ctx, CASE_EVIDENCE),
                prompts.data_block("verifier assessment (latest completed run)", assessment),
                prompts.data_block("entities in this investigation's events", entities),
                prompts.action_catalogue(CATALOGUE),
                "Give your response plan.",
            ]
        )
        system = prompts.RESPONSE_PLANNER
        rejection = ""
        for attempt in range(settings.agent_max_invalid_outputs):
            user = base
            if rejection:
                user += f"\n\nYour previous reply was rejected: {rejection}. Reply with one "
                user += "valid JSON object."
            text = model.complete(
                [ChatMessage("system", system), ChatMessage("user", user)],
                json_schema(ResponsePlan),
            )
            try:
                return parse_output(ResponsePlan, text)
            except InvalidOutputError as exc:
                rejection = str(exc)[:300]
                if attempt == settings.agent_max_invalid_outputs - 1:
                    raise
        raise InvalidOutputError("no usable reply")  # pragma: no cover (loop always returns)

    def _notice(self, investigation_id: str, text: str, author: str = "system") -> None:
        self.agents.chat.add(
            investigation_id,
            author=author,
            mode=ChatMode.CONTROL,
            kind=ChatKind.NOTICE,
            content=text,
        )
