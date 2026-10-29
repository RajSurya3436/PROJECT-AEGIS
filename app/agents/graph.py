"""The agent graph: a small, explicit state machine.

    orchestrate --> specialist (log_investigator | threat_intel) --> orchestrate --> ...
         \\--> verify --> done

Every transition is decided here, not by the model: the orchestrator only *proposes* the next
specialist, and the graph overrides it when a limit is near (the last model call is always kept
for the verifier). After every step the whole ``RunState`` is checkpointed, so an interrupted
run resumes from where it stopped. Model replies that fail validation are retried with the
error, then the run fails; tool calls that are refused go back to the model as results.

The analyst steers a run through ``RunControls``, read at every step boundary: pause and stop
requests, and directives (instructions, redirects, replies to an agent's question). A redirect
ends the current turn and sends the work where the analyst said; evidence is never removed.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from pydantic import BaseModel, Field

from app.agents import prompts
from app.agents.llm import ChatMessage, ChatModel, ModelError, ModelUnavailableError
from app.agents.schemas import (
    InvalidOutputError,
    ModelOutput,
    RouteDecision,
    SpecialistAction,
    VerifierReport,
    json_schema,
    parse_output,
)
from app.agents.tools import (
    BuildTimelineArgs,
    ToolContext,
    build_timeline,
    compact_evidence,
    execute,
    tools_for,
)
from app.config import Settings
from app.domain.enums import (
    AgentRole,
    AgentRunStatus,
    Confidence,
    Disposition,
    EvidenceCategory,
    EvidenceSource,
    InvestigationStatus,
)
from app.domain.models import Assessment, ChatEntry, Evidence
from app.investigations.service import InvestigationService
from app.storage.agents import AgentRunRepository

MAX_NOTES = 12
MAX_ANALYST_MESSAGES = 10
CASE_EVIDENCE = 40
VERIFIER_EVIDENCE = 80
FULL_RESULTS_IN_TURN = 2
MALICIOUS = (Disposition.CONFIRMED_MALICIOUS, Disposition.LIKELY_MALICIOUS)
# Sources whose observations come from deterministic code, not from a model's own claim.
GROUNDED_SOURCES = frozenset(
    {
        EvidenceSource.ALERT,
        EvidenceSource.EVENT,
        EvidenceSource.LOCAL_IOC,
        EvidenceSource.REPUTATION,
        EvidenceSource.ANALYST,
    }
)


@dataclass(frozen=True)
class Limits:
    max_model_calls: int
    max_tool_calls: int
    max_steps_per_turn: int
    max_specialist_turns: int
    max_run_seconds: int
    max_invalid_outputs: int

    @classmethod
    def from_settings(cls, settings: Settings) -> Limits:
        return cls(
            max_model_calls=settings.agent_max_model_calls,
            max_tool_calls=settings.agent_max_tool_calls,
            max_steps_per_turn=settings.agent_max_steps_per_turn,
            max_specialist_turns=settings.agent_max_specialist_turns,
            max_run_seconds=settings.agent_max_run_seconds,
            max_invalid_outputs=settings.agent_max_invalid_outputs,
        )


class RunState(BaseModel):
    """Everything needed to continue a run. Stored as the run's checkpoint after each step."""

    node: Literal["orchestrate", "specialist", "verify", "done"] = "orchestrate"
    role: AgentRole | None = None
    instruction: str = ""
    turn: list[dict[str, Any]] = Field(default_factory=list)
    turn_steps: int = 0
    specialist_turns: int = 0
    notes: list[dict[str, str]] = Field(default_factory=list)
    returned_event_ids: list[str] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)
    model_calls: int = 0
    tool_calls: int = 0
    invalid_outputs: int = 0
    last_rejection: str = ""
    elapsed_seconds: float = 0.0
    analyst_messages: list[dict[str, str]] = Field(default_factory=list)
    waiting_question: str = ""  # set while the run waits for the analyst's reply
    bonus_turns: int = 0  # extra specialist turns granted by analyst directives (capped)
    # Analyst instructions not yet routed, oldest first. One is routed each time the work
    # comes back to the orchestrator, so several instructions are carried out in order.
    queued: list[dict[str, Any]] = Field(default_factory=list)
    awaiting_route: bool = False  # an untargeted instruction waits for the orchestrator


class RunControls(Protocol):
    """How the analyst reaches a run between steps (backed by the database in practice)."""

    def requested(self) -> str | None:
        """``pause``, ``stop`` or None."""
        ...

    def take_directives(self) -> list[ChatEntry]:
        """Pending instructions, redirects and replies, each returned once."""
        ...


class NoControls:
    def requested(self) -> str | None:
        return None

    def take_directives(self) -> list[ChatEntry]:
        return []


@dataclass(frozen=True)
class RunOutcome:
    status: AgentRunStatus
    assessment: Assessment | None = None
    error: str | None = None


class AgentGraph:
    def __init__(
        self,
        investigations: InvestigationService,
        runs: AgentRunRepository,
        model: ChatModel,
        limits: Limits,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.investigations = investigations
        self.runs = runs
        self.model = model
        self.limits = limits
        self._clock = clock

    def run(
        self,
        run_id: str,
        investigation_id: str,
        state: RunState,
        controls: RunControls | None = None,
    ) -> RunOutcome:
        controls = controls or NoControls()
        started = self._clock()
        base_elapsed = state.elapsed_seconds
        limits = self.limits
        while state.node != "done":
            state.elapsed_seconds = base_elapsed + (self._clock() - started)
            self._checkpoint(run_id, state)
            if self.investigations.get(investigation_id).status is not InvestigationStatus.OPEN:
                return RunOutcome(AgentRunStatus.STOPPED, error="the investigation was closed")
            requested = controls.requested()
            if requested == "stop":
                return RunOutcome(AgentRunStatus.STOPPED, error="stopped by the analyst")
            if requested == "pause":
                self._log(run_id, AgentRole.ORCHESTRATOR, "control", "paused by the analyst")
                return RunOutcome(AgentRunStatus.PAUSED)
            directives = controls.take_directives()
            if directives:
                self._receive(run_id, state, directives)
            if self._route_queued(run_id, state) or directives:
                self._checkpoint(run_id, state)
            if state.waiting_question:
                return RunOutcome(AgentRunStatus.WAITING)
            if state.elapsed_seconds > limits.max_run_seconds:
                return self._limit(run_id, f"time limit of {limits.max_run_seconds} s reached")
            if state.model_calls >= limits.max_model_calls:
                return self._limit(run_id, f"model call limit ({limits.max_model_calls}) reached")
            if state.node != "verify" and state.model_calls >= limits.max_model_calls - 1:
                self._to_verifier(run_id, state, "model call budget nearly used")
            if state.node == "specialist" and state.tool_calls >= limits.max_tool_calls:
                self._end_turn(state, "tool call limit reached")
                self._to_verifier(run_id, state, f"tool call limit ({limits.max_tool_calls})")
            try:
                outcome = self._step(run_id, investigation_id, state)
            except ModelUnavailableError as exc:
                self._log(run_id, AgentRole.ORCHESTRATOR, "error", str(exc))
                return RunOutcome(AgentRunStatus.FAILED, error=f"AI unavailable: {exc}")
            except (ModelError, InvalidOutputError) as exc:
                state.invalid_outputs += 1
                state.last_rejection = str(exc)[:300]
                if state.invalid_outputs >= limits.max_invalid_outputs:
                    return RunOutcome(
                        AgentRunStatus.FAILED,
                        error=f"{state.invalid_outputs} unusable model replies in a row: {exc}",
                    )
                continue
            if outcome is not None:
                state.elapsed_seconds = base_elapsed + (self._clock() - started)
                self._checkpoint(run_id, state)
                return outcome
        return RunOutcome(AgentRunStatus.COMPLETED)

    # --- nodes -----------------------------------------------------------------------------

    def _step(self, run_id: str, investigation_id: str, state: RunState) -> RunOutcome | None:
        if state.node == "orchestrate":
            self._orchestrate(run_id, investigation_id, state)
            return None
        if state.node == "specialist":
            return self._specialist(run_id, investigation_id, state)
        return self._verify(run_id, investigation_id, state)

    def _receive(self, run_id: str, state: RunState, directives: list[ChatEntry]) -> None:
        """Take in a batch of analyst directives. A reply answers the waiting question and the
        turn carries on. Instructions and redirects join the queue; if any arrived, the
        current specialist turn is cut short once (not once per message). Evidence, notes and
        the step log stay."""
        interrupting = False
        for directive in directives:
            text = directive.content.strip()
            kind = directive.kind.value
            message: dict[str, str] = {"kind": kind, "text": text}
            if state.waiting_question:
                message["in_reply_to"] = state.waiting_question
                state.waiting_question = ""
            state.analyst_messages = [*state.analyst_messages, message][-MAX_ANALYST_MESSAGES:]
            if kind == "reply" and "in_reply_to" in message:
                self._log(
                    run_id,
                    AgentRole.ORCHESTRATOR,
                    "redirect",
                    f"analyst replied: {text}",
                    {"message_id": directive.message_id, "text": text},
                )
                continue
            interrupting = True
            target = directive.target_role
            state.queued.append(
                {
                    "message_id": directive.message_id,
                    "kind": kind,
                    "text": text,
                    "target": target.value if target else None,
                }
            )
        if interrupting and state.node == "specialist":
            if state.turn_steps:
                self._end_turn(state, "turn ended: redirected by the analyst")
            else:  # nothing was done yet: drop the turn without a note or using up a turn
                state.node, state.role, state.instruction = "orchestrate", None, ""
                state.turn, state.turn_steps = [], 0
        if interrupting:
            state.awaiting_route = False  # the newest instructions take over

    def _route_queued(self, run_id: str, state: RunState) -> bool:
        """Route the oldest queued instruction when the work is back with the orchestrator
        (or about to be verified). Returns True if something was routed."""
        if not state.queued or state.awaiting_route or state.node == "specialist":
            return False
        item = state.queued.pop(0)
        target = AgentRole(item["target"]) if item["target"] else None
        if target is not AgentRole.VERIFIER:
            state.bonus_turns = min(state.bonus_turns + 1, self.limits.max_specialist_turns)
        if target in (AgentRole.LOG_INVESTIGATOR, AgentRole.THREAT_INTEL):
            state.node, state.role, state.instruction = "specialist", target, item["text"]
            state.turn, state.turn_steps = [], 0
        elif target is AgentRole.VERIFIER:
            state.node = "verify"
        else:
            state.node, state.awaiting_route = "orchestrate", True
        where = target.value if target else "orchestrator"
        self._log(
            run_id,
            AgentRole.ORCHESTRATOR,
            "redirect",
            f"analyst {item['kind']} -> {where}: {item['text']}",
            {"message_id": item["message_id"], "target": where, "text": item["text"]},
        )
        return True

    def _orchestrate(self, run_id: str, investigation_id: str, state: RunState) -> None:
        ctx = self._tool_context(run_id, investigation_id, AgentRole.ORCHESTRATOR, state)
        user = "\n\n".join(
            [
                self._case_file(ctx, state, CASE_EVIDENCE),
                f"Specialist turns used: {state.specialist_turns} of {self._turn_limit(state)}.",
                "Decide who works next.",
            ]
        )
        decision = self._call(
            run_id, AgentRole.ORCHESTRATOR, prompts.ORCHESTRATOR, user, state, RouteDecision
        )
        self._sync(ctx, state)
        state.awaiting_route = False
        if decision.next == "verifier":
            self._to_verifier(run_id, state, decision.rationale or "orchestrator chose to verify")
            return
        if state.specialist_turns >= self._turn_limit(state):
            self._to_verifier(run_id, state, "specialist turn limit reached")
            return
        state.node, state.role = "specialist", AgentRole(decision.next)
        state.instruction = decision.instruction or "Investigate the alert."
        state.turn, state.turn_steps = [], 0
        self._log(
            run_id,
            AgentRole.ORCHESTRATOR,
            "route",
            f"-> {decision.next}: {state.instruction}",
            {
                "next": decision.next,
                "instruction": state.instruction,
                "rationale": decision.rationale,
            },
        )

    def _specialist(self, run_id: str, investigation_id: str, state: RunState) -> RunOutcome | None:
        role = state.role
        assert role is not None
        ctx = self._tool_context(run_id, investigation_id, role, state)
        system = "\n\n".join(
            [
                prompts.LOG_INVESTIGATOR
                if role is AgentRole.LOG_INVESTIGATOR
                else prompts.THREAT_INTEL,
                prompts.tool_catalogue(tools_for(role)),
                prompts.SPECIALIST_REPLY,
            ]
        )
        user = "\n\n".join(
            [
                self._case_file(ctx, state, CASE_EVIDENCE),
                prompts.data_block("instruction from the orchestrator", state.instruction),
                self._turn_so_far(state),
                f"Step {state.turn_steps + 1} of at most {self.limits.max_steps_per_turn}.",
            ]
        )
        action = self._call(run_id, role, system, user, state, SpecialistAction)
        if action.action == "finish" or not action.tool:
            self._log(
                run_id,
                role,
                "model_output",
                f"finished: {action.summary[:200]}",
                {"summary": action.summary},
            )
            self._end_turn(state, action.summary or "(no summary)")
            self._sync(ctx, state)
            return None
        self._log(
            run_id,
            role,
            "tool_call",
            f"{action.tool}: {action.rationale[:150]}",
            {"tool": action.tool, "arguments": action.arguments, "rationale": action.rationale},
        )
        started = self._clock()
        outcome = execute(ctx, action.tool, action.arguments)
        state.tool_calls += 1
        self._sync(ctx, state)
        self._log(
            run_id,
            role,
            "tool_result" if outcome.ok else "tool_rejected",
            f"{action.tool}: {outcome.summary}",
            outcome.result,
            int((self._clock() - started) * 1000),
        )
        state.turn.append(
            {
                "tool": action.tool,
                "arguments": action.arguments,
                "ok": outcome.ok,
                "summary": outcome.summary,
                "result": outcome.result,
            }
        )
        state.turn_steps += 1
        if state.turn_steps >= self.limits.max_steps_per_turn:
            self._end_turn(
                state,
                f"turn ended at the {self.limits.max_steps_per_turn}-step "
                "limit before the specialist finished",
            )
        if ctx.waiting_question:  # after the limit check: a reply never buys an extra step
            state.waiting_question = ctx.waiting_question
            return RunOutcome(AgentRunStatus.WAITING)
        return None

    def _verify(self, run_id: str, investigation_id: str, state: RunState) -> RunOutcome:
        ctx = self._tool_context(run_id, investigation_id, AgentRole.VERIFIER, state)
        user = "\n\n".join(
            [self._case_file(ctx, state, VERIFIER_EVIDENCE), "Give your assessment."]
        )
        report = self._call(
            run_id, AgentRole.VERIFIER, prompts.VERIFIER, user, state, VerifierReport
        )
        assessment = check_assessment(
            report, self.investigations.evidence(investigation_id), state.open_questions
        )
        state.node = "done"
        self._log(
            run_id,
            AgentRole.VERIFIER,
            "assessment",
            f"{assessment.disposition.value} ({assessment.confidence.value})",
            assessment.model_dump(mode="json"),
        )
        return RunOutcome(AgentRunStatus.COMPLETED, assessment)

    # --- helpers ---------------------------------------------------------------------------

    def _call(
        self,
        run_id: str,
        role: AgentRole,
        system: str,
        user: str,
        state: RunState,
        schema: type[ModelOutput],
    ) -> Any:
        if state.last_rejection:
            user += (
                f"\n\nYour previous reply was rejected: {state.last_rejection}. Reply again "
                "with one valid JSON object."
            )
        state.model_calls += 1
        started = self._clock()
        try:
            text = self.model.complete(
                [ChatMessage("system", system), ChatMessage("user", user)], json_schema(schema)
            )
        except ModelError as exc:
            self._log(run_id, role, "error", f"model call failed: {exc}")
            raise
        duration = int((self._clock() - started) * 1000)
        try:
            parsed = parse_output(schema, text)
        except InvalidOutputError as exc:
            self._log(
                run_id, role, "error", f"invalid reply: {exc}", {"reply": text[:500]}, duration
            )
            raise
        state.invalid_outputs, state.last_rejection = 0, ""
        if schema is RouteDecision or schema is VerifierReport:
            self._log(
                run_id,
                role,
                "model_output",
                parsed.rationale[:200] or "(no rationale)",
                parsed.model_dump(mode="json"),
                duration,
            )
        return parsed

    def _tool_context(
        self, run_id: str, investigation_id: str, role: AgentRole, state: RunState
    ) -> ToolContext:
        return ToolContext(
            investigations=self.investigations,
            investigation_id=investigation_id,
            run_id=run_id,
            role=role,
            model_name=self.model.name,
            returned_event_ids=set(state.returned_event_ids),
            open_questions=list(state.open_questions),
        )

    @staticmethod
    def _sync(ctx: ToolContext, state: RunState) -> None:
        state.returned_event_ids = sorted(ctx.returned_event_ids)
        state.open_questions = list(ctx.open_questions)

    def _case_file(self, ctx: ToolContext, state: RunState, evidence_limit: int) -> str:
        return build_case_file(
            self.investigations,
            ctx,
            evidence_limit,
            notes=state.notes,
            questions=state.open_questions,
            analyst_messages=state.analyst_messages,
        )

    def _turn_limit(self, state: RunState) -> int:
        return self.limits.max_specialist_turns + state.bonus_turns

    @staticmethod
    def _turn_so_far(state: RunState) -> str:
        if not state.turn:
            return "No tool calls yet in this turn."
        shown = []
        for i, step in enumerate(state.turn):
            entry = {k: step[k] for k in ("tool", "arguments", "ok", "summary")}
            if i >= len(state.turn) - FULL_RESULTS_IN_TURN:
                entry["result"] = step["result"]
            shown.append(entry)
        return prompts.data_block("your tool calls in this turn (oldest first)", shown)

    def _end_turn(self, state: RunState, summary: str) -> None:
        if state.role is not None:
            state.notes.append({"role": state.role.value, "summary": summary[:1_500]})
            state.notes = state.notes[-MAX_NOTES:]
        state.specialist_turns += 1
        state.node, state.role, state.instruction = "orchestrate", None, ""
        state.turn, state.turn_steps = [], 0

    def _to_verifier(self, run_id: str, state: RunState, reason: str) -> None:
        if state.node == "verify":
            return
        if state.node == "specialist":
            self._end_turn(state, f"turn cut short: {reason}")
        state.node = "verify"
        self._log(
            run_id,
            AgentRole.ORCHESTRATOR,
            "route",
            f"-> verifier: {reason}",
            {"next": "verifier", "reason": reason},
        )

    def _limit(self, run_id: str, reason: str) -> RunOutcome:
        self._log(run_id, AgentRole.ORCHESTRATOR, "error", reason)
        return RunOutcome(AgentRunStatus.LIMIT_REACHED, error=reason)

    def _checkpoint(self, run_id: str, state: RunState) -> None:
        self.runs.save_checkpoint(
            run_id, state.model_dump(mode="json"), state.model_calls, state.tool_calls
        )

    def _log(
        self,
        run_id: str,
        role: AgentRole,
        kind: str,
        summary: str,
        payload: dict[str, Any] | None = None,
        duration_ms: int | None = None,
    ) -> None:
        text = json.dumps(payload or {}, default=str)
        if len(text) > 20_000:
            payload = {"truncated": True, "preview": text[:2_000]}
        self.runs.add_step(run_id, role, kind, summary[:300], payload, duration_ms)


def build_case_file(
    service: InvestigationService,
    ctx: ToolContext,
    evidence_limit: int,
    *,
    notes: list[dict[str, str]] | None = None,
    questions: list[str] | None = None,
    analyst_messages: list[dict[str, str]] | None = None,
) -> str:
    """Built by code from stored state on every call, so agents always see the current
    evidence. The timeline goes through the same tool, which registers its IDs as returned
    (citable). Analyst messages come last, outside the DATA fences: besides the role prompt
    they are the only source of direction."""
    investigation = service.get(ctx.investigation_id)
    alerts = [a for a in (service.alerts.get(i) for i in investigation.alert_ids) if a]
    evidence = service.evidence(ctx.investigation_id)
    timeline, _ = build_timeline(ctx, BuildTimelineArgs())
    parts = [
        prompts.data_block(
            "investigation",
            {
                "investigation_id": investigation.investigation_id,
                "title": investigation.title,
                "objective": investigation.objective,
            },
        ),
        prompts.data_block(
            "alerts",
            [
                {
                    "alert_id": a.alert_id,
                    "rule_id": a.rule_id,
                    "severity": a.severity.value,
                    "explanation": a.explanation,
                    "first_seen": a.first_seen.isoformat(),
                    "last_seen": a.last_seen.isoformat(),
                }
                for a in alerts
            ],
        ),
        prompts.data_block(
            f"evidence (latest {min(len(evidence), evidence_limit)} of {len(evidence)})",
            [compact_evidence(e) for e in evidence[-evidence_limit:]],
        ),
        prompts.data_block("timeline", timeline),
    ]
    if notes:
        parts.append(prompts.data_block("specialist notes so far", notes[-MAX_NOTES:]))
    if questions:
        parts.append(prompts.data_block("questions asked of the analyst", questions))
    if analyst_messages:
        parts.append(prompts.analyst_block(analyst_messages[-MAX_ANALYST_MESSAGES:]))
    return "\n\n".join(parts)


def check_assessment(
    report: VerifierReport, evidence: list[Evidence], open_questions: list[str]
) -> Assessment:
    """Deterministic checks on the verifier's reply. The model's wording is kept, but IDs it
    could not have seen are dropped and the verdict is downgraded when the evidence cannot
    carry it. Each change is listed in ``adjustments``."""
    by_id = {e.evidence_id: e for e in evidence}
    adjustments: list[str] = []
    unsupported = list(report.unsupported_claims)

    def known(ids: list[str]) -> list[str]:
        kept = []
        for evidence_id in dict.fromkeys(ids):
            if evidence_id in by_id:
                kept.append(evidence_id)
            else:
                unsupported.append(f"cited evidence {evidence_id} does not exist")
                adjustments.append(f"dropped unknown evidence ID {evidence_id}")
        return kept

    supporting = known(report.supporting_evidence_ids)
    contradicting = [e for e in known(report.contradicting_evidence_ids) if e not in supporting]
    disposition, confidence = report.disposition, report.confidence

    if disposition is not Disposition.INSUFFICIENT_DATA and not supporting:
        adjustments.append(
            f"{disposition.value} cited no existing evidence; changed to insufficient_data"
        )
        disposition, confidence = Disposition.INSUFFICIENT_DATA, Confidence.LOW
    if disposition in MALICIOUS and not any(
        by_id[e].category is EvidenceCategory.OBSERVATION
        and by_id[e].source_type in GROUNDED_SOURCES
        for e in supporting
    ):
        adjustments.append(
            f"{disposition.value} needs at least one observation from events, the alert, the "
            "IOC list, a provider or the analyst (not only agent-written claims); changed to "
            "suspicious_inconclusive"
        )
        disposition = Disposition.SUSPICIOUS_INCONCLUSIVE
    if disposition is Disposition.CONFIRMED_MALICIOUS and contradicting:
        adjustments.append(
            "contradicting evidence cited; confirmed_malicious lowered to likely_malicious"
        )
        disposition = Disposition.LIKELY_MALICIOUS
    missing = [e for e in evidence if e.category is EvidenceCategory.MISSING_TELEMETRY]
    if confidence is Confidence.HIGH and missing:
        adjustments.append(
            f"{len(missing)} missing-telemetry item(s) recorded; high confidence capped at medium"
        )
        confidence = Confidence.MEDIUM

    gaps = list(dict.fromkeys(report.gaps))
    for item in missing:
        if len(gaps) >= 15:
            break
        if item.claim not in gaps:
            gaps.append(item.claim[:500])
    return Assessment(
        disposition=disposition,
        confidence=confidence,
        rationale=report.rationale,
        supporting_evidence_ids=supporting,
        contradicting_evidence_ids=contradicting,
        gaps=gaps,
        unsupported_claims=unsupported[:20],
        adjustments=adjustments,
        open_questions=list(open_questions),
    )
