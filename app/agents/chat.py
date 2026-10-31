"""Analyst chat: Ask (read-only), Investigate (instruct the agents) and Control (pause,
resume, stop, redirect). Every message and instruction is stored before anything acts on it.

Ask runs a short read-only loop right away and stores the answer. Investigate and redirect
store a *directive* and make sure a run will read it: a new run is started if none is open, a
paused or waiting run is resumed, and an executing run picks it up at its next step. Pause and
stop are requests on the run row, honoured at the next step boundary.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from app.agents import prompts
from app.agents.graph import build_case_file
from app.agents.llm import ChatMessage, ModelError, ModelUnavailableError
from app.agents.schemas import InvalidOutputError, SpecialistAction, json_schema, parse_output
from app.agents.service import SYSTEM, AgentService
from app.agents.tools import ToolContext, execute, tools_for
from app.domain.enums import (
    ACTIVE_RUN_STATUSES,
    AgentRole,
    AgentRunStatus,
    ChatKind,
    ChatMode,
    InvestigationStatus,
)
from app.domain.errors import InvestigationError
from app.domain.models import AgentRun, ChatEntry

ANALYST = "analyst"
ASK_ROLES = (AgentRole.LOG_INVESTIGATOR, AgentRole.THREAT_INTEL, AgentRole.VERIFIER)
MAX_MESSAGE_CHARS = 2_000
CASE_EVIDENCE = 40
EVIDENCE_REF = re.compile(r"\bev-[0-9a-f]{16}\b")
EVENT_REF = re.compile(r"\b[0-9a-f]{32}\b")


class ChatService:
    def __init__(self, agents: AgentService, launch: Callable[[str], object]) -> None:
        """``launch(run_id)`` executes a run: on a worker thread in the app, inline in tests
        and with in-memory databases."""
        self.agents = agents
        self.chat = agents.chat
        self.runs = agents.runs
        self.investigations = agents.investigations
        self._launch = launch

    # --- reading ---------------------------------------------------------------------------

    def messages(self, investigation_id: str) -> list[ChatEntry]:
        return self.chat.for_investigation(investigation_id)

    def open_run(self, investigation_id: str) -> AgentRun | None:
        return self.runs.open_run(investigation_id)

    def status(self, investigation_id: str) -> tuple[str, str]:
        """(state, detail) for the chat header, read from stored state only."""
        run = self.open_run(investigation_id)
        if run is None:
            runs = self.runs.for_investigation(investigation_id, limit=1)
            if not runs:
                return "idle", "No agent run yet."
            last = runs[0]
            detail = f"Last run {last.run_id} {last.status.value.replace('_', ' ')}."
            if last.status is AgentRunStatus.INTERRUPTED:
                detail += " Resume it from Control, or start a new one with Investigate."
            return last.status.value, detail
        if run.status is AgentRunStatus.WAITING:
            question = run.checkpoint.get("waiting_question", "")
            return "waiting", f"The agents are waiting for your reply: {question}"
        if run.status is AgentRunStatus.PAUSED:
            return "paused", f"Run {run.run_id} is paused."
        if run.control:
            return (
                f"{run.control} requested",
                f"Run {run.run_id} will {run.control} at its next step.",
            )
        return run.status.value, (
            f"Run {run.run_id}: {run.model_calls} model call(s), {run.tool_calls} tool call(s)."
        )

    def pending(self, investigation_id: str) -> list[ChatEntry]:
        return self.chat.pending(investigation_id)

    # --- Investigate and redirect ----------------------------------------------------------

    def start(self, investigation_id: str) -> AgentRun:
        """Start a run with no instruction: the orchestrator works from the alert."""
        run = self.agents.create_run(investigation_id)
        self._note(investigation_id, f"Started run {run.run_id}.", run.run_id)
        self._launch(run.run_id)
        return self.agents.get(run.run_id)

    def investigate(
        self, investigation_id: str, text: str, role: AgentRole | None = None
    ) -> ChatEntry:
        """Instruct the agents. Answers the agents' question if they are waiting for one."""
        run = self.open_run(investigation_id)
        waiting = run is not None and run.status is AgentRunStatus.WAITING and role is None
        kind = ChatKind.REPLY if waiting else ChatKind.INSTRUCTION
        return self._direct(investigation_id, text, role, ChatMode.INVESTIGATE, kind)

    def redirect(
        self, investigation_id: str, text: str, role: AgentRole | None = None
    ) -> ChatEntry:
        return self._direct(investigation_id, text, role, ChatMode.CONTROL, ChatKind.REDIRECT)

    def _direct(
        self,
        investigation_id: str,
        text: str,
        role: AgentRole | None,
        mode: ChatMode,
        kind: ChatKind,
    ) -> ChatEntry:
        self._require_open(investigation_id)
        text = self._clean(text)
        if role is AgentRole.ORCHESTRATOR:
            raise InvestigationError("choose a specialist, or leave it to the orchestrator")
        if role is AgentRole.RESPONSE_PLANNER:
            raise InvestigationError("the response planner runs from the Response tab")
        run = self.open_run(investigation_id)
        message = self.chat.add(
            investigation_id,
            author=ANALYST,
            mode=mode,
            kind=kind,
            content=text,
            target_role=role,
            run_id=run.run_id if run else None,
        )
        self._audit(message)
        if run is None:
            try:
                run = self.agents.create_run(investigation_id)
            except InvestigationError:
                # Another start won the race; that open run will read this directive.
                return message
            self._note(investigation_id, f"Started run {run.run_id}.", run.run_id)
        if run.status is not AgentRunStatus.RUNNING:  # running: read at its next step
            self._launch(run.run_id)
        return self.chat.get(message.message_id) or message

    # --- Control ---------------------------------------------------------------------------

    def pause(self, investigation_id: str) -> ChatEntry:
        run = self._executing(investigation_id, "pause")
        message = self._control_message(investigation_id, ChatKind.PAUSE, "Pause", run)
        self.runs.request_control(run.run_id, "pause")
        return message

    def resume(self, investigation_id: str) -> ChatEntry:
        self._require_open(investigation_id)
        run = self.controlled_run(investigation_id)
        if run is None:
            raise InvestigationError("nothing to resume; start a run with Investigate")
        if run.status is AgentRunStatus.RUNNING:
            raise InvestigationError("the run is already running")
        if run.status is AgentRunStatus.WAITING and not self.chat.pending(investigation_id):
            raise InvestigationError(
                "the agents are waiting for your reply; answer them in Investigate mode"
            )
        message = self._control_message(investigation_id, ChatKind.RESUME, "Resume", run)
        self._launch(run.run_id)
        return message

    def stop(self, investigation_id: str) -> ChatEntry:
        run = self.controlled_run(investigation_id)
        if run is None:
            raise InvestigationError("no agent run to stop")
        message = self._control_message(investigation_id, ChatKind.STOP, "Stop", run)
        self._end(run, "stopped by the analyst")
        return message

    def on_investigation_closed(self, investigation_id: str) -> None:
        """Close hook: a closed case keeps no open run and no pending instructions."""
        run = self.open_run(investigation_id)
        if run is not None:
            self._end(run, "the investigation was closed")
        self.chat.discard_pending(investigation_id)

    def _end(self, run: AgentRun, reason: str) -> None:
        if run.status in ACTIVE_RUN_STATUSES and self.runs.request_control(run.run_id, "stop"):
            return  # the worker stops at its next step, drops pending work and announces it
        self.chat.discard_pending(run.investigation_id)
        if self.runs.stop_unfinished(run.run_id, reason):
            self._note(run.investigation_id, f"Run stopped: {reason}.", run.run_id)
        # else it finished on its own a moment ago; its result stands

    def _executing(self, investigation_id: str, action: str) -> AgentRun:
        run = self.open_run(investigation_id)
        if run is None or run.status not in ACTIVE_RUN_STATUSES:
            raise InvestigationError(f"no running agent run to {action}")
        return run

    def controlled_run(self, investigation_id: str) -> AgentRun | None:
        """The run Pause, Resume and Stop act on: the open run, else the latest run if it
        was interrupted."""
        run = self.open_run(investigation_id)
        if run is not None:
            return run
        runs = self.runs.for_investigation(investigation_id, limit=1)
        return runs[0] if runs and runs[0].status is AgentRunStatus.INTERRUPTED else None

    def _control_message(
        self, investigation_id: str, kind: ChatKind, label: str, run: AgentRun
    ) -> ChatEntry:
        message = self.chat.add(
            investigation_id,
            author=ANALYST,
            mode=ChatMode.CONTROL,
            kind=kind,
            content=f"{label} run {run.run_id}",
            run_id=run.run_id,
        )
        self._audit(message)
        return message

    def _audit(self, message: ChatEntry) -> None:
        """Every analyst instruction, question and control request."""
        self.agents.audit.record(
            ANALYST,
            f"chat.{message.kind.value}",
            "chat_message",
            message.message_id,
            investigation_id=message.investigation_id,
            details={
                "mode": message.mode.value,
                "target_role": message.target_role.value if message.target_role else None,
                "run_id": message.run_id,
                "text": message.content[:500],
            },
        )

    # --- Ask (read-only) -------------------------------------------------------------------

    def ask(self, investigation_id: str, question: str, role: AgentRole | None = None) -> ChatEntry:
        """Answer a question with read-only tools. Works on closed investigations too, since
        nothing is written except the two chat messages."""
        self.investigations.get(investigation_id)
        role = role or AgentRole.LOG_INVESTIGATOR
        if role not in ASK_ROLES:
            raise InvestigationError("ask the log investigator, threat intel or the verifier")
        question = self._clean(question)
        asked = self.chat.add(
            investigation_id,
            author=ANALYST,
            mode=ChatMode.ASK,
            kind=ChatKind.QUESTION,
            content=question,
            target_role=role,
        )
        self._audit(asked)
        try:
            answer, payload = self._answer(investigation_id, asked, role)
        except ModelUnavailableError as exc:
            return self._note(investigation_id, f"AI unavailable: {exc}", mode=ChatMode.ASK)
        except (ModelError, InvalidOutputError) as exc:
            return self._note(
                investigation_id, f"No usable answer from the model: {exc}", mode=ChatMode.ASK
            )
        return self.chat.add(
            investigation_id,
            author=role.value,
            mode=ChatMode.ASK,
            kind=ChatKind.ANSWER,
            content=answer,
            target_role=role,
            payload=payload,
        )

    def _answer(
        self, investigation_id: str, asked: ChatEntry, role: AgentRole
    ) -> tuple[str, dict[str, Any]]:
        settings = self.agents.settings
        model = self.agents.model()
        ctx = ToolContext(
            investigations=self.investigations,
            investigation_id=investigation_id,
            run_id=f"ask:{asked.message_id}",
            role=role,
            model_name=model.name,
            read_only=True,
        )
        specs = [] if role is AgentRole.VERIFIER else tools_for(role, read_only=True)
        system = prompts.ask_prompt(role.value, prompts.tool_catalogue(specs))
        steps: list[dict[str, Any]] = []
        seen: list[str] = []  # everything the model was shown, for the reference check
        calls, invalid, rejection = 0, 0, ""
        max_steps = settings.agent_max_ask_steps
        while calls < max_steps + settings.agent_max_invalid_outputs:
            last = len(steps) >= max_steps - 1
            parts = [
                build_case_file(self.investigations, ctx, CASE_EVIDENCE),
                prompts.data_block("your lookups so far", steps) if steps else "",
                prompts.analyst_block([{"kind": "question", "text": asked.content}]),
                "This is your last step: answer now." if last else "",
                f"Your previous reply was rejected: {rejection}. Reply with one valid JSON object."
                if rejection
                else "",
            ]
            calls += 1
            seen.append(parts[0])
            text = model.complete(
                [
                    ChatMessage("system", system),
                    ChatMessage("user", "\n\n".join(p for p in parts if p)),
                ],
                json_schema(SpecialistAction),
            )
            try:
                action = parse_output(SpecialistAction, text)
            except InvalidOutputError as exc:
                invalid += 1
                rejection = str(exc)[:300]
                if invalid >= settings.agent_max_invalid_outputs:
                    raise
                continue
            rejection = ""
            if action.action == "finish" or not action.tool or last:
                answer = action.summary.strip() or "(no answer)"
                if action.action != "finish":
                    answer = (
                        f"I could not finish looking within {max_steps} steps. "
                        f"{action.rationale}".strip()
                    )
                return self._checked(investigation_id, answer, steps, calls, seen)
            outcome = execute(ctx, action.tool, action.arguments)
            seen.append(outcome.as_text())
            steps.append(
                {
                    "tool": action.tool,
                    "arguments": action.arguments,
                    "ok": outcome.ok,
                    "summary": outcome.summary,
                    "result": outcome.result,
                }
            )
        raise InvalidOutputError("too many unusable replies")

    def _checked(
        self,
        investigation_id: str,
        answer: str,
        steps: list[dict[str, Any]],
        calls: int,
        seen: list[str],
    ) -> tuple[str, dict[str, Any]]:
        """Flag IDs in the answer that do not exist, so a made-up citation is visible. A
        32-hex string that is not an event ID but appeared in the data the model was shown
        (an MD5 from a command line, say) is quoted data, not a citation."""
        evidence = {e.evidence_id for e in self.investigations.evidence(investigation_id)}
        unknown = [i for i in dict.fromkeys(EVIDENCE_REF.findall(answer)) if i not in evidence]
        events = list(dict.fromkeys(EVENT_REF.findall(answer)))
        found = {e.event_id for e in self.investigations.events.get_many(events)}
        shown = "\n".join(seen).lower()
        unknown += [i for i in events if i not in found and i not in shown]
        if unknown:
            answer += f"\n\n[Unverified references, not found in the data: {', '.join(unknown)}]"
        payload = {
            "model_calls": calls,
            "lookups": [{k: s[k] for k in ("tool", "arguments", "ok", "summary")} for s in steps],
            "unverified_references": unknown,
        }
        return answer, payload

    # --- helpers ---------------------------------------------------------------------------

    def _require_open(self, investigation_id: str) -> None:
        if self.investigations.get(investigation_id).status is not InvestigationStatus.OPEN:
            raise InvestigationError("investigation is closed; reopen it to direct the agents")

    @staticmethod
    def _clean(text: str) -> str:
        text = (text or "").strip()
        if not text:
            raise InvestigationError("write a message first")
        if len(text) > MAX_MESSAGE_CHARS:
            raise InvestigationError(f"messages are limited to {MAX_MESSAGE_CHARS} characters")
        return text

    def _note(
        self,
        investigation_id: str,
        text: str,
        run_id: str | None = None,
        mode: ChatMode = ChatMode.CONTROL,
    ) -> ChatEntry:
        return self.chat.add(
            investigation_id,
            author=SYSTEM,
            mode=mode,
            kind=ChatKind.NOTICE,
            content=text,
            run_id=run_id,
        )
