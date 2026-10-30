"""Starting, running, resuming and controlling agent runs.

``AgentService`` runs a graph synchronously on the caller's connection (tests, in-memory
databases). ``AgentRunner`` runs it on a worker thread with its own connection, so the UI stays
responsive. Control requests and analyst directives are rows in SQLite, read by the graph at
every step boundary, so they reach a run whichever thread or connection executes it. Only one
run per investigation can be open (queued, running, paused or waiting) at a time.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from collections.abc import Callable

from app.agents.graph import AgentGraph, Limits, RunOutcome, RunState
from app.agents.llm import ChatModel, OllamaChatModel
from app.audit.log import FAILED, OK, AuditLog
from app.config import Settings
from app.domain.enums import (
    RESUMABLE_RUN_STATUSES,
    AgentRole,
    AgentRunStatus,
    ChatKind,
    ChatMode,
    InvestigationStatus,
)
from app.domain.errors import InvestigationError, NotFoundError
from app.domain.models import AgentRun, ChatEntry
from app.investigations.service import InvestigationService
from app.storage.agents import AgentRunRepository
from app.storage.chat import ChatRepository

logger = logging.getLogger(__name__)

ModelFactory = Callable[[Settings], ChatModel]
SYSTEM = "system"


def ollama_model(settings: Settings) -> ChatModel:
    return OllamaChatModel(
        settings.ollama_base_url,
        settings.ollama_model,
        settings.agent_model_timeout_seconds,
        settings.agent_context_tokens,
    )


class DbControls:
    """``RunControls`` backed by the run row (pause/stop) and the chat table (directives)."""

    def __init__(
        self, runs: AgentRunRepository, chat: ChatRepository, run_id: str, investigation_id: str
    ) -> None:
        self.runs, self.chat = runs, chat
        self.run_id, self.investigation_id = run_id, investigation_id

    def requested(self) -> str | None:
        return self.runs.requested_control(self.run_id)

    def take_directives(self) -> list[ChatEntry]:
        return self.chat.take_pending(self.investigation_id, self.run_id)


class AgentService:
    def __init__(
        self,
        conn: sqlite3.Connection,
        settings: Settings,
        investigations: InvestigationService,
        model_factory: ModelFactory = ollama_model,
    ) -> None:
        self.settings = settings
        self.investigations = investigations
        self.runs = AgentRunRepository(conn)
        self.chat = ChatRepository(conn)
        self.audit = AuditLog(conn)
        self._model_factory = model_factory

    def model(self) -> ChatModel:
        return self._model_factory(self.settings)

    def create_run(self, investigation_id: str) -> AgentRun:
        if self.investigations.get(investigation_id).status is not InvestigationStatus.OPEN:
            raise InvestigationError("investigation is closed; reopen it to run agents")
        run_id = "run-" + uuid.uuid4().hex[:12]
        if not self.runs.create(run_id, investigation_id, self.settings.ollama_model):
            raise InvestigationError(
                "an agent run is already open on this investigation (running, paused or "
                "waiting); control it from the chat instead"
            )
        self.audit.record(
            SYSTEM, "agent_run.created", "agent_run", run_id, investigation_id=investigation_id
        )
        return self.get(run_id)

    def get(self, run_id: str) -> AgentRun:
        run = self.runs.get(run_id)
        if run is None:
            raise NotFoundError(f"unknown agent run: {run_id}")
        return run

    def execute(self, run_id: str) -> AgentRun:
        """Run (or resume) until it completes, pauses, waits for the analyst, stops, fails or
        hits a limit. Never raises for model or tool trouble: the run ends with a status and
        a message, and evidence already recorded is kept."""
        run = self.get(run_id)
        if run.status not in RESUMABLE_RUN_STATUSES:
            raise InvestigationError(f"run is {run.status.value}; it cannot be started again")
        while True:
            if not self.runs.claim(run_id):
                if run.status is AgentRunStatus.QUEUED:  # a queued run would block the case
                    self.runs.finish(run_id, AgentRunStatus.FAILED, None, "could not start")
                raise InvestigationError("another agent run is open on this investigation")
            run = self.get(run_id)
            state = RunState.model_validate(run.checkpoint) if run.checkpoint else RunState()
            outcome = self._run_graph(run, state)
            self.runs.finish(run_id, outcome.status, outcome.assessment, outcome.error)
            run = self.get(run_id)
            self._audit_end(run)
            self._announce(run, state)
            pending = self.chat.pending(run.investigation_id)
            if run.status is AgentRunStatus.WAITING and pending:
                continue  # a reply arrived while this worker was returning
            if run.status is AgentRunStatus.STOPPED:
                self.chat.discard_pending(run.investigation_id)  # abandoned with the run
            if run.status is AgentRunStatus.COMPLETED and pending:
                follow_up = self._follow_up(run)
                if follow_up is not None:
                    run_id, run = follow_up.run_id, follow_up
                    continue
            return run

    def _follow_up(self, run: AgentRun) -> AgentRun | None:
        """Instructions that arrived after the verifier started are not lost: a new run
        starts and reads them first."""
        try:
            follow_up = self.create_run(run.investigation_id)
        except InvestigationError:
            return None  # closed meanwhile, or another run already holds the case
        self.chat.add(
            run.investigation_id,
            author=SYSTEM,
            mode=ChatMode.CONTROL,
            kind=ChatKind.NOTICE,
            content=f"Started follow-up run {follow_up.run_id} for instructions that arrived "
            f"after {run.run_id} began its assessment.",
            run_id=follow_up.run_id,
        )
        return follow_up

    def _run_graph(self, run: AgentRun, state: RunState) -> RunOutcome:
        controls = DbControls(self.runs, self.chat, run.run_id, run.investigation_id)
        try:
            graph = AgentGraph(
                self.investigations,
                self.runs,
                self.model(),
                Limits.from_settings(self.settings),
            )
            return graph.run(run.run_id, run.investigation_id, state, controls)
        except Exception as exc:  # a bug must not leave the run "running" forever
            logger.exception("agent run %s failed", run.run_id)
            return RunOutcome(AgentRunStatus.FAILED, error=f"{type(exc).__name__}: {exc}")

    def _audit_end(self, run: AgentRun) -> None:
        bad = (AgentRunStatus.FAILED, AgentRunStatus.LIMIT_REACHED)
        details: dict[str, object] = {
            "model_calls": run.model_calls,
            "tool_calls": run.tool_calls,
            "error": run.error,
        }
        if run.assessment is not None:
            details["assessment"] = run.assessment.disposition.value
            details["confidence"] = run.assessment.confidence.value
        self.audit.record(
            "agents",
            f"agent_run.{run.status.value}",
            "agent_run",
            run.run_id,
            investigation_id=run.investigation_id,
            outcome=FAILED if run.status in bad else OK,
            details=details,
        )

    def run_now(self, investigation_id: str) -> AgentRun:
        return self.execute(self.create_run(investigation_id).run_id)

    def _announce(self, run: AgentRun, state: RunState) -> None:
        """Tell the chat how the run ended this time, so status changes are visible there."""
        status = run.status
        if status is AgentRunStatus.WAITING:
            role = state.role or AgentRole.ORCHESTRATOR
            self.chat.add(
                run.investigation_id,
                author=role.value,
                mode=ChatMode.INVESTIGATE,
                kind=ChatKind.AGENT_QUESTION,
                content=state.waiting_question,
                run_id=run.run_id,
            )
            return
        if status is AgentRunStatus.COMPLETED and run.assessment is not None:
            a = run.assessment
            text = (
                f"Assessment: {a.disposition.value} ({a.confidence.value} confidence). "
                f"{a.rationale}"
            )
            if a.adjustments:
                text += f" Adjusted by checks: {'; '.join(a.adjustments)}"
            author = AgentRole.VERIFIER.value
        else:
            author = SYSTEM
            text = f"Run {status.value.replace('_', ' ')}" + (
                f": {run.error}" if run.error else "."
            )
            if status is AgentRunStatus.PAUSED:
                text = "Run paused. Resume it, redirect it or stop it from the chat."
        self.chat.add(
            run.investigation_id,
            author=author,
            mode=ChatMode.CONTROL,
            kind=ChatKind.NOTICE,
            content=text,
            run_id=run.run_id,
            payload={"status": status.value},
        )


SessionFactory = Callable[[], tuple[AgentService, Callable[[], None]]]


class AgentRunner:
    """Background execution. Each launch gets a fresh service on its own SQLite connection.
    Stopping and pausing go through the database (``request_control``), not this object."""

    def __init__(self, session_factory: SessionFactory) -> None:
        self._factory = session_factory
        self._lock = threading.Lock()
        self._threads: dict[str, threading.Thread] = {}
        self._again: set[str] = set()  # launched while its worker was still winding down

    def start(self, service: AgentService, investigation_id: str) -> str:
        run = service.create_run(investigation_id)
        self.launch(run.run_id)
        return run.run_id

    def launch(self, run_id: str) -> None:
        with self._lock:
            existing = self._threads.get(run_id)
            if existing is not None and existing.is_alive():
                # Executing runs read new directives at their next step; one that is just
                # ending (e.g. paused) is executed again by the same worker.
                self._again.add(run_id)
                return
            thread = threading.Thread(
                target=self._work, args=(run_id,), name=f"agents-{run_id}", daemon=True
            )
            self._threads[run_id] = thread
            thread.start()

    def is_running(self, run_id: str) -> bool:
        with self._lock:
            thread = self._threads.get(run_id)
        return thread is not None and thread.is_alive()

    def join(self, run_id: str, timeout: float | None = None) -> None:
        with self._lock:
            thread = self._threads.get(run_id)
        if thread is not None:
            thread.join(timeout)

    def _work(self, run_id: str) -> None:
        service, close = self._factory()
        try:
            while True:
                try:
                    service.execute(run_id)
                except InvestigationError:
                    pass  # not resumable any more (finished, or another run holds the case)
                except Exception:
                    logger.exception("agent run %s could not start", run_id)
                with self._lock:
                    if run_id not in self._again:
                        # Leaving: forget the thread so a later launch starts a new one.
                        self._threads.pop(run_id, None)
                        return
                    self._again.discard(run_id)
        finally:
            close()
