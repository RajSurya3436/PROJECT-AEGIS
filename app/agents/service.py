"""Starting, running, resuming and stopping agent runs.

``AgentService`` runs a graph synchronously on the caller's connection (tests, in-memory
databases). ``AgentRunner`` runs it on a worker thread with its own connection, so the UI stays
responsive; a stop request is checked between steps. Only one run per investigation can be
active at a time (enforced in the database).
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from collections.abc import Callable

from app.agents.graph import AgentGraph, Limits, RunOutcome, RunState
from app.agents.llm import ChatModel, OllamaChatModel
from app.config import Settings
from app.domain.enums import AgentRunStatus, InvestigationStatus
from app.domain.errors import InvestigationError, NotFoundError
from app.domain.models import AgentRun
from app.investigations.service import InvestigationService
from app.storage.agents import RESUMABLE, AgentRunRepository

logger = logging.getLogger(__name__)

ModelFactory = Callable[[Settings], ChatModel]


def ollama_model(settings: Settings) -> ChatModel:
    return OllamaChatModel(
        settings.ollama_base_url,
        settings.ollama_model,
        settings.agent_model_timeout_seconds,
        settings.agent_context_tokens,
    )


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
        self._model_factory = model_factory

    def create_run(self, investigation_id: str) -> AgentRun:
        if self.investigations.get(investigation_id).status is not InvestigationStatus.OPEN:
            raise InvestigationError("investigation is closed; reopen it to run agents")
        run_id = "run-" + uuid.uuid4().hex[:12]
        if not self.runs.create(run_id, investigation_id, self.settings.ollama_model):
            raise InvestigationError("agents are already running on this investigation")
        return self.get(run_id)

    def get(self, run_id: str) -> AgentRun:
        run = self.runs.get(run_id)
        if run is None:
            raise NotFoundError(f"unknown agent run: {run_id}")
        return run

    def execute(self, run_id: str, should_stop: Callable[[], bool] = lambda: False) -> AgentRun:
        """Run (or resume) to the end. Never raises for model or tool trouble: the run ends
        with a status and an error message, and evidence already recorded is kept."""
        run = self.get(run_id)
        if run.status.value not in RESUMABLE:
            raise InvestigationError(f"run is {run.status.value}; it cannot be started again")
        if not self.runs.claim(run_id):
            if run.status is AgentRunStatus.QUEUED:  # a queued run would block the case
                self.runs.finish(run_id, AgentRunStatus.FAILED, None, "could not start")
            raise InvestigationError("another agent run is active on this investigation")
        state = RunState.model_validate(run.checkpoint) if run.checkpoint else RunState()
        try:
            graph = AgentGraph(
                self.investigations,
                self.runs,
                self._model_factory(self.settings),
                Limits.from_settings(self.settings),
            )
            outcome = graph.run(run_id, run.investigation_id, state, should_stop)
        except Exception as exc:  # a bug must not leave the run "running" forever
            logger.exception("agent run %s failed", run_id)
            outcome = RunOutcome(AgentRunStatus.FAILED, error=f"{type(exc).__name__}: {exc}")
        self.runs.finish(run_id, outcome.status, outcome.assessment, outcome.error)
        return self.get(run_id)

    def run_now(self, investigation_id: str) -> AgentRun:
        return self.execute(self.create_run(investigation_id).run_id)


SessionFactory = Callable[[], tuple[AgentService, Callable[[], None]]]


class AgentRunner:
    """Background execution. Each run gets a fresh service on its own SQLite connection."""

    def __init__(self, session_factory: SessionFactory) -> None:
        self._factory = session_factory
        self._lock = threading.Lock()
        self._threads: dict[str, threading.Thread] = {}
        self._stops: dict[str, threading.Event] = {}

    def start(self, service: AgentService, investigation_id: str) -> str:
        run = service.create_run(investigation_id)
        self._launch(run.run_id)
        return run.run_id

    def resume(self, service: AgentService, run_id: str) -> None:
        run = service.get(run_id)
        if run.status.value not in RESUMABLE:
            raise InvestigationError(f"run is {run.status.value}; it cannot be resumed")
        self._launch(run_id)

    def stop(self, run_id: str) -> None:
        with self._lock:
            event = self._stops.get(run_id)
        if event is not None:
            event.set()

    def is_running(self, run_id: str) -> bool:
        with self._lock:
            thread = self._threads.get(run_id)
        return thread is not None and thread.is_alive()

    def any_running(self) -> bool:
        with self._lock:
            return any(t.is_alive() for t in self._threads.values())

    def join(self, run_id: str, timeout: float | None = None) -> None:
        with self._lock:
            thread = self._threads.get(run_id)
        if thread is not None:
            thread.join(timeout)

    def _launch(self, run_id: str) -> None:
        with self._lock:
            existing = self._threads.get(run_id)
            if existing is not None and existing.is_alive():
                raise InvestigationError("this run is already executing")
            stop = threading.Event()
            thread = threading.Thread(
                target=self._work, args=(run_id, stop), name=f"agents-{run_id}", daemon=True
            )
            self._threads[run_id], self._stops[run_id] = thread, stop
            thread.start()

    def _work(self, run_id: str, stop: threading.Event) -> None:
        service, close = self._factory()
        try:
            service.execute(run_id, stop.is_set)
        except Exception:
            logger.exception("agent run %s could not start", run_id)
        finally:
            close()
