"""Shared wiring: one DB connection and service set per process (used by the UI)."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass

from app.agents.chat import ChatService
from app.agents.planner import ResponsePlanner
from app.agents.service import AgentRunner, AgentService, ModelFactory, ollama_model
from app.audit.log import AuditLog
from app.config import Settings, get_settings
from app.detection.engine import DetectionEngine
from app.ingestion.file_tail import TailManager
from app.ingestion.http_receiver import HttpReceiver
from app.ingestion.iocs import load_demo_iocs
from app.ingestion.replay import ReplayEngine, ReplayRunner, build_plan
from app.ingestion.service import IngestionService
from app.investigations.service import InvestigationService
from app.policy.service import ResponseService
from app.storage.agents import AgentRunRepository
from app.storage.alerts import AlertRepository, IocRepository
from app.storage.db import open_database
from app.storage.repositories import DataSourceRepository, EventRepository, ParseErrorRepository
from app.tools.reputation.http import Transport, urllib_transport
from app.tools.reputation.service import ReputationService, build_providers


@dataclass
class AppContext:
    settings: Settings
    conn: sqlite3.Connection
    ingestion: IngestionService
    detection: DetectionEngine
    events: EventRepository
    sources: DataSourceRepository
    parse_errors: ParseErrorRepository
    alerts: AlertRepository
    iocs: IocRepository
    reputation: ReputationService
    investigations: InvestigationService
    agents: AgentService
    chat: ChatService
    responses: ResponseService
    planner: ResponsePlanner
    audit: AuditLog
    replay: ReplayRunner | None  # None for in-memory databases (a thread needs its own connection)
    agent_runner: AgentRunner | None  # None for in-memory databases; runs execute inline
    tails: TailManager  # followed files; live polling only with a file database
    receiver: HttpReceiver  # loopback HTTP receiver; started from the Data sources page


def build_ingestion(
    conn: sqlite3.Connection, settings: Settings
) -> tuple[IngestionService, DetectionEngine]:
    """The one ingestion pipeline: every source shares it, and detection runs as its hook."""
    detection = DetectionEngine(conn)
    return IngestionService(conn, settings, hooks=[detection.detect]), detection


def build_context(
    settings: Settings | None = None,
    database: str | None = None,
    reputation_transport: Transport = urllib_transport,
    model_factory: ModelFactory = ollama_model,
) -> AppContext:
    settings = settings or get_settings()
    database = database or str(settings.database_path)
    conn = open_database(database)
    ingestion, detection = build_ingestion(conn, settings)

    def build_services(
        conn: sqlite3.Connection, detection: DetectionEngine
    ) -> tuple[ReputationService, InvestigationService, AgentService]:
        reputation = ReputationService(
            conn, settings, build_providers(settings, reputation_transport)
        )
        investigations = InvestigationService(conn, settings, detection, reputation)
        return (
            reputation,
            investigations,
            AgentService(conn, settings, investigations, model_factory),
        )

    def new_replay_engine() -> ReplayEngine:
        replay_conn = open_database(database)
        service, _ = build_ingestion(replay_conn, settings)
        load_demo_iocs(IocRepository(replay_conn))
        return ReplayEngine(
            service,
            build_plan(snippet_chars=settings.parse_error_snippet_chars),
            close=replay_conn.close,
        )

    def new_agent_session() -> tuple[AgentService, Callable[[], None]]:
        agent_conn = open_database(database)
        return build_services(agent_conn, DetectionEngine(agent_conn))[2], agent_conn.close

    def new_ingestion_session() -> tuple[IngestionService, sqlite3.Connection]:
        """Live inputs ingest on their own connection (and thread) with a file database."""
        if database == ":memory:":
            return ingestion, conn
        live_conn = open_database(database)
        return build_ingestion(live_conn, settings)[0], live_conn

    reputation, investigations, agents = build_services(conn, detection)
    agent_runner = None
    if database != ":memory:":
        # Runs marked active by an earlier process are not running any more.
        AgentRunRepository(conn).mark_interrupted()
        agent_runner = AgentRunner(new_agent_session)
    # Runs execute on a worker with a file database, inline with an in-memory one.
    chat = ChatService(agents, agent_runner.launch if agent_runner else agents.execute)
    investigations.close_hooks.append(chat.on_investigation_closed)
    responses = ResponseService(investigations)
    tails = TailManager(settings, new_ingestion_session, threaded=database != ":memory:")
    if tails.threaded and tails.configs():
        tails.start()  # files followed before the restart are followed again
    return AppContext(
        settings=settings,
        conn=conn,
        ingestion=ingestion,
        detection=detection,
        events=EventRepository(conn),
        sources=DataSourceRepository(conn),
        parse_errors=ParseErrorRepository(conn),
        alerts=AlertRepository(conn),
        iocs=IocRepository(conn),
        reputation=reputation,
        investigations=investigations,
        agents=agents,
        chat=chat,
        responses=responses,
        planner=ResponsePlanner(agents, responses),
        audit=AuditLog(conn),
        replay=None if database == ":memory:" else ReplayRunner(new_replay_engine),
        agent_runner=agent_runner,
        tails=tails,
        receiver=HttpReceiver(settings, new_ingestion_session),
    )
