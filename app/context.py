"""Shared wiring: one DB connection and service set per process (used by the UI)."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from app.config import Settings, get_settings
from app.detection.engine import DetectionEngine
from app.ingestion.iocs import load_demo_iocs
from app.ingestion.replay import ReplayEngine, ReplayRunner, build_plan
from app.ingestion.service import IngestionService
from app.investigations.service import InvestigationService
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
    replay: ReplayRunner | None  # None for in-memory databases (a thread needs its own connection)


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
) -> AppContext:
    settings = settings or get_settings()
    database = database or str(settings.database_path)
    conn = open_database(database)
    ingestion, detection = build_ingestion(conn, settings)

    def new_replay_engine() -> ReplayEngine:
        replay_conn = open_database(database)
        service, _ = build_ingestion(replay_conn, settings)
        load_demo_iocs(IocRepository(replay_conn))
        return ReplayEngine(
            service,
            build_plan(snippet_chars=settings.parse_error_snippet_chars),
            close=replay_conn.close,
        )

    reputation = ReputationService(conn, settings, build_providers(settings, reputation_transport))
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
        investigations=InvestigationService(conn, settings, detection, reputation),
        replay=None if database == ":memory:" else ReplayRunner(new_replay_engine),
    )
