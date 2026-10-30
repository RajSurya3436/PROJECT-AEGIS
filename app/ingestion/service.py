"""The single ingestion path shared by upload, demo/replay, file tail and the HTTP receiver:

parse -> (adapter) -> validate/normalize -> deduplicate -> persist -> post-persist hooks ->
source health
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Callable, Iterable
from datetime import UTC, datetime

from app.config import Settings
from app.domain.enums import EventType, InputFormat, SourceStatus, SourceType
from app.domain.errors import IngestLimitError, NormalizationError
from app.domain.models import IngestResult, NormalizedEvent, ParseErrorRecord
from app.ingestion.adapters import RecordAdapter, get_adapter
from app.ingestion.normalizer import canonical_json, normalize_record
from app.ingestion.parsers import ParsedItem, RawRecord, decode_bytes, parse_text, safe_snippet
from app.storage.repositories import DataSourceRepository, EventRepository, ParseErrorRepository

logger = logging.getLogger(__name__)

# Called after each persisted batch with only the newly inserted events (Phase 2: detection).
PostPersistHook = Callable[[list[NormalizedEvent]], None]

BATCH_SIZE = 500


class IngestionService:
    def __init__(
        self,
        conn: sqlite3.Connection,
        settings: Settings,
        hooks: list[PostPersistHook] | None = None,
    ) -> None:
        self.settings = settings
        self.sources = DataSourceRepository(conn)
        self.events = EventRepository(conn)
        self.parse_errors = ParseErrorRepository(conn)
        self.hooks: list[PostPersistHook] = list(hooks or [])

    def ingest_bytes(
        self,
        content: bytes,
        fmt: InputFormat,
        *,
        source_id: str,
        source_type: SourceType,
        source_name: str,
        default_event_type: EventType | None = None,
        adapter: RecordAdapter | None = None,
    ) -> IngestResult:
        if len(content) > self.settings.max_upload_bytes:
            raise IngestLimitError(
                f"input is {len(content):,} bytes; limit is {self.settings.max_upload_bytes:,}"
            )
        text = decode_bytes(content)
        items = parse_text(text, fmt, source_id, self.settings.parse_error_snippet_chars)
        return self.ingest_items(
            items,
            source_id=source_id,
            source_type=source_type,
            source_name=source_name,
            default_event_type=default_event_type,
            adapter=adapter,
        )

    def ingest_items(
        self,
        items: Iterable[ParsedItem],
        *,
        source_id: str,
        source_type: SourceType,
        source_name: str,
        default_event_type: EventType | None = None,
        adapter: RecordAdapter | None = None,
    ) -> IngestResult:
        adapter = adapter or get_adapter(None)
        default_event_type = default_event_type or adapter.default_event_type
        self.sources.ensure(source_id, source_type, source_name)
        self.sources.set_status(source_id, SourceStatus.INGESTING)
        result = IngestResult(source_id=source_id)
        ingest_time = datetime.now(UTC)
        events: list[NormalizedEvent] = []
        errors: list[ParseErrorRecord] = []
        try:
            for item in items:
                if result.received >= self.settings.max_rows_per_ingest:
                    result.truncated = True
                    break
                result.received += 1
                if isinstance(item, ParseErrorRecord):
                    errors.append(item)
                else:
                    event_or_error = self._normalize(
                        item, source_id, ingest_time, default_event_type, adapter
                    )
                    if isinstance(event_or_error, ParseErrorRecord):
                        errors.append(event_or_error)
                    else:
                        events.append(event_or_error)
                if len(events) >= BATCH_SIZE:
                    self._flush(events, result)
                    events = []
            self._flush(events, result)
            result.quarantined = len(errors)
            self.parse_errors.add_many(errors)
        except Exception as exc:
            self.sources.set_status(source_id, SourceStatus.ERROR, f"ingest failed: {exc}")
            raise
        finally:
            self.sources.record_ingest(source_id, result.inserted, len(errors))

        problems: list[str] = []
        if result.truncated:
            problems.append(
                f"stopped after {self.settings.max_rows_per_ingest:,} rows (max_rows_per_ingest)"
            )
        problems.extend(result.hook_errors)
        self.sources.set_status(
            source_id,
            SourceStatus.ERROR if problems else SourceStatus.OK,
            "; ".join(problems) or None,
        )
        return result

    def _normalize(
        self,
        record: RawRecord,
        source_id: str,
        ingest_time: datetime,
        default_event_type: EventType | None,
        adapter: RecordAdapter,
    ) -> NormalizedEvent | ParseErrorRecord:
        try:
            shaped = adapter.transform(record.data)
            return normalize_record(
                shaped,
                source_id=source_id,
                locator=record.locator,
                ingest_time=ingest_time,
                default_event_type=default_event_type,
                received=None if shaped is record.data else record.data,
            )
        except (NormalizationError, ValueError, TypeError) as exc:
            return ParseErrorRecord(
                source_id=source_id,
                locator=record.locator,
                error=str(exc),
                raw_snippet=safe_snippet(
                    canonical_json(record.data), self.settings.parse_error_snippet_chars
                ),
            )

    def _flush(self, events: list[NormalizedEvent], result: IngestResult) -> None:
        if not events:
            return
        unique: dict[str, NormalizedEvent] = {}
        for event in events:
            unique.setdefault(event.event_id, event)  # identical rows within one batch
        inserted_ids = self.events.insert_many(list(unique.values()))
        result.inserted += len(inserted_ids)
        result.duplicates += len(events) - len(inserted_ids)
        result.inserted_event_ids.extend(inserted_ids)
        if not inserted_ids or not self.hooks:
            return
        new_events = [unique[event_id] for event_id in inserted_ids]
        for hook in self.hooks:
            try:
                hook(new_events)
            except Exception as exc:  # a hook failure must not lose already-stored events
                logger.exception("post-persist hook failed")
                result.hook_errors.append(f"{getattr(hook, '__name__', 'hook')}: {exc}")
