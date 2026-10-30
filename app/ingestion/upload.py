"""Analyst file upload: a side-effect-free preview, then ingestion through the shared service."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from app.config import Settings
from app.domain.enums import EventType, InputFormat, SourceType
from app.domain.errors import IngestLimitError, NormalizationError
from app.domain.models import IngestResult, ParseErrorRecord
from app.ingestion.adapters import RecordAdapter, get_adapter
from app.ingestion.normalizer import canonical_json, flatten, map_fields, normalize_record
from app.ingestion.parsers import RawRecord, decode_bytes, parse_text, safe_snippet
from app.ingestion.service import IngestionService

PREVIEW_ROWS = 20


@dataclass
class UploadPreview:
    fmt: InputFormat
    records_previewed: int = 0
    columns: list[str] = field(default_factory=list)
    mapping: dict[str, str] = field(default_factory=dict)  # input key -> canonical field
    unmapped: list[str] = field(default_factory=list)
    rows: list[dict[str, Any]] = field(default_factory=list)
    errors: list[ParseErrorRecord] = field(default_factory=list)


def upload_source_id(filename: str) -> str:
    """Stable per-filename source ID, so re-uploading the same file deduplicates."""
    slug = re.sub(r"[^a-z0-9]+", "-", filename.lower()).strip("-")[:40] or "file"
    digest = hashlib.sha256(filename.encode("utf-8")).hexdigest()[:8]
    return f"upload-{slug}-{digest}"


def preview_upload(
    content: bytes,
    fmt: InputFormat,
    settings: Settings,
    *,
    default_event_type: EventType | None = None,
    max_rows: int = PREVIEW_ROWS,
    adapter: RecordAdapter | None = None,
) -> UploadPreview:
    """Parse and normalize the first ``max_rows`` records without persisting anything."""
    if len(content) > settings.max_upload_bytes:
        raise IngestLimitError(
            f"file is {len(content):,} bytes; limit is {settings.max_upload_bytes:,}"
        )
    adapter = adapter or get_adapter(None)
    preview = UploadPreview(fmt=fmt)
    columns: dict[str, None] = {}
    mapping: dict[str, str] = {}
    for item in parse_text(
        decode_bytes(content), fmt, "preview", settings.parse_error_snippet_chars
    ):
        if preview.records_previewed >= max_rows:
            break
        preview.records_previewed += 1
        if isinstance(item, ParseErrorRecord):
            preview.errors.append(item)
            continue
        flat = flatten(adapter.transform(item.data))
        columns.update(dict.fromkeys(flat))
        _, _, chosen = map_fields(flat)
        mapping.update(chosen)
        _preview_row(item, preview, default_event_type, settings, adapter)
    preview.columns = list(columns)
    preview.mapping = mapping
    preview.unmapped = [c for c in columns if c not in mapping]
    return preview


def _preview_row(
    item: RawRecord,
    preview: UploadPreview,
    default_event_type: EventType | None,
    settings: Settings,
    adapter: RecordAdapter,
) -> None:
    try:
        event = normalize_record(
            adapter.transform(item.data),
            source_id="preview",
            locator=item.locator,
            default_event_type=default_event_type,
        )
    except (NormalizationError, ValueError, TypeError) as exc:
        preview.errors.append(
            ParseErrorRecord(
                source_id="preview",
                locator=item.locator,
                error=str(exc),
                raw_snippet=safe_snippet(
                    canonical_json(item.data), settings.parse_error_snippet_chars
                ),
            )
        )
        return
    preview.rows.append(
        event.model_dump(
            mode="json", exclude={"raw", "source_id", "ingest_time", "event_id", "schema_version"}
        )
    )


def ingest_upload(
    service: IngestionService,
    filename: str,
    content: bytes,
    fmt: InputFormat,
    *,
    default_event_type: EventType | None = None,
    adapter: RecordAdapter | None = None,
) -> IngestResult:
    return service.ingest_bytes(
        content,
        fmt,
        source_id=upload_source_id(filename),
        source_type=SourceType.UPLOAD,
        source_name=filename,
        default_event_type=default_event_type,
        adapter=adapter,
    )
