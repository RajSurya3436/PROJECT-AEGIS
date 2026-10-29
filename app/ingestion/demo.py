"""Load the bundled synthetic demo dataset through the shared ingestion service."""

from __future__ import annotations

import json
from pathlib import Path

from app.config import DEMO_DATA_DIR
from app.domain.enums import EventType, InputFormat, SourceType
from app.domain.models import IngestResult
from app.ingestion.service import IngestionService


def load_manifest(demo_dir: Path = DEMO_DATA_DIR) -> dict:
    return json.loads((demo_dir / "manifest.json").read_text(encoding="utf-8"))


def ingest_demo(service: IngestionService, demo_dir: Path = DEMO_DATA_DIR) -> list[IngestResult]:
    """Ingest every file in the manifest. Safe to call repeatedly: event IDs are stable."""
    manifest = load_manifest(demo_dir)
    results: list[IngestResult] = []
    for entry in manifest["files"]:
        content = (demo_dir / entry["path"]).read_bytes()
        results.append(
            service.ingest_bytes(
                content,
                InputFormat(entry["format"]),
                source_id=entry["source_id"],
                source_type=SourceType.DEMO_REPLAY,
                source_name=entry["name"],
                default_event_type=EventType(entry["default_event_type"]),
            )
        )
    return results
