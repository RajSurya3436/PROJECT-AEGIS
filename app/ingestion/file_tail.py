"""Follow growing JSONL files (e.g. Wazuh's alerts.json) through the shared ingestion path.

Each poll opens the file, reads from the saved offset, ingests complete lines and closes it
again (holding it open would stop other programs rotating it on Windows). The cursor (offset
plus a fingerprint of the file's first bytes) is stored on the source, so a restart continues
where it stopped:

- a line without its newline yet is left for the next poll (partial write);
- a file shorter than the offset was truncated: reading restarts at 0;
- a different first-bytes fingerprint means the file was replaced (rotation): restart at 0.
  Lines appended to the old file after the last poll and before rotation are not seen; keep
  the poll interval short (default 2 s) relative to rotation;
- a line longer than ``file_tail_max_line_bytes`` is quarantined and skipped;
- re-reading lines is harmless: event IDs are stable, so duplicates are not stored.

``TailManager`` keeps the followed files in ``app_settings`` and polls them on one background
thread with its own SQLite connection.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import sqlite3
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.audit.log import AuditLog
from app.config import Settings
from app.domain.enums import SourceStatus, SourceType
from app.domain.errors import SocCopilotError
from app.domain.models import ParseErrorRecord
from app.ingestion.adapters import get_adapter
from app.ingestion.parsers import ParsedItem, RawRecord, safe_snippet
from app.ingestion.service import IngestionService
from app.storage.repositories import AppSettingsRepository

logger = logging.getLogger(__name__)

FINGERPRINT_BYTES = 256
TAILS_KEY = "ingestion.file_tails"


class TailError(SocCopilotError):
    """A followed file cannot be added or read."""


def _first_line(head: bytes) -> bytes:
    end = head.find(b"\n")
    return head if end < 0 else head[: end + 1]


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tail_source_id(path: Path) -> str:
    """Stable per resolved path, so following the same file again continues its cursor."""
    resolved = str(path.resolve())
    slug = re.sub(r"[^a-z0-9]+", "-", path.name.lower()).strip("-")[:30] or "file"
    return f"tail-{slug}-{hashlib.sha256(resolved.encode('utf-8')).hexdigest()[:8]}"


@dataclass
class PollResult:
    source_id: str
    inserted: int = 0
    duplicates: int = 0
    quarantined: int = 0
    bytes_read: int = 0
    reset: str | None = None  # "truncated" or "rotated" when reading restarted at 0
    waiting_partial: bool = False
    error: str | None = None


@dataclass(frozen=True)
class TailConfig:
    path: str
    adapter: str = "generic"
    name: str = ""
    start_at_end: bool = False

    @property
    def source_id(self) -> str:
        return tail_source_id(Path(self.path))


class FileTailer:
    def __init__(self, service: IngestionService, config: TailConfig) -> None:
        self.service = service
        self.config = config
        self.path = Path(config.path)
        self.source_id = config.source_id
        self.adapter = get_adapter(config.adapter)
        settings = service.settings
        self.max_bytes = settings.file_tail_max_bytes_per_poll
        self.max_line = settings.file_tail_max_line_bytes
        self.snippet_chars = settings.parse_error_snippet_chars

    def poll(self) -> PollResult:
        result = PollResult(self.source_id)
        sources = self.service.sources
        source = sources.ensure(self.source_id, SourceType.FILE_TAIL, self._name())
        cursor = dict(source.cursor)
        try:
            size = self.path.stat().st_size
            if not self.path.is_file():
                raise OSError("not a regular file")
            with self.path.open("rb") as handle:
                cursor = self._check_identity(handle, size, cursor, result)
                handle.seek(cursor["offset"])
                chunk = handle.read(self.max_bytes)
        except OSError as exc:
            result.error = f"cannot read {self.path}: {exc.strerror or exc}"
            sources.set_status(self.source_id, SourceStatus.ERROR, result.error)
            return result
        items, consumed, cursor = self._lines(chunk, cursor, result)
        if items:
            ingest = self.service.ingest_items(
                items,
                source_id=self.source_id,
                source_type=SourceType.FILE_TAIL,
                source_name=self._name(),
                adapter=self.adapter,
            )
            result.inserted, result.duplicates = ingest.inserted, ingest.duplicates
            result.quarantined += ingest.quarantined
        cursor["offset"] += consumed
        cursor["last_poll"] = datetime.now(UTC).isoformat()
        result.bytes_read = consumed
        sources.set_cursor(self.source_id, cursor)  # only after the lines are stored
        if not items:
            sources.set_status(self.source_id, SourceStatus.OK)
        return result

    def _name(self) -> str:
        return self.config.name or f"{self.path.name} (tail, {self.adapter.name})"

    def _check_identity(
        self, handle: Any, size: int, cursor: dict[str, Any], result: PollResult
    ) -> dict[str, Any]:
        """The file is "the same file" while its first line (up to 256 bytes) is unchanged."""
        head = _first_line(handle.read(FINGERPRINT_BYTES))
        if "offset" not in cursor or cursor.get("path") != str(self.path):
            offset = 0
            skip = False
            if self.config.start_at_end:
                offset = size
                handle.seek(max(size - 1, 0))
                skip = size > 0 and handle.read(1) != b"\n"  # mid-line: wait for the next one
            return self._fresh(head, offset, skip)
        known_len = cursor.get("fingerprint_len", 0)
        same = len(head) >= known_len and _digest(head[:known_len]) == cursor.get("fingerprint")
        if size < cursor["offset"] and (same or size == 0):
            result.reset = "truncated"
            return self._fresh(head, 0, False)
        if not same:
            result.reset = "rotated"
            return self._fresh(head, 0, False)
        if len(head) > known_len:  # the first line was still being written last time
            cursor["fingerprint"], cursor["fingerprint_len"] = _digest(head), len(head)
        return cursor

    def _fresh(self, head: bytes, offset: int, skip: bool) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "offset": offset,
            "fingerprint": _digest(head),
            "fingerprint_len": len(head),
            "skip_to_newline": skip,
        }

    def _lines(
        self, chunk: bytes, cursor: dict[str, Any], result: PollResult
    ) -> tuple[list[ParsedItem], int, dict[str, Any]]:
        """Complete lines of ``chunk`` as parsed items, and how many bytes they used."""
        items: list[ParsedItem] = []
        position = 0
        base = cursor["offset"]
        if cursor.get("skip_to_newline"):
            end = chunk.find(b"\n")
            if end < 0:
                return items, len(chunk), cursor  # still inside the overlong/partial line
            position = end + 1
            cursor["skip_to_newline"] = False
        while position < len(chunk):
            end = chunk.find(b"\n", position)
            if end < 0:
                rest = len(chunk) - position
                if rest >= self.max_line:  # an overlong line: quarantine, skip to its end
                    items.append(self._error(base + position, chunk[position:], "line too long"))
                    cursor["skip_to_newline"] = True
                    return items, len(chunk), cursor
                result.waiting_partial = True
                break
            line = chunk[position:end]
            locator = base + position
            position = end + 1
            if len(line) > self.max_line:
                items.append(self._error(locator, line, "line too long"))
            elif line.strip():
                items.append(self._parse(locator, line))
        return items, position, cursor

    def _parse(self, offset: int, line: bytes) -> ParsedItem:
        try:
            value = json.loads(line.decode("utf-8-sig"))
        except UnicodeDecodeError:
            return self._error(offset, line, "line is not valid UTF-8")
        except json.JSONDecodeError as exc:
            return self._error(offset, line, f"invalid JSON: {exc.msg} (col {exc.colno})")
        if not isinstance(value, dict):
            return self._error(offset, line, f"expected a JSON object, got {type(value).__name__}")
        return RawRecord(f"offset:{offset}", value)

    def _error(self, offset: int, line: bytes, message: str) -> ParseErrorRecord:
        if message == "line too long":
            message = f"line longer than {self.max_line:,} bytes"
        return ParseErrorRecord(
            source_id=self.source_id,
            locator=f"offset:{offset}",
            error=message,
            raw_snippet=safe_snippet(line[:2_000].decode("utf-8", "replace"), self.snippet_chars),
        )


@dataclass
class TailStatus:
    running: bool
    configs: list[TailConfig]
    last: dict[str, PollResult] = field(default_factory=dict)
    last_poll: datetime | None = None


class TailManager:
    """The followed files and one polling thread. All polling (thread or "Poll now") goes
    through one lock and one connection, so a file is never read by two pollers at once."""

    def __init__(
        self,
        settings: Settings,
        session: Callable[[], tuple[IngestionService, sqlite3.Connection]],
        threaded: bool = True,
    ) -> None:
        self.settings = settings
        self.service, self.conn = session()
        self.app_settings = AppSettingsRepository(self.conn)
        self.audit = AuditLog(self.conn)
        self.threaded = threaded
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last: dict[str, PollResult] = {}
        self._last_poll: datetime | None = None

    # --- configuration ---------------------------------------------------------------------

    def configs(self) -> list[TailConfig]:
        return [TailConfig(**c) for c in self.app_settings.get(TAILS_KEY, [])]

    def add(
        self, path: str, adapter: str = "generic", *, start_at_end: bool = False, name: str = ""
    ) -> TailConfig:
        file = Path(path.strip().strip('"')).expanduser()
        if not file.is_file():
            raise TailError(f"{file} is not an existing file")
        get_adapter(adapter)
        config = TailConfig(str(file.resolve()), adapter, name.strip()[:100], start_at_end)
        with self._lock:
            kept = [c for c in self.configs() if c.source_id != config.source_id]
            self._save([*kept, config])
        self.audit.record(
            "analyst",
            "ingestion.file_tail_added",
            "source",
            config.source_id,
            details={"path": config.path, "adapter": adapter, "start_at_end": start_at_end},
        )
        return config

    def remove(self, source_id: str) -> None:
        with self._lock:
            self._save([c for c in self.configs() if c.source_id != source_id])
            self._last.pop(source_id, None)
        self.audit.record("analyst", "ingestion.file_tail_removed", "source", source_id)

    def _save(self, configs: list[TailConfig]) -> None:
        self.app_settings.set(TAILS_KEY, [c.__dict__ for c in configs])

    # --- polling ---------------------------------------------------------------------------

    def poll_all(self) -> list[PollResult]:
        with self._lock:
            results = []
            for config in self.configs():
                try:
                    result = FileTailer(self.service, config).poll()
                except Exception as exc:  # one bad file must not stop the others
                    logger.exception("file tail %s failed", config.path)
                    result = PollResult(config.source_id, error=f"{type(exc).__name__}: {exc}")
                self._last[config.source_id] = result
                results.append(result)
            self._last_poll = datetime.now(UTC)
            return results

    def start(self) -> None:
        if not self.threaded:
            raise TailError("live following needs a file database; use Poll now")
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, name="file-tail", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        with self._lock:
            thread = self._thread
        if thread is None:
            return
        self._stop.set()
        thread.join(timeout=10)

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def status(self) -> TailStatus:
        with self._lock:
            return TailStatus(self.running, self.configs(), dict(self._last), self._last_poll)

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.poll_all()
            self._stop.wait(self.settings.file_tail_poll_seconds)
