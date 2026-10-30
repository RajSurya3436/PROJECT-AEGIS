"""Local HTTP receiver: other tools on this machine POST events into the shared ingestion path.

    POST http://127.0.0.1:8787/ingest?source=<name>&adapter=generic|wazuh
    Content-Type: application/json            (one object, an array, or {"events": [...]})
               or application/x-ndjson        (one JSON object per line)
    GET  http://127.0.0.1:8787/health

Safety, all enforced here:
- binds to a loopback address only (127.0.0.1 / ::1 / localhost); anything else is refused;
- a ``Host`` header that is not loopback is refused (DNS rebinding), and so is any request
  carrying an ``Origin`` header (a web page in a browser), and any content type a browser can
  send without a CORS preflight; together these stop websites from posting events;
- optional shared token (``HTTP_RECEIVER_TOKEN``): ``Authorization: Bearer <token>``;
- body size, records per request and requests per minute are capped; the body is never echoed.
Standard library only (``http.server``); one ingestion connection, used under a lock.
"""

from __future__ import annotations

import hmac
import json
import logging
import re
import sqlite3
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

from app.audit.log import AuditLog
from app.config import Settings
from app.domain.enums import SourceType
from app.domain.errors import SocCopilotError
from app.domain.models import ParseErrorRecord
from app.ingestion.adapters import ADAPTERS, get_adapter
from app.ingestion.parsers import ParsedItem, RawRecord, safe_snippet
from app.ingestion.service import IngestionService

logger = logging.getLogger(__name__)

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
JSON_TYPES = frozenset({"application/json"})
NDJSON_TYPES = frozenset({"application/x-ndjson", "application/jsonl", "application/ndjson"})
DRAIN_LIMIT = 16 * 1024 * 1024  # rejected bodies up to this size are read and dropped
_SOURCE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")


class ReceiverError(SocCopilotError):
    """The receiver cannot start with the given settings."""


class RequestRejected(Exception):
    def __init__(self, status: HTTPStatus, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass
class ReceiverStats:
    requests: int = 0
    accepted: int = 0
    rejected: int = 0
    events_inserted: int = 0
    last_error: str | None = None
    last_request: float | None = None
    by_status: dict[int, int] = field(default_factory=dict)


class RateLimiter:
    """Fixed one-minute window; enough to stop a runaway sender flooding the database."""

    def __init__(self, per_minute: int, clock: Callable[[], float] = time.monotonic) -> None:
        self.per_minute = per_minute
        self._clock = clock
        self._window = clock()
        self._count = 0
        self._lock = threading.Lock()

    def allow(self) -> bool:
        with self._lock:
            now = self._clock()
            if now - self._window >= 60:
                self._window, self._count = now, 0
            if self._count >= self.per_minute:
                return False
            self._count += 1
            return True


def http_source_id(name: str) -> str:
    return f"http-{name}"


class HttpReceiver:
    def __init__(
        self,
        settings: Settings,
        session: Callable[[], tuple[IngestionService, sqlite3.Connection]],
    ) -> None:
        host = settings.http_receiver_host.strip().strip("[]")
        if host not in LOOPBACK_HOSTS:
            raise ReceiverError(
                f"HTTP_RECEIVER_HOST must be a loopback address (127.0.0.1, ::1 or localhost); "
                f"{host!r} would expose the receiver to the network"
            )
        self.settings = settings
        self.host = host
        self._session = session
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()  # one ingestion at a time on the receiver's connection
        self.service: IngestionService | None = None
        self.audit: AuditLog | None = None
        self.stats = ReceiverStats()
        self.limiter = RateLimiter(settings.http_receiver_requests_per_minute)

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def port(self) -> int | None:
        return self._server.server_address[1] if self._server else None

    @property
    def url(self) -> str | None:
        if self._server is None:
            return None
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{host}:{self.port}"

    def start(self) -> None:
        if self.running:
            return
        if self.service is None:
            self.service, conn = self._session()
            self.audit = AuditLog(conn)
        handler = _make_handler(self)
        try:
            server_class = _Ipv6Server if ":" in self.host else ThreadingHTTPServer
            self._server = server_class((self.host, self.settings.http_receiver_port), handler)
        except OSError as exc:
            raise ReceiverError(
                f"cannot listen on {self.host}:{self.settings.http_receiver_port}: {exc}"
            ) from exc
        self._server.daemon_threads = True
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="http-receiver", daemon=True
        )
        self._thread.start()
        assert self.audit is not None
        self.audit.record(
            "analyst",
            "ingestion.http_receiver_started",
            "receiver",
            self.url or "",
            details={"token_required": self._token_required()},
        )

    def _token_required(self) -> bool:
        token = self.settings.http_receiver_token
        return token is not None and bool(token.get_secret_value())

    def stop(self) -> None:
        server, thread = self._server, self._thread
        if server is None:
            return
        server.shutdown()
        server.server_close()
        if thread is not None:
            thread.join(timeout=10)
        if self.audit is not None:
            self.audit.record(
                "analyst", "ingestion.http_receiver_stopped", "receiver", self.url or ""
            )
        self._server = self._thread = None

    # --- request handling (called from handler threads) ------------------------------------

    def handle(self, method: str, path: str, headers: Any, read_body: Callable[[int], bytes]):
        """Returns (status, JSON-able body). Raises nothing."""
        self.stats.requests += 1
        self.stats.last_request = time.time()
        try:
            status, body = self._route(method, path, headers, read_body)
            self.stats.accepted += 1
        except RequestRejected as exc:
            status, body = exc.status, {"error": exc.message}
            self.stats.rejected += 1
            self.stats.last_error = f"{exc.status.value}: {exc.message}"
        except Exception as exc:  # a bug must answer 500, not kill the server thread
            logger.exception("HTTP receiver request failed")
            status, body = HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal error"}
            self.stats.rejected += 1
            self.stats.last_error = f"500: {type(exc).__name__}"
        self.stats.by_status[status.value] = self.stats.by_status.get(status.value, 0) + 1
        return status, body

    def _route(self, method, path, headers, read_body) -> tuple[HTTPStatus, dict[str, Any]]:
        self._check_origin(headers)
        url = urlsplit(path)
        if method == "GET" and url.path == "/health":
            return HTTPStatus.OK, {"status": "ok", "adapters": sorted(ADAPTERS)}
        if url.path != "/ingest":
            raise RequestRejected(HTTPStatus.NOT_FOUND, "unknown path; use POST /ingest")
        if method != "POST":
            raise RequestRejected(HTTPStatus.METHOD_NOT_ALLOWED, "use POST /ingest")
        self._check_token(headers)
        if not self.limiter.allow():
            raise RequestRejected(HTTPStatus.TOO_MANY_REQUESTS, "rate limit reached; slow down")
        content_type = (headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if content_type not in JSON_TYPES | NDJSON_TYPES:
            raise RequestRejected(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "Content-Type must be application/json or application/x-ndjson",
            )
        length = self._length(headers)
        query = parse_qs(url.query)
        source = (query.get("source") or ["default"])[0].strip().lower()
        if not _SOURCE.match(source):
            raise RequestRejected(
                HTTPStatus.BAD_REQUEST, "source must be 1-40 characters: a-z, 0-9 and '-'"
            )
        try:
            adapter = get_adapter((query.get("adapter") or ["generic"])[0])
        except SocCopilotError as exc:
            raise RequestRejected(HTTPStatus.BAD_REQUEST, str(exc)) from None
        body = read_body(length)
        items = self._parse(body, content_type in NDJSON_TYPES, http_source_id(source))
        assert self.service is not None
        with self._lock:
            result = self.service.ingest_items(
                items,
                source_id=http_source_id(source),
                source_type=SourceType.HTTP,
                source_name=f"HTTP {source} ({adapter.name})",
                adapter=adapter,
            )
        self.stats.events_inserted += result.inserted
        return HTTPStatus.OK, {
            "source_id": result.source_id,
            "received": result.received,
            "inserted": result.inserted,
            "duplicates": result.duplicates,
            "quarantined": result.quarantined,
        }

    def _check_origin(self, headers: Any) -> None:
        if headers.get("Origin") is not None:
            raise RequestRejected(HTTPStatus.FORBIDDEN, "browser requests are not accepted")
        host = (headers.get("Host") or "").strip().lower()
        name = host.rsplit(":", 1)[0] if not host.startswith("[") else host[1:].split("]")[0]
        if name not in LOOPBACK_HOSTS:
            raise RequestRejected(HTTPStatus.FORBIDDEN, "Host must be a loopback address")

    def _check_token(self, headers: Any) -> None:
        token = self.settings.http_receiver_token
        if not self._token_required() or token is None:
            return
        expected = f"Bearer {token.get_secret_value()}"
        given = headers.get("Authorization") or ""
        if not hmac.compare_digest(given.encode("utf-8"), expected.encode("utf-8")):
            raise RequestRejected(HTTPStatus.UNAUTHORIZED, "missing or wrong bearer token")

    def _length(self, headers: Any) -> int:
        raw = headers.get("Content-Length")
        if raw is None:
            raise RequestRejected(HTTPStatus.LENGTH_REQUIRED, "Content-Length is required")
        try:
            length = int(raw)
        except ValueError:
            raise RequestRejected(HTTPStatus.BAD_REQUEST, "invalid Content-Length") from None
        if length < 0:
            raise RequestRejected(HTTPStatus.BAD_REQUEST, "invalid Content-Length")
        if length > self.settings.http_receiver_max_body_bytes:
            raise RequestRejected(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                f"body over {self.settings.http_receiver_max_body_bytes:,} bytes",
            )
        return length

    def _parse(self, body: bytes, ndjson: bool, source_id: str) -> list[ParsedItem]:
        try:
            text = body.decode("utf-8-sig")
        except UnicodeDecodeError:
            raise RequestRejected(HTTPStatus.BAD_REQUEST, "body is not valid UTF-8") from None
        limit = self.settings.http_receiver_max_records
        snippet = self.settings.parse_error_snippet_chars
        items: list[ParsedItem] = []
        if ndjson:
            lines = [(n, line) for n, line in enumerate(text.splitlines(), 1) if line.strip()]
            if len(lines) > limit:
                raise RequestRejected(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE, f"more than {limit:,} records"
                )
            for number, line in lines:
                items.append(_item(line, f"line:{number}", source_id, snippet))
            return items
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as exc:
            raise RequestRejected(HTTPStatus.BAD_REQUEST, f"invalid JSON: {exc.msg}") from None
        if isinstance(doc, dict) and isinstance(doc.get("events"), list):
            records = doc["events"]
        elif isinstance(doc, list):
            records = doc
        elif isinstance(doc, dict):
            records = [doc]
        else:
            raise RequestRejected(
                HTTPStatus.BAD_REQUEST, 'send an object, an array or {"events": [...]}'
            )
        if len(records) > limit:
            raise RequestRejected(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE, f"more than {limit:,} records"
            )
        for index, record in enumerate(records):
            if isinstance(record, dict):
                items.append(RawRecord(f"index:{index}", record))
            else:
                items.append(
                    ParseErrorRecord(
                        source_id=source_id,
                        locator=f"index:{index}",
                        error=f"expected a JSON object, got {type(record).__name__}",
                        raw_snippet=safe_snippet(json.dumps(record, default=str), snippet),
                    )
                )
        return items


def _item(line: str, locator: str, source_id: str, snippet: int) -> ParsedItem:
    try:
        value = json.loads(line)
    except json.JSONDecodeError as exc:
        return ParseErrorRecord(
            source_id=source_id,
            locator=locator,
            error=f"invalid JSON: {exc.msg} (col {exc.colno})",
            raw_snippet=safe_snippet(line, snippet),
        )
    if not isinstance(value, dict):
        return ParseErrorRecord(
            source_id=source_id,
            locator=locator,
            error=f"expected a JSON object, got {type(value).__name__}",
            raw_snippet=safe_snippet(line, snippet),
        )
    return RawRecord(locator, value)


class _Ipv6Server(ThreadingHTTPServer):
    import socket as _socket

    address_family = _socket.AF_INET6


def _make_handler(receiver: HttpReceiver) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "AgenticSOC-Receiver"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def _serve(self, method: str) -> None:
            consumed = False

            def read_body(length: int) -> bytes:
                nonlocal consumed
                consumed = True
                return self.rfile.read(length)

            status, body = receiver.handle(method, self.path, self.headers, read_body)
            if not consumed:
                self._drain()  # so the sender reads our answer instead of a reset
            payload = json.dumps(body).encode("utf-8")
            self.send_response(status.value)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("X-Content-Type-Options", "nosniff")
            if status is not HTTPStatus.OK:
                self.send_header("Connection", "close")
                self.close_connection = True
            self.end_headers()
            self.wfile.write(payload)

        def _drain(self) -> None:
            """Discard an unread request body, up to a bound; beyond it just close."""
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return
            if 0 < length <= DRAIN_LIMIT:
                remaining = length
                while remaining:
                    chunk = self.rfile.read(min(remaining, 65_536))
                    if not chunk:
                        break
                    remaining -= len(chunk)

        def do_GET(self) -> None:
            self._serve("GET")

        def do_POST(self) -> None:
            self._serve("POST")

        def do_PUT(self) -> None:
            self._serve("PUT")

        def do_DELETE(self) -> None:
            self._serve("DELETE")

        def do_OPTIONS(self) -> None:  # no CORS: preflights get no allow headers
            self._serve("OPTIONS")

        def log_message(self, format: str, *args: Any) -> None:
            logger.debug("receiver: " + format, *args)

    return Handler
