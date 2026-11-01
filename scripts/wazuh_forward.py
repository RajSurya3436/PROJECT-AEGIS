"""Forward live Wazuh alerts from a Docker container to this app's local HTTP receiver.

    python scripts/wazuh_forward.py                                  # defaults below
    python scripts/wazuh_forward.py --container single-node-wazuh.manager-1 --from-start

Reads ``/var/ossec/logs/alerts/alerts.json`` inside the Wazuh manager container with
``docker exec <container> tail -F`` (the official single-node compose keeps it in a named
volume, so the app cannot tail the file directly) and POSTs the lines in batches to
``http://127.0.0.1:<port>/ingest?source=<source>&adapter=wazuh``. Start the receiver first
(Live inputs page). Uses HTTP_RECEIVER_TOKEN from .env when it is set.

Batches stay under the receiver's limits (records, bytes, requests per minute). If the receiver
is down or busy the batch is kept and retried; a batch it rejects as invalid is reported and
dropped, so one bad line cannot block the stream. Standard library only. Stop with Ctrl+C.
"""

from __future__ import annotations

import argparse
import queue
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import get_settings

ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
DEFAULT_CONTAINER = "single-node-wazuh.manager-1"
MAX_RECORDS = 500  # receiver default limit: 1,000 per request
MAX_BYTES = 512 * 1024  # receiver default limit: 1 MiB per body
FLUSH_SECONDS = 2.0  # at most ~30 requests a minute (receiver default limit: 120)
MAX_BUFFERED = 20_000  # lines kept while the receiver is unreachable; oldest dropped after
RETRY_SECONDS = 5.0
CONTAINER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")  # Docker's own rule
SOURCE_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")  # the receiver's rule


@dataclass
class PostResult:
    ok: bool
    retry: bool  # keep the batch and try again later
    message: str


Poster = Callable[[bytes], PostResult]


def http_poster(url: str, token: str | None, timeout: float = 30.0) -> Poster:
    if not url.startswith(("http://127.0.0.1:", "http://localhost:")):
        raise ValueError("the forwarder only posts to the local receiver (http://127.0.0.1:...)")

    def post(body: bytes) -> PostResult:
        headers = {"Content-Type": "application/x-ndjson"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        # loopback http only, checked above
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")  # noqa: S310
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
                return PostResult(True, False, response.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:300]
            retry = exc.code == 429 or exc.code >= 500
            return PostResult(False, retry, f"HTTP {exc.code}: {detail}")
        except (urllib.error.URLError, OSError) as exc:
            return PostResult(False, True, f"receiver unreachable: {exc}")

    return post


@dataclass
class Forwarder:
    """Collects alert lines and sends them in batches; no I/O of its own except ``post``."""

    post: Poster
    log: Callable[[str], None] = print
    max_records: int = MAX_RECORDS
    max_bytes: int = MAX_BYTES
    flush_seconds: float = FLUSH_SECONDS
    max_buffered: int = MAX_BUFFERED
    pending: list[str] = field(default_factory=list)
    first_at: float | None = None
    retry_after: float = 0.0
    sent: int = 0
    dropped: int = 0

    def add(self, line: str, now: float) -> None:
        line = line.strip()
        if not line:
            return
        if len(line.encode("utf-8")) > self.max_bytes:
            self.dropped += 1
            self.log(f"skipped one alert larger than {self.max_bytes:,} bytes")
            return
        self.pending.append(line)
        if len(self.pending) > self.max_buffered:
            overflow = len(self.pending) - self.max_buffered
            del self.pending[:overflow]
            self.dropped += overflow
            self.log(f"buffer full: dropped the {overflow} oldest alert(s)")
        if self.first_at is None:
            self.first_at = now

    def due(self, now: float) -> bool:
        if not self.pending or now < self.retry_after:
            return False
        assert self.first_at is not None
        return len(self.pending) >= self.max_records or now - self.first_at >= self.flush_seconds

    def _next_batch(self) -> list[str]:
        batch: list[str] = []
        size = 0
        for line in self.pending[: self.max_records]:
            n = len(line.encode("utf-8")) + 1
            if batch and size + n > self.max_bytes:
                break
            batch.append(line)
            size += n
        return batch

    def flush(self, now: float) -> None:
        while self.pending and now >= self.retry_after:
            batch = self._next_batch()
            result = self.post(("\n".join(batch) + "\n").encode("utf-8"))
            if result.retry:
                self.retry_after = now + RETRY_SECONDS
                self.log(f"{result.message}; retrying in {RETRY_SECONDS:.0f} s")
                return
            del self.pending[: len(batch)]
            if result.ok:
                self.sent += len(batch)
                self.log(f"sent {len(batch)} alert(s) ({self.sent} in total): {result.message}")
            else:
                self.dropped += len(batch)
                self.log(f"receiver rejected {len(batch)} alert(s), dropped: {result.message}")
        self.first_at = now if self.pending else None


def _read_lines(stream, lines: queue.Queue[str | None]) -> None:
    for raw in iter(stream.readline, b""):
        lines.put(raw.decode("utf-8", "replace"))
    lines.put(None)  # tail ended


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").strip().splitlines()[0])
    parser.add_argument("--container", default=DEFAULT_CONTAINER, help="Wazuh manager container")
    parser.add_argument("--source", default="wazuh-live", help="source name shown in the app")
    parser.add_argument(
        "--from-start", action="store_true", help="send the whole alerts file, not only new alerts"
    )
    args = parser.parse_args()
    if not CONTAINER_NAME.match(args.container):
        parser.error("--container is not a valid Docker container name")
    if not SOURCE_NAME.match(args.source):
        parser.error("--source: lowercase letters, digits and '-', up to 40 characters")

    settings = get_settings()
    url = (
        f"http://127.0.0.1:{settings.http_receiver_port}/ingest?source={args.source}&adapter=wazuh"
    )
    token = (
        settings.http_receiver_token.get_secret_value() if settings.http_receiver_token else None
    )
    command = [
        "docker",
        "exec",
        args.container,
        "tail",
        "-n",
        "+1" if args.from_start else "0",
        "-F",
        ALERTS_FILE,
    ]
    try:
        # fixed argument list, no shell; the container name is validated above
        tail = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  # noqa: S603
    except FileNotFoundError:
        print("docker was not found; install Docker Desktop and start it.")
        return 2
    lines: queue.Queue[str | None] = queue.Queue()
    threading.Thread(target=_read_lines, args=(tail.stdout, lines), daemon=True).start()
    forwarder = Forwarder(http_poster(url, token))
    print(f"Forwarding {ALERTS_FILE} from container {args.container} to {url.split('?')[0]}")
    print("Press Ctrl+C to stop.")
    try:
        while True:
            try:
                line = lines.get(timeout=0.5)
            except queue.Empty:
                line = ""
            now = time.monotonic()
            if line is None:
                forwarder.flush(now)
                error = (tail.stderr.read() if tail.stderr else b"").decode("utf-8", "replace")
                print(f"docker exec ended: {error.strip() or 'no output'}")
                print("Is the container running?  docker ps --format '{{.Names}}'")
                return 1
            forwarder.add(line, now)
            if forwarder.due(now):
                forwarder.flush(now)
    except KeyboardInterrupt:
        forwarder.flush(time.monotonic())
        print(f"Stopped. Sent {forwarder.sent}, dropped {forwarder.dropped}.")
        return 0
    finally:
        tail.terminate()


if __name__ == "__main__":
    raise SystemExit(main())
