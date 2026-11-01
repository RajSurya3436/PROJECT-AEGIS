"""scripts/wazuh_forward.py: batching, retries, and delivery to the real local receiver."""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Iterator

import pytest
from fixtures.settings import make_settings

from app.config import PROJECT_ROOT
from app.context import build_context

SAMPLE = PROJECT_ROOT / "data" / "samples" / "wazuh_alerts.jsonl"
_spec = importlib.util.spec_from_file_location(
    "wazuh_forward", PROJECT_ROOT / "scripts" / "wazuh_forward.py"
)
assert _spec is not None and _spec.loader is not None
fw = importlib.util.module_from_spec(_spec)
sys.modules["wazuh_forward"] = fw  # dataclasses look their module up here
_spec.loader.exec_module(fw)


class FakeReceiver:
    def __init__(self, results: list) -> None:
        self.results = results
        self.bodies: list[bytes] = []

    def __call__(self, body: bytes):
        self.bodies.append(body)
        return self.results.pop(0) if self.results else fw.PostResult(True, False, "ok")


def _forwarder(post, **kw):
    return fw.Forwarder(post, log=lambda _m: None, **kw)


def test_waits_for_the_flush_interval_or_a_full_batch():
    post = FakeReceiver([])
    f = _forwarder(post, max_records=3, flush_seconds=2)
    f.add('{"a":1}\n', now=0)
    f.add("   \n", now=0.5)  # blank lines are ignored
    assert not f.due(1.0)
    assert f.due(2.0)
    f.add('{"a":2}', now=1)
    f.add('{"a":3}', now=1)
    assert f.due(1.1)  # three records: full
    f.flush(1.1)
    assert post.bodies == [b'{"a":1}\n{"a":2}\n{"a":3}\n'] and f.sent == 3 and not f.pending
    assert f.first_at is None


def test_batches_respect_the_byte_limit():
    post = FakeReceiver([])
    f = _forwarder(post, max_bytes=20)
    for i in range(3):
        f.add(f'{{"n":"{i:010d}"}}', now=0)  # 18 bytes each
    f.add("x" * 21, now=0)  # one alert over the limit is skipped, not sent
    f.flush(5)
    assert len(post.bodies) == 3 and all(len(b) <= 20 for b in post.bodies)
    assert f.sent == 3 and f.dropped == 1


def test_receiver_down_keeps_the_batch_and_retries_later():
    post = FakeReceiver([fw.PostResult(False, True, "receiver unreachable")])
    f = _forwarder(post)
    f.add('{"a":1}', now=0)
    f.flush(10)
    assert f.pending == ['{"a":1}'] and f.sent == 0
    assert not f.due(11)  # backing off
    assert f.due(10 + fw.RETRY_SECONDS)
    f.flush(10 + fw.RETRY_SECONDS)
    assert f.sent == 1 and len(post.bodies) == 2 and post.bodies[0] == post.bodies[1]


def test_rejected_batch_is_dropped_so_the_stream_continues():
    post = FakeReceiver([fw.PostResult(False, False, "HTTP 400: invalid JSON")])
    f = _forwarder(post, max_records=1)
    f.add("not json", now=0)
    f.add('{"a":1}', now=0)
    f.flush(5)
    assert f.dropped == 1 and f.sent == 1 and not f.pending


def test_buffer_drops_the_oldest_when_full():
    f = _forwarder(FakeReceiver([]), max_buffered=2)
    for i in range(4):
        f.add(f'{{"a":{i}}}', now=0)
    assert f.pending == ['{"a":2}', '{"a":3}'] and f.dropped == 2


@pytest.fixture
def receiver(tmp_path) -> Iterator:
    ctx = build_context(make_settings(http_receiver_port=0), str(tmp_path / "fw.db"))
    ctx.receiver.start()
    yield ctx
    ctx.receiver.stop()


def test_wazuh_sample_reaches_the_receiver_and_is_detected(receiver):
    url = f"http://127.0.0.1:{receiver.receiver.port}/ingest?source=wazuh-live&adapter=wazuh"
    f = fw.Forwarder(fw.http_poster(url, None), log=lambda _m: None, max_records=4)
    lines = SAMPLE.read_text(encoding="utf-8").splitlines()
    for line in lines:
        f.add(line, now=0)
    f.flush(1)
    assert f.sent == len(lines) and f.dropped == 0
    rules = {a.rule_id for a in receiver.alerts.list()}
    assert "siem.high_severity_alert" in rules and "auth.failures_then_success" in rules


def test_unreachable_receiver_asks_for_a_retry():
    post = fw.http_poster("http://127.0.0.1:9/ingest", None, timeout=2)
    result = post(b'{"a":1}\n')
    assert not result.ok and result.retry


@pytest.mark.parametrize(
    "url", ["http://10.0.0.5:8787/ingest", "https://127.0.0.1:8787/", "file:///etc/passwd"]
)
def test_only_the_local_receiver_is_allowed(url):
    with pytest.raises(ValueError, match="local receiver"):
        fw.http_poster(url, None)
