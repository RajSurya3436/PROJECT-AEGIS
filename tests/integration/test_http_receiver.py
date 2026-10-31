from __future__ import annotations

import http.client
import json
from collections.abc import Iterator
from typing import Any, cast

import pytest
from fixtures.settings import make_settings

from app.config import PROJECT_ROOT, Settings
from app.context import build_context
from app.ingestion.http_receiver import HttpReceiver, ReceiverError
from app.storage.audit import AuditFilters

SAMPLE = PROJECT_ROOT / "data" / "samples" / "wazuh_alerts.jsonl"
EVENT = {
    "timestamp": "2026-03-10T10:00:00Z",
    "event_type": "auth",
    "outcome": "failure",
    "user": "dave",
    "src_ip": "198.51.100.7",
}


def _settings(**overrides) -> Settings:
    return make_settings(http_receiver_port=0, **overrides)


@pytest.fixture
def running(tmp_path) -> Iterator:
    ctx = build_context(_settings(), str(tmp_path / "rx.db"))
    ctx.receiver.start()
    yield ctx
    ctx.receiver.stop()


def _request(ctx, method="POST", path="/ingest", body=b"", headers=None, host=None):
    conn = http.client.HTTPConnection("127.0.0.1", ctx.receiver.port, timeout=10)
    sent = {"Content-Type": "application/json", **(headers or {})}
    if host is not None:
        conn.putrequest(method, path, skip_host=True)
        conn.putheader("Host", host)
        for k, v in sent.items():
            conn.putheader(k, v)
        conn.putheader("Content-Length", str(len(body)))
        conn.endheaders(body)
    else:
        conn.request(method, path, body=body, headers=sent)
    response = conn.getresponse()
    data = json.loads(response.read() or b"{}")
    conn.close()
    return response.status, data


def test_health_and_json_ingest(running):
    assert _request(running, "GET", "/health")[0] == 200
    status, body = _request(running, body=json.dumps(EVENT).encode())
    assert status == 200 and body["inserted"] == 1 and body["source_id"] == "http-default"
    status, body = _request(running, body=json.dumps({"events": [EVENT, 5]}).encode())
    assert (body["inserted"], body["duplicates"], body["quarantined"]) == (0, 1, 1)
    assert running.events.count() == 1  # visible from the app's own connection
    assert running.sources.get("http-default").source_type.value == "http"


def test_wazuh_ndjson_ingest_detects(running):
    from app.ingestion.iocs import load_demo_iocs

    load_demo_iocs(running.iocs)
    status, body = _request(
        running,
        path="/ingest?source=lab&adapter=wazuh",
        body=SAMPLE.read_bytes(),
        headers={"Content-Type": "application/x-ndjson"},
    )
    assert status == 200 and body["inserted"] == 17 and body["source_id"] == "http-lab"
    assert len(running.alerts.list()) == 7


@pytest.mark.parametrize(
    ("headers", "host", "status", "message"),
    [
        ({"Origin": "https://evil.example"}, None, 403, "browser"),
        ({}, "evil.example:8787", 403, "loopback"),  # DNS rebinding
        ({"Content-Type": "text/plain"}, None, 415, "Content-Type"),  # no-preflight type
        ({"Content-Type": "application/x-www-form-urlencoded"}, None, 415, "Content-Type"),
    ],
)
def test_browser_style_requests_are_refused(running, headers, host, status, message):
    code, body = _request(running, body=json.dumps(EVENT).encode(), headers=headers, host=host)
    assert code == status and message in body["error"]
    assert running.events.count() == 0


def test_bad_requests(running):
    assert _request(running, path="/ingest?source=Bad%20Name!", body=b"{}")[0] == 400
    assert _request(running, path="/ingest?adapter=splunk", body=b"{}")[0] == 400
    assert _request(running, body=b"{not json")[0] == 400
    assert _request(running, body=b'"text"')[0] == 400
    assert _request(running, body=b"\xff\xfe")[0] == 400
    assert _request(running, "GET", "/ingest")[0] == 405
    assert _request(running, "GET", "/admin")[0] == 404
    assert _request(running, "OPTIONS", "/ingest")[0] == 405  # no CORS preflight answer
    assert running.receiver.stats.rejected == 8


def test_size_record_and_rate_limits(tmp_path):
    ctx = build_context(
        _settings(
            http_receiver_max_body_bytes=2_048,
            http_receiver_max_records=3,
            http_receiver_requests_per_minute=4,
        ),
        str(tmp_path / "limits.db"),
    )
    ctx.receiver.start()
    try:
        big = json.dumps([EVENT] * 40).encode()
        assert _request(ctx, body=big)[0] == 413
        assert _request(ctx, body=json.dumps([EVENT] * 4).encode())[0] == 413
        ndjson = b"\n".join(json.dumps(EVENT).encode() for _ in range(4))
        code, _ = _request(ctx, body=ndjson, headers={"Content-Type": "application/x-ndjson"})
        assert code == 413
        assert _request(ctx, body=json.dumps(EVENT).encode())[0] == 200
        code, body = _request(ctx, body=json.dumps(EVENT).encode())
        assert code == 429 and "rate limit" in body["error"]
    finally:
        ctx.receiver.stop()


def test_bearer_token(tmp_path):
    ctx = build_context(_settings(http_receiver_token="s3cret"), str(tmp_path / "token.db"))
    ctx.receiver.start()
    try:
        body = json.dumps(EVENT).encode()
        assert _request(ctx, body=body)[0] == 401
        assert _request(ctx, body=body, headers={"Authorization": "Bearer wrong"})[0] == 401
        assert _request(ctx, body=body, headers={"Authorization": "Bearer s3cret"})[0] == 200
    finally:
        ctx.receiver.stop()


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "example.com", "::"])
def test_only_loopback_binds_are_allowed(host):
    with pytest.raises(ReceiverError, match="loopback"):
        HttpReceiver(_settings(http_receiver_host=host), lambda: cast(Any, (None, None)))


def test_start_and_stop_are_audited(tmp_path):
    ctx = build_context(_settings(), str(tmp_path / "audit.db"))
    ctx.receiver.start()
    url = ctx.receiver.url
    assert url and url.startswith("http://127.0.0.1:")
    ctx.receiver.stop()
    assert not ctx.receiver.running
    actions = [e.action for e in ctx.audit.list(AuditFilters(action_prefix="ingestion."))]
    assert actions == ["ingestion.http_receiver_stopped", "ingestion.http_receiver_started"]
