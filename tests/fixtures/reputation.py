"""Fake provider transport and canned responses (shapes follow the public API docs)."""

from __future__ import annotations

import json
from collections.abc import Mapping

from app.tools.reputation.http import HttpResponse

ABUSE_KEY = "abuse-test-key-1234567890"
VT_KEY = "vt-test-key-0987654321"


def abuse_body(score: int = 100, reports: int = 42, **extra) -> bytes:
    data = {
        "ipAddress": "8.8.8.8",
        "isPublic": True,
        "abuseConfidenceScore": score,
        "countryCode": "US",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "Example ISP",
        "domain": "example.net",
        "isTor": False,
        "isWhitelisted": False,
        "totalReports": reports,
        "numDistinctUsers": 7,
        "lastReportedAt": "2026-10-20T12:00:00+00:00",
        **extra,
    }
    return json.dumps({"data": data}).encode()


def vt_body(malicious: int = 5, suspicious: int = 1, **extra) -> bytes:
    attributes = {
        "last_analysis_stats": {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": 60,
            "undetected": 20,
            "timeout": 0,
        },
        "reputation": -12,
        "as_owner": "Example AS",
        "asn": 64500,
        "country": "US",
        "network": "8.8.8.0/24",
        "last_analysis_date": 1_790_000_000,
        **extra,
    }
    return json.dumps({"data": {"id": "8.8.8.8", "attributes": attributes}}).encode()


class FakeTransport:
    """Returns queued responses in order; an Exception in the queue is raised instead."""

    def __init__(self, *responses: HttpResponse | Exception) -> None:
        self.queue = list(responses)
        self.calls: list[tuple[str, dict[str, str], float]] = []

    def __call__(self, url: str, headers: Mapping[str, str], timeout: float) -> HttpResponse:
        self.calls.append((url, dict(headers), timeout))
        if not self.queue:
            raise AssertionError(f"unexpected request to {url}")
        item = self.queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class RoutingTransport:
    """Answers each provider by URL host; counts calls per provider."""

    def __init__(self, abuse: HttpResponse, vt: HttpResponse) -> None:
        self.abuse = abuse
        self.vt = vt
        self.calls: list[str] = []

    def __call__(self, url: str, headers: Mapping[str, str], timeout: float) -> HttpResponse:
        self.calls.append(url)
        return self.abuse if "abuseipdb" in url else self.vt
