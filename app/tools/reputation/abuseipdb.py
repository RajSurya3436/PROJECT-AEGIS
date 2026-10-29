"""AbuseIPDB v2 ``check`` endpoint: community abuse reports and a 0-100 confidence score."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

from app.tools.reputation.base import ReputationProvider, boolean, integer, text

API_URL = "https://api.abuseipdb.com/api/v2/check"
HIGH_SCORE = 75
MEDIUM_SCORE = 25


class AbuseIPDBProvider(ReputationProvider):
    name = "abuseipdb"
    title = "AbuseIPDB"

    def __init__(self, *args: Any, max_age_days: int = 90, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.max_age_days = max_age_days

    def _request(self, ip: str, api_key: str) -> tuple[str, dict[str, str]]:
        query = urlencode({"ipAddress": ip, "maxAgeInDays": self.max_age_days})
        return f"{API_URL}?{query}", {"Key": api_key, "Accept": "application/json"}

    def _parse(self, payload: Any) -> tuple[bool, str | None, dict[str, Any]]:
        data = payload["data"]
        score = integer(data.get("abuseConfidenceScore"))
        reports = integer(data.get("totalReports"))
        summary = {
            "abuse_confidence_score": score,
            "total_reports": reports,
            "distinct_reporters": integer(data.get("numDistinctUsers")),
            "last_reported_at": text(data.get("lastReportedAt"), 40),
            "is_whitelisted": boolean(data.get("isWhitelisted")),
            "is_tor": boolean(data.get("isTor")),
            "country_code": text(data.get("countryCode"), 8),
            "usage_type": text(data.get("usageType")),
            "isp": text(data.get("isp")),
            "domain": text(data.get("domain")),
        }
        if score is None:
            raise ValueError("response has no abuse confidence score")
        found = bool(reports)
        return found, abuse_signal(score), summary


def abuse_signal(score: int) -> str:
    if score >= HIGH_SCORE:
        return "high"
    if score >= MEDIUM_SCORE:
        return "medium"
    return "low"
