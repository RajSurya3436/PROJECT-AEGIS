"""VirusTotal v3 IP address report: vendor detection counts and community reputation."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.tools.reputation.base import ReputationProvider, integer, text

API_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
HIGH_MALICIOUS = 3
STATS_KEYS = ("malicious", "suspicious", "harmless", "undetected", "timeout")


class VirusTotalProvider(ReputationProvider):
    name = "virustotal"
    title = "VirusTotal"

    def _request(self, ip: str, api_key: str) -> tuple[str, dict[str, str]]:
        # The IP is validated by ipaddress before it gets here, so it is safe in the path.
        return f"{API_URL}{ip}", {"x-apikey": api_key, "Accept": "application/json"}

    def _not_found_is_data(self) -> bool:
        return True

    def _parse(self, payload: Any) -> tuple[bool, str | None, dict[str, Any]]:
        attributes = payload["data"]["attributes"]
        raw_stats = attributes.get("last_analysis_stats")
        if not isinstance(raw_stats, dict):
            raise ValueError("response has no analysis stats")
        stats = {key: integer(raw_stats.get(key)) or 0 for key in STATS_KEYS}
        analysed = integer(attributes.get("last_analysis_date"))
        summary = {
            "malicious": stats["malicious"],
            "suspicious": stats["suspicious"],
            "harmless": stats["harmless"],
            "undetected": stats["undetected"],
            "engines": sum(stats.values()),
            "reputation": integer(attributes.get("reputation")),
            "last_analysis_date": (
                datetime.fromtimestamp(analysed, UTC).isoformat() if analysed else None
            ),
            "as_owner": text(attributes.get("as_owner")),
            "asn": integer(attributes.get("asn")),
            "country": text(attributes.get("country"), 8),
            "network": text(attributes.get("network"), 64),
        }
        return True, vt_signal(stats["malicious"], stats["suspicious"]), summary


def vt_signal(malicious: int, suspicious: int) -> str:
    if malicious >= HIGH_MALICIOUS:
        return "high"
    if malicious >= 1 or suspicious >= 2:
        return "medium"
    return "low"
