"""Combines the local IOC list, the cache and the external providers for one IP.

Lookups only happen when called (an analyst action, later an agent tool call); nothing here
runs per ingested event. Only the queried IP leaves the machine, and only when it is public,
the provider is configured and external lookups are switched on.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterable
from datetime import timedelta

from app.config import Settings
from app.domain.enums import ReputationStatus
from app.domain.models import IpReputationReport, ReputationResult
from app.storage.alerts import IocRepository
from app.storage.repositories import AppSettingsRepository
from app.storage.reputation import ReputationCacheRepository
from app.tools.local_ioc import lookup_local_ioc
from app.tools.reputation.abuseipdb import AbuseIPDBProvider
from app.tools.reputation.base import Clock, RateLimiter, ReputationProvider, classify_ip, utc_now
from app.tools.reputation.http import Transport, urllib_transport
from app.tools.reputation.virustotal import VirusTotalProvider

EXTERNAL_LOOKUPS_KEY = "reputation.external_lookups_enabled"


def build_providers(
    settings: Settings,
    transport: Transport = urllib_transport,
    sleep: Callable[[float], None] | None = None,
    clock: Clock = utc_now,
) -> dict[str, ReputationProvider]:
    common = {
        "timeout": settings.reputation_timeout_seconds,
        "max_retries": settings.reputation_max_retries,
        "cache_ttl": timedelta(hours=settings.reputation_cache_ttl_hours),
        "clock": clock,
    }
    if sleep is not None:
        common["sleep"] = sleep
    providers: list[ReputationProvider] = [
        AbuseIPDBProvider(
            settings.abuseipdb_api_key,
            transport,
            RateLimiter(
                settings.abuseipdb_requests_per_minute, settings.abuseipdb_requests_per_day
            ),
            max_age_days=settings.abuseipdb_max_age_days,
            **common,
        ),
        VirusTotalProvider(
            settings.virustotal_api_key,
            transport,
            RateLimiter(
                settings.virustotal_requests_per_minute, settings.virustotal_requests_per_day
            ),
            **common,
        ),
    ]
    return {p.name: p for p in providers}


class ReputationService:
    def __init__(
        self,
        conn: sqlite3.Connection,
        settings: Settings,
        providers: dict[str, ReputationProvider],
        clock: Clock = utc_now,
    ) -> None:
        self.settings = settings
        self.providers = providers
        self.cache = ReputationCacheRepository(conn)
        self.iocs = IocRepository(conn)
        self.app_settings = AppSettingsRepository(conn)
        self._clock = clock

    @property
    def external_enabled(self) -> bool:
        """The Settings page switch; falls back to ENABLE_EXTERNAL_REPUTATION."""
        return bool(
            self.app_settings.get(EXTERNAL_LOOKUPS_KEY, self.settings.enable_external_reputation)
        )

    def set_external_enabled(self, enabled: bool) -> None:
        self.app_settings.set(EXTERNAL_LOOKUPS_KEY, bool(enabled))

    def lookup_ip(
        self,
        value: str,
        providers: Iterable[str] | None = None,
        *,
        force_refresh: bool = False,
    ) -> IpReputationReport:
        """Local IOC match plus one result per requested provider. Never raises for provider
        problems; each failure is a status on that provider's result."""
        names = list(self.providers) if providers is None else list(providers)
        unknown = [n for n in names if n not in self.providers]
        if unknown:
            raise ValueError(f"unknown reputation provider(s): {', '.join(unknown)}")
        ip, scope = classify_ip(value)
        report = IpReputationReport(
            indicator=ip or value.strip()[:100],
            valid=ip is not None,
            scope=scope,
            local_ioc=lookup_local_ioc(self.iocs, ip) if ip else None,
        )
        for name in names:
            report.results.append(self._lookup_one(self.providers[name], ip, scope, force_refresh))
        return report

    def _lookup_one(
        self, provider: ReputationProvider, ip: str | None, scope: str, force_refresh: bool
    ) -> ReputationResult:
        def status(code: ReputationStatus, message: str) -> ReputationResult:
            return ReputationResult(
                provider=provider.name, indicator=ip or "", status=code, message=message
            )

        if ip is None:
            return status(ReputationStatus.SKIPPED, "Not a valid IP address; nothing was sent.")
        if scope != "public":
            return status(
                ReputationStatus.SKIPPED,
                f"{scope.replace('_', '-')} address; external lookups only cover public IPs.",
            )
        if not force_refresh:
            cached = self.cache.get(provider.name, ip, self._clock())
            if cached is not None:
                return cached
        if not provider.configured:
            return status(
                ReputationStatus.NOT_CONFIGURED,
                f"Set {provider.name.upper()}_API_KEY in the environment or .env to enable.",
            )
        if not self.external_enabled:
            return status(
                ReputationStatus.DISABLED,
                "External lookups are switched off (Settings page).",
            )
        result = provider.lookup(ip)
        if result.status is ReputationStatus.FRESH:
            self.cache.put(result)
        return result

    def cache_stats(self) -> dict[str, dict[str, int]]:
        return self.cache.stats(self._clock())

    def purge_expired(self) -> int:
        return self.cache.purge_expired(self._clock())

    def clear_cache(self) -> int:
        return self.cache.clear()
