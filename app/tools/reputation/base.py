"""Common provider behaviour: IP scope checks, rate limiting, bounded retries and turning every
failure into a status instead of an exception."""

from __future__ import annotations

import ipaddress
import json
import threading
import time
from abc import ABC, abstractmethod
from collections import deque
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import SecretStr

from app.domain.enums import ReputationStatus
from app.domain.models import ReputationResult
from app.tools.reputation.http import HttpResponse, Transport

MAX_TEXT_CHARS = 200
MAX_RETRY_AFTER_SECONDS = 3600
DEFAULT_RETRY_AFTER_SECONDS = 60
MAX_BACKOFF_SECONDS = 8.0

Clock = Callable[[], datetime]

# RFC 5737 / RFC 3849 example ranges, used by the synthetic demo data. Never sent out.
DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)


def utc_now() -> datetime:
    return datetime.now(UTC)


def classify_ip(value: str) -> tuple[str | None, str]:
    """Return (normalised IP or None, scope). Only scope ``public`` may be sent to a provider."""
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return None, "invalid"
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    for scope, flag in (
        ("unspecified", ip.is_unspecified),
        ("loopback", ip.is_loopback),
        ("link_local", ip.is_link_local),
        ("multicast", ip.is_multicast),
        ("documentation", any(ip.version == n.version and ip in n for n in DOCUMENTATION_NETWORKS)),
        ("reserved", ip.is_reserved),
        ("private", ip.is_private),
    ):
        if flag:
            return str(ip), scope
    # Covers shared address space (100.64/10) and other special ranges not flagged above.
    return str(ip), "public" if ip.is_global else "reserved"


def text(value: Any, limit: int = MAX_TEXT_CHARS) -> str | None:
    """Provider strings are untrusted: keep plain str values only, capped in length."""
    return value[:limit] if isinstance(value, str) else None


def integer(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def boolean(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


class RateLimiter:
    """Client-side request budget (per minute and per day) plus a cooldown set from a
    provider's 429 response. In-memory: the daily count restarts with the app."""

    def __init__(
        self, per_minute: int, per_day: int, monotonic: Callable[[], float] = time.monotonic
    ) -> None:
        self.per_minute = per_minute
        self.per_day = per_day
        self._monotonic = monotonic
        self._minute: deque[float] = deque()
        self._day: deque[float] = deque()
        self._blocked_until = 0.0
        self._lock = threading.Lock()

    def acquire(self) -> int | None:
        """Take one request slot. Returns None on success, else seconds to wait."""
        with self._lock:
            now = self._monotonic()
            if now < self._blocked_until:
                return max(1, int(self._blocked_until - now))
            for window, length in ((self._minute, 60.0), (self._day, 86_400.0)):
                while window and now - window[0] >= length:
                    window.popleft()
            if len(self._day) >= self.per_day:
                return max(1, int(86_400 - (now - self._day[0])))
            if len(self._minute) >= self.per_minute:
                return max(1, int(60 - (now - self._minute[0])))
            self._minute.append(now)
            self._day.append(now)
            return None

    def block_for(self, seconds: int) -> None:
        with self._lock:
            self._blocked_until = max(self._blocked_until, self._monotonic() + seconds)


class ReputationProvider(ABC):
    """One external IP reputation service. ``lookup`` never raises for provider problems."""

    name: str
    title: str

    def __init__(
        self,
        api_key: SecretStr | None,
        transport: Transport,
        limiter: RateLimiter,
        *,
        timeout: float = 10.0,
        max_retries: int = 2,
        cache_ttl: timedelta = timedelta(hours=24),
        sleep: Callable[[float], None] = time.sleep,
        clock: Clock = utc_now,
    ) -> None:
        self._api_key = api_key
        self._transport = transport
        self.limiter = limiter
        self.timeout = timeout
        self.max_retries = max_retries
        self.cache_ttl = cache_ttl
        self._sleep = sleep
        self._clock = clock

    def __repr__(self) -> str:  # never show the key
        return f"{type(self).__name__}(configured={self.configured})"

    @property
    def configured(self) -> bool:
        return bool(self._api_key and self._api_key.get_secret_value())

    @abstractmethod
    def _request(self, ip: str, api_key: str) -> tuple[str, dict[str, str]]:
        """Build (url, headers). Only the IP may go in the URL; the key goes in a header."""

    @abstractmethod
    def _parse(self, payload: Any) -> tuple[bool, str | None, dict[str, Any]]:
        """Turn a 200 response body into (found, signal, sanitised summary)."""

    def _not_found_is_data(self) -> bool:
        """Whether HTTP 404 means 'no record of this IP' rather than an error."""
        return False

    def lookup(self, ip: str) -> ReputationResult:
        """Query the provider for a public IP that the caller has already validated."""
        if not self.configured:
            return self._result(ip, ReputationStatus.NOT_CONFIGURED, "No API key configured.")
        assert self._api_key is not None
        url, headers = self._request(ip, self._api_key.get_secret_value())
        attempts = self.max_retries + 1
        failure = self._result(ip, ReputationStatus.PROVIDER_ERROR, "No attempt was made.")
        for attempt in range(attempts):
            if attempt:
                self._sleep(min(MAX_BACKOFF_SECONDS, 2.0 ** (attempt - 1)))
            wait = self.limiter.acquire()
            if wait is not None:
                return self._rate_limited(ip, wait, "Local request budget used up.")
            try:
                response = self._transport(url, headers, self.timeout)
            except TimeoutError:
                failure = self._result(
                    ip, ReputationStatus.TIMEOUT, f"No response within {self.timeout:g} s."
                )
                continue
            except OSError:  # includes ConnectionError
                failure = self._result(
                    ip, ReputationStatus.PROVIDER_ERROR, "Could not reach the provider."
                )
                continue
            outcome = self._handle(ip, response)
            if outcome is not None:
                return outcome
            failure = self._result(
                ip, ReputationStatus.PROVIDER_ERROR, f"Provider returned HTTP {response.status}."
            )
        failure.message += f" Gave up after {attempts} attempt(s)."
        return failure

    def _handle(self, ip: str, response: HttpResponse) -> ReputationResult | None:
        """Final result for this response, or None when the request should be retried.
        Messages are fixed text plus the status code: provider bodies are never echoed."""
        status = response.status
        if status == 200:
            try:
                found, signal, summary = self._parse(json.loads(response.body))
            except (ValueError, TypeError, KeyError, AttributeError, OverflowError, OSError):
                return self._result(
                    ip, ReputationStatus.PROVIDER_ERROR, "Provider sent an unexpected response."
                )
            return self._fresh(ip, found, signal, summary)
        if status == 404 and self._not_found_is_data():
            return self._fresh(ip, False, None, {})
        if status == 429:
            wait = _retry_after(response.headers)
            self.limiter.block_for(wait)
            return self._rate_limited(ip, wait, "Provider rate limit or quota reached.")
        if status in (401, 403):
            return self._result(
                ip,
                ReputationStatus.PROVIDER_ERROR,
                f"Provider rejected the request (HTTP {status}); check the API key and plan.",
            )
        if status >= 500 or status == 408:
            return None
        return self._result(
            ip, ReputationStatus.PROVIDER_ERROR, f"Provider returned HTTP {status}."
        )

    def _fresh(
        self, ip: str, found: bool, signal: str | None, summary: dict[str, Any]
    ) -> ReputationResult:
        now = self._clock().replace(microsecond=0)
        return ReputationResult(
            provider=self.name,
            indicator=ip,
            status=ReputationStatus.FRESH,
            found=found,
            signal=signal,
            summary=summary,
            queried_at=now,
            expires_at=now + self.cache_ttl,
        )

    def _rate_limited(self, ip: str, wait: int, message: str) -> ReputationResult:
        result = self._result(ip, ReputationStatus.RATE_LIMITED, f"{message} Retry in {wait} s.")
        result.retry_after_seconds = wait
        return result

    def _result(self, ip: str, status: ReputationStatus, message: str) -> ReputationResult:
        return ReputationResult(provider=self.name, indicator=ip, status=status, message=message)


def _retry_after(headers: Mapping[str, str]) -> int:
    lowered = {k.lower(): v for k, v in headers.items()}
    try:
        seconds = int(str(lowered.get("retry-after", "")).strip())
    except ValueError:
        return DEFAULT_RETRY_AFTER_SECONDS
    return min(max(seconds, 1), MAX_RETRY_AFTER_SECONDS)
