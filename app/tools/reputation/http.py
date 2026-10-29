"""Minimal HTTPS GET transport. Providers receive it as a callable, so tests substitute a
fake and never touch the network."""

from __future__ import annotations

import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

MAX_BODY_BYTES = 1024 * 1024


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: bytes = b""
    headers: Mapping[str, str] = field(default_factory=dict)


# (url, headers, timeout_seconds) -> response. Raises TimeoutError on timeout and
# ConnectionError when no response was received.
Transport = Callable[[str, Mapping[str, str], float], HttpResponse]


def _urlopen(request: urllib.request.Request, timeout: float):
    return urllib.request.urlopen(request, timeout=timeout)  # noqa: S310 - https URL checked


def urllib_transport(url: str, headers: Mapping[str, str], timeout: float) -> HttpResponse:
    if not url.startswith("https://"):
        raise ValueError("reputation providers are only contacted over HTTPS")
    request = urllib.request.Request(url, headers=dict(headers), method="GET")  # noqa: S310
    try:
        with _urlopen(request, timeout) as resp:
            return HttpResponse(resp.status, resp.read(MAX_BODY_BYTES), dict(resp.headers))
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_BODY_BYTES) if exc.fp else b""
        return HttpResponse(exc.code, body, dict(exc.headers or {}))
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            raise TimeoutError("request timed out") from None
        raise ConnectionError("could not reach the provider") from None
    except TimeoutError:
        raise TimeoutError("request timed out") from None
    except OSError:
        raise ConnectionError("could not reach the provider") from None
