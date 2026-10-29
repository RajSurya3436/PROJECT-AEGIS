"""Chat model interface and the local Ollama client.

Agents only see ``ChatModel``, so tests pass a scripted model and nothing reaches the network.
The Ollama client talks to a loopback URL only and asks for JSON that matches a schema; the
graph still validates every reply itself, because a constrained decoder is not a guarantee.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlparse

from app.domain.errors import SocCopilotError

MAX_RESPONSE_BYTES = 1024 * 1024
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


class ModelUnavailableError(SocCopilotError):
    """The model server cannot be reached, or the model is not installed."""


class ModelError(SocCopilotError):
    """The model server answered, but not with a usable reply (HTTP error, timeout, no text)."""


@dataclass(frozen=True)
class ChatMessage:
    role: str  # system, user or assistant
    content: str


class ChatModel(Protocol):
    name: str

    def complete(self, messages: list[ChatMessage], schema: dict[str, Any]) -> str:
        """Return the reply text, which should be JSON matching ``schema``."""
        ...


# (url, json_body, timeout_seconds) -> (http_status, body). Raises TimeoutError on timeout and
# ConnectionError when no response was received.
PostTransport = Callable[[str, bytes, float], tuple[int, bytes]]


def require_loopback(base_url: str) -> str:
    parsed = urlparse(base_url)
    if parsed.scheme != "http" or parsed.hostname not in LOOPBACK_HOSTS:
        raise ValueError("refusing to contact a non-loopback Ollama URL")
    return base_url.rstrip("/")


def urllib_post(url: str, body: bytes, timeout: float) -> tuple[int, bytes]:
    request = urllib.request.Request(  # noqa: S310 - loopback http URL checked by the caller
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:  # noqa: S310
            return resp.status, resp.read(MAX_RESPONSE_BYTES)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_RESPONSE_BYTES) if exc.fp else b""
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            raise TimeoutError("model call timed out") from None
        raise ConnectionError("could not reach Ollama") from None
    except TimeoutError:
        raise TimeoutError("model call timed out") from None
    except OSError:
        raise ConnectionError("could not reach Ollama") from None


class OllamaChatModel:
    """Non-streaming ``/api/chat`` with ``format`` set to the expected JSON schema.
    Temperature 0 and thinking off, so replies are short and as repeatable as the model allows.
    ``num_ctx`` is raised from Ollama's small default so the case file fits."""

    def __init__(
        self,
        base_url: str,
        model: str,
        timeout: float,
        context_tokens: int = 16_384,
        transport: PostTransport | None = None,
    ) -> None:
        self.base_url = require_loopback(base_url)
        self.name = model
        self.timeout = timeout
        self.context_tokens = context_tokens
        self._transport = transport

    def complete(self, messages: list[ChatMessage], schema: dict[str, Any]) -> str:
        body = json.dumps(
            {
                "model": self.name,
                "messages": [{"role": m.role, "content": m.content} for m in messages],
                "format": schema,
                "stream": False,
                "think": False,
                "options": {"temperature": 0, "num_ctx": self.context_tokens},
            }
        ).encode("utf-8")
        try:
            transport = self._transport or urllib_post
            status, raw = transport(f"{self.base_url}/api/chat", body, self.timeout)
        except ConnectionError as exc:
            raise ModelUnavailableError(f"Ollama is not reachable at {self.base_url}") from exc
        except TimeoutError as exc:
            raise ModelError(f"model call exceeded {self.timeout:.0f} s") from exc
        if status == 404:
            raise ModelUnavailableError(
                f"model {self.name!r} is not installed (ollama pull {self.name})"
            )
        if status != 200:
            raise ModelError(f"Ollama returned HTTP {status}")
        try:
            content = json.loads(raw)["message"]["content"]
        except (ValueError, KeyError, TypeError) as exc:
            raise ModelError("Ollama reply had no message content") from exc
        if not isinstance(content, str) or not content.strip():
            raise ModelError("Ollama returned an empty reply")
        return content
