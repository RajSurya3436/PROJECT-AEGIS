"""Read-only Ollama health check (never pulls or runs a model)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from urllib.parse import urlparse


def ollama_status(base_url: str, model: str, timeout: float = 2.0) -> tuple[str, list[str]]:
    """Return (status, installed_models). Status: reachable_model_present,
    reachable_model_missing or unreachable. Only loopback URLs are contacted."""
    parsed = urlparse(base_url)
    if parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("refusing to contact a non-loopback Ollama URL")
    try:
        with urllib.request.urlopen(f"{base_url.rstrip('/')}/api/tags", timeout=timeout) as resp:  # noqa: S310
            payload = json.load(resp)
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
        return "unreachable", []
    names = [m.get("name", "") for m in payload.get("models", [])]
    present = model in names or f"{model}:latest" in names
    return ("reachable_model_present" if present else "reachable_model_missing"), names
