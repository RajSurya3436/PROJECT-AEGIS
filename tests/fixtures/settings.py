"""Settings for tests: defaults plus overrides, never the developer's .env file."""

from __future__ import annotations

from typing import Any

from app.config import Settings


def make_settings(**overrides: Any) -> Settings:
    # ``_env_file`` is a pydantic-settings init argument that type checkers do not see.
    return Settings(**{"_env_file": None, **overrides})
