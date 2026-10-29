from __future__ import annotations

import pytest

from app.config import Settings
from app.context import AppContext, build_context


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None)


@pytest.fixture
def ctx(settings: Settings) -> AppContext:
    return build_context(settings, ":memory:")


@pytest.fixture(autouse=True)
def _no_reputation_network(monkeypatch):
    """Provider tests use fake transports; a real HTTPS call from a test is a bug."""

    def refuse(*_args, **_kwargs):
        raise AssertionError("tests must not contact reputation providers")

    monkeypatch.setattr("app.tools.reputation.http._urlopen", refuse)
