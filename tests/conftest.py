from __future__ import annotations

import pytest
from fixtures.settings import make_settings

from app.config import Settings
from app.context import AppContext, build_context


@pytest.fixture
def settings() -> Settings:
    return make_settings()


@pytest.fixture
def ctx(settings: Settings) -> AppContext:
    return build_context(settings, ":memory:")


@pytest.fixture(autouse=True)
def _no_reputation_network(monkeypatch):
    """Provider tests use fake transports; a real HTTPS call from a test is a bug."""

    def refuse(*_args, **_kwargs):
        raise AssertionError("tests must not contact reputation providers")

    monkeypatch.setattr("app.tools.reputation.http._urlopen", refuse)


@pytest.fixture(autouse=True)
def _no_model_server(monkeypatch):
    """Agent tests use scripted models; a real Ollama call from a test is a bug."""

    def refuse(*_args, **_kwargs):
        raise AssertionError("tests must not contact Ollama")

    monkeypatch.setattr("app.agents.llm.urllib_post", refuse)


@pytest.fixture(autouse=True)
def _ollama_looks_down(monkeypatch):
    """UI pages check Ollama's health; report it down so results do not depend on whether
    the developer happens to have it running."""
    for module in ("app.ui.agents_panel", "app.ui.dashboard", "app.ui.settings"):
        monkeypatch.setattr(f"{module}.ollama_status", lambda *_a, **_k: ("unreachable", []))
