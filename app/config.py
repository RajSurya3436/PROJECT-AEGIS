"""Application settings.

Values come from environment variables or an ignored ``.env`` file. API keys are
``SecretStr`` so they never appear in reprs/logs, and they are never written to SQLite.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEMO_DATA_DIR = PROJECT_ROOT / "data" / "demo"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "qwen3:8b"

    abuseipdb_api_key: SecretStr | None = None
    virustotal_api_key: SecretStr | None = None
    # Default for the external lookup switch; the Settings page can override it at runtime.
    enable_external_reputation: bool = False

    # Reputation lookups. Defaults stay inside the free tiers: AbuseIPDB 1,000 checks/day,
    # VirusTotal public API 4 requests/minute and 500/day.
    reputation_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    reputation_max_retries: int = Field(default=2, ge=0, le=5)
    reputation_cache_ttl_hours: int = Field(default=24, gt=0, le=24 * 30)
    abuseipdb_max_age_days: int = Field(default=90, ge=1, le=365)
    abuseipdb_requests_per_minute: int = Field(default=30, gt=0)
    abuseipdb_requests_per_day: int = Field(default=1_000, gt=0)
    virustotal_requests_per_minute: int = Field(default=4, gt=0)
    virustotal_requests_per_day: int = Field(default=500, gt=0)

    # Investigations: how far around an alert related events are collected, and scope size cap.
    investigation_window_minutes: int = Field(default=30, gt=0, le=24 * 60)
    investigation_max_scope_events: int = Field(default=500, gt=0, le=5_000)

    # Agents: hard limits enforced by code, whatever the model asks for.
    agent_model_timeout_seconds: float = Field(default=120.0, gt=0, le=900)
    agent_context_tokens: int = Field(default=16_384, ge=2_048, le=131_072)
    agent_max_model_calls: int = Field(default=40, gt=0, le=500)
    agent_max_tool_calls: int = Field(default=30, gt=0, le=500)
    agent_max_steps_per_turn: int = Field(default=6, gt=0, le=50)
    agent_max_specialist_turns: int = Field(default=4, gt=0, le=20)
    agent_max_run_seconds: int = Field(default=900, gt=0, le=3_600)
    agent_max_invalid_outputs: int = Field(default=3, gt=0, le=10)
    agent_max_ask_steps: int = Field(default=4, gt=0, le=20)  # model calls per Ask answer

    database_path: Path = PROJECT_ROOT / "data" / "agentic_soc.db"

    app_host: str = "127.0.0.1"
    app_port: int = 8501

    # Ingestion limits
    max_upload_bytes: int = Field(default=25 * 1024 * 1024, gt=0)
    max_rows_per_ingest: int = Field(default=200_000, gt=0)
    parse_error_snippet_chars: int = Field(default=500, gt=0)

    @property
    def abuseipdb_configured(self) -> bool:
        return bool(self.abuseipdb_api_key and self.abuseipdb_api_key.get_secret_value())

    @property
    def virustotal_configured(self) -> bool:
        return bool(self.virustotal_api_key and self.virustotal_api_key.get_secret_value())


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
