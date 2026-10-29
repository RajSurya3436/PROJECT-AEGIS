"""Report whether the local Ollama server is reachable and the configured model is installed.

Read-only: it never pulls or runs a model.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import Settings
from app.ollama_health import ollama_status


def main() -> int:
    settings = Settings()
    status, names = ollama_status(settings.ollama_base_url, settings.ollama_model)
    print(f"Ollama URL : {settings.ollama_base_url}")
    print(f"Model      : {settings.ollama_model}")
    print(f"Status     : {status}")
    print(f"Installed  : {', '.join(names) if names else '(none)'}")
    if status == "reachable_model_missing":
        print(f"Install later with: ollama pull {settings.ollama_model}  (about 5 GB)")
    return 0 if status == "reachable_model_present" else 1


if __name__ == "__main__":
    raise SystemExit(main())
