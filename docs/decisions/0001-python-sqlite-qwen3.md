# ADR 0001: Python 3.14, stdlib sqlite3, qwen3:8b

Date: 2026-10-26. Status: accepted.

- **Python**: only 3.14.7 is installed; `requires-python >=3.11`. Pydantic 2.14, pydantic-settings
  2.16, Streamlit 1.66, pytest 9 and ruff 0.17 installed and pass on 3.14. Fall back to 3.12 only
  if a later dependency (e.g. LangGraph in Phase 5) fails on 3.14; record the result here.
- **SQLite**: built-in `sqlite3`, hand-written numbered migrations, repositories as the only SQL
  location. No ORM, to keep parameterisation and allowlisting auditable.
- **Model**: `qwen3:8b` targeted (about 5 GB, fits 8 GB VRAM). Not pulled during Phases 0-4.
  Structured-output and tool-use behaviour must be tested before Phase 5 relies on it.
- **Git**: repository initialised; the user makes the commits.
