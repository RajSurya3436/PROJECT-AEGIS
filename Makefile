# Convenience targets. On Windows without `make`, run the equivalent commands
# listed in README.md directly.
PY ?= .venv/Scripts/python

.PHONY: install test lint format run validate check-ollama

install:
	python -m venv .venv
	$(PY) -m pip install -e ".[dev]"

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check .
	$(PY) -m ruff format --check .

format:
	$(PY) -m ruff format .

run:
	$(PY) -m streamlit run app/main.py --server.address 127.0.0.1 --server.port 8501

validate:
	$(PY) scripts/validate_dataset.py

check-ollama:
	$(PY) scripts/check_ollama.py
