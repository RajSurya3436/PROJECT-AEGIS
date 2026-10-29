# Agentic SOC Investigation Copilot

A local-first SOC investigation app: ingest security events, run deterministic detections, and
(in later phases) investigate alerts with tool-using agents and an evidence-backed report.
It is an investigation layer, **not** a SIEM replacement.

**Status: Phases 0 to 4 complete (data foundation, replay, deterministic detection, IP
reputation, investigations and reports).** Working
today: JSONL/NDJSON/CSV/JSON import with field-mapping preview, UTC normalization, quarantine of
malformed rows, a SQLite event store with search and related-event lookup, a bundled synthetic
demo dataset with timed replay (speed, pause, resume, stop, restart), five versioned detection
rules that create event-linked alerts without any model, an alert queue with a status lifecycle,
on-request IP reputation (local IOC list, optional AbuseIPDB and VirusTotal with cache, rate
limits and retries), and a Streamlit UI (Overview, Events explorer, Alert queue, Data sources,
Detection rules, Settings, Investigations). Investigations collect related events and
evidence with provenance, record a disposition, and export Markdown/JSON reports. Not yet
built: agents, chat, response planning, audit log. See
[docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md),
[docs/detection-rules.md](docs/detection-rules.md) and [docs/reputation.md](docs/reputation.md).

## Setup (Windows PowerShell)

Requires Python 3.11+ (developed on 3.14).

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
copy .env.example .env        # optional; the app runs with no .env at all
.\.venv\Scripts\python -m streamlit run app\main.py
```

Then open **Data sources** and either **Load demo dataset** (instant) or use the replay controls
(pick a speed, press Start) and watch **Alert queue** fill: the demo yields five alerts.
Open an alert and press **Investigate**, then go to **Investigations** to see the timeline,
evidence and gaps, add notes, record a verdict and download the report.
`make install|test|lint|run` are equivalents if you have `make`.

```powershell
.\.venv\Scripts\python -m pytest -q
.\.venv\Scripts\python -m ruff check . ; .\.venv\Scripts\python -m ruff format --check .
.\.venv\Scripts\python scripts\validate_dataset.py
.\.venv\Scripts\python scripts\check_ollama.py
```

## Data privacy

- Everything runs locally. Events are stored in a local SQLite file (`data/agentic_soc.db`,
  git-ignored). Nothing leaves the machine unless you switch on external reputation lookups.
- The app only sees data you load. It does **not** read Windows Event Logs, EDR alerts or
  system logs on its own.
- Use only synthetic or properly licensed data. Get permission before importing workplace logs.
- API keys belong in environment variables or an ignored `.env`, never in the database.
- External reputation lookups are off by default (`ENABLE_EXTERNAL_REPUTATION=false`; the
  **Settings** page can switch them on). When on, a lookup you request sends **only the queried
  IP** to each configured provider. Private, loopback, link-local, multicast, reserved and
  documentation addresses are never sent, and nothing is looked up automatically per event.

## Reputation providers (optional)

Put keys in `.env` and restart: `ABUSEIPDB_API_KEY=...`, `VIRUSTOTAL_API_KEY=...`. Then switch
on lookups in **Settings** and use **Look up an IP** or **Check reputation** on an alert.

| Provider | Free-tier limit (check your plan) | App default budget |
|---|---|---|
| AbuseIPDB | 1,000 checks/day | 30/min, 1,000/day |
| VirusTotal public API | 4 requests/min, 500/day; not for commercial use | 4/min, 500/day |

Override with `ABUSEIPDB_REQUESTS_PER_MINUTE`, `VIRUSTOTAL_REQUESTS_PER_DAY` and similar.
Results are cached for 24 h (`REPUTATION_CACHE_TTL_HOURS`). Respect each provider's terms.
Without keys the app still checks the local IOC list.

## Ollama

The planned model is `qwen3:8b` (about 5 GB, fits 8 GB VRAM). It is not needed until Phase 5 and
is never pulled automatically. `scripts\check_ollama.py` reports whether the server is reachable
and the model is installed. With Ollama stopped, ingestion and search work normally.

## Troubleshooting

- *Upload rejected as too large*: raise `MAX_UPLOAD_BYTES` (default 25 MB).
- *Rows quarantined*: see the table on **Data sources**; the usual causes are a missing or
  unparseable timestamp, or invalid JSON. Add the column name to
  `app/ingestion/field_aliases.py` if your timestamp field is not recognised.
- *Dashboard says Ollama unavailable*: expected unless `ollama serve` is running. Detection and
  alerts do not need it.
- *No IOC alert after uploading your own data*: load the IOC list first (the demo load does it),
  or press **Re-run detection** on the Detection rules page.
- *Reputation shows "skipped" for demo IPs*: expected. The demo uses documentation ranges
  (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), which are never sent to providers; the
  local IOC match still shows.
- *Reputation shows "rate limited"*: the provider returned 429 or the local budget is used
  up; the note says how long to wait. *"HTTP 401/403"*: check the API key and plan.
- *Replay controls missing*: replay needs a file-backed database (the default), not `:memory:`.
