# Agentic SOC Investigation Copilot

A local-first investigation copilot for security analysts. It ingests security events,
raises alerts with **deterministic rules**, and lets a team of AI agents on a **local model**
investigate each alert with evidence the analyst can check. The analyst stays in charge: they
chat with the agents, redirect them, accept or reject the verdict, and approve **simulated**
response actions. It is an investigation layer, **not** a SIEM replacement, and nothing leaves
the machine unless you switch on external IP reputation.

**Status: complete (Phases 0-9).** What it does:

- **Ingest** JSONL/NDJSON/CSV/JSON uploads with a field-mapping preview, a timed replay of a
  synthetic demo dataset, a followed (tailed) JSONL file, or a loopback-only HTTP receiver —
  all through one pipeline that normalises to UTC, deduplicates and quarantines bad rows.
  **Wazuh** `alerts.json` is supported through a record adapter.
- **Detect** with six versioned rules (repeated failures, failures then success, password
  spray, suspicious PowerShell, connection to a local IOC, high-level upstream SIEM alert) that
  link each alert to its exact events. No model is involved.
- **Investigate**: related events, evidence with provenance, telemetry gaps, timeline, IP
  reputation (local IOC list; AbuseIPDB and VirusTotal optional, opt-in, cached and
  rate-limited), verdicts, and Markdown/JSON reports.
- **Agents** (orchestrator, log investigator, threat intel, verifier, response planner) share
  one local Ollama model. They act only through allowlisted, schema-checked tools, may only cite
  events a tool returned, and their verdict is checked and downgraded by code when the evidence
  cannot carry it. Log text is fenced as data, so injected instructions do not override policy.
- **Chat**: Ask (read-only questions), Investigate (instructions, answers to the agents'
  questions), Control (pause, resume, stop, redirect).
- **Respond, simulated only**: a fixed catalogue of eight actions behind a code policy gate
  (targets must come from the investigation, impact proportional to the verdict, approval for
  medium/high impact). There is no firewall, EDR or identity integration.
- **Audit**: an append-only log of instructions, agent tool calls, external requests,
  approvals, simulations and failures.
- **Evaluate**: seven scenarios with known ground truth (attacks, benign activity that trips
  the rules, undecidable cases) grade detection and the agents' verdicts; see
  [docs/evaluation.md](docs/evaluation.md).

## Quick start (Windows PowerShell)

Requires Python 3.11+ (developed on 3.14). Ollama with `qwen3:8b` is needed only for the agents.

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
copy .env.example .env        # optional; the app runs with no .env at all
.\.venv\Scripts\python -m streamlit run app\main.py
```

Run it **from the project folder**: `.streamlit/config.toml` there binds the app to
127.0.0.1, turns off Streamlit's usage statistics and hides stack traces. Open
http://127.0.0.1:8501, go to **Data sources** → **Load demo dataset**, and follow
[docs/demo-runbook.md](docs/demo-runbook.md) for the full story (alert → investigation → chat →
agents → verdict → simulated response → report → audit).

```powershell
.\.venv\Scripts\python -m pytest -q                         # all tests; no network, no Ollama
.\.venv\Scripts\python -m ruff check . ; .\.venv\Scripts\python -m ruff format --check .
.\.venv\Scripts\python scripts\check_ollama.py              # is the model ready?
.\.venv\Scripts\python scripts\run_agent_demo.py            # demo story against the real model
.\.venv\Scripts\python scripts\run_eval.py                  # evaluation set (add --detection-only)
```

`make install|test|lint|run|demo-agents|eval|eval-detection` are equivalents if you have `make`.

## Documentation

| Topic | File |
|---|---|
| Demo walkthrough | [docs/demo-runbook.md](docs/demo-runbook.md) |
| Evaluation set and results | [docs/evaluation.md](docs/evaluation.md) |
| Architecture and modules | [docs/architecture.md](docs/architecture.md) |
| Data sources, field aliases, limits | [docs/data-sources.md](docs/data-sources.md) |
| Live inputs (file tail, HTTP receiver) and Wazuh | [docs/live-inputs.md](docs/live-inputs.md) |
| Detection rules | [docs/detection-rules.md](docs/detection-rules.md) |
| IP reputation providers | [docs/reputation.md](docs/reputation.md) |
| Agents, chat, limits | [docs/agents.md](docs/agents.md) |
| Response policy and audit | [docs/response-and-audit.md](docs/response-and-audit.md) |
| Decisions (ADRs) | [docs/decisions/](docs/decisions/) |
| Build log and acceptance checklist | [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md) |

## Data privacy

- Everything runs locally. Events are stored in a local SQLite file (`data/agentic_soc.db`,
  git-ignored). Nothing leaves the machine unless you switch on external reputation lookups.
- The web app listens on 127.0.0.1 only and Streamlit's usage statistics are off
  (`.streamlit/config.toml`); the HTTP receiver also binds to loopback only.
- Prompts and logs go only to the local Ollama server (loopback URLs only); no hosted LLM is used.
- The audit log records every external reputation request (provider, indicator, outcome).
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

Agents use `qwen3:8b` (about 5 GB, fits 8 GB VRAM). It is never pulled automatically:
run `ollama pull qwen3:8b` once, then `ollama serve`. `scripts\check_ollama.py` reports whether
the server is reachable and the model is installed. Only loopback Ollama URLs are accepted.
With Ollama stopped, everything except agent runs works; the **Agents** tab says AI is
unavailable. Run limits (`AGENT_MAX_MODEL_CALLS` and others) are listed in
[docs/agents.md](docs/agents.md).

## Troubleshooting

- *Upload rejected as too large*: raise `MAX_UPLOAD_BYTES` (default 25 MB).
- *Rows quarantined*: see the table on **Data sources**; the usual causes are a missing or
  unparseable timestamp, or invalid JSON. Add the column name to
  `app/ingestion/field_aliases.py` if your timestamp field is not recognised.
- *Dashboard says Ollama unavailable*: expected unless `ollama serve` is running. Detection and
  alerts do not need it.
- *Agent run failed with "unusable model replies"*: the model did not return valid JSON three
  times in a row; the step log on the **Agents** tab shows each rejected reply. Raise
  `AGENT_MODEL_TIMEOUT_SECONDS` if the errors are timeouts.
- *Agent run shows "interrupted"*: the app stopped mid-run. Press **Resume from checkpoint**.
- *Chat says the agents are "waiting"*: they asked you a question. Reply in **Investigate** mode;
  the run carries on. **Stop** ends it instead.
- *"An agent run is already open"*: a paused or waiting run still holds the investigation.
  Resume, redirect or stop it from the chat.
- *No IOC alert after uploading your own data*: load the IOC list first (the demo load does it),
  or press **Re-run detection** on the Detection rules page.
- *Reputation shows "skipped" for demo IPs*: expected. The demo uses documentation ranges
  (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), which are never sent to providers; the
  local IOC match still shows.
- *Reputation shows "rate limited"*: the provider returned 429 or the local budget is used
  up; the note says how long to wait. *"HTTP 401/403"*: check the API key and plan.
- *Replay controls missing*: replay needs a file-backed database (the default), not `:memory:`.
- *The app opens on another address or Streamlit asks for an email*: start it from the project
  folder so `.streamlit/config.toml` is read.
- *A followed file shows "waiting for line end"*: the writer has not finished the last line
  yet; it is read on the next poll.
- *HTTP receiver answers 403*: requests with an `Origin` header (browsers) or a non-loopback
  `Host` are refused by design; send from a script or `curl.exe`.
- *Agent steps time out on an 8 GB GPU*: set `AGENT_CONTEXT_TOKENS=8192` (fits the GPU) or
  raise `AGENT_MODEL_TIMEOUT_SECONDS`.
