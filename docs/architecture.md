# Architecture

Modular monolith: one Python package (`app/`), one SQLite file, one Streamlit process.

```
demo dataset / file upload / file tail / loopback HTTP receiver
            |
     record adapter (generic, wazuh)  (app/ingestion/adapters/)
            |
     IngestionService  (app/ingestion/service.py)
            |
 parse -> normalize/validate -> deduplicate -> persist -> post-persist hooks -> source health
            |  malformed rows
            +--> parse_errors (quarantine)
            |
         SQLite  (events, data_sources, parse_errors, app_settings)
            |
            |  new events only (post-persist hook)
     DetectionEngine  (app/detection/)  -> alerts + alert_events (exact event links)
            |
 InvestigationService (app/investigations/) -> scope, evidence, timeline
            |                                       -> reports (app/reporting/)
 AgentGraph (app/agents/) -> allowlisted tools -> the same service methods
   orchestrator / log investigator / threat intel / verifier; one local model (Ollama)
                 |
     ResponsePlanner -> propose_response -> policy gate (app/policy) -> simulate only
     AuditLog <- every service that changes state or sends data out
                 |
     ReputationService (app/tools/reputation/)   <- on request only, never per event
       local IOC list + cache (reputation_cache) + AbuseIPDB / VirusTotal over HTTPS
```

Replay (`app/ingestion/replay.py`) feeds `IngestionService` like any other source.

## Modules (Phase 1)

| Module | Responsibility |
|---|---|
| `app/config.py` | `Settings` from env/`.env`; keys are `SecretStr`, never persisted |
| `app/domain/` | Pydantic models, enums, errors; no I/O |
| `app/storage/` | connection, migrations (`migrations/NNNN_*.sql`), repositories (all SQL) |
| `app/ingestion/` | parsers, alias table, normalizer, shared service, upload preview, demo loader |
| `app/ui/` | Streamlit pages; thin, call services only |
| `app/context.py` | wiring of connection + services for the UI |
| `app/ollama_health.py` | read-only, loopback-only Ollama status check |
| `app/detection/` | rule interface, five rules, engine (hook, rescan, rule config, alert lifecycle) |
| `app/storage/alerts.py` | rule settings, alerts and links, local IOCs (all SQL) |
| `app/ingestion/replay.py`, `iocs.py` | timed replay engine and runner, IOC CSV loader |
| `app/tools/local_ioc.py` | offline IOC lookup (ip, domain, sha256) |
| `app/tools/reputation/` | provider interface, AbuseIPDB and VirusTotal adapters, rate limiter, HTTPS transport, service combining cache + IOC + providers |
| `app/investigations/` | investigation lifecycle, scope collection, evidence rules, coverage checks, timeline and event descriptions |
| `app/reporting/report.py` | deterministic report model, JSON and escaped Markdown |
| `app/storage/investigations.py` | investigations, alert links, scope, evidence (all SQL) |
| `app/storage/reputation.py` | reputation cache (all SQL); `AppSettingsRepository` in `repositories.py` holds the lookup switch |
| `app/agents/` | model client, output schemas, tool allowlist, prompts, state machine, run service and background runner (see `docs/agents.md`) |
| `app/storage/agents.py` | agent runs with checkpoints, step log (all SQL) |
| `app/ui/agents_panel.py` | Agents tab: run, pause, resume, stop, activity log, verifier assessment |
| `app/agents/chat.py` | analyst chat: Ask (read-only), Investigate, Control; directives and run control |
| `app/storage/chat.py` | chat messages and pending directives (all SQL) |
| `app/ui/chat_panel.py` | Chat tab |
| `app/policy/` | response action catalogue, deterministic policy gate, `ResponseService` (simulation only) |
| `app/agents/planner.py` | response planner: one model call, proposals via `propose_response` |
| `app/audit/`, `app/storage/audit.py` | append-only audit log written by the services |
| `app/storage/responses.py` | recommendations (all SQL) |
| `app/ui/response_panel.py`, `app/ui/audit.py` | Response tab, Audit log page |
| `app/ingestion/adapters/` | record adapters: generic, Wazuh alerts.json |
| `app/ingestion/file_tail.py`, `http_receiver.py` | live inputs: followed files, loopback receiver |
| `app/detection/siem_rules.py` | `siem.high_severity_alert` over upstream SIEM levels |
| `app/ui/live_inputs.py` | Live inputs on the Data sources page |

## Rules

- UTC everywhere internally; naive input timestamps are assumed UTC and flagged.
- SQLite: foreign keys on, WAL for file databases, explicit transactions
  (`app.storage.db.transaction`), versioned migrations tracked in `schema_migrations`.
- No logic in UI callbacks. No model-generated SQL or code, ever (a test parses `app/agents/`).
- Event content (messages, command lines, user agents) is untrusted data and is rendered with
  escaping widgets (`st.json`, `st.dataframe`).
