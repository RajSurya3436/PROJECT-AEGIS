# Architecture

Modular monolith: one Python package (`app/`), one SQLite file, one Streamlit process.

```
demo dataset / file upload   (file tail, HTTP receiver: later phases)
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
 [Phase 5+] agents call the same service methods as tools
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

## Rules

- UTC everywhere internally; naive input timestamps are assumed UTC and flagged.
- SQLite: foreign keys on, WAL for file databases, explicit transactions
  (`app.storage.db.transaction`), versioned migrations tracked in `schema_migrations`.
- No logic in UI callbacks. No model-generated SQL or code, ever (enforced from Phase 5).
- Event content (messages, command lines, user agents) is untrusted data and is rendered with
  escaping widgets (`st.json`, `st.dataframe`).
