# Implementation plan

Source: `Agentic_SOC_Copilot_Full_Project_Plan_and_Master_Prompt.pdf`. Work proceeds phase by
phase; each phase ends with tests + lint and a review before the next starts.

## Environment (inspected 2026-10-26)

| Item | Finding |
|---|---|
| OS | Windows 11 Home |
| Python | 3.14.7 (only interpreter; project declares `>=3.11`) |
| RAM / GPU | 15.7 GB / RTX 5060 Laptop, 8 GB VRAM |
| Disk | ~546 GB free |
| Ollama | installed, server reachable, **no models pulled** |
| Chosen model | `qwen3:8b` (~5 GB), pulled by the user before Phase 5 |
| Git | repo initialised, no commits made |

## Phases

- [x] **0 Environment/config/docs**: pyproject, .gitignore, .env.example, Settings, Makefile, docs
- [x] **1 Data foundation**: models, SQLite migrations/repositories, parsers, normalizer, shared
  ingestion service, quarantine, search/related, demo data, Streamlit pages
- [x] **2 Replay engine + deterministic rules + alert queue**: five versioned rules, dedup /
  suppression, alert lifecycle, timed replay with pause/resume/stop/restart, local IOC list,
  Alert queue and Detection rules pages (see `docs/detection-rules.md`)
- [x] **3 Reputation**: AbuseIPDB and VirusTotal adapters behind one interface, local IOC
  lookup, SQLite cache with expiry, rate limits, retries, Settings page, mocked tests (see
  `docs/reputation.md`)
- [x] **4 Investigations**: lifecycle (open, close with disposition, reopen), event
  scope with related-event collection, evidence with provenance, timeline, coverage
  (missing telemetry) checks, deterministic Markdown/JSON reports, Investigations page
- [ ] 5 Agent graph (LangGraph or tested state machine), prompts, tool contracts, limits
- [ ] 6 Analyst chat, pause/resume/stop/redirect, state locking
- [ ] 7 Response policy, simulation, audit, Markdown/JSON export
- [ ] 8 Optional file tail + loopback HTTP receiver
- [ ] 9 Hardening, end-to-end tests, README, demo runbook

## Acceptance checklist (blueprint section 10)

- [~] Clean install documented and repeatable (documented; not yet tried on a second machine)
- [~] JSONL/NDJSON/CSV import, mapping preview, quarantine (done; also JSON)
- [~] Replay/upload/file-tail/HTTP share one ingestion path (upload, demo and replay share it and
  detection; file tail and HTTP pending)
- [x] Replay pause/resume/restart avoids duplicates (tested: a restart inserts 0 events and adds 0 alerts)
- [x] Deterministic alerts with event links (same dataset gives the same 5 alerts, tested)
- [x] Detection without Ollama
- [x] Provider adapters, mocked tests (no network or keys needed; a guard fails any real call)
- [x] Investigation, evidence provenance (deterministic; agents add to it from Phase 5)
- [ ] Agents with real allowlisted tools
- [ ] Chat / redirect / pause / resume / stop
- [ ] Verifier with inconclusive outcome
- [ ] Policy: simulation only
- [~] Audit log, Markdown/JSON reports (reports done; audit log is Phase 7)
- [ ] Prompt injection does not override policy (data is stored verbatim; agent-side checks are Phase 5)
- [~] README: privacy, keys, provider limits, troubleshooting (present; demo steps pending)

## Phase 1 design notes

- Event IDs are `sha256(source_id + id-or-canonical raw)[:32]`, so re-ingest and replay restart
  cannot duplicate events. Identical rows within one source collapse to one event by design.
- Only a missing/unparseable timestamp quarantines a row. Other invalid values (IP, port) are
  dropped from the canonical field, listed in `extra._invalid_fields`, and the event is marked
  `partial`; the raw record is always kept.
- Post-persist hooks (`IngestionService.hooks`) receive only newly inserted events. Phase 2
  registers detection there. A hook failure is recorded on the source and never loses events.
- All SQL lives in `app/storage/` (`repositories.py`, `alerts.py`); column names come from fixed
  allowlists.

## Phase 2 design notes

- Detection is the ingestion post-persist hook (`DetectionEngine.detect`). Rules recompute the
  affected entity's findings from stored events, so results do not depend on arrival order.
- Replay (`app/ingestion/replay.py`) is a synchronous `ReplayEngine` (one record per step, so
  alerts appear as data arrives) plus a threaded `ReplayRunner`. The runner builds a fresh engine
  with its own SQLite connection per start; in-memory databases get no runner.
- Idle gaps in event time are capped (default 300 s) so replay does not sit through overnight
  hours. Speeds: 1x, 10x, 60x, 600x, maximum.
- `local_iocs` is loaded from the demo manifest; Phase 3 builds provider lookups on top of it.
- Not done on purpose: grouping related alerts, an audit log of status changes (Phase 7), and the
  "Investigate" action (Phase 4; the button is disabled).

## Phase 3 design notes

- Code lives in `app/tools/` (`local_ioc.py`, `reputation/`), the layout the Phase 5 tools
  (`lookup_local_ioc`, `lookup_abuseipdb`, `lookup_virustotal_ip`) will wrap.
- Providers use stdlib `urllib` through an injected transport callable, so tests swap in a fake
  and no HTTP dependency was added. `tests/conftest.py` makes any real provider call fail.
- A lookup never raises for provider trouble: every outcome is a `ReputationStatus` (fresh,
  cached, not_configured, disabled, skipped, rate_limited, timeout, provider_error).
- Only `fresh` results are cached (parsed allowlisted summary, never raw bodies or keys).
  Failures are not cached; a 429 sets an in-memory cooldown instead.
- The external lookup switch defaults to `ENABLE_EXTERNAL_REPUTATION` and can be changed on the
  Settings page (stored in `app_settings`). Cached results stay visible when it is off, since
  showing them sends nothing.
- Lookups run only on an explicit action (Settings page form, "Check reputation" on an alert).
  Ingestion and detection never call providers (tested).
- The demo IPs are RFC 5737 documentation addresses, so they are classified `documentation`
  and never sent out; the local IOC list still matches them.
- Not done on purpose: domain and hash lookups at providers (the local IOC list covers them), a
  persisted daily request counter (the in-memory one restarts with the app).

## Phase 4 design notes

- `app/investigations/service.py` holds the rules Phase 5 agents will be bound by: evidence
  may only cite events in the investigation's scope, closed investigations are read-only, every
  disposition except `insufficient_data` must cite evidence, and a malicious one must cite at
  least one observation. Confidence is low/medium/high only (no invented numbers).
- Starting from an alert adds its events to the scope, then every event sharing a user, host or
  IP with them within +/-30 min (`INVESTIGATION_WINDOW_MINUTES`), capped at 500 events
  (`INVESTIGATION_MAX_SCOPE_EVENTS`; alert events are always kept). It records the alert as an
  observation, local IOC matches, and missing-telemetry gaps (no process events for the host,
  no auth events for the user, no network events for an IP, partially parsed events).
- Starting an investigation never contacts reputation providers; "Check reputation and
  record" does, and stores provider data as observations and unavailable providers as
  missing telemetry, with query/expiry timestamps in provenance.
- Evidence IDs are hashes of (investigation, category, source, claim, cited events), so
  repeating a step does not duplicate evidence. Reopening keeps all evidence.
- Reports (`app/reporting/report.py`) are built only from stored state; the same state and
  `generated_at` give byte-identical JSON and Markdown. Untrusted values are escaped in Markdown.
  Recommendations and simulated actions are placeholders until Phase 7.
- Not done on purpose: linking several alerts to one investigation from the UI (the data model
  supports it), per-investigation locking (Phase 6), audit trail (Phase 7).
