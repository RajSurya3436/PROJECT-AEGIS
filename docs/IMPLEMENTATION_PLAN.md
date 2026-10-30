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
- [x] **5 Agent graph**: tested state machine (ADR 0002), orchestrator / log investigator /
  threat intel / verifier prompts, ten allowlisted tools with strict argument schemas, structured
  outputs, citation checks, verifier adjustments, step/tool/time limits, checkpoints with
  resume and stop, Agents tab (see `docs/agents.md`)
- [x] **6 Analyst chat**: persistent chat with Ask (read-only) / Investigate / Control modes,
  specialist selection, pause/resume/stop/redirect, blocking agent questions, truthful run
  statuses, one open run per investigation (see `docs/agents.md`)
- [ ] 7 Response policy, simulation, audit, Markdown/JSON export
- [ ] 8 Optional file tail + loopback HTTP receiver, Wazuh integration (see below)
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
- [x] Investigation, evidence provenance (agents add to it through `add_evidence`)
- [x] Agents with real allowlisted tools (scripted-model tests; demo case run with real `qwen3:8b`)
- [x] Chat / redirect / pause / resume / stop (prior evidence kept on redirect, tested)
- [x] Verifier with inconclusive outcome (deterministic downgrades when evidence cannot carry a verdict)
- [ ] Policy: simulation only
- [~] Audit log, Markdown/JSON reports (reports done; audit log is Phase 7)
- [x] Prompt injection does not override policy (fenced data, allowlist, citation and verdict
  checks; tested with a model that obeys injected text)
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

## Phase 5 design notes

- `app/agents/`: `llm.py` (ChatModel protocol, loopback-only Ollama client), `schemas.py`
  (strict output models), `tools.py` (allowlist, role map, argument models, handlers),
  `prompts.py` (role prompts, DATA fencing), `graph.py` (state machine, limits, verifier
  checks), `service.py` (create/execute/resume, background runner).
- The model only names a tool and gives JSON arguments; code validates and runs it. Refusals go
  back to the model as tool results. Invalid replies are retried with the error message.
- Citable events are those a tool returned in this run, tracked in the checkpoint. Citing one
  brings it into the scope (`InvestigationService.add_to_scope`) before the Phase 4 rules run.
- `check_reputation` gained a `providers` argument so each provider tool looks up only itself.
- One model call is always kept for the verifier; tool and turn limits also route to it, so most
  limit hits still end with an assessment. Only the time limit and the model call limit end a
  run without one.
- The verifier's assessment is stored on the run, never applied automatically. "Close
  investigation with this assessment" calls the normal `close()`.
- Tests use `tests/fixtures/agents.py` (scripted model); `tests/conftest.py` makes any real
  Ollama call fail.
- To do once `qwen3:8b` is pulled: run the demo investigation end to end, check that replies
  validate (format-constrained JSON with thinking off), and tune the prompts and limits.

## Phase 6 design notes

- `app/agents/chat.py` (`ChatService`), `app/storage/chat.py`, migration `0006_chat.sql`,
  `app/ui/chat_panel.py`. The service takes a `launch(run_id)` callable: the background runner
  in the app, `AgentService.execute` (inline) for in-memory databases and tests.
- Control goes through the database, not thread events: `agent_runs.control` (pause/stop) and
  pending directive rows in `chat_messages`, both read by the graph at each step boundary.
  This works for any worker or connection and survives restarts.
- Pause ends the worker after checkpointing (status `paused`); resume starts a new worker from
  the checkpoint. Stopped is now final (it was resumable in Phase 5); paused, waiting and
  interrupted runs resume.
- `request_analyst_input` now blocks: the run ends the step as `waiting`, the question is posted
  to the chat, and the analyst's reply resumes the same turn. `execute` re-checks for a reply
  that arrived while it was returning, so a reply is never stranded.
- Open runs (queued, running, paused, waiting) hold the investigation; `interrupted` does not,
  so a crash never wedges a case, but resuming it is refused while another run is open.
- `InvestigationService.close_hooks` lets the chat stop an open run and discard pending
  instructions when the case closes.
- Ask is a separate short loop (`ChatService._answer`), not a run: read-only `ToolContext`,
  `AGENT_MAX_ASK_STEPS` model calls, IDs in the answer checked against stored data.
- Not done on purpose: chat transcript in the exported report and an audit view (Phase 7).

### Phase 6 review fixes (2026-10-30)

From `/code-review` of the Phase 6 commit; each has a test.

- A pause or stop requested while a run is still queued is honoured (`claim` no longer clears
  `control`). A closed investigation is checked before control requests, so the reason shown
  is accurate.
- Stopping never overwrites a run that finished meanwhile (`stop_unfinished`).
- `AgentRunner.launch` on a run whose worker is winding down re-executes it in that worker.
- The Agents tab only shows Pause/Resume/Stop on the run those buttons act on
  (`ChatService.controlled_run`).
- A stopped run discards its pending instructions.
- Directives are queued and routed one at a time when the work returns to the orchestrator;
  a turn with no steps is dropped without a note or using a turn. Bonus turns: specialists and
  orchestrator only, capped at `AGENT_MAX_SPECIALIST_TURNS`.
- The step limit is checked before a run waits for the analyst.
- Ask does not flag 32-hex strings (e.g. MD5s) that appeared in the data it was shown.
- Instructions that arrive during the verifier's step get an automatic follow-up run.

### First run with the real model (2026-10-30)

`scripts/run_agent_demo.py` with `qwen3:8b` on the demo case: completed in 135 s (8 model
calls, 3 tool calls), every reply valid JSON, no rejected tool calls, verdict
`likely_malicious` (medium) citing only real evidence IDs. The model needs ~7.8 GB at 16k
context, so with 8 GB VRAM part of it runs on the CPU. Two problems, fixed:

- The log investigator read events and finished without `add_evidence`, so the run added no
  agent evidence. Code now reminds a log investigator turn once (step kind `nudge`) when it
  tries to finish after successful lookups without recording anything; a second finish is
  accepted. The reminder is placed outside the DATA blocks (inside one, the model rightly
  ignored it as data) and is shown only until something is recorded.
- With the reminder showing, the model repeated the same `add_evidence` call. A tool call
  identical to an earlier successful one in the same turn is now refused without running.
- Ask filed brute-force signs under "evidence against compromise". The Ask prompt now asks
  for labelled "For compromise:" / "Against compromise:" sections.

After the fixes: completed in 202 s (10 model calls, 4 tool calls, one `nudge`), one agent
observation citing 13 events, verdict `suspicious_inconclusive` (medium). Known limitation:
Ask once called 203.0.113.45 an IOC (the IOC is 203.0.113.80); Ask checks IDs, not facts.

Tests no longer depend on whether Ollama happens to be running (the UI health check is stubbed
in `tests/conftest.py`).

## Phase 8 scope: live inputs and Wazuh (added 2026-10-30)

Wazuh is not installed yet. Everything below must be buildable and testable without it, using
recorded sample Wazuh JSON as fixtures; a real Wazuh install is only needed for the final check.

- **File tail** (planned): follow a growing JSONL file, survive rotation/truncation, remember the
  read offset across restarts, feed `IngestionService` like every other source.
- **Loopback HTTP receiver** (planned): local-only endpoint for pushed events, size and rate
  limits, shared ingestion path.
- **Wazuh field mapping**: map Wazuh alert JSON (`timestamp`, `agent.name`, `data.srcip`,
  `data.dstuser`/`data.srcuser`, `rule.id`/`rule.level`/`rule.description`/`rule.groups`,
  `full_log`, ...) to the canonical event model; unknown fields kept in `extra`, raw record
  always kept.
- **Wazuh as a source**:
  - A. Tail `/var/ossec/logs/alerts/alerts.json` (first target; uses the file tail).
  - B. Wazuh integration (`integratord`) posting alerts to the receiver. Wazuh's manager runs on
    Linux, so on this laptop it would be in Docker or WSL and reach the receiver over a
    non-loopback address: needs a token, an allowlisted source address and an ADR before the
    receiver may bind beyond loopback.
  - C. Optional: poll the Wazuh indexer (OpenSearch) API for new alerts when Wazuh is remote.
- **Wazuh alerts vs. our rules**: decide (ADR) whether Wazuh alerts become alerts here directly
  (keeping Wazuh's rule id and level mapped to severity) and/or are stored as events for our
  rules and agent searches. Optional: ingest `archives.json` (raw events) so our five rules and
  the agents see the underlying logon/process/network activity.
- **Setup guide**: install Wazuh (single-node Docker) on this laptop, enrol the Windows host as
  an agent, point the app at the alert file, run an end-to-end check.
- Other SIEMs (Elastic/Security Onion via API, Splunk via HTTP forwarding, Graylog via file or
  HTTP) reuse the same file/HTTP/poll paths; only their field mappings differ. Not in scope
  unless asked.
