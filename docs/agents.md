# Agents (Phase 5)

Four roles, one local model (`qwen3:8b` through Ollama), distinct prompts. The model proposes;
deterministic code decides. Code lives in `app/agents/`.

| Role | Does | Tools |
|---|---|---|
| Orchestrator | picks the next specialist and gives it an instruction | none |
| Log investigator | searches and correlates events, records supporting and contradicting evidence | `search_events`, `get_event`, `get_related_events`, `build_timeline`, `get_alert_rule_explanation`, `add_evidence`, `request_analyst_input` |
| Threat intel | local IOC list, AbuseIPDB, VirusTotal; provider results are recorded with provenance | `lookup_local_ioc`, `lookup_abuseipdb`, `lookup_virustotal_ip`, `get_event`, `build_timeline`, `get_alert_rule_explanation`, `add_evidence`, `request_analyst_input` |
| Verifier | checks evidence and notes, proposes a disposition (may be inconclusive) | none (reads the case file) |

`propose_response` is not registered until Phase 7 (response policy); calling it is refused like
any unknown tool.

## Flow

```
orchestrate -> log_investigator | threat_intel -> orchestrate -> ... -> verify -> done
```

`app/agents/graph.py` is a hand-written state machine (ADR 0002). Each model call gets the role
prompt plus a case file that code builds from stored state on every call: investigation,
alerts, latest evidence, timeline, specialist notes. A specialist works one tool call per model
call until it finishes or hits the per-turn step limit, then control returns to the
orchestrator. The verifier runs once at the end.

## What code enforces

- **Allowlist and roles.** Unknown tools and tools outside the caller's role are refused.
  Arguments are strict Pydantic models (unknown keys rejected, sizes capped). Search filters go
  through the existing allowlisted repository; there is no SQL, eval, shell or dynamic import
  (a test parses `app/agents/` to check).
- **Citations.** `add_evidence` only accepts event IDs that a tool returned in this run (the
  case-file timeline counts, because code builds it with the same tool). Cited events are
  brought into the scope, then the Phase 4 rules apply. An agent observation must cite an event;
  `based_on_evidence_ids` must exist. Agent evidence has source `agent`, `collected_by`
  `agent:<role>`, the run ID and model in provenance, and a reliability note saying it is
  model-generated.
- **Reputation.** Provider tools record evidence the same way the analyst button does. An IP must
  appear in an event the agents have seen; private and documentation IPs are never sent.
- **Structured output.** Every reply is parsed against a schema (the same schema is sent to
  Ollama as `format`). An invalid reply is logged and retried with the error;
  `AGENT_MAX_INVALID_OUTPUTS` in a row fail the run.
- **Verifier checks** (`check_assessment`): unknown evidence IDs are dropped and listed; a verdict
  citing nothing becomes `insufficient_data`; a malicious verdict needs an observation from the
  alert, events, IOC list, a provider or the analyst (agent claims alone are not enough) or it
  becomes `suspicious_inconclusive`; contradictions lower `confirmed` to `likely`; recorded
  missing telemetry caps confidence at medium. Every change is listed under *adjustments*.
- **Human decision.** Agents never close an investigation. The assessment is a proposal; the
  analyst can accept it, which goes through the normal close rules again.
- **Prompt injection.** Log, IOC and provider values sit inside `<<<DATA ...>>>` blocks; any
  `<<<`/`>>>` inside them is broken up so data cannot close its fence. The prompts say data is
  never instructions, but the protection is the list above: a model that obeys injected text
  can still only call allowlisted tools with validated arguments.

## Limits (environment variables)

| Setting | Default | Effect |
|---|---|---|
| `AGENT_MAX_MODEL_CALLS` | 40 | run ends `limit_reached`; the last call is kept for the verifier |
| `AGENT_MAX_TOOL_CALLS` | 30 | specialist work stops, verifier runs |
| `AGENT_MAX_STEPS_PER_TURN` | 6 | specialist turn ends, back to the orchestrator |
| `AGENT_MAX_SPECIALIST_TURNS` | 4 | orchestrator is overruled, verifier runs |
| `AGENT_MAX_RUN_SECONDS` | 900 | run ends `limit_reached` |
| `AGENT_MAX_INVALID_OUTPUTS` | 3 | consecutive unusable replies fail the run |
| `AGENT_MODEL_TIMEOUT_SECONDS` | 120 | per model call |
| `AGENT_CONTEXT_TOKENS` | 16384 | Ollama `num_ctx` (its default is too small for the case file) |

## Runs, checkpoints, stopping

Runs are stored in `agent_runs` with the whole `RunState` as a checkpoint after every step, and
every routing decision, tool call, result, refusal and error in `agent_steps` (shown on the
**Agents** tab). Only one run per investigation can be active (checked in the same transaction
as the insert). With a file database runs execute on a worker thread with their own connection;
**Stop run** is checked between steps. Stopped runs, and runs left active when the app exited
(marked `interrupted` at start-up), resume from their checkpoint. Closing the investigation
stops a run at its next step.

Statuses: `queued`, `running`, `completed`, `stopped`, `limit_reached`, `failed`,
`interrupted`.

## Without Ollama

Everything except agent runs works. The Agents tab shows *AI unavailable*; a run started anyway
fails at its first call with that message, and no deterministic data is touched.
`scripts\check_ollama.py` reports the server and model state.

## Not done yet (on purpose)

- Chat, Ask/Investigate/Control modes, pause and redirect (Phase 6). `request_analyst_input`
  records the question for the analyst but does not pause the run.
- Response planning and `propose_response` (Phase 7).
- The prompts have only been exercised with a scripted model in tests; behaviour with the real
  `qwen3:8b` still has to be checked once it is pulled (see the implementation plan).
