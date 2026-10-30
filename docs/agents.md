# Agents and analyst chat (Phases 5 and 6)

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
| `AGENT_MAX_ASK_STEPS` | 4 | model calls for one Ask answer (the last must answer) |
| `AGENT_MAX_MODEL_CALLS` | 40 | run ends `limit_reached`; the last call is kept for the verifier |
| `AGENT_MAX_TOOL_CALLS` | 30 | specialist work stops, verifier runs |
| `AGENT_MAX_STEPS_PER_TURN` | 6 | specialist turn ends, back to the orchestrator |
| `AGENT_MAX_SPECIALIST_TURNS` | 4 | orchestrator is overruled, verifier runs |
| `AGENT_MAX_RUN_SECONDS` | 900 | run ends `limit_reached` |
| `AGENT_MAX_INVALID_OUTPUTS` | 3 | consecutive unusable replies fail the run |
| `AGENT_MODEL_TIMEOUT_SECONDS` | 120 | per model call |
| `AGENT_CONTEXT_TOKENS` | 16384 | Ollama `num_ctx` (its default is too small for the case file) |

## Runs, checkpoints, statuses

Runs are stored in `agent_runs` with the whole `RunState` as a checkpoint after every step, and
every routing decision, redirect, tool call, result, refusal and error in `agent_steps` (shown on
the **Agents** tab). With a file database runs execute on a worker thread with their own
connection; with an in-memory one they run inline.

| Status | Meaning | Next |
|---|---|---|
| `queued`, `running` | executing | pause, stop, redirect |
| `paused` | the analyst paused it | resume, redirect (resumes), stop |
| `waiting` | an agent asked a question (`request_analyst_input`) | reply in Investigate mode (resumes), stop |
| `interrupted` | the app exited mid-run (set at start-up) | resume, stop |
| `completed` | the verifier gave an assessment | final |
| `stopped` | stopped by the analyst, or the investigation was closed | final |
| `limit_reached`, `failed` | a limit, or the model was unavailable / kept replying badly | final |

**Concurrency.** An investigation has at most one *open* run (queued, running, paused or
waiting). Creating a run checks that in the same transaction as the insert; claiming a run to
execute it is a single conditional `UPDATE`, so two clicks or two workers cannot both win, and
chat directives are marked applied atomically so each is acted on exactly once. Closing an
investigation stops its open run (at the next step if it is executing) and discards pending
instructions.

## Analyst chat (Phase 6)

The **Chat** tab of an investigation stores every message and instruction in `chat_messages`
before anything acts on it, next to notices from the agents (run started, paused, waiting with
their question, finished with the assessment). All text is shown as plain text.

- **Ask** (read-only): pick the log investigator, threat intel or the verifier. It answers from
  the case file and may use read-only tools (search, events, timeline, rule explanation, local
  IOC list). `add_evidence`, `request_analyst_input` and the provider lookups are refused in
  code, not just left out of the prompt. Evidence and event IDs in the answer are checked and
  unknown ones flagged. Ask works on closed investigations and is not a run.
- **Investigate**: an instruction for the agents, optionally for one specialist. With no open
  run it starts one; a paused run resumes with it; an executing run reads it at its next step.
  When the agents are waiting, the message is the reply to their question and the turn carries
  on.
- **Control**: Pause, Resume, Stop, and Redirect (same as Investigate, logged as a redirect).

How directives act (`AgentGraph._receive` and `_route_queued`): new instructions cut the
current specialist turn short (once per batch; a turn that had not taken a step yet is dropped
without using up a turn) and join a queue. Each time the work is back with the orchestrator,
the oldest queued instruction is routed: to the chosen specialist, to the verifier, or to the
orchestrator, which is told to act on the latest analyst message first. So several instructions
sent together are carried out in order. The analyst's words appear in every later prompt under
*ANALYST MESSAGES*, outside the DATA fences. An instruction for a specialist or the
orchestrator grants one extra specialist turn (at most `AGENT_MAX_SPECIALIST_TURNS` extra in
total), so a redirect is honoured even after the turn limit. Nothing is deleted: evidence,
notes and the step log stay.

An instruction that arrives after the verifier has started cannot change that assessment; when
the run completes, a **follow-up run** starts automatically and reads it first (the chat says
so). A reply that arrives while a worker is returning, or a Resume pressed while it is still
winding down, is picked up by the same worker rather than lost. Stopping a run discards its
pending instructions; a stop that races a run finishing on its own leaves the finished result
as it is.

Analyst messages direct the work but cannot lift the rules: tools, roles, citation checks and
verifier adjustments apply to them like to anything else.

## Without Ollama

Everything except agent runs and Ask works. The Chat and Agents tabs show *AI unavailable*; a
run started anyway fails at its first call with that message, an Ask gets a system reply saying
so, and no deterministic data is touched.
`scripts\check_ollama.py` reports the server and model state.

## Not done yet (on purpose)

- Several analysts on one case at once are kept consistent by the database rules above; there
  is no presence or editing-lock UI.
- The response planner is a separate, on-request step, not part of a run; see
  [response-and-audit.md](response-and-audit.md).
- Prompts were tuned once against the real `qwen3:8b` on the demo case
  (`scripts/run_agent_demo.py`); other datasets have not been tried.
