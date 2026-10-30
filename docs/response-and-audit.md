# Response policy, simulation and audit (Phase 7)

**Every response action is simulated.** This app has no firewall, EDR or identity-provider
integration. Approving and simulating an action records what a real integration *would* do and
changes nothing outside the app. Design decisions: [ADR 0003](decisions/0003-response-policy-and-audit.md).

## Where it is

- Code: `app/policy/rules.py` (catalogue, policy checks, simulation text),
  `app/policy/service.py` (`ResponseService`: propose, approve, reject, simulate),
  `app/agents/planner.py` (`ResponsePlanner`), `app/audit/log.py`, `app/storage/audit.py`,
  `app/storage/responses.py`, migration `0007_response_audit.sql`.
- UI: the **Response** tab of an investigation, and the **Audit log** page.

## Action catalogue

| Action | Target | Impact | Reversible | Approval |
|---|---|---|---|---|
| `block_ip` | external IP from the events | high | yes | required |
| `isolate_host` | host from the events | high | yes | required |
| `disable_account` | user from the events | high | yes | required |
| `reset_credentials` | user | medium | no | required |
| `revoke_sessions` | user | medium | no | required |
| `collect_triage` | host | low | yes (read-only) | not required |
| `watchlist` | IP, host or user | low | yes | not required |
| `escalate` | none | low | yes | not required |

## Policy (deterministic, in code)

A proposal — from the planner or the analyst — is **blocked** (stored, with the reason) when:

- the target is not of the right kind, or does not appear in the investigation's events
  (matching ignores case; the stored target is spelled as in the events);
- `block_ip` names a private, loopback, link-local, multicast or reserved address (isolate the
  internal host instead). Documentation ranges count as external, because the demo data uses
  them in place of public addresses;
- no evidence is cited, or a cited ID is not in this investigation;
- an **agent** proposes a high-impact action without a `likely_malicious`/`confirmed_malicious`
  assessment, or a medium-impact one without at least `suspicious_inconclusive`;
- an **analyst** proposes a medium/high-impact action without citing an observation.

The same undecided action on the same target is not proposed twice; the existing one is
returned.

## Lifecycle

`proposed` → (`approved` →) `simulated`, or → `rejected`. `blocked` is final. Medium and high
impact need `approved` first; low impact is simulated directly. Closed investigations are
read-only (reopen to change their response).

## Response planner

*Propose response with AI* on the Response tab makes one model call with the case file, the
verifier's latest assessment (it refuses to run without one), the entities seen in the events
and the action catalogue. It returns a short summary and up to five proposals; each is sent
through the allowlisted `propose_response` tool (response-planner role only), so the schema,
the policy and the audit apply. An action outside the catalogue fails schema validation, so a
model that obeys injected text cannot invent one. The result is posted to the chat.

## Audit log

Append-only table `audit_events` (database triggers refuse UPDATE and DELETE). Each row has the
time (UTC), actor (`analyst`, `system`, `agents`, `agent:<role>`), action, target, investigation,
outcome (`ok`, `rejected`, `failed`) and size-capped details. Recorded:

| Action prefix | What |
|---|---|
| `chat.` | every analyst question, instruction, reply, redirect, pause, resume, stop |
| `agent_run.` | run created and every way a run ends (completed, paused, waiting, failed, ...) |
| `tool.` | every agent tool call, accepted or refused, with its arguments |
| `response.` | proposals, policy blocks, approvals, rejections, simulations, planner runs |
| `investigation.`, `evidence.` | opened, closed (disposition), reopened, analyst scope changes and notes |
| `alert.` | status changes |
| `reputation.` | every request sent (or attempted) to an external provider |
| `rule.`, `settings.` | rule configuration, external lookup switch |
| `report.` | Markdown/JSON report downloads |

The Audit log page filters by group, investigation and outcome and downloads JSON. Reports
include the investigation's audit trail.

## Report additions (schema version 2)

Analyst instructions, the agent assessment (advisory), recommendations with policy notes,
simulated actions, next steps (undecided recommendations, then gaps) and the audit trail.
