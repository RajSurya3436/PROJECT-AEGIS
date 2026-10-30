# ADR 0003: response actions are a fixed, simulated catalogue behind a code policy gate

Date: 2026-10-30. Status: accepted.

The blueprint requires response recommendations with rationale, evidence, risk, reversibility
and approval status; all actions simulated; a deterministic policy gate; and an audit trail.

**Decisions:**

1. **A fixed catalogue of eight actions** (`app/policy/rules.py`): block_ip, isolate_host,
   disable_account (high impact), reset_credentials, revoke_sessions (medium),
   collect_triage, watchlist, escalate (low). The model can only name one of these; there is no
   free-text action and no integration code behind any of them. "Simulate" records what a real
   integration would do and nothing else.
2. **The policy is code, not prompt.** A proposal is checked for: a catalogued action; a target
   of the right kind that appears in the investigation's own events (so log text cannot point
   an action at another system); block_ip on external addresses only; cited evidence that
   exists in the investigation; and proportionality — an agent may propose high-impact actions
   only on a likely/confirmed malicious assessment, medium ones only on suspicious or worse.
   Analyst proposals skip the assessment check but medium/high ones must cite an observation.
3. **Blocked proposals are stored**, with the reason, so the analyst sees what the model wanted.
4. **Approval:** medium and high-impact actions must be approved before they can be simulated;
   low-impact ones are simulated directly. Approved/simulated/rejected/blocked are final except
   approved → simulated or rejected. Closed investigations are read-only.
5. **The response planner is not a node in the agent run.** It is one model call made when
   the analyst presses *Propose response with AI*, working from the latest completed run's
   assessment. It does not use the run's model-call budget, it cannot fire on a half-finished
   case, and run behaviour (and its tests) stay unchanged. Its proposals still go through the
   allowlisted `propose_response` tool, so role, schema, policy and audit apply as to any tool.
6. **Audit log in the same SQLite file, append-only by trigger.** Services write it as a side
   effect of the actions themselves (not the UI), so nothing that changes state or sends data
   out is missed. Details are size-capped.

**Cost:** the catalogue must be extended in code for new actions; the planner is a separate
button rather than part of the run; the append-only triggers protect against the app and
casual edits, not against someone with write access to the database file.
