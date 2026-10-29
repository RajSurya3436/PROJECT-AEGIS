# ADR 0002: hand-written agent state machine instead of LangGraph

Date: 2026-10-29. Status: accepted.

The blueprint allows "LangGraph or a tested state machine" for Phase 5.

**Decision:** a small explicit state machine in `app/agents/graph.py`, with Ollama called over
its HTTP API through an injected transport (stdlib `urllib`, like the reputation providers).

**Why:**
- The graph is fixed and short (orchestrate, specialist, verify). The hard parts are the
  safety rules (allowlist, citation checks, limits, verifier adjustments), which are ours to
  write either way.
- No new dependencies. LangGraph and the LangChain Ollama integration bring a large tree, and
  their Python 3.14 support was not established (ADR 0001 kept 3.12 as a fallback only for this
  case).
- Checkpoints are one JSON column in our own SQLite file, next to the evidence they explain, and
  resuming is a plain loop over that state. Every transition is unit-testable with a scripted
  model and no network.

**Cost:** no LangGraph tooling (graph visualisation, built-in persistence back-ends). If the
graph grows branches, parallel specialists or human-in-the-loop interrupts beyond Phase 6,
revisit this.
