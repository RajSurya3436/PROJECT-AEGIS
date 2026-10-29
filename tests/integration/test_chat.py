from __future__ import annotations

import pytest
from fixtures.agents import ScriptedModel, call, finish, route, verdict

from app.agents.llm import ModelUnavailableError
from app.config import Settings
from app.context import build_context
from app.domain.enums import (
    AgentRole,
    AgentRunStatus,
    ChatKind,
    ChatMode,
    Confidence,
    Disposition,
    EvidenceSource,
)
from app.domain.errors import InvestigationError
from app.ingestion.demo import ingest_demo
from app.ingestion.iocs import load_demo_iocs
from app.storage.repositories import EventFilters

RULE = "auth.failures_then_success"


class Holder:
    model: ScriptedModel | None = None


@pytest.fixture
def holder():
    return Holder()


@pytest.fixture
def demo(settings, holder):
    ctx = build_context(settings, ":memory:", model_factory=lambda _s: holder.model)
    load_demo_iocs(ctx.iocs)
    ingest_demo(ctx.ingestion)
    return ctx


@pytest.fixture
def inv(demo):
    alert = next(a for a in demo.alerts.list() if a.rule_id == RULE)
    return demo.investigations.start_from_alert(alert.alert_id).investigation_id


def _script(holder, *replies):
    holder.model = ScriptedModel(list(replies))
    return holder.model


def _kinds(demo, inv):
    return [(m.author, m.kind.value) for m in demo.chat.messages(inv)]


def _evidence_ids(demo, inv):
    return {e.evidence_id for e in demo.investigations.evidence(inv)}


# --- Ask ----------------------------------------------------------------------------------


def test_ask_answers_read_only_and_records_both_messages(demo, holder, inv):
    before = _evidence_ids(demo, inv)
    model = _script(
        holder,
        call("search_events", user="dave", outcome="success"),
        call("add_evidence", category="inference", claim="should not be stored"),
        call("lookup_abuseipdb", ip="203.0.113.45"),
        finish("One success after 12 failures (alert ev). Could be legitimate if dave travels."),
    )
    answer = demo.chat.ask(inv, "Could this be legitimate?")

    assert answer.kind is ChatKind.ANSWER and answer.author == "log_investigator"
    assert answer.mode is ChatMode.ASK and "legitimate" in answer.content
    lookups = answer.payload["lookups"]
    assert [lk["ok"] for lk in lookups] == [True, False, False]
    assert "read-only Ask mode" in lookups[1]["summary"]
    assert _evidence_ids(demo, inv) == before  # nothing written
    assert _kinds(demo, inv) == [("analyst", "question"), ("log_investigator", "answer")]
    assert "Could this be legitimate?" in model.user_prompt(0)
    assert "add_evidence" not in model.system_prompt(0)  # writing tools are not offered
    assert not demo.agents.runs.for_investigation(inv)  # Ask is not a run


def test_ask_flags_references_that_do_not_exist(demo, holder, inv):
    real = sorted(_evidence_ids(demo, inv))[0]
    _script(holder, finish(f"See {real} and ev-0123456789abcdef and {'f' * 32}."))
    answer = demo.chat.ask(inv, "What supports it?", AgentRole.VERIFIER)
    assert answer.payload["unverified_references"] == ["ev-0123456789abcdef", "f" * 32]
    assert "Unverified references" in answer.content and real not in answer.content.split("[")[1]


def test_verifier_answers_without_tools(demo, holder, inv):
    model = _script(holder, call("search_events", user="dave"), finish("Thin evidence."))
    answer = demo.chat.ask(inv, "Is it enough?", AgentRole.VERIFIER)
    assert answer.payload["lookups"][0]["ok"] is False
    assert "Tools you may call" not in model.system_prompt(0)


def test_ask_stops_looking_at_the_step_limit(demo, holder, inv):
    demo.agents.settings = Settings(_env_file=None, agent_max_ask_steps=2)
    _script(holder, call("build_timeline"), call("build_timeline"))
    answer = demo.chat.ask(inv, "Everything about dave?")
    assert "could not finish looking within 2 steps" in answer.content


def test_ask_when_ai_is_unavailable(demo, holder, inv):
    _script(holder, ModelUnavailableError("Ollama is not reachable"))
    note = demo.chat.ask(inv, "Anything?")
    assert note.author == "system" and note.content.startswith("AI unavailable")


def test_ask_works_on_a_closed_investigation_but_directing_does_not(demo, holder, inv):
    demo.investigations.close(inv, Disposition.INSUFFICIENT_DATA, Confidence.LOW, "n/a", [])
    _script(holder, finish("Closed as insufficient data."))
    assert demo.chat.ask(inv, "Why was it closed?").kind is ChatKind.ANSWER
    with pytest.raises(InvestigationError, match="closed"):
        demo.chat.investigate(inv, "keep going")
    with pytest.raises(InvestigationError, match="write a message"):
        demo.chat.ask(inv, "   ")


# --- Investigate and redirect -------------------------------------------------------------


def test_investigate_starts_a_run_with_the_chosen_specialist(demo, holder, inv):
    model = _script(
        holder,
        call("search_events", user="dave"),
        finish("dave: 12 failures then success"),
        route("verifier"),
        verdict(),
    )
    message = demo.chat.investigate(
        inv,
        "Search the same user's events for 30 minutes before and after.",
        AgentRole.LOG_INVESTIGATOR,
    )
    (run,) = demo.agents.runs.for_investigation(inv)
    assert run.status is AgentRunStatus.COMPLETED
    # The first model call went straight to the chosen specialist, not the orchestrator.
    assert "log investigator" in model.system_prompt(0)
    assert "ANALYST MESSAGES" in model.user_prompt(0)
    assert "30 minutes before and after" in model.user_prompt(0).split("ANALYST MESSAGES")[1]
    stored = demo.chat.chat.get(message.message_id)
    assert stored.status == "applied" and stored.run_id == run.run_id
    kinds = _kinds(demo, inv)
    assert kinds[0] == ("analyst", "instruction")
    assert ("system", "notice") in kinds and kinds[-1] == ("verifier", "notice")
    redirects = [s for s in demo.agents.runs.steps(run.run_id) if s.kind == "redirect"]
    assert "-> log_investigator" in redirects[0].summary


def test_redirect_mid_run_changes_course_and_keeps_evidence(demo, holder, inv):
    before = _evidence_ids(demo, inv)
    process = demo.events.query(EventFilters(equals={"host": "WS-DAVE04"}))

    def analyst_redirects(_messages):
        demo.chat.redirect(inv, "Check 198.51.100.66 instead.", AgentRole.THREAT_INTEL)
        return call("get_event", event_id=process[0].event_id)

    model = _script(
        holder,
        route("log_investigator"),
        call("search_events", host="WS-DAVE04"),
        call(
            "add_evidence",
            category="observation",
            claim="Activity on WS-DAVE04.",
            event_ids=[process[0].event_id],
        ),
        analyst_redirects,
        call("lookup_local_ioc", indicator="198.51.100.66"),
        finish("checked"),
        route("verifier"),
        verdict(),
    )
    demo.agents.run_now(inv)
    (run,) = demo.agents.runs.for_investigation(inv)
    assert run.status is AgentRunStatus.COMPLETED
    steps = demo.agents.runs.steps(run.run_id)
    redirect = next(s for s in steps if s.kind == "redirect")
    assert redirect.summary.startswith("analyst redirect -> threat_intel")
    # The redirected turn is the threat intel analyst, with the analyst's words in its prompt.
    assert "threat intelligence analyst" in model.system_prompt(4)
    assert "Check 198.51.100.66 instead." in model.user_prompt(4)
    notes = run.checkpoint["notes"]
    assert (
        notes[0]["role"] == "log_investigator"
        and "redirected by the analyst" in notes[0]["summary"]
    )
    after = _evidence_ids(demo, inv)
    assert before < after  # prior evidence kept, the log investigator's finding kept
    assert any(e.source_type is EvidenceSource.AGENT for e in demo.investigations.evidence(inv))


def test_redirect_after_the_turn_limit_still_gets_a_turn(demo, holder, inv):
    demo.agents.settings = Settings(_env_file=None, agent_max_specialist_turns=1)

    def redirect_now(_messages):
        demo.chat.redirect(inv, "one more look at the process tree")
        return finish("first turn")

    _script(
        holder,
        route("log_investigator"),
        redirect_now,
        route("log_investigator", "process tree"),
        finish("process tree checked"),
        route("verifier"),
        verdict(),
    )
    run = demo.agents.run_now(inv)
    assert run.status is AgentRunStatus.COMPLETED
    assert [n["summary"] for n in run.checkpoint["notes"]] == [
        "first turn",
        "process tree checked",
    ]


# --- Control ------------------------------------------------------------------------------


def test_pause_and_resume_from_the_chat(demo, holder, inv):
    def pause(_messages):
        demo.chat.pause(inv)
        return call("build_timeline")

    _script(holder, route("log_investigator"), pause)
    run = demo.chat.start(inv)
    assert run.status is AgentRunStatus.PAUSED
    assert demo.chat.status(inv)[0] == "paused"
    with pytest.raises(InvestigationError, match="no running agent run to pause"):
        demo.chat.pause(inv)
    with pytest.raises(InvestigationError, match="already open"):
        demo.chat.start(inv)  # the paused run still holds the investigation

    _script(holder, finish("after pause"), route("verifier"), verdict())
    demo.chat.resume(inv)
    run = demo.agents.get(run.run_id)
    assert run.status is AgentRunStatus.COMPLETED and run.tool_calls == 1
    kinds = [k for _, k in _kinds(demo, inv)]
    assert kinds.count("pause") == 1 and kinds.count("resume") == 1
    assert demo.chat.status(inv)[0] == "completed"


def test_instruction_while_paused_resumes_with_it(demo, holder, inv):
    def pause(_messages):
        demo.chat.pause(inv)
        return route("log_investigator")

    _script(holder, pause)
    run = demo.chat.start(inv)
    assert run.status is AgentRunStatus.PAUSED
    model = _script(holder, finish("looked at threat intel"), route("verifier"), verdict())
    demo.chat.investigate(inv, "Look at the IOC hits", AgentRole.THREAT_INTEL)
    assert demo.agents.get(run.run_id).status is AgentRunStatus.COMPLETED
    assert "threat intelligence analyst" in model.system_prompt(0)
    assert len(demo.agents.runs.for_investigation(inv)) == 1  # same run, not a new one


def test_agent_question_waits_for_the_analyst_reply(demo, holder, inv):
    _script(
        holder,
        route("log_investigator"),
        call("request_analyst_input", question="Is dave travelling this week?"),
    )
    run = demo.chat.start(inv)
    assert run.status is AgentRunStatus.WAITING
    state, detail = demo.chat.status(inv)
    assert state == "waiting" and "Is dave travelling this week?" in detail
    last = demo.chat.messages(inv)[-1]
    assert last.kind is ChatKind.AGENT_QUESTION and last.author == "log_investigator"
    with pytest.raises(InvestigationError, match="waiting for your reply"):
        demo.chat.resume(inv)

    model = _script(holder, finish("no travel: suspicious"), route("verifier"), verdict())
    reply = demo.chat.investigate(inv, "No, he is in the office.")
    assert reply.kind is ChatKind.REPLY
    run = demo.agents.get(run.run_id)
    assert run.status is AgentRunStatus.COMPLETED
    assert run.checkpoint["notes"][0]["summary"] == "no travel: suspicious"  # same turn went on
    prompt = model.user_prompt(0)
    assert "No, he is in the office." in prompt and "in_reply_to" in prompt
    assert run.assessment.open_questions == ["Is dave travelling this week?"]


def test_stop_from_the_chat_is_final_and_frees_the_case(demo, holder, inv):
    def pause(_messages):
        demo.chat.pause(inv)
        return route("log_investigator")

    _script(holder, pause)
    run = demo.chat.start(inv)
    demo.chat.stop(inv)
    run = demo.agents.get(run.run_id)
    assert run.status is AgentRunStatus.STOPPED and run.error == "stopped by the analyst"
    with pytest.raises(InvestigationError, match="no agent run to stop"):
        demo.chat.stop(inv)
    _script(holder, route("verifier"), verdict())
    assert demo.chat.start(inv).status is AgentRunStatus.COMPLETED


def test_closing_the_case_stops_a_parked_run_and_drops_pending_instructions(demo, holder, inv):
    _script(holder, route("log_investigator"), call("request_analyst_input", question="?"))
    run = demo.chat.start(inv)
    assert run.status is AgentRunStatus.WAITING
    demo.chat.chat.add(
        inv, author="analyst", mode=ChatMode.CONTROL, kind=ChatKind.REDIRECT, content="later"
    )
    demo.investigations.close(inv, Disposition.INSUFFICIENT_DATA, Confidence.LOW, "n/a", [])
    run = demo.agents.get(run.run_id)
    assert run.status is AgentRunStatus.STOPPED and "closed" in run.error
    assert not demo.chat.pending(inv)
    assert demo.chat.messages(inv)[-2].status == "discarded"


def test_instruction_that_arrives_too_late_waits_for_the_next_run(demo, holder, inv):
    def late(_messages):
        demo.chat.investigate(inv, "also check the DNS traffic")
        return verdict()

    _script(holder, route("verifier"), late)
    run = demo.chat.start(inv)
    assert run.status is AgentRunStatus.COMPLETED
    (pending,) = demo.chat.pending(inv)
    assert pending.content == "also check the DNS traffic"

    model = _script(holder, route("log_investigator"), finish(), route("verifier"), verdict())
    demo.chat.start(inv)
    assert "also check the DNS traffic" in model.user_prompt(0)
    assert not demo.chat.pending(inv)


def test_only_specialists_can_be_chosen(demo, holder, inv):
    with pytest.raises(InvestigationError, match="choose a specialist"):
        demo.chat.investigate(inv, "x", AgentRole.ORCHESTRATOR)
    with pytest.raises(InvestigationError, match="ask the log investigator"):
        demo.chat.ask(inv, "x", AgentRole.ORCHESTRATOR)


def test_interrupted_run_resumes_from_the_chat(demo, holder, inv):
    run = demo.agents.create_run(inv)
    demo.agents.runs.claim(run.run_id)
    demo.agents.runs.mark_interrupted()
    assert demo.chat.status(inv)[0] == "interrupted"
    _script(holder, route("verifier"), verdict())
    demo.chat.resume(inv)
    assert demo.agents.get(run.run_id).status is AgentRunStatus.COMPLETED


def test_background_chat_run_and_restart_keeps_parked_runs(tmp_path, holder):
    settings = Settings(_env_file=None, database_path=tmp_path / "soc.db")
    ctx = build_context(settings, model_factory=lambda _s: holder.model)
    load_demo_iocs(ctx.iocs)
    ingest_demo(ctx.ingestion)
    alert = next(a for a in ctx.alerts.list() if a.rule_id == RULE)
    inv = ctx.investigations.start_from_alert(alert.alert_id).investigation_id
    _script(holder, route("log_investigator"), call("request_analyst_input", question="ok?"))
    run = ctx.chat.start(inv)
    ctx.agent_runner.join(run.run_id, timeout=30)
    assert ctx.agents.get(run.run_id).status is AgentRunStatus.WAITING

    again = build_context(settings, model_factory=lambda _s: holder.model)
    assert again.agents.get(run.run_id).status is AgentRunStatus.WAITING  # not "interrupted"
    _script(holder, finish("thanks"), route("verifier"), verdict())
    again.chat.investigate(inv, "yes")
    again.agent_runner.join(run.run_id, timeout=30)
    assert again.agents.get(run.run_id).status is AgentRunStatus.COMPLETED
