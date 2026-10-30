from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.domain.enums import (
    Disposition,
    EvidenceCategory,
    EvidenceSource,
    ResponseAction,
    RiskLevel,
)
from app.domain.models import Evidence
from app.policy.rules import CATALOGUE, NO_TARGET, PolicyContext, evaluate, simulate

SCOPE = {
    "ip": {"203.0.113.45", "10.20.1.44", "8.8.8.8"},
    "host": {"WS-DAVE04"},
    "user": {"dave"},
}


def _evidence(evidence_id: str, category: EvidenceCategory) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        investigation_id="inv-1",
        category=category,
        source_type=EvidenceSource.EVENT,
        source_ref="x",
        claim="c",
        collected_at=datetime(2026, 1, 1, tzinfo=UTC),
        collected_by="system",
    )


EVIDENCE = {
    "ev-obs": _evidence("ev-obs", EvidenceCategory.OBSERVATION),
    "ev-inf": _evidence("ev-inf", EvidenceCategory.INFERENCE),
}


def _ctx(assessment: Disposition | None = None, by_agent: bool = True) -> PolicyContext:
    return PolicyContext(scope=SCOPE, evidence=EVIDENCE, assessment=assessment, by_agent=by_agent)


def test_every_action_is_catalogued_and_low_risk_needs_no_approval():
    assert set(CATALOGUE) == set(ResponseAction)
    for spec in CATALOGUE.values():
        assert spec.requires_approval is (spec.risk is not RiskLevel.LOW)


def test_high_impact_agent_action_needs_a_malicious_assessment():
    blocked = evaluate(
        ResponseAction.ISOLATE_HOST,
        "WS-DAVE04",
        ["ev-obs"],
        _ctx(Disposition.SUSPICIOUS_INCONCLUSIVE),
    )
    assert not blocked.allowed and "likely_malicious" in blocked.notes[0]
    allowed = evaluate(
        ResponseAction.ISOLATE_HOST, "WS-DAVE04", ["ev-obs"], _ctx(Disposition.LIKELY_MALICIOUS)
    )
    assert allowed.allowed and "needs analyst approval" in allowed.notes[0]


def test_medium_impact_agent_action_needs_at_least_suspicious():
    benign = evaluate(
        ResponseAction.RESET_CREDENTIALS, "dave", ["ev-obs"], _ctx(Disposition.BENIGN_OR_EXPECTED)
    )
    assert not benign.allowed
    suspicious = evaluate(
        ResponseAction.RESET_CREDENTIALS,
        "dave",
        ["ev-obs"],
        _ctx(Disposition.SUSPICIOUS_INCONCLUSIVE),
    )
    assert suspicious.allowed
    assert any("Not reversible" in n for n in suspicious.notes)


def test_low_impact_actions_are_allowed_whatever_the_assessment():
    for action, target in (
        (ResponseAction.COLLECT_TRIAGE, "WS-DAVE04"),
        (ResponseAction.WATCHLIST, "203.0.113.45"),
        (ResponseAction.ESCALATE, ""),
    ):
        decision = evaluate(action, target, ["ev-inf"], _ctx(Disposition.BENIGN_OR_EXPECTED))
        assert decision.allowed, (action, decision.notes)
    assert evaluate(ResponseAction.ESCALATE, "anything", ["ev-inf"], _ctx()).target == NO_TARGET


@pytest.mark.parametrize(
    ("action", "target", "reason"),
    [
        (ResponseAction.ISOLATE_HOST, "DC01", "not a host seen"),  # not in the events
        (ResponseAction.DISABLE_ACCOUNT, "Administrator", "not a user seen"),
        (ResponseAction.BLOCK_IP, "198.51.100.7", "not an IP seen"),  # valid but not in scope
        (ResponseAction.BLOCK_IP, "10.20.1.44", "private address"),  # internal: isolate instead
        (ResponseAction.BLOCK_IP, "127.0.0.1", "loopback address"),
        (ResponseAction.BLOCK_IP, "not-an-ip", "not an IP address"),
        (ResponseAction.WATCHLIST, "evil.example", "not an IP, host or user"),
        (ResponseAction.ISOLATE_HOST, "WS-DAVE04\nrm -rf", "needs a host"),
    ],
)
def test_targets_must_come_from_the_investigation(action, target, reason):
    decision = evaluate(action, target, ["ev-obs"], _ctx(Disposition.CONFIRMED_MALICIOUS))
    assert not decision.allowed
    assert any(reason in note for note in decision.notes), decision.notes


def test_targets_match_case_insensitively_and_ips_are_normalised():
    decision = evaluate(
        ResponseAction.COLLECT_TRIAGE, "ws-dave04", ["ev-obs"], _ctx(Disposition.BENIGN_OR_EXPECTED)
    )
    assert decision.allowed and decision.target == "WS-DAVE04"
    public = evaluate(
        ResponseAction.BLOCK_IP, " 8.8.8.8 ", ["ev-obs"], _ctx(Disposition.LIKELY_MALICIOUS)
    )
    assert public.allowed and public.target == "8.8.8.8"


def test_evidence_is_required_and_must_exist():
    none = evaluate(ResponseAction.WATCHLIST, "dave", [], _ctx())
    assert not none.allowed and "cite the evidence" in none.notes[0]
    unknown = evaluate(ResponseAction.WATCHLIST, "dave", ["ev-made-up"], _ctx())
    assert not unknown.allowed and "ev-made-up" in unknown.notes[0]


def test_analyst_proposals_skip_the_assessment_but_need_an_observation():
    no_obs = evaluate(ResponseAction.DISABLE_ACCOUNT, "dave", ["ev-inf"], _ctx(by_agent=False))
    assert not no_obs.allowed and "observation" in no_obs.notes[0]
    with_obs = evaluate(ResponseAction.DISABLE_ACCOUNT, "dave", ["ev-obs"], _ctx(by_agent=False))
    assert with_obs.allowed


def test_simulation_never_executes():
    result = simulate(ResponseAction.BLOCK_IP, "203.0.113.45")
    assert result["executed"] is False and result["mode"] == "simulation"
    assert "203.0.113.45" in result["would"]
