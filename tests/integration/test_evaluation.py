from __future__ import annotations

import importlib.util
import json
import re

import pytest
from fixtures.agents import ScriptedModel, route

from app.config import PROJECT_ROOT
from app.domain.enums import Disposition
from app.evaluation.runner import (
    EVAL_DIR,
    grade,
    load_scenarios,
    run_scenario,
    summarize,
    to_json,
    to_markdown,
)

SCENARIOS = load_scenarios()
EVIDENCE = re.compile(r"ev-[0-9a-f]{16}")


def test_eval_set_is_current():
    """The checked-in scenarios are exactly what the generator writes."""
    spec = importlib.util.spec_from_file_location(
        "make_eval_set", PROJECT_ROOT / "scripts" / "make_eval_set.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for scenario in module.SCENARIOS:
        expected = "".join(json.dumps(r, sort_keys=True) + "\n" for r in scenario["build"]())
        path = EVAL_DIR / "scenarios" / f"{scenario['id']}.jsonl"
        assert path.read_text(encoding="utf-8") == expected, scenario["id"]
    assert [s["id"] for s in SCENARIOS] == [s["id"] for s in module.SCENARIOS]


def test_the_set_is_balanced():
    truths = [s["truth"] for s in SCENARIOS]
    assert 5 <= len(SCENARIOS) <= 10
    assert set(truths) == {"malicious", "benign", "undetermined"}
    assert truths.count("benign") >= 2  # false positives are what an analyst copilot must handle


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s["id"] for s in SCENARIOS])
def test_detection_matches_ground_truth(scenario, settings):
    result = run_scenario(scenario, settings, with_agents=False)
    assert result.detection_ok, (result.expected_alerts, result.found_alerts)
    assert result.grade is None


@pytest.mark.parametrize(
    ("truth", "disposition", "expected"),
    [
        ("malicious", Disposition.LIKELY_MALICIOUS, "correct"),
        ("malicious", Disposition.SUSPICIOUS_INCONCLUSIVE, "cautious"),
        ("malicious", Disposition.BENIGN_OR_EXPECTED, "wrong"),
        ("benign", Disposition.BENIGN_OR_EXPECTED, "correct"),
        ("benign", Disposition.INSUFFICIENT_DATA, "cautious"),
        ("benign", Disposition.CONFIRMED_MALICIOUS, "wrong"),
        ("undetermined", Disposition.SUSPICIOUS_INCONCLUSIVE, "correct"),
        ("undetermined", Disposition.LIKELY_MALICIOUS, "wrong"),
        ("undetermined", Disposition.BENIGN_OR_EXPECTED, "wrong"),
        ("malicious", None, "no verdict"),
    ],
)
def test_grading(truth, disposition, expected):
    assert grade(truth, disposition) == expected


def _always_malicious(_settings):
    """A model that skips straight to the verifier and calls everything likely malicious,
    citing the first evidence ID it is shown (the alert's own observation)."""

    def verdict(messages):
        evidence = EVIDENCE.findall(messages[-1].content)[:1]
        return {
            "disposition": "likely_malicious",
            "confidence": "medium",
            "rationale": "everything looks bad",
            "supporting_evidence_ids": evidence,
            "contradicting_evidence_ids": [],
            "gaps": [],
            "unsupported_claims": [],
        }

    return ScriptedModel([route("verifier"), verdict])


def test_runner_grades_a_biased_model_and_reports_it(settings):
    results = [run_scenario(s, settings, model_factory=_always_malicious) for s in SCENARIOS]
    by_truth = {}
    for r in results:
        assert r.run_status == "completed" and r.disposition == "likely_malicious"
        by_truth.setdefault(r.truth, set()).add(r.grade)
    assert by_truth == {"malicious": {"correct"}, "benign": {"wrong"}, "undetermined": {"wrong"}}
    summary = summarize(results)
    assert summary["false_accusations"] == 2 and summary["overconfident"] == 2
    assert summary["missed_attacks"] == 0 and summary["agreement"] == round(3 / 7, 2)
    markdown = to_markdown(results, summary, {"model": "scripted", "started": "now"})
    assert "2 false accusation(s)" in markdown and "Detection as expected: 7 of 7" in markdown
    assert json.loads(to_json(results, summary, {}))["summary"]["graded"] == 7


def test_a_failed_run_has_no_verdict(settings):
    from app.agents.llm import ModelUnavailableError

    def down(_settings):
        return ScriptedModel([ModelUnavailableError("connection refused")])

    result = run_scenario(SCENARIOS[0], settings, model_factory=down)
    assert result.grade == "no verdict" and result.run_status == "failed"
    assert result.error and "AI unavailable" in result.error
