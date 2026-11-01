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
    ScenarioResult,
    grade,
    load_scenarios,
    majority,
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
    generated = module.SCENARIOS + module.HOLDOUT
    for scenario in generated:
        expected = "".join(json.dumps(r, sort_keys=True) + "\n" for r in scenario["build"]())
        path = EVAL_DIR / "scenarios" / f"{scenario['id']}.jsonl"
        assert path.read_text(encoding="utf-8") == expected, scenario["id"]
    assert [s["id"] for s in SCENARIOS] == [s["id"] for s in generated]


@pytest.mark.parametrize("name", ["tuning", "holdout"])
def test_each_set_is_balanced(name):
    truths = [s["truth"] for s in SCENARIOS if s["set"] == name]
    assert 5 <= len(truths) <= 10
    assert set(truths) == {"malicious", "benign", "undetermined"}
    assert truths.count("benign") >= 2  # false positives are what an analyst copilot must handle


def test_holdout_scenarios_are_new():
    """Held-out scenarios share no external address with the tuning set."""

    def addresses(name):
        found = set()
        for s in SCENARIOS:
            if s["set"] == name:
                text = (EVAL_DIR / s["file"]).read_text(encoding="utf-8")
                found |= set(re.findall(r"(?:198\.51\.100|203\.0\.113|192\.0\.2)\.\d+", text))
        return found

    assert addresses("tuning").isdisjoint(addresses("holdout"))


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
    tuning = [s for s in SCENARIOS if s["set"] == "tuning"]
    results = [run_scenario(s, settings, model_factory=_always_malicious) for s in tuning]
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


def _run(grade_: str | None, disposition: str | None, seconds: float) -> ScenarioResult:
    return ScenarioResult(
        id="x",
        title="x",
        truth="malicious",
        expected_alerts={},
        found_alerts={},
        detection_ok=True,
        disposition=disposition,
        grade=grade_,
        seconds=seconds,
    )


def test_majority_takes_the_most_common_grade():
    runs = [
        _run("correct", "likely_malicious", 60),
        _run("cautious", "suspicious_inconclusive", 90),
        _run("correct", "confirmed_malicious", 70),
    ]
    combined = majority(runs)
    assert combined.grade == "correct" and combined.disposition == "likely_malicious"
    assert combined.run_grades == ["correct", "cautious", "correct"]
    assert combined.run_dispositions == [
        "likely_malicious",
        "suspicious_inconclusive",
        "confirmed_malicious",
    ]
    assert combined.seconds == 70


def test_a_tie_counts_as_the_worse_grade():
    runs = [_run("correct", "likely_malicious", 1), _run("wrong", "benign_or_expected", 1)]
    assert majority(runs).grade == "wrong"
    runs = [_run("cautious", "insufficient_data", 1), _run(None, None, 1)]
    assert majority(runs).grade == "cautious"  # a run that was never graded does not vote


def test_summary_reports_unstable_scenarios():
    stable = majority([_run("correct", "likely_malicious", 1)] * 3)
    shaky = majority(
        [
            _run("correct", "likely_malicious", 1),
            _run("wrong", "benign_or_expected", 1),
            _run("correct", "likely_malicious", 1),
        ]
    )
    summary = summarize([stable, shaky])
    assert summary["runs_per_scenario"] == 3
    assert summary["unstable"] == 1 and summary["wrong_in_some_run"] == 1
    assert summary["grades"]["correct"] == 2
    markdown = to_markdown([stable, shaky], summary, {})
    assert "3 runs per scenario" in markdown and "correct, wrong, correct" in markdown
