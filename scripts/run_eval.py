"""Run the evaluation set (data/eval) against the local model and write a report.

    python scripts/run_eval.py                      # detection + agents, every scenario
    python scripts/run_eval.py --detection-only     # no model needed (seconds)
    python scripts/run_eval.py --only s2_mistyped_password s5_lone_ioc_hit

Writes data/eval/results/<UTC time>.md and .json (git-ignored). Needs Ollama running with the
configured model unless --detection-only. Each scenario uses a throw-away in-memory database;
external reputation lookups stay off.
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import get_settings
from app.evaluation.runner import EVAL_DIR, load_scenarios, run_scenario, summarize
from app.evaluation.runner import to_json as results_json
from app.evaluation.runner import to_markdown as results_markdown
from app.ollama_health import ollama_status


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").strip().splitlines()[0])
    parser.add_argument("--detection-only", action="store_true")
    parser.add_argument("--only", nargs="*", help="scenario IDs to run")
    args = parser.parse_args()

    settings = get_settings()
    scenarios = load_scenarios()
    if args.only:
        unknown = set(args.only) - {s["id"] for s in scenarios}
        if unknown:
            print(f"unknown scenario(s): {', '.join(sorted(unknown))}")
            return 2
        scenarios = [s for s in scenarios if s["id"] in args.only]
    with_agents = not args.detection_only
    if with_agents:
        status, _ = ollama_status(settings.ollama_base_url, settings.ollama_model)
        if status != "reachable_model_present":
            print(f"Ollama not ready ({status}); start it, or use --detection-only.")
            return 2

    started = datetime.now(UTC)
    meta = {
        "started": started.strftime("%Y-%m-%d %H:%M UTC"),
        "model": settings.ollama_model if with_agents else "(detection only)",
        "context_tokens": settings.agent_context_tokens,
    }
    results = []
    for number, scenario in enumerate(scenarios, 1):
        print(f"[{number}/{len(scenarios)}] {scenario['id']} ...", flush=True)
        result = run_scenario(scenario, settings, with_agents=with_agents)
        results.append(result)
        verdict = f"{result.disposition} ({result.confidence})" if result.disposition else "-"
        print(
            f"    detection {'ok' if result.detection_ok else 'MISMATCH'}; truth {result.truth}; "
            f"verdict {verdict}; grade {result.grade or '-'}; "
            f"{result.seconds or 0:.0f} s; {result.error or ''}",
            flush=True,
        )
    summary = summarize(results)
    out = EVAL_DIR / "results"
    out.mkdir(parents=True, exist_ok=True)
    stem = started.strftime("%Y%m%dT%H%M%SZ") + ("-detection" if not with_agents else "")
    markdown = results_markdown(results, summary, meta)
    (out / f"{stem}.md").write_text(markdown, encoding="utf-8")
    (out / f"{stem}.json").write_text(results_json(results, summary, meta), encoding="utf-8")
    print()
    print(markdown)
    print(f"Saved to {out / stem}.md and .json")
    return 0 if summary["detection_ok"] == summary["scenarios"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
