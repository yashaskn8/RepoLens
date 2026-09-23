"""Opt-in CLI for candidate trials, paired comparisons and promotion checks."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Sequence

from pydantic import ValidationError

from app.evaluation.agent.loader import DEFAULT_DATASET_ROOT, load_agent_dataset
from app.evaluation.system.comparison import compare_system_reports, promote_check
from app.evaluation.system.full_analysis import run_full_analysis_evaluation
from app.evaluation.system.runner import DEVELOPMENT_TRIALS_PER_CASE, run_system_evaluation
from app.evaluation.system.schemas import (
    SystemEvalMode,
    SystemEvalSuite,
    SystemEvaluationReport,
)
from app.llm.types import LLMProvider


def _read_report(path: Path) -> SystemEvaluationReport:
    try:
        return SystemEvaluationReport.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError, ValueError) as exc:
        raise ValueError(f"invalid system evaluation report '{path.name}': {type(exc).__name__}") from exc


def _write_payload(payload: dict, path: Path | None) -> str:
    serialized = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(serialized, encoding="utf-8")
    return serialized


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run bounded RepoLens system evaluations and promotion checks.")
    commands = parser.add_subparsers(dest="command", required=True)

    run = commands.add_parser("run", help="Run repeated isolated investigator trials.")
    run.add_argument(
        "--scope",
        choices=("investigator", "full-analysis"),
        default="investigator",
        help="Evaluate the Phase-1 investigator graph or the production full analysis graph.",
    )
    run.add_argument("--mode", choices=[item.value.lower() for item in SystemEvalMode], default="scripted")
    run.add_argument("--dataset-root", type=Path, default=DEFAULT_DATASET_ROOT)
    run.add_argument("--suite", choices=[item.value for item in SystemEvalSuite], default="ALL")
    run.add_argument("--provider", choices=[item.value for item in LLMProvider])
    run.add_argument("--model", help="Exact candidate model ID; required for live runs.")
    run.add_argument("--allow-live", action="store_true", help="Explicitly allow provider calls.")
    run.add_argument("--trials", type=int, default=DEVELOPMENT_TRIALS_PER_CASE)
    run.add_argument("--max-cases", type=int, default=3)
    run.add_argument("--case-id", action="append", dest="case_ids")
    run.add_argument(
        "--counterfactual-replay",
        action="store_true",
        help="Opt in to bounded evaluator-only corrective replay (DEV full-analysis scope only).",
    )
    run.add_argument("--output", type=Path)

    compare = commands.add_parser("compare", help="Compare two completed, compatible live reports.")
    compare.add_argument("baseline", type=Path)
    compare.add_argument("candidate", type=Path)
    compare.add_argument("--output", type=Path)

    promote = commands.add_parser("promote-check", help="Apply the non-mutating human promotion gate.")
    promote.add_argument("baseline", type=Path)
    promote.add_argument("candidate", type=Path)
    promote.add_argument("--minimum-trials", type=int, default=5)
    promote.add_argument("--output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "run":
            mode = SystemEvalMode(args.mode.upper())
            if mode == SystemEvalMode.LIVE and not args.allow_live:
                raise ValueError("live runs require the explicit --allow-live flag")
            if mode == SystemEvalMode.LIVE and (not args.provider or not args.model):
                raise ValueError("live runs require an exact --provider and --model")
            if mode == SystemEvalMode.SCRIPTED and (args.provider or args.model or args.allow_live):
                raise ValueError("scripted runs do not accept provider, model, or --allow-live options")
            if args.counterfactual_replay and args.scope != "full-analysis":
                raise ValueError("--counterfactual-replay requires --scope full-analysis")
            if args.scope == "full-analysis":
                if args.dataset_root != DEFAULT_DATASET_ROOT:
                    raise ValueError("--dataset-root applies only to investigator scope")
                if mode == SystemEvalMode.LIVE:
                    planned_cases = min(args.max_cases, 64)
                    print(
                        f"Full-analysis live plan: at most {planned_cases} case(s) × {args.trials} fresh trial(s); "
                        "one-at-a-time, per-workflow cloud budgets enabled.",
                        file=sys.stderr,
                    )
                report = asyncio.run(run_full_analysis_evaluation(
                    suite=SystemEvalSuite(args.suite),
                    mode=mode,
                    provider=args.provider,
                    model=args.model,
                    trials_per_case=args.trials,
                    max_cases=args.max_cases,
                    case_ids=args.case_ids,
                    allow_live=args.allow_live,
                    counterfactual_replay=args.counterfactual_replay,
                ))
            else:
                dataset = load_agent_dataset(args.dataset_root)
                report = asyncio.run(run_system_evaluation(
                    dataset=dataset,
                    suite=SystemEvalSuite(args.suite),
                    mode=mode,
                    provider=args.provider,
                    model=args.model,
                    trials_per_case=args.trials,
                    max_cases=args.max_cases,
                    case_ids=args.case_ids,
                    allow_live=args.allow_live,
                ))
            serialized = _write_payload(report.model_dump(mode="json"), args.output)
            print(serialized, end="")
            return 0 if report.execution_status.value == "COMPLETED" and report.metrics.failed_trials == 0 else 1

        baseline = _read_report(args.baseline)
        candidate = _read_report(args.candidate)
        if args.command == "compare":
            comparison = compare_system_reports(baseline, candidate)
            print(_write_payload(comparison.model_dump(mode="json"), args.output), end="")
            return 0 if comparison.valid else 2
        if not 1 <= args.minimum_trials <= 5:
            raise ValueError("--minimum-trials must be between 1 and 5")
        decision = promote_check(
            baseline,
            candidate,
            minimum_trials_per_case=args.minimum_trials,
        )
        print(_write_payload(decision.model_dump(mode="json"), args.output), end="")
        return 0 if decision.eligible_for_human_review else 1
    except (ValueError, OSError) as exc:
        print(f"system evaluation failed: {exc}")
        return 2


__all__ = ["build_parser", "main"]
