"""Command-line entry point for the RepoLens Evidence Investigator evaluator."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Sequence

from app.evaluation.agent.grading import compute_metrics, grade_trial
from app.evaluation.agent.gate import assert_report_passes_gate, load_gate
from app.evaluation.agent.loader import DEFAULT_DATASET_ROOT, load_agent_dataset
from app.evaluation.agent.report import AgentEvalReportMode, report_for_dataset
from app.evaluation.agent.runner import run_scripted_trial
from app.evaluation.agent.runner import run_live_trial
from app.evaluation.agent.schemas import AgentEvalMode, AgentEvalSplit
from app.core.config import get_settings


async def _run_scripted(dataset, *, split: str | None, case_ids: set[str] | None):
    cases = [
        case for case in dataset.cases
        if (split is None or case.split.value == split)
        and (case_ids is None or case.case_id in case_ids)
    ]
    trials = []
    grades = []
    for case in cases:
        trial = await run_scripted_trial(case, interrupt_after_tool=case.annotation.durability_case)
        trials.append(trial)
        grades.append(grade_trial(case, trial))
    return report_for_dataset(
        dataset,
        mode=AgentEvalReportMode.SCRIPTED,
        grades=grades,
        metrics=compute_metrics(grades, trials),
        live_status="NOT_EXECUTED",
    )


async def _run_live(dataset, *, trial_count: int):
    cases = list(dataset.cases)[:max(1, min(trial_count, 3))]
    trials = [await run_live_trial(case) for case in cases]
    grades = [grade_trial(case, trial) for case, trial in zip(cases, trials)]
    used = any(trial.live_provider_used for trial in trials)
    failures = [trial.error for trial in trials if trial.error]
    status = "LIVE EXECUTED" if used else "LIVE CAPABILITY EVALUATION: NOT EXECUTED"
    if failures and used:
        status = "LIVE EXECUTED WITH PROVIDER FAILURES"
    return report_for_dataset(
        dataset,
        mode=AgentEvalReportMode.LIVE,
        grades=grades if used else [],
        metrics=compute_metrics(grades if used else [], trials if used else []),
        live_status=status,
        model_capability_measured=used,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run RepoLens Evidence Investigator evaluation.")
    parser.add_argument("--mode", choices=[item.value.lower() for item in AgentEvalMode], default="scripted")
    parser.add_argument("--dataset-root", type=Path, default=DEFAULT_DATASET_ROOT)
    parser.add_argument("--split", choices=[item.value for item in AgentEvalSplit])
    parser.add_argument("--case-id", action="append", dest="case_ids")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--regression-gate", type=Path)
    parser.add_argument("--allow-live", action="store_true", help="Permit real provider calls; never used by default CI.")
    parser.add_argument("--live-trials", type=int, default=3)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    dataset = load_agent_dataset(args.dataset_root)
    if args.mode == "live":
        settings = get_settings()
        provider_configured = any((
            settings.GEMINI_API_KEY,
            settings.GROQ_API_KEY,
            settings.NVIDIA_API_KEY,
            settings.HUGGINGFACE_API_KEY,
            settings.MISTRAL_API_KEY,
            settings.OPENROUTER_API_KEY,
            settings.LOCAL_LLM_ENABLED,
        ))
        if not args.allow_live or not provider_configured:
            report = report_for_dataset(
                dataset,
                mode=AgentEvalReportMode.LIVE,
                grades=[],
                metrics=compute_metrics([], []),
                live_status="LIVE CAPABILITY EVALUATION: NOT EXECUTED",
            )
        else:
            report = asyncio.run(_run_live(dataset, trial_count=args.live_trials))
    else:
        report = asyncio.run(_run_scripted(dataset, split=args.split, case_ids=set(args.case_ids) if args.case_ids else None))
    payload = report.model_dump(mode="json")
    serialized = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized, encoding="utf-8")
    print(serialized, end="")
    if args.regression_gate and args.mode == "scripted":
        try:
            assert_report_passes_gate(report, load_gate(args.regression_gate))
        except Exception as exc:
            print(f"REGRESSION GATE FAILED: {exc}")
            return 1
    return 0 if all(item.passed for item in report.grades) else 1


__all__ = ["build_parser", "main"]
