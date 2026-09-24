"""Manual CLI for bounded context/tool experiments."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from app.evaluation.context_tool.runner import run_context_tool_experiment
from app.evaluation.system.schemas import SystemEvalMode
from app.llm.types import LLMProvider


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run RepoLens context/tool ablation experiments.")
    parser.add_argument("--mode", choices=[item.value.lower() for item in SystemEvalMode], default="scripted")
    parser.add_argument("--provider", choices=[item.value for item in LLMProvider])
    parser.add_argument("--model")
    parser.add_argument("--case-id", action="append", dest="case_ids")
    parser.add_argument("--max-cases", type=int, default=4)
    parser.add_argument("--trials", type=int)
    parser.add_argument("--candidate-limit", type=int, default=4)
    parser.add_argument("--allow-live", action="store_true", help="Explicit permission for live provider calls.")
    parser.add_argument(
        "--allow-context-tool-experiments",
        action="store_true",
        help="Separate opt-in required in addition to --allow-live.",
    )
    parser.add_argument("--output", type=Path, help="Write content-minimized JSON report to this path.")
    return parser


async def _run(args: argparse.Namespace) -> int:
    report = await run_context_tool_experiment(
        mode=SystemEvalMode(args.mode.upper()),
        provider=args.provider,
        model=args.model,
        case_ids=args.case_ids,
        max_cases=args.max_cases,
        trials_per_case=args.trials,
        candidate_limit=args.candidate_limit,
        allow_live=args.allow_live,
        allow_context_tool_experiments=args.allow_context_tool_experiments,
    )
    rendered = report.model_dump_json(indent=2)
    if args.output:
        destination = args.output.resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            raise FileExistsError("refusing to overwrite an existing context/tool experiment artifact")
        destination.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0 if report.termination_reason == "COMPLETED" else 2


def main() -> int:
    args = build_parser().parse_args()
    try:
        return asyncio.run(_run(args))
    except (ValueError, RuntimeError, TimeoutError, FileExistsError) as exc:
        print(f"context/tool experiment refused or incomplete: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
