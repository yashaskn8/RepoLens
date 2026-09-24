"""Command-line entry point for the RepoLens adversarial agent-security harness."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Sequence

from app.evaluation.security.contracts import AgentSecurityMode
from app.evaluation.security.runner import run_agent_security_evaluation
from app.llm.types import LLMProvider


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run RepoLens public DEV agent-security evaluation.")
    parser.add_argument("--mode", choices=[item.value.lower() for item in AgentSecurityMode], default="scripted")
    parser.add_argument("--case-id", action="append", dest="case_ids")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--provider", choices=[item.value for item in LLMProvider])
    parser.add_argument("--model", help="Exact provider/model identity for live trials.")
    parser.add_argument("--trials", type=int)
    parser.add_argument("--allow-live", action="store_true", help="Permit real model-provider calls.")
    parser.add_argument(
        "--allow-adversarial-security-eval",
        action="store_true",
        help="Additional explicit authorization for adversarial live evaluation.",
    )
    parser.add_argument("--output", type=Path, help="Optional path for a content-minimized JSON report.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    mode = AgentSecurityMode(args.mode.upper())
    try:
        report = asyncio.run(run_agent_security_evaluation(
            mode=mode,
            provider=args.provider,
            model=args.model,
            case_ids=args.case_ids,
            trials_per_case=args.trials,
            mutation_seed=args.seed,
            allow_live=args.allow_live,
            allow_adversarial_security_eval=args.allow_adversarial_security_eval,
        ))
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"agent security evaluation failed ({type(exc).__name__}): {str(exc)[:240]}")
        return 2
    serialized = json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized, encoding="utf-8")
    print(serialized, end="")
    return 0 if report.gate.value == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["build_parser", "main"]
