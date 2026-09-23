"""Opt-in command line for analysis and explicitly authorized prompt optimization."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Sequence

from pydantic import ValidationError

from app.evaluation.improvement.corpus import build_improvement_corpus
from app.evaluation.improvement.optimizer import run_improvement_optimization
from app.evaluation.system.schemas import SystemEvaluationReport
from app.llm.types import LLMProvider


def _has_private_holdout_path_component(path: Path) -> bool:
    return any("holdout" in part.casefold() or "private" in part.casefold() for part in path.parts)


def _validate_artifact_path(path: Path) -> Path:
    """Permit new JSON artifacts, but never overwrite or write into source/data."""
    candidate = path.expanduser()
    if candidate.suffix.casefold() != ".json":
        raise ValueError("Improvement Lab artifacts must use a new .json file path")
    resolved = candidate.resolve(strict=False)
    if _has_private_holdout_path_component(candidate) or _has_private_holdout_path_component(resolved):
        raise ValueError("private holdout paths are forbidden for Improvement Lab artifacts")
    if candidate.exists() or candidate.is_symlink():
        raise ValueError("refusing to overwrite an existing Improvement Lab artifact")
    repository_root = Path(__file__).resolve().parents[4]
    allowed_repository_artifacts = (repository_root / "backend" / "evaluation_artifacts" / "improvement_lab").resolve()
    try:
        inside_repository = resolved.is_relative_to(repository_root)
        inside_artifact_area = resolved.is_relative_to(allowed_repository_artifacts)
    except ValueError:
        inside_repository = False
        inside_artifact_area = False
    if inside_repository and not inside_artifact_area:
        raise ValueError("repository outputs are restricted to backend/evaluation_artifacts/improvement_lab")
    return resolved


def _load_report(path: Path) -> SystemEvaluationReport:
    resolved = path.expanduser().resolve(strict=False)
    if _has_private_holdout_path_component(path) or _has_private_holdout_path_component(resolved):
        raise ValueError("refusing to open a baseline report located under a private or holdout path")
    try:
        return SystemEvaluationReport.model_validate_json(resolved.read_text(encoding="utf-8"))
    except (OSError, ValidationError, ValueError) as exc:
        raise ValueError(f"invalid evaluation report '{path.name}': {type(exc).__name__}") from exc


def _write_json(payload: dict, path: Path | None) -> str:
    text = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if path is not None:
        safe_path = _validate_artifact_path(path)
        safe_path.parent.mkdir(parents=True, exist_ok=True)
        with safe_path.open("x", encoding="utf-8", newline="\n") as output:
            output.write(text)
    return text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Offline, prompt-only RepoLens Improvement Lab.")
    commands = parser.add_subparsers(dest="command", required=True)
    analyze = commands.add_parser("analyze", help="Build a sanitized corpus and deterministic target summary; no model calls.")
    analyze.add_argument("baseline", type=Path)
    analyze.add_argument("--output", type=Path)
    optimize = commands.add_parser("optimize", help="Propose and evaluate bounded prompt candidates against public DEV only.")
    optimize.add_argument("baseline", type=Path)
    optimize.add_argument("--allow-live-optimization", action="store_true", help="Explicitly authorize bounded model and evaluation calls.")
    optimize.add_argument("--generator-provider", choices=[item.value for item in LLMProvider])
    optimize.add_argument("--generator-model", help="Exact provider model for reflection and candidate generation.")
    optimize.add_argument("--output", type=Path, help="Run report path; candidate evaluation reports are written to a sibling artifacts directory.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "optimize" and args.allow_live_optimization and args.output is None:
            raise ValueError("live optimization requires --output so its complete audit bundle is persisted")
        if args.output is not None:
            _validate_artifact_path(args.output)
        baseline = _load_report(args.baseline)
        if args.command == "analyze":
            corpus = build_improvement_corpus(baseline)
            eligible = sorted({item.target_prompt_component for item in corpus.optimization_examples})
            payload = {
                "schema_version": "improvement-analysis/1.0",
                "baseline_report_digest": baseline.report_digest,
                "baseline_mode": baseline.mode.value,
                "corpus": corpus.model_dump(mode="json"),
                "deterministic_targets": eligible,
                "note": "Analysis is offline. A scripted baseline may describe harness behavior but is not eligible for semantic prompt optimization.",
            }
            print(_write_json(payload, args.output), end="")
            return 0
        if args.allow_live_optimization and (not args.generator_provider or not args.generator_model):
            raise ValueError("live optimization requires an exact --generator-provider and --generator-model")
        if not args.allow_live_optimization and (args.generator_provider or args.generator_model):
            raise ValueError("generator provider/model are accepted only with --allow-live-optimization")
        output = asyncio.run(run_improvement_optimization(
            baseline,
            allow_live_optimization=args.allow_live_optimization,
            generator_provider=args.generator_provider or LLMProvider.GEMINI,
            generator_model=args.generator_model or "not-used-without-live-permission",
        ))
        artifacts_dir: Path | None = None
        if args.output is not None:
            artifacts_dir = args.output.parent / f"{args.output.stem}.artifacts"
            for candidate in output.report.candidates:
                candidate_path = artifacts_dir / f"{candidate.candidate_id.replace(':', '-')}.json"
                _write_json(candidate.model_dump(mode="json"), candidate_path)
            for item in output.evaluation_artifacts:
                filename = f"{item.candidate_id.replace(':', '-')}.{item.stage.lower()}.evaluation.json"
                _write_json(item.report.model_dump(mode="json"), artifacts_dir / filename)
            if output.corpus is not None:
                _write_json(output.corpus.model_dump(mode="json"), artifacts_dir / "corpus.json")
            if output.reflection is not None:
                _write_json(output.reflection.model_dump(mode="json"), artifacts_dir / "reflection.json")
        print(_write_json(output.report.model_dump(mode="json"), args.output), end="")
        return 0 if output.report.termination_reason.value == "PROMOTION_CANDIDATE_FOUND" else 1
    except (ValueError, OSError) as exc:
        print(f"improvement lab failed: {exc}", file=sys.stderr)
        return 2


__all__ = ["build_parser", "main"]
