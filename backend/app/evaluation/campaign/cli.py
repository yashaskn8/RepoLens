"""Explicit CLI for readiness, planning, staged live evaluation, and analysis."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Sequence

from app.evaluation.campaign.contracts import CampaignStage, SupplementalGateKind
from app.evaluation.campaign.plan import create_campaign_plan
from app.evaluation.campaign.preflight import run_campaign_preflight
from app.evaluation.campaign.runner import (
    _safe_campaign_directory,
    load_plan,
    load_stage_report,
    run_live_stage,
    save_plan,
)
from app.llm.types import LLMProvider


def _parse_arm(value: str) -> tuple[str, LLMProvider, str]:
    candidate_id, separator, endpoint = value.partition("=")
    provider_text, model_separator, model = endpoint.partition(":")
    if not separator or not candidate_id or not model_separator or not model:
        raise argparse.ArgumentTypeError("arm must be candidate-id=provider:exact-model")
    try:
        provider = LLMProvider(provider_text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("arm provider is not a supported RepoLens provider") from exc
    return candidate_id, provider, model


def _parse_candidates(values: list[str] | None) -> list[tuple[str, LLMProvider, str]]:
    try:
        return [_parse_arm(item) for item in values or []]
    except argparse.ArgumentTypeError as exc:
        raise ValueError(str(exc)) from exc


def _json(payload: object) -> str:
    if hasattr(payload, "model_dump"):
        payload = payload.model_dump(mode="json")
    return json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def _write_immutable(path: Path, payload: object) -> None:
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError("campaign artifact paths cannot contain symlinks")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        raise ValueError("campaign artifact already exists; refusing to overwrite immutable evidence")
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(_json(payload))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run an explicit, staged RepoLens full-workflow model evaluation campaign."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    preflight = commands.add_parser("preflight", help="Check registered model readiness without provider calls.")
    preflight.add_argument("--arm", action="append", required=True, metavar="ID=PROVIDER:MODEL")

    plan = commands.add_parser("plan", help="Freeze the exact model/system/public-DEV identities; no model calls.")
    plan.add_argument("--arm", action="append", required=True, metavar="ID=PROVIDER:MODEL")
    plan.add_argument("--baseline", required=True, help="Candidate ID used as the paired baseline.")
    plan.add_argument("--seed", type=int, default=0)

    stage = commands.add_parser("stage", help="Execute one explicitly opted-in live stage.")
    stage.add_argument("campaign_id")
    stage.add_argument("stage", choices=("smoke", "pilot", "full"))
    stage.add_argument("--candidate-id", action="append", dest="candidate_ids")
    stage.add_argument("--allow-live", action="store_true")
    stage.add_argument("--allow-model-campaign", action="store_true")
    stage.add_argument("--allow-full-campaign", action="store_true")

    security = commands.add_parser("security-gate", help="Run the independently opted-in live agent-security gate.")
    security.add_argument("campaign_id")
    security.add_argument("--allow-live", action="store_true")
    security.add_argument("--allow-model-campaign", action="store_true")
    security.add_argument("--allow-adversarial-security-eval", action="store_true")

    context = commands.add_parser("context-gate", help="Run the independently opted-in live context/tool gate.")
    context.add_argument("campaign_id")
    context.add_argument("--allow-live", action="store_true")
    context.add_argument("--allow-model-campaign", action="store_true")
    context.add_argument("--allow-context-tool-experiments", action="store_true")

    analyze = commands.add_parser("analyze", help="Build deterministic paired analysis from completed campaign artifacts.")
    analyze.add_argument("campaign_id")
    return parser


def _load_supplemental_if_present(campaign_id: str, kind: SupplementalGateKind):
    from app.evaluation.campaign.runner import _safe_campaign_directory
    from app.evaluation.campaign.supplemental import load_gate_report

    name = "security-gate.json" if kind == SupplementalGateKind.SECURITY else "context-tool-gate.json"
    if (_safe_campaign_directory(campaign_id) / name).exists():
        return load_gate_report(campaign_id, kind)
    return None


async def _run(args: argparse.Namespace) -> object:
    if args.command == "preflight":
        return run_campaign_preflight(_parse_candidates(args.arm))

    if args.command == "plan":
        plan = await create_campaign_plan(
            _parse_candidates(args.arm),
            baseline_candidate_id=args.baseline,
            schedule_seed=args.seed,
        )
        save_plan(plan)
        return {"plan": plan.model_dump(mode="json"), "artifact": "backend/evaluation_artifacts/model_campaigns/<campaign_id>/plan.json"}

    if args.command == "stage":
        plan = load_plan(args.campaign_id)
        stage = {
            "smoke": CampaignStage.LIVE_SMOKE,
            "pilot": CampaignStage.LIVE_PILOT,
            "full": CampaignStage.LIVE_FULL,
        }[args.stage]
        prior_stage = {
            CampaignStage.LIVE_PILOT: CampaignStage.LIVE_SMOKE,
            CampaignStage.LIVE_FULL: CampaignStage.LIVE_PILOT,
        }.get(stage)
        prior = load_stage_report(args.campaign_id, prior_stage) if prior_stage is not None else None
        report = await run_live_stage(
            plan,
            stage,
            allow_live=args.allow_live,
            allow_model_campaign=args.allow_model_campaign,
            allow_full_campaign=args.allow_full_campaign,
            prior_report=prior,
            candidate_ids=args.candidate_ids,
        )
        return report

    if args.command in {"security-gate", "context-gate"}:
        from app.evaluation.campaign.supplemental import run_supplemental_gate

        gate = SupplementalGateKind.SECURITY if args.command == "security-gate" else SupplementalGateKind.CONTEXT_TOOL
        return await run_supplemental_gate(
            args.campaign_id,
            gate,
            allow_live=args.allow_live,
            allow_model_campaign=args.allow_model_campaign,
            allow_adversarial_security_eval=getattr(args, "allow_adversarial_security_eval", False),
            allow_context_tool_experiments=getattr(args, "allow_context_tool_experiments", False),
        )

    if args.command == "analyze":
        from app.evaluation.campaign.analysis import build_analysis_report
        from app.evaluation.campaign.supplemental import load_gate_report

        plan = load_plan(args.campaign_id)
        smoke = load_stage_report(args.campaign_id, CampaignStage.LIVE_SMOKE)
        pilot = load_stage_report(args.campaign_id, CampaignStage.LIVE_PILOT)
        full = load_stage_report(args.campaign_id, CampaignStage.LIVE_FULL)
        security_gate = _load_supplemental_if_present(args.campaign_id, SupplementalGateKind.SECURITY)
        context_gate = _load_supplemental_if_present(args.campaign_id, SupplementalGateKind.CONTEXT_TOOL)
        report, samples = build_analysis_report(
            plan, smoke, pilot, full, security_gate=security_gate, context_tool_gate=context_gate,
        )
        directory = _safe_campaign_directory(args.campaign_id)
        _write_immutable(directory / "analysis.json", report)
        samples_directory = directory / "review-samples"
        if samples_directory.is_symlink():
            raise ValueError("review sample artifact directory cannot be a symlink")
        for sample in samples:
            slug = re.sub(r"[^a-zA-Z0-9._-]", "-", sample.candidate_id).strip(".-")[:48] or "candidate"
            suffix = hashlib.sha256(sample.candidate_id.encode("utf-8")).hexdigest()[:10]
            _write_immutable(samples_directory / f"{slug}-{suffix}.json", sample)
        return report

    raise ValueError("unsupported campaign command")


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = asyncio.run(_run(args))
        print(_json(result), end="")
        return 0
    except (ValueError, OSError) as exc:
        print(f"model campaign failed: {exc}", file=sys.stderr)
        return 2


__all__ = ["build_parser", "main"]
