"""Frozen plan construction for the explicit multi-model evaluation campaign."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import subprocess
from uuid import uuid4

from app.evaluation.ground_truth.loader import compute_canonical_benchmark_hash
from app.evaluation.ground_truth.public_dev import load_public_dev_repository_cases
from app.evaluation.ground_truth.leakage import LeakageDetector
from app.evaluation.system.full_analysis import FullAnalysisFixture
from app.evaluation.system.identity import build_agent_system_identity
from app.evaluation.campaign.contracts import (
    CampaignCandidate,
    CampaignStagePolicy,
    ModelEvaluationCampaignPlan,
    ModelStability,
    PLAN_SCHEMA_VERSION,
    canonical_digest,
)
from app.llm.capabilities import ModelCapabilitySpec
from app.llm.router import get_llm_router
from app.llm.types import LLMProvider, ModelCapability


DATASET_VERSION = "ground-truth-v1-DEV-REPOSITORY_SCAN"
MIN_REQUIRED_CONTEXT_TOKENS = 5_700
MIN_REQUIRED_OUTPUT_TOKENS = 700
FULL_ANALYSIS_CAPABILITY_SET = frozenset({
    ModelCapability.REPOSITORY_ANALYSIS,
    ModelCapability.CODE_REASONING,
    ModelCapability.SECURITY_REASONING,
    ModelCapability.VERIFICATION,
})


def _candidate_stability(spec: ModelCapabilitySpec) -> ModelStability:
    if spec.model_revision:
        return ModelStability.PINNED_VERSION
    if any(part.endswith("-latest") or part == "latest" for part in spec.model.casefold().replace(":", "/").split("/")):
        return ModelStability.MUTABLE_ALIAS
    return ModelStability.UNKNOWN_STABILITY


def _make_candidate(candidate_id: str, spec: ModelCapabilitySpec, identity) -> CampaignCandidate:
    missing_capabilities = sorted(
        item.value for item in FULL_ANALYSIS_CAPABILITY_SET if item not in spec.capabilities
    )
    payload = {
        "candidate_id": candidate_id,
        "provider": spec.provider.value,
        "requested_model": spec.model,
        "registry_status": "REGISTERED_ENABLED",
        "structured_output_declared": True,
        "context_window_tokens": spec.context_window_tokens,
        "max_output_tokens": spec.max_output_tokens,
        "declared_capabilities": sorted(capability.value for capability in spec.capabilities),
        "declared_capability_gaps": missing_capabilities,
        "model_revision": spec.model_revision,
        "model_stability": _candidate_stability(spec).value,
        "role": "PINNED_MODEL",
        "system_identity_digest": identity.system_digest,
        "compatibility_digest": identity.compatibility_digest,
    }
    return CampaignCandidate(**payload, candidate_digest=canonical_digest(payload))


async def create_campaign_plan(
    candidates: list[tuple[str, LLMProvider | str, str]],
    *,
    baseline_candidate_id: str,
    schedule_seed: int = 0,
    stage_policy: CampaignStagePolicy | None = None,
) -> ModelEvaluationCampaignPlan:
    """Build an immutable identity against the fixed public DEV inventory.

    This performs no provider calls. Candidate names resolve only through the
    canonical router capability registry and adapter map.
    """
    if not 2 <= len(candidates) <= 4:
        raise ValueError("campaign plan requires two to four distinct registered candidate arms")
    ids = [item[0] for item in candidates]
    if len(ids) != len(set(ids)):
        raise ValueError("candidate IDs must be unique")
    if baseline_candidate_id not in ids:
        raise ValueError("baseline candidate must be one of the frozen candidate arms")
    if not 0 <= schedule_seed <= 2**32 - 1:
        raise ValueError("schedule seed is outside the supported range")

    normalized = [(candidate_id, LLMProvider(provider), model) for candidate_id, provider, model in candidates]
    if any(not model or len(model) > 256 for _, _, model in normalized):
        raise ValueError("model identifiers must be non-empty and bounded")
    if len({(provider, model) for _, provider, model in normalized}) != len(normalized):
        raise ValueError("campaign arms must be distinct provider/model pairs")

    router = get_llm_router()
    capability_registry = router._capability_gateway.registry
    specifications: list[tuple[str, ModelCapabilitySpec]] = []
    for candidate_id, provider, model in normalized:
        spec = capability_registry.get(provider, model)
        if spec is None or not spec.enabled:
            raise ValueError(f"candidate {candidate_id} is not an enabled exact registry entry")
        if not spec.supports_structured_output:
            raise ValueError(f"candidate {candidate_id} does not declare structured-output support")
        if spec.context_window_tokens < MIN_REQUIRED_CONTEXT_TOKENS:
            raise ValueError(f"candidate {candidate_id} cannot satisfy the fixed workflow context budget")
        if spec.max_output_tokens < MIN_REQUIRED_OUTPUT_TOKENS:
            raise ValueError(f"candidate {candidate_id} cannot satisfy the fixed workflow output budget")
        try:
            router.get_adapter(provider)
        except ValueError as exc:
            raise ValueError(f"candidate {candidate_id} has no canonical provider adapter") from exc
        specifications.append((candidate_id, spec))

    cases = load_public_dev_repository_cases()
    case_ids = sorted(case.case_id for case in cases)
    if len(case_ids) != 35:
        raise ValueError("campaign requires the exact 35-case public DEV repository-scan inventory")
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("public DEV inventory contains duplicate case IDs")

    fixture = FullAnalysisFixture(LeakageDetector.bifurcate_input(cases[0]))
    try:
        await fixture.initialize_runtime()
        identities = {
            candidate_id: build_agent_system_identity(
                provider=spec.provider,
                model=spec.model,
                registry=fixture.registry,
                scope="FULL_ANALYSIS_GRAPH",
            )
            for candidate_id, spec in specifications
        }
    finally:
        fixture.close()

    compatibility = {identity.compatibility_digest for identity in identities.values()}
    if len(compatibility) != 1:
        raise ValueError("candidate arms differ in non-model system compatibility")
    baseline_identity = identities[baseline_candidate_id]
    prompt_inventory = [
        component.model_dump(mode="json")
        for component in baseline_identity.prompt_components
    ]
    arms = [
        _make_candidate(candidate_id, spec, identities[candidate_id])
        for candidate_id, spec in specifications
    ]
    source_revision = _git_head()
    created_at = datetime.now(timezone.utc)
    stage_policy_model = stage_policy or CampaignStagePolicy()
    raw = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "campaign_id": uuid4().hex,
        "created_at": created_at,
        "source_revision": source_revision,
        "dataset_version": DATASET_VERSION,
        "dataset_digest": compute_canonical_benchmark_hash(cases),
        "case_ids": case_ids,
        "graph_identity_digest": baseline_identity.graph_identity_digest,
        "evaluation_contract_hash": baseline_identity.evaluation_contract_hash,
        "prompt_inventory_digest": canonical_digest(prompt_inventory),
        "tool_manifest_digest": baseline_identity.tool_manifest_digest,
        "context_policy_digest": baseline_identity.context_policy_digest,
        "system_compatibility_digest": baseline_identity.compatibility_digest,
        "candidate_arms": arms,
        "baseline_candidate_id": baseline_candidate_id,
        "schedule_seed": schedule_seed,
        "stage_policy": stage_policy_model,
    }
    normalized = ModelEvaluationCampaignPlan.model_construct(
        **raw, plan_digest="0" * 64,
    ).model_dump(mode="json", exclude={"plan_digest"})
    return ModelEvaluationCampaignPlan(**normalized, plan_digest=canonical_digest(normalized))


def _git_head() -> str:
    """Return the current commit without shell interpolation or secret output."""
    repository = Path(__file__).resolve().parents[4]
    result = subprocess.run(
        ["git", "-c", f"safe.directory={repository.as_posix()}", "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    revision = result.stdout.strip().lower()
    if len(revision) not in {40, 64} or any(char not in "0123456789abcdef" for char in revision):
        raise ValueError("could not establish a canonical source revision")
    return revision


__all__ = ["DATASET_VERSION", "create_campaign_plan"]
