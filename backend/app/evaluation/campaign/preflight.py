"""Read-only campaign readiness checks; never prints credentials or calls providers."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.evaluation.campaign.contracts import ModelStability
from app.evaluation.campaign.plan import (
    FULL_ANALYSIS_CAPABILITY_SET,
    MIN_REQUIRED_CONTEXT_TOKENS,
    MIN_REQUIRED_OUTPUT_TOKENS,
    _candidate_stability,
    _git_head,
)
from app.evaluation.ground_truth.public_dev import load_public_dev_repository_cases
from app.llm.router import get_llm_router
from app.llm.types import LLMProvider
from app.core.config import get_settings


class CandidateReadiness(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    candidate_id: str = Field(min_length=1, max_length=128)
    provider: LLMProvider
    model: str = Field(min_length=1, max_length=256)
    status: Literal["READY", "NOT_REGISTERED", "DISABLED", "NO_ADAPTER", "NO_CREDENTIAL", "INSUFFICIENT_CONTEXT", "NO_STRUCTURED_OUTPUT", "CAPABILITY_GAP"]
    registry_enabled: bool
    structured_output: bool
    context_window_tokens: int | None
    max_output_tokens: int | None
    declared_revision: str | None
    capability_gaps: list[str] = Field(max_length=8)
    stability: ModelStability
    credential_configured: bool
    local_runtime_reachability: Literal["NOT_PROBED"] = "NOT_PROBED"


class CampaignPreflight(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    source_revision: str = Field(pattern=r"^[0-9a-f]{40,64}$")
    dataset_version: str
    dataset_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    public_dev_case_count: int = Field(ge=1, le=35)
    category_counts: dict[str, int]
    candidate_readiness: list[CandidateReadiness] = Field(min_length=1, max_length=4)
    live_execution_performed: Literal[False] = False
    report_scope: Literal["READINESS_ONLY_NO_PROVIDER_CALLS"] = "READINESS_ONLY_NO_PROVIDER_CALLS"


def _credential_configured(provider: LLMProvider, adapter) -> bool:
    if provider == LLMProvider.CLOUDFLARE:
        return bool(getattr(adapter, "api_token", "") and getattr(adapter, "account_id", ""))
    if provider == LLMProvider.OLLAMA:
        return bool(get_settings().LOCAL_LLM_ENABLED)
    return bool(getattr(adapter, "api_key", ""))


def run_campaign_preflight(candidates: list[tuple[str, LLMProvider | str, str]]) -> CampaignPreflight:
    if not 1 <= len(candidates) <= 4:
        raise ValueError("preflight accepts one to four explicitly named registered candidates")
    ids = [item[0] for item in candidates]
    if len(ids) != len(set(ids)):
        raise ValueError("candidate IDs must be unique")
    router = get_llm_router()
    registry = router._capability_gateway.registry
    readiness: list[CandidateReadiness] = []
    for candidate_id, provider_value, model in candidates:
        provider = LLMProvider(provider_value)
        spec = registry.get(provider, model)
        try:
            adapter = router.get_adapter(provider)
            has_adapter = True
        except ValueError:
            adapter = None
            has_adapter = False
        credentials = _credential_configured(provider, adapter) if adapter is not None else False
        if spec is None:
            status = "NOT_REGISTERED"
        elif not spec.enabled:
            status = "DISABLED"
        elif not has_adapter:
            status = "NO_ADAPTER"
        elif not spec.supports_structured_output:
            status = "NO_STRUCTURED_OUTPUT"
        elif spec.context_window_tokens < MIN_REQUIRED_CONTEXT_TOKENS or spec.max_output_tokens < MIN_REQUIRED_OUTPUT_TOKENS:
            status = "INSUFFICIENT_CONTEXT"
        elif not credentials:
            status = "NO_CREDENTIAL"
        elif spec is not None and FULL_ANALYSIS_CAPABILITY_SET - spec.capabilities:
            status = "CAPABILITY_GAP"
        else:
            status = "READY"
        readiness.append(CandidateReadiness(
            candidate_id=candidate_id,
            provider=provider,
            model=model,
            status=status,
            registry_enabled=bool(spec and spec.enabled),
            structured_output=bool(spec and spec.supports_structured_output),
            context_window_tokens=spec.context_window_tokens if spec else None,
            max_output_tokens=spec.max_output_tokens if spec else None,
            declared_revision=spec.model_revision if spec else None,
            capability_gaps=sorted(
                item.value for item in FULL_ANALYSIS_CAPABILITY_SET - spec.capabilities
            ) if spec else sorted(item.value for item in FULL_ANALYSIS_CAPABILITY_SET),
            stability=_candidate_stability(spec) if spec else ModelStability.UNKNOWN_STABILITY,
            credential_configured=credentials,
        ))
    cases = load_public_dev_repository_cases()
    categories: dict[str, int] = {}
    for case in cases:
        name = case.category.value
        categories[name] = categories.get(name, 0) + 1
    from app.evaluation.ground_truth.loader import compute_canonical_benchmark_hash
    from app.evaluation.campaign.plan import DATASET_VERSION

    return CampaignPreflight(
        source_revision=_git_head(),
        dataset_version=DATASET_VERSION,
        dataset_digest=compute_canonical_benchmark_hash(cases),
        public_dev_case_count=len(cases),
        category_counts=dict(sorted(categories.items())),
        candidate_readiness=readiness,
    )


__all__ = ["CampaignPreflight", "CandidateReadiness", "run_campaign_preflight"]
