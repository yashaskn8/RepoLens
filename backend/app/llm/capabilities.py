"""Provider-neutral model capability registry and deterministic routing policy."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Iterable, Mapping, Sequence

from app.core.config import Settings, get_settings
from app.llm.types import LLMProvider, ModelCapability, ModelCostTier, TaskPolicy


@dataclass(frozen=True, slots=True)
class ModelCapabilitySpec:
    """Immutable, non-secret description of one configured model endpoint."""

    provider: LLMProvider
    model: str
    capabilities: frozenset[ModelCapability]
    cost_tier: ModelCostTier
    quality_rank: int
    context_window_tokens: int
    max_output_tokens: int
    supports_structured_output: bool = True
    model_revision: str | None = None
    enabled: bool = True

    def supports(self, capability: ModelCapability) -> bool:
        return self.enabled and capability in self.capabilities


_POLICY_CAPABILITIES: Mapping[TaskPolicy, ModelCapability] = {
    TaskPolicy.ARCHITECTURE: ModelCapability.DEEP_REASONING,
    TaskPolicy.INTEGRATION_CODE: ModelCapability.CODE_REASONING,
    TaskPolicy.BUG_REASONING: ModelCapability.CODE_REASONING,
    TaskPolicy.SECURITY_REASONING: ModelCapability.SECURITY_REASONING,
    TaskPolicy.LIGHTWEIGHT_CLASSIFICATION: ModelCapability.CLASSIFICATION,
    TaskPolicy.VERIFICATION: ModelCapability.VERIFICATION,
    TaskPolicy.RESEARCH: ModelCapability.RESEARCH,
    TaskPolicy.FIX_PLANNING: ModelCapability.DEEP_REASONING,
    TaskPolicy.PATCH_GENERATION: ModelCapability.PATCH_GENERATION,
    TaskPolicy.PATCH_CRITIC: ModelCapability.VERIFICATION,
    TaskPolicy.CHANGE_REVIEW: ModelCapability.DEEP_REASONING,
}


def capability_for_policy(policy: TaskPolicy) -> ModelCapability:
    return _POLICY_CAPABILITIES.get(policy, ModelCapability.DEEP_REASONING)


class ModelCapabilityRegistry:
    """Versioned in-process view of operator-approved model capabilities.

    The registry contains no credentials and can be reconstructed from an immutable
    policy snapshot. Operational disablement is applied by ``RoutingPolicy``.
    """

    def __init__(self, specifications: Iterable[ModelCapabilitySpec]):
        specs = tuple(specifications)
        keys = [(item.provider, item.model) for item in specs]
        if len(keys) != len(set(keys)):
            raise ValueError("Model capability registry contains a duplicate provider/model entry")
        self._specifications = specs
        canonical = [
            {
                "provider": spec.provider.value,
                "model": spec.model,
                "capabilities": sorted(value.value for value in spec.capabilities),
                "cost_tier": spec.cost_tier.value,
                "quality_rank": spec.quality_rank,
                "context_window_tokens": spec.context_window_tokens,
                "max_output_tokens": spec.max_output_tokens,
                "supports_structured_output": spec.supports_structured_output,
                "model_revision": spec.model_revision,
                "enabled": spec.enabled,
            }
            for spec in specs
        ]
        payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
        self.version = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @classmethod
    def from_settings(cls, settings: Settings | None = None) -> "ModelCapabilityRegistry":
        configured = settings or get_settings()
        return cls(
            (
                ModelCapabilitySpec(
                    provider=LLMProvider.GROQ,
                    model=configured.MODEL_LIGHTWEIGHT_CLASSIFICATION,
                    capabilities=frozenset(
                        {
                            ModelCapability.CLASSIFICATION,
                            ModelCapability.STRUCTURED_EXTRACTION,
                            ModelCapability.RERANKING,
                        }
                    ),
                    cost_tier=ModelCostTier.FREE,
                    quality_rank=10,
                    context_window_tokens=32_768,
                    max_output_tokens=8_192,
                ),
                ModelCapabilitySpec(
                    provider=LLMProvider.HUGGINGFACE,
                    model=configured.MODEL_INTEGRATION_CODE,
                    capabilities=frozenset(
                        {
                            ModelCapability.CODE_REASONING,
                            ModelCapability.PATCH_GENERATION,
                            ModelCapability.STRUCTURED_EXTRACTION,
                        }
                    ),
                    cost_tier=ModelCostTier.FREE,
                    quality_rank=20,
                    context_window_tokens=65_536,
                    max_output_tokens=16_384,
                ),
                ModelCapabilitySpec(
                    provider=LLMProvider.GEMINI,
                    model=configured.MODEL_ARCHITECTURE,
                    capabilities=frozenset(
                        {
                            ModelCapability.CODE_REASONING,
                            ModelCapability.DEEP_REASONING,
                            ModelCapability.STRUCTURED_EXTRACTION,
                            ModelCapability.VERIFICATION,
                            ModelCapability.RESEARCH,
                        }
                    ),
                    cost_tier=ModelCostTier.CHEAP,
                    quality_rank=10,
                    context_window_tokens=1_000_000,
                    max_output_tokens=65_536,
                ),
                ModelCapabilitySpec(
                    provider=LLMProvider.NVIDIA,
                    model=configured.MODEL_BUG_REASONING,
                    capabilities=frozenset(
                        {
                            ModelCapability.CODE_REASONING,
                            ModelCapability.DEEP_REASONING,
                            ModelCapability.SECURITY_REASONING,
                            ModelCapability.PATCH_GENERATION,
                        }
                    ),
                    cost_tier=ModelCostTier.CHEAP,
                    quality_rank=20,
                    context_window_tokens=131_072,
                    max_output_tokens=16_384,
                ),
                ModelCapabilitySpec(
                    provider=LLMProvider.GROQ,
                    model=configured.MODEL_SECURITY_REASONING,
                    capabilities=frozenset(
                        {
                            ModelCapability.DEEP_REASONING,
                            ModelCapability.SECURITY_REASONING,
                            ModelCapability.STRUCTURED_EXTRACTION,
                            ModelCapability.VERIFICATION,
                            ModelCapability.RESEARCH,
                        }
                    ),
                    cost_tier=ModelCostTier.STANDARD,
                    quality_rank=10,
                    context_window_tokens=131_072,
                    max_output_tokens=32_768,
                ),
                ModelCapabilitySpec(
                    provider=LLMProvider.NVIDIA,
                    model=configured.MODEL_VERIFICATION,
                    capabilities=frozenset(
                        {ModelCapability.DEEP_REASONING, ModelCapability.VERIFICATION}
                    ),
                    cost_tier=ModelCostTier.PREMIUM,
                    quality_rank=10,
                    context_window_tokens=131_072,
                    max_output_tokens=16_384,
                ),
            )
        )

    @property
    def specifications(self) -> tuple[ModelCapabilitySpec, ...]:
        return self._specifications

    def get(self, provider: LLMProvider, model: str) -> ModelCapabilitySpec | None:
        return next(
            (item for item in self._specifications if item.provider == provider and item.model == model),
            None,
        )

    def candidates(self, capability: ModelCapability) -> tuple[ModelCapabilitySpec, ...]:
        return tuple(item for item in self._specifications if item.supports(capability))


class RoutingPolicy:
    """Select one ordered, sequential chain with cheap/healthy/capable models first."""

    version = "capability-routing/1.0"

    def __init__(
        self,
        registry: ModelCapabilityRegistry,
        *,
        disabled_providers: Sequence[LLMProvider] = (),
        disabled_models: Sequence[str] = (),
    ) -> None:
        self.registry = registry
        self.disabled_providers = frozenset(disabled_providers)
        self.disabled_models = frozenset(disabled_models)

    def candidates(
        self,
        capability: ModelCapability,
        *,
        max_cost_tier: ModelCostTier,
        required_context_tokens: int,
        structured_output: bool,
    ) -> tuple[ModelCapabilitySpec, ...]:
        eligible = [
            spec
            for spec in self.registry.candidates(capability)
            if spec.provider not in self.disabled_providers
            and spec.model not in self.disabled_models
            and spec.cost_tier.value <= max_cost_tier.value
            and spec.context_window_tokens >= required_context_tokens
            and (not structured_output or spec.supports_structured_output)
        ]
        eligible.sort(key=lambda spec: (spec.cost_tier.value, spec.quality_rank, spec.provider.value, spec.model))
        return tuple(eligible)

