"""Versioned, conservative policy for prompt-only optimization experiments."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from app.evaluation.improvement.contracts import ImprovementModel
from app.evaluation.improvement.digest import canonical_digest


class ImprovementPolicy(ImprovementModel):
    version: Literal["prompt-improvement-policy/1.1"] = "prompt-improvement-policy/1.1"
    max_generations: int = Field(default=2, ge=1, le=2)
    max_candidates_per_generation: int = Field(default=4, ge=1, le=4)
    max_reflection_examples: int = Field(default=8, ge=1, le=12)
    max_preserve_examples: int = Field(default=3, ge=0, le=4)
    max_trace_events_per_example: int = Field(default=12, ge=1, le=32)
    max_evidence_refs_per_example: int = Field(default=8, ge=1, le=32)
    validation_partition_percent: int = Field(default=25, ge=20, le=40)
    screen_case_limit: int = Field(default=8, ge=4, le=16)
    screen_trials_per_case: int = Field(default=1, ge=1, le=1)
    max_candidate_screen_workflows: int = Field(default=8, ge=1, le=8)
    full_trials_per_case: int = Field(default=5, ge=5, le=5)
    max_total_case_trial_work_units: int = Field(default=640, ge=1, le=640)
    max_full_evaluation_candidates: int = Field(default=3, ge=1, le=3)
    max_reflection_calls: int = Field(default=2, ge=1, le=2)
    max_generation_calls: int = Field(default=8, ge=1, le=8)
    max_total_optimizer_calls: int = Field(default=10, ge=1, le=10)
    max_optimizer_reserved_tokens: int = Field(default=160_000, ge=1, le=160_000)
    max_input_tokens_per_model_call: int = Field(default=12_000, ge=1, le=12_000)
    max_output_tokens_per_model_call: int = Field(default=8_000, ge=1, le=8_000)
    model_timeout_seconds: int = Field(default=45, ge=1, le=45)
    max_wall_clock_seconds: int = Field(default=3_600, ge=1, le=3_600)
    candidate_sanitizer_version: str = "prompt-candidate-sanitizer/1.2"
    corpus_selection_policy: str = "failure-group-hash-split/1.0"
    screen_selection_policy: str = "target-validation-security-preserve-regression/1.0"
    ranking_policy: str = "hard-safety-target-preserve-precision-recall/1.1"
    allowed_components: tuple[str, ...] = (
        "architecture-agent", "security-agent", "bug-agent", "verifier-agent",
        "revision-agent", "evidence-investigator",
    )
    live_only_baseline: bool = True
    holdout_policy: str = "canonical-dev-only-no-custom-root/1.0"

    @property
    def digest(self) -> str:
        payload = self.model_dump(mode="json")
        from app.evaluation.improvement.registry import OptimizablePromptRegistry

        payload["prompt_registry_digest"] = OptimizablePromptRegistry().digest
        return canonical_digest(payload)


__all__ = ["ImprovementPolicy"]
