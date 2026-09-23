"""Immutable contracts for prompt-only agent improvement experiments."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.evaluation.system.schemas import FailureClass


class ImprovementModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CandidateStatus(str, Enum):
    PROPOSED = "PROPOSED"
    SANITIZER_REJECTED = "SANITIZER_REJECTED"
    SCREEN_FAILED = "SCREEN_FAILED"
    SCREEN_PASSED = "SCREEN_PASSED"
    FULL_EVAL_FAILED = "FULL_EVAL_FAILED"
    REGRESSION_DETECTED = "REGRESSION_DETECTED"
    SAFETY_BLOCKED = "SAFETY_BLOCKED"
    INCONCLUSIVE = "INCONCLUSIVE"
    PROMOTION_ELIGIBLE = "PROMOTION_ELIGIBLE"


CANDIDATE_STATUS_TRANSITIONS: dict[CandidateStatus, frozenset[CandidateStatus]] = {
    CandidateStatus.PROPOSED: frozenset({
        CandidateStatus.SANITIZER_REJECTED,
        CandidateStatus.SCREEN_FAILED,
        CandidateStatus.SCREEN_PASSED,
        CandidateStatus.SAFETY_BLOCKED,
        CandidateStatus.INCONCLUSIVE,
    }),
    CandidateStatus.SCREEN_PASSED: frozenset({
        CandidateStatus.FULL_EVAL_FAILED,
        CandidateStatus.REGRESSION_DETECTED,
        CandidateStatus.SAFETY_BLOCKED,
        CandidateStatus.INCONCLUSIVE,
        CandidateStatus.PROMOTION_ELIGIBLE,
    }),
    CandidateStatus.INCONCLUSIVE: frozenset({
        CandidateStatus.FULL_EVAL_FAILED,
        CandidateStatus.REGRESSION_DETECTED,
        CandidateStatus.SAFETY_BLOCKED,
    }),
}


class ImprovementTerminationReason(str, Enum):
    LIVE_PERMISSION_REQUIRED = "LIVE_PERMISSION_REQUIRED"
    PROMOTION_CANDIDATE_FOUND = "PROMOTION_CANDIDATE_FOUND"
    NO_ACTIONABLE_FAILURES = "NO_ACTIONABLE_FAILURES"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    ALL_CANDIDATES_REJECTED = "ALL_CANDIDATES_REJECTED"
    NO_MEANINGFUL_IMPROVEMENT = "NO_MEANINGFUL_IMPROVEMENT"
    SAFETY_BLOCKED = "SAFETY_BLOCKED"
    OPTIMIZATION_BUDGET_EXHAUSTED = "OPTIMIZATION_BUDGET_EXHAUSTED"
    PROVIDER_FAILURE = "PROVIDER_FAILURE"
    INVALID_BASELINE = "INVALID_BASELINE"
    HARNESS_FAILURE = "HARNESS_FAILURE"


class SafeImprovementEvent(ImprovementModel):
    """Allowlisted, content-free event projection for reflection context."""

    node: str = Field(min_length=1, max_length=64)
    status: Literal["COMPLETED", "COMPLETED_WITH_ERRORS"]
    duration_ms: float = Field(ge=0.0, le=1_000_000_000.0)
    model_identities: tuple[str, ...] = Field(default=(), max_length=8)
    model_execution_count: int = Field(default=0, ge=0, le=10_000)
    tool_names: tuple[str, ...] = Field(default=(), max_length=8)
    tool_execution_count: int = Field(default=0, ge=0, le=16)
    evidence_count: int = Field(default=0, ge=0, le=1_000_000)
    failure_codes: tuple[str, ...] = Field(default=(), max_length=8)


class ImprovementExample(ImprovementModel):
    """One sanitized attributed trial; source and hidden reasoning are excluded."""

    case_id: str = Field(min_length=1, max_length=128)
    target_prompt_component: str = Field(min_length=1, max_length=128)
    failure_class: FailureClass | None = None
    failure_stage: str = Field(min_length=1, max_length=64)
    primary_node: str | None = Field(default=None, max_length=64)
    observed_behavior: str = Field(min_length=1, max_length=512)
    expected_behavior: str = Field(min_length=1, max_length=512)
    supporting_evidence_refs: tuple[str, ...] = Field(default=(), max_length=32)
    downstream_effect: str = Field(min_length=1, max_length=512)
    workflow_events: tuple[SafeImprovementEvent, ...] = Field(default=(), max_length=32)
    safety_codes: tuple[str, ...] = Field(default=(), max_length=32)
    truncated_fields: tuple[str, ...] = Field(default=(), max_length=8)
    baseline_system_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    baseline_report_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    outcome: Literal["FAILURE", "PRESERVE"] = "FAILURE"

    @model_validator(mode="after")
    def validate_outcome_attribution(self) -> "ImprovementExample":
        if self.outcome == "FAILURE" and self.failure_class is None:
            raise ValueError("failure examples require deterministic failure attribution")
        if self.outcome == "PRESERVE" and self.failure_class is not None:
            raise ValueError("preserve examples cannot be labeled as failures")
        return self


class ImprovementCorpus(ImprovementModel):
    schema_version: Literal["improvement-corpus/1.0"] = "improvement-corpus/1.0"
    baseline_report_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    baseline_system_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    optimization_examples: tuple[ImprovementExample, ...] = Field(max_length=64)
    preserve_examples: tuple[ImprovementExample, ...] = Field(max_length=16)
    validation_case_ids: tuple[str, ...] = Field(max_length=64)
    selection_policy: str = Field(min_length=1, max_length=128)
    selection_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    truncated: bool = False
    corpus_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def verify_corpus_digest(self) -> "ImprovementCorpus":
        from app.evaluation.improvement.digest import canonical_digest

        payload = self.model_dump(mode="json", exclude={"corpus_digest"})
        if canonical_digest(payload) != self.corpus_digest:
            raise ValueError("improvement corpus digest does not match its content")
        if set(self.validation_case_ids) & {
            example.case_id for example in (*self.optimization_examples, *self.preserve_examples)
        }:
            raise ValueError("validation cases must not appear in reflection corpus examples")
        return self


class PromptReflection(ImprovementModel):
    schema_version: Literal["prompt-reflection/1.0"] = "prompt-reflection/1.0"
    hypothesis_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    target_component: str = Field(min_length=1, max_length=128)
    observed_failure_patterns: tuple[str, ...] = Field(min_length=1, max_length=8)
    supporting_example_refs: tuple[str, ...] = Field(max_length=12)
    likely_prompt_weakness: str = Field(min_length=1, max_length=600)
    proposed_strategy: str = Field(min_length=1, max_length=600)
    behaviors_to_preserve: tuple[str, ...] = Field(default=(), max_length=8)
    safety_constraints: tuple[str, ...] = Field(min_length=1, max_length=12)
    risk_of_regression: str = Field(min_length=1, max_length=500)
    insufficient_evidence: bool = False


class SanitizerResult(ImprovementModel):
    accepted: bool
    rejection_codes: tuple[str, ...] = Field(default=(), max_length=32)
    prompt_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    prompt_chars: int = Field(ge=0, le=32_000)


class CandidateGenerationBudget(ImprovementModel):
    calls: int = Field(default=1, ge=1, le=1)
    max_output_tokens: int = Field(default=8_000, ge=1, le=8_000)


class ImprovementCandidate(ImprovementModel):
    schema_version: Literal["improvement-candidate/1.0"] = "improvement-candidate/1.0"
    optimization_run_id: str = Field(min_length=1, max_length=128)
    candidate_id: str = Field(min_length=1, max_length=128)
    target_component: str = Field(min_length=1, max_length=128)
    baseline_prompt_version: str = Field(min_length=1, max_length=128)
    baseline_prompt_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_prompt: str = Field(min_length=1, max_length=32_000)
    candidate_prompt_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    hypothesis_id: str = Field(min_length=1, max_length=128)
    supporting_failure_ids: tuple[str, ...] = Field(default=(), max_length=12)
    parent_candidate_id: str | None = Field(default=None, max_length=128)
    generator_provider: str = Field(min_length=1, max_length=32)
    generator_model: str = Field(min_length=1, max_length=256)
    generation_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reflection_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    optimization_dataset_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    validation_dataset_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    generation_budget: CandidateGenerationBudget = Field(default_factory=CandidateGenerationBudget)
    artifact_digest: str = "NOT_COMPUTED"
    sanitizer_result: SanitizerResult
    screen_report_digest: str = "NOT_EXECUTED"
    screen_case_ids: tuple[str, ...] = Field(default=(), max_length=16)
    screen_case_selection_digest: str = "NOT_EXECUTED"
    screen_selection_policy: str = "NOT_EXECUTED"
    full_eval_report_digest: str = "NOT_EXECUTED"
    comparison_digest: str = "NOT_EXECUTED"
    status: CandidateStatus = CandidateStatus.PROPOSED
    status_history: tuple[CandidateStatus, ...] = Field(
        default=(CandidateStatus.PROPOSED,), max_length=4,
    )
    rationale: str = Field(default="", max_length=600)

    def model_post_init(self, __context: Any) -> None:
        if self.artifact_digest == "NOT_COMPUTED":
            from app.evaluation.improvement.digest import canonical_digest

            digest = canonical_digest(self.model_dump(mode="json", exclude={"artifact_digest"}))
            object.__setattr__(self, "artifact_digest", digest)

    @model_validator(mode="after")
    def validate_candidate(self) -> "ImprovementCandidate":
        from app.agent_runtime.prompt_overlay import prompt_digest
        from app.evaluation.improvement.digest import canonical_digest

        if prompt_digest(self.candidate_prompt) != self.candidate_prompt_digest:
            raise ValueError("candidate prompt digest does not match prompt text")
        if not self.status_history or self.status_history[-1] != self.status:
            raise ValueError("candidate status must match the final status transition")
        if self.status_history[0] != CandidateStatus.PROPOSED:
            raise ValueError("candidate status history must begin at PROPOSED")
        for previous, current in zip(self.status_history, self.status_history[1:]):
            if current not in CANDIDATE_STATUS_TRANSITIONS.get(previous, frozenset()):
                raise ValueError("candidate status history contains an invalid transition")
        if not self.sanitizer_result.accepted and self.status not in {
            CandidateStatus.SANITIZER_REJECTED, CandidateStatus.SAFETY_BLOCKED,
        }:
            raise ValueError("a sanitizer-rejected candidate cannot advance")
        if self.status in {CandidateStatus.SCREEN_FAILED, CandidateStatus.SCREEN_PASSED}:
            if (
                not re.fullmatch(r"[0-9a-f]{64}", self.screen_report_digest)
                or not re.fullmatch(r"[0-9a-f]{64}", self.screen_case_selection_digest)
                or self.screen_selection_policy == "NOT_EXECUTED"
                or not self.screen_case_ids
            ):
                raise ValueError("screened candidates require a recorded screen report and selection")
        if self.status in {CandidateStatus.REGRESSION_DETECTED, CandidateStatus.PROMOTION_ELIGIBLE}:
            if (
                not re.fullmatch(r"[0-9a-f]{64}", self.full_eval_report_digest)
                or not re.fullmatch(r"[0-9a-f]{64}", self.comparison_digest)
            ):
                raise ValueError("full-evaluation outcomes require report and comparison digests")
        if self.status == CandidateStatus.SAFETY_BLOCKED:
            has_screen = re.fullmatch(r"[0-9a-f]{64}", self.screen_report_digest) is not None
            has_full = re.fullmatch(r"[0-9a-f]{64}", self.full_eval_report_digest) is not None
            if not (has_screen or has_full):
                raise ValueError("safety-blocked candidates require an evaluated report digest")
        if self.status == CandidateStatus.PROMOTION_ELIGIBLE and self.status_history[-2:] != (
            CandidateStatus.SCREEN_PASSED, CandidateStatus.PROMOTION_ELIGIBLE,
        ):
            raise ValueError("promotion eligibility must follow a passed screen")
        expected_artifact_digest = canonical_digest(
            self.model_dump(mode="json", exclude={"artifact_digest"})
        )
        if self.artifact_digest != expected_artifact_digest:
            raise ValueError("improvement candidate artifact digest does not match its content")
        return self


class ImprovementResourceUsage(ImprovementModel):
    reflection_calls: int = Field(default=0, ge=0, le=2)
    generation_calls: int = Field(default=0, ge=0, le=8)
    candidate_screen_runs: int = Field(default=0, ge=0, le=8)
    candidate_full_runs: int = Field(default=0, ge=0, le=3)
    evaluation_trials: int = Field(default=0, ge=0, le=640)
    reserved_model_tokens: int = Field(default=0, ge=0, le=160_000)
    reported_input_tokens: int = Field(default=0, ge=0)
    reported_output_tokens: int = Field(default=0, ge=0)
    elapsed_seconds: float = Field(default=0.0, ge=0.0)


class ImprovementRunReport(ImprovementModel):
    schema_version: Literal["improvement-run-report/1.0"] = "improvement-run-report/1.0"
    optimization_run_id: str = Field(min_length=1, max_length=128)
    policy_version: str = Field(min_length=1, max_length=64)
    policy_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    baseline_report_digest: str = "NOT_EXECUTED"
    baseline_system_digest: str = "NOT_EXECUTED"
    corpus_digest: str = "NOT_EXECUTED"
    generator_provider: str | None = Field(default=None, max_length=32)
    generator_model: str | None = Field(default=None, max_length=256)
    target_prompt_component: str | None = None
    reflection_digest: str = "NOT_EXECUTED"
    candidates: tuple[ImprovementCandidate, ...] = Field(default=(), max_length=8)
    comparison_digests: tuple[str, ...] = Field(default=(), max_length=8)
    winner_candidate_id: str | None = None
    termination_reason: ImprovementTerminationReason
    reasons: tuple[str, ...] = Field(default=(), max_length=16)
    resources: ImprovementResourceUsage = Field(default_factory=ImprovementResourceUsage)
    report_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def verify_run_digest(self) -> "ImprovementRunReport":
        from app.evaluation.improvement.digest import canonical_digest

        if canonical_digest(self.model_dump(mode="json", exclude={"report_digest"})) != self.report_digest:
            raise ValueError("improvement run report digest does not match its content")
        if self.winner_candidate_id is not None and not any(
            item.candidate_id == self.winner_candidate_id and item.status == CandidateStatus.PROMOTION_ELIGIBLE
            for item in self.candidates
        ):
            raise ValueError("winner must be a promotion-eligible human-review candidate")
        if (self.generator_provider is None) != (self.generator_model is None):
            raise ValueError("generator provider and model identity must be recorded together")
        return self


__all__ = [
    "CandidateStatus", "ImprovementCandidate", "ImprovementCorpus", "ImprovementExample",
    "CANDIDATE_STATUS_TRANSITIONS",
    "CandidateGenerationBudget",
    "ImprovementResourceUsage", "ImprovementRunReport", "ImprovementTerminationReason",
    "PromptReflection", "SanitizerResult",
    "SafeImprovementEvent",
]
