"""Versioned, content-minimized contracts for staged model campaigns."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, model_validator

from app.evaluation.system.schemas import SystemEvaluationReport
from app.evaluation.system.schemas import SystemTrialGrade, WorkflowNodeEvent
from app.llm.types import LLMProvider


PLAN_SCHEMA_VERSION = "live-model-campaign-plan/1.1"
STAGE_REPORT_SCHEMA_VERSION = "live-model-campaign-stage/1.0"
ANALYSIS_SCHEMA_VERSION = "live-model-campaign-analysis/1.0"
SCHEDULE_POLICY_VERSION = "live-model-campaign-schedule/1.0"
SMOKE_SELECTION_POLICY_VERSION = "live-model-campaign-smoke-selection/2.0"
PILOT_SELECTION_POLICY_VERSION = "live-model-campaign-pilot-selection/1.0"
COMPARISON_POLICY_VERSION = "live-model-campaign-comparison/1.0"
PARETO_POLICY_VERSION = "live-model-campaign-pareto/1.0"


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def build_digested_model(model_type: type[BaseModel], payload: dict[str, Any], digest_field: str) -> BaseModel:
    """Coerce a payload through declared field types before hashing its canonical JSON form."""
    if digest_field not in model_type.model_fields or digest_field in payload:
        raise ValueError("digest field must be a declared field omitted from its input payload")
    parsed: dict[str, Any] = {}
    for name, value in payload.items():
        field = model_type.model_fields.get(name)
        if field is None:
            raise ValueError(f"unknown {model_type.__name__} field")
        parsed[name] = TypeAdapter(field.rebuild_annotation()).validate_python(value)
    draft = model_type.model_construct(**parsed)
    normalized = draft.model_dump(mode="json", exclude={digest_field})
    return model_type(**parsed, **{digest_field: canonical_digest(normalized)})


class CampaignModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CampaignStage(str, Enum):
    PLAN = "PLAN"
    SCRIPTED_VALIDATE = "SCRIPTED_VALIDATE"
    LIVE_SMOKE = "LIVE_SMOKE"
    LIVE_PILOT = "LIVE_PILOT"
    LIVE_FULL = "LIVE_FULL"
    LIVE_SECURITY = "LIVE_SECURITY"
    LIVE_CONTEXT_TOOL = "LIVE_CONTEXT_TOOL"
    ANALYZE = "ANALYZE"


class ModelStability(str, Enum):
    PINNED_VERSION = "PINNED_VERSION"
    MUTABLE_ALIAS = "MUTABLE_ALIAS"
    UNKNOWN_STABILITY = "UNKNOWN_STABILITY"


class CampaignCandidateStatus(str, Enum):
    FULL_STAGE_ELIGIBLE = "FULL_STAGE_ELIGIBLE"
    QUALITY_ELIGIBLE = "QUALITY_ELIGIBLE"
    PARETO_EFFICIENT = "PARETO_EFFICIENT"
    QUALITY_REGRESSION = "QUALITY_REGRESSION"
    SAFETY_BLOCKED = "SAFETY_BLOCKED"
    RELIABILITY_BLOCKED = "RELIABILITY_BLOCKED"
    IDENTITY_INVALID = "IDENTITY_INVALID"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_EXECUTED = "NOT_EXECUTED"


class CampaignExecutionStatus(str, Enum):
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    HARNESS_FAILURE = "HARNESS_FAILURE"
    INVALID = "INVALID"


class CampaignUnitStatus(str, Enum):
    COMPLETED = "COMPLETED"
    PROVIDER_FAILURE = "PROVIDER_FAILURE"
    IDENTITY_INVALID = "IDENTITY_INVALID"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    HARNESS_FAILURE = "HARNESS_FAILURE"
    NOT_EXECUTED = "NOT_EXECUTED"


class ReviewStatus(str, Enum):
    NOT_REVIEWED = "NOT_REVIEWED"
    PARTIALLY_REVIEWED = "PARTIALLY_REVIEWED"
    REVIEWED = "REVIEWED"


class SupplementalGateKind(str, Enum):
    SECURITY = "SECURITY"
    CONTEXT_TOOL = "CONTEXT_TOOL"


class SupplementalGateStatus(str, Enum):
    PASS = "PASS"
    HARD_FAIL = "HARD_FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"
    INVALID = "INVALID"


class UsageMetric(CampaignModel):
    status: Literal["MEASURED", "NOT_MEASURED"] = "NOT_MEASURED"
    value: float | None = Field(default=None, ge=0.0)
    unit: str = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def validate_measurement(self) -> "UsageMetric":
        if (self.status == "MEASURED") != (self.value is not None):
            raise ValueError("unknown usage must remain NOT_MEASURED and measured usage needs a value")
        return self


class CampaignCandidate(CampaignModel):
    candidate_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._:-]*$")
    provider: LLMProvider
    requested_model: str = Field(min_length=1, max_length=256)
    registry_status: Literal["REGISTERED_ENABLED"] = "REGISTERED_ENABLED"
    structured_output_declared: Literal[True] = True
    context_window_tokens: int = Field(ge=1, le=10_000_000)
    max_output_tokens: int = Field(ge=1, le=1_000_000)
    declared_capabilities: list[str] = Field(max_length=32)
    declared_capability_gaps: list[str] = Field(default_factory=list, max_length=16)
    model_revision: str | None = Field(default=None, max_length=128)
    model_stability: ModelStability
    role: Literal["PINNED_MODEL"] = "PINNED_MODEL"
    system_identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    compatibility_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_candidate_digest(self) -> "CampaignCandidate":
        payload = self.model_dump(mode="json", exclude={"candidate_digest"})
        if canonical_digest(payload) != self.candidate_digest:
            raise ValueError("campaign candidate digest mismatch")
        return self


class CampaignStagePolicy(CampaignModel):
    max_candidate_arms: int = Field(default=4, ge=1, le=4)
    max_full_finalists: int = Field(default=2, ge=1, le=2)
    smoke_cases: int = Field(default=2, ge=2, le=2)
    smoke_trials_per_case: int = Field(default=1, ge=1, le=1)
    pilot_cases: int = Field(default=8, ge=8, le=8)
    pilot_trials_per_case: int = Field(default=2, ge=2, le=2)
    full_cases: int = Field(default=35, ge=35, le=35)
    full_trials_per_case: int = Field(default=5, ge=5, le=5)
    max_full_work_units: int = Field(default=350, ge=350, le=350)
    max_total_full_analysis_work_units: int = Field(default=422, ge=1, le=422)
    max_concurrency: Literal[1] = 1
    max_wall_clock_seconds: int = Field(default=86_400, ge=1, le=86_400)
    max_total_wall_clock_seconds: int = Field(default=172_800, ge=1, le=172_800)
    schedule_policy_version: str = SCHEDULE_POLICY_VERSION
    smoke_selection_policy_version: str = SMOKE_SELECTION_POLICY_VERSION
    pilot_selection_policy_version: str = PILOT_SELECTION_POLICY_VERSION
    comparison_policy_version: str = COMPARISON_POLICY_VERSION
    pareto_policy_version: str = PARETO_POLICY_VERSION


class ModelEvaluationCampaignPlan(CampaignModel):
    schema_version: str = PLAN_SCHEMA_VERSION
    campaign_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-f0-9]{32}$")
    created_at: datetime
    source_revision: str = Field(pattern=r"^[0-9a-f]{40,64}$")
    dataset_version: str = Field(min_length=1, max_length=64)
    dataset_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    case_ids: list[str] = Field(min_length=1, max_length=35)
    graph_identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    evaluation_contract_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    prompt_inventory_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    tool_manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    context_policy_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    system_compatibility_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_arms: list[CampaignCandidate] = Field(min_length=2, max_length=4)
    baseline_candidate_id: str = Field(min_length=1, max_length=128)
    schedule_seed: int = Field(ge=0, le=2**32 - 1)
    stage_policy: CampaignStagePolicy = Field(default_factory=CampaignStagePolicy)
    plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_plan(self) -> "ModelEvaluationCampaignPlan":
        if self.schema_version != PLAN_SCHEMA_VERSION:
            raise ValueError("unsupported campaign plan schema")
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("campaign creation time must include a timezone")
        if self.created_at > utc_now():
            raise ValueError("campaign creation time cannot be in the future")
        ids = [item.candidate_id for item in self.candidate_arms]
        if len(ids) != len(set(ids)) or self.baseline_candidate_id not in ids:
            raise ValueError("campaign plan candidate inventory or baseline is invalid")
        model_pairs = [(item.provider.value, item.requested_model) for item in self.candidate_arms]
        if len(model_pairs) != len(set(model_pairs)):
            raise ValueError("campaign candidate arms must identify distinct provider/model pairs")
        if len(self.case_ids) != len(set(self.case_ids)) or self.case_ids != sorted(self.case_ids):
            raise ValueError("campaign plan case IDs must be unique and canonical")
        if any(item.compatibility_digest != self.system_compatibility_digest for item in self.candidate_arms):
            raise ValueError("campaign candidates do not share the same non-model system compatibility")
        payload = self.model_dump(mode="json", exclude={"plan_digest"})
        if canonical_digest(payload) != self.plan_digest:
            raise ValueError("campaign plan digest mismatch")
        return self


class CampaignTrialUnit(CampaignModel):
    ordinal: int = Field(ge=1, le=4_000)
    candidate_id: str = Field(min_length=1, max_length=128)
    case_id: str = Field(min_length=1, max_length=128)
    trial_number: int = Field(ge=1, le=5)
    unit_key: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_key(self) -> "CampaignTrialUnit":
        expected = canonical_digest({
            "candidate_id": self.candidate_id,
            "case_id": self.case_id,
            "trial_number": self.trial_number,
        })
        if self.unit_key != expected:
            raise ValueError("campaign trial unit key mismatch")
        return self


class CampaignUnitResult(CampaignModel):
    schema_version: str = STAGE_REPORT_SCHEMA_VERSION
    plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    stage: CampaignStage
    unit: CampaignTrialUnit
    status: CampaignUnitStatus
    started_at: datetime
    completed_at: datetime | None = None
    duration_seconds: float = Field(default=0.0, ge=0.0, le=120.0)
    report: SystemEvaluationReport | None = None
    observed_model_pairs: list[str] = Field(default_factory=list, max_length=16)
    provider_returned_revision: str | None = Field(default=None, max_length=128)
    revision_status: Literal["MEASURED", "NOT_MEASURED"] = "NOT_MEASURED"
    safe_failure_code: str | None = Field(default=None, max_length=64)
    result_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_unit_result(self) -> "CampaignUnitResult":
        if self.schema_version != STAGE_REPORT_SCHEMA_VERSION:
            raise ValueError("unsupported campaign unit result schema")
        if self.status == CampaignUnitStatus.NOT_EXECUTED:
            if self.report is not None or self.completed_at is not None or self.duration_seconds != 0.0:
                raise ValueError("unexecuted campaign units cannot contain trial reports")
        elif self.completed_at is None:
            raise ValueError("executed campaign units require a completion timestamp")
        if self.status == CampaignUnitStatus.COMPLETED and self.report is None:
            raise ValueError("completed campaign units require a canonical system evaluation report")
        if self.report is not None:
            if self.report.metrics.trial_count != 1 or self.report.evaluated_case_ids != [self.unit.case_id]:
                raise ValueError("campaign unit report must contain exactly its one planned case/trial")
        payload = self.model_dump(mode="json", exclude={"result_digest"})
        if canonical_digest(payload) != self.result_digest:
            raise ValueError("campaign unit result digest mismatch")
        return self


class CandidateConsistency(CampaignModel):
    case_id: str = Field(min_length=1, max_length=128)
    successful_trials: int = Field(ge=0, le=5)
    planned_trials: int = Field(ge=1, le=5)
    empirical_success_rate: float = Field(ge=0.0, le=1.0)
    outcome: Literal["ALL_SUCCESS", "ALL_FAILURE", "MIXED", "INCOMPLETE"]


class CampaignCandidateSummary(CampaignModel):
    candidate_id: str = Field(min_length=1, max_length=128)
    status: CampaignCandidateStatus
    planned_units: int = Field(ge=0, le=350)
    completed_units: int = Field(ge=0, le=350)
    successful_trials: int = Field(ge=0, le=350)
    failed_trials: int = Field(ge=0, le=350)
    provider_failures: int = Field(ge=0, le=350)
    harness_failures: int = Field(ge=0, le=350)
    identity_failures: int = Field(ge=0, le=350)
    hard_safety_violations: int = Field(ge=0, le=350)
    unsupported_confirmations: int = Field(ge=0, le=350)
    task_success_rate: UsageMetric
    precision: UsageMetric
    recall: UsageMetric
    f1: UsageMetric
    input_tokens: UsageMetric
    output_tokens: UsageMetric
    measured_cost_usd: UsageMetric
    mean_latency_ms: UsageMetric
    tool_calls: int = Field(ge=0, le=100_000)
    model_calls: int = Field(ge=0, le=100_000)
    fallback_count: UsageMetric
    retry_count: UsageMetric
    failure_distribution: dict[str, int] = Field(default_factory=dict, max_length=64)
    category_success_rates: dict[str, UsageMetric] = Field(default_factory=dict, max_length=8)
    family_success_rates: dict[str, UsageMetric] = Field(default_factory=dict, max_length=32)
    per_case_consistency: list[CandidateConsistency] = Field(default_factory=list, max_length=35)
    all_trials_success_cases: int = Field(default=0, ge=0, le=35)
    all_trials_failure_cases: int = Field(default=0, ge=0, le=35)
    mixed_result_cases: int = Field(default=0, ge=0, le=35)
    case_success_histogram: dict[str, int] = Field(default_factory=dict, max_length=6)
    calls_by_node: dict[str, int] = Field(default_factory=dict, max_length=32)
    tool_calls_by_name: dict[str, int] = Field(default_factory=dict, max_length=32)
    tool_progress_by_name: dict[str, dict[str, int]] = Field(default_factory=dict, max_length=32)
    observed_model_pairs: list[str] = Field(default_factory=list, max_length=16)
    provider_returned_revisions: list[str] = Field(default_factory=list, max_length=16)
    registry_model_revision: str | None = Field(default=None, max_length=128)
    model_stability: ModelStability
    metric_scope: Literal["SCRIPTED_HARNESS_ONLY", "LIVE_PINNED_MODEL"]


class CampaignPairwiseComparison(CampaignModel):
    candidate_a: str = Field(min_length=1, max_length=128)
    candidate_b: str = Field(min_length=1, max_length=128)
    valid: bool
    outcome: Literal["MEANINGFUL_IMPROVEMENT", "LIKELY_REGRESSION", "INCONCLUSIVE", "INVALID_COMPARISON"]
    paired_trials: int = Field(ge=0, le=350)
    candidate_a_successes: int = Field(ge=0, le=350)
    candidate_b_successes: int = Field(ge=0, le=350)
    candidate_a_wilson_95: tuple[float, float] | None = None
    candidate_b_wilson_95: tuple[float, float] | None = None
    success_rate_delta_b_minus_a: float | None = Field(default=None, ge=-1.0, le=1.0)
    hard_safety_delta_b_minus_a: int | None = None
    evidence_success_delta_b_minus_a: float | None = Field(default=None, ge=-1.0, le=1.0)
    tool_calls_delta_per_trial: float | None = None
    latency_delta_ms_per_trial: float | None = None
    input_tokens_delta_per_trial: float | None = None
    output_tokens_delta_per_trial: float | None = None
    measured_cost_delta_usd_per_trial: float | None = None
    child_comparison_digests: list[str] = Field(default_factory=list, max_length=350)
    reasons: list[str] = Field(default_factory=list, max_length=32)


class CampaignStageReport(CampaignModel):
    schema_version: str = STAGE_REPORT_SCHEMA_VERSION
    campaign_id: str = Field(min_length=1, max_length=128)
    plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_revision: str = Field(pattern=r"^[0-9a-f]{40,64}$")
    stage: CampaignStage
    mode: Literal["SCRIPTED", "LIVE"]
    semantics: Literal["HARNESS_VALIDATION_ONLY", "PINNED_SINGLE_MODEL_CAMPAIGN"]
    execution_status: CampaignExecutionStatus
    started_at: datetime
    completed_at: datetime
    schedule_policy_version: str = SCHEDULE_POLICY_VERSION
    schedule: list[CampaignTrialUnit] = Field(max_length=350)
    schedule_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    unit_results: list[CampaignUnitResult] = Field(max_length=350)
    candidate_summaries: list[CampaignCandidateSummary] = Field(max_length=4)
    pairwise_comparisons: list[CampaignPairwiseComparison] = Field(max_length=6)
    full_stage_eligible_candidate_ids: list[str] = Field(default_factory=list, max_length=4)
    resource_usage: dict[str, int | float | str | None] = Field(max_length=32)
    review_status: ReviewStatus = ReviewStatus.NOT_REVIEWED
    report_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_stage_report(self) -> "CampaignStageReport":
        if self.schema_version != STAGE_REPORT_SCHEMA_VERSION:
            raise ValueError("unsupported campaign stage report schema")
        if self.schedule_digest != canonical_digest([item.model_dump(mode="json") for item in self.schedule]):
            raise ValueError("campaign stage schedule digest mismatch")
        expected_keys = [item.unit_key for item in self.schedule]
        result_keys = [item.unit.unit_key for item in self.unit_results]
        if result_keys != expected_keys:
            raise ValueError("campaign report must retain every scheduled unit exactly once in schedule order")
        if any(item.plan_digest != self.plan_digest for item in self.unit_results):
            raise ValueError("campaign unit belongs to a different frozen plan")
        if any(item.stage != self.stage for item in self.unit_results):
            raise ValueError("campaign report contains a unit from another stage")
        if self.mode == "SCRIPTED" and self.semantics != "HARNESS_VALIDATION_ONLY":
            raise ValueError("scripted campaign output cannot claim live model evidence")
        if self.mode == "LIVE" and self.semantics != "PINNED_SINGLE_MODEL_CAMPAIGN":
            raise ValueError("live campaign output must identify its pinned-model scope")
        if self.execution_status == CampaignExecutionStatus.COMPLETED and any(
            item.status == CampaignUnitStatus.NOT_EXECUTED for item in self.unit_results
        ):
            raise ValueError("completed campaign report contains unexecuted scheduled units")
        if any(item.candidate_id not in {entry.candidate_id for entry in self.candidate_summaries}
               for item in self.schedule):
            raise ValueError("campaign schedule references a missing candidate summary")
        payload = self.model_dump(mode="json", exclude={"report_digest"})
        if canonical_digest(payload) != self.report_digest:
            raise ValueError("campaign stage report digest mismatch")
        return self


class CampaignAnalysisReport(CampaignModel):
    schema_version: str = ANALYSIS_SCHEMA_VERSION
    campaign_id: str = Field(min_length=1, max_length=128)
    plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_revision: str = Field(pattern=r"^[0-9a-f]{40,64}$")
    stage_report_digests: list[str] = Field(min_length=1, max_length=8)
    review_sample_digests: list[str] = Field(default_factory=list, max_length=4)
    candidate_summaries: list[CampaignCandidateSummary] = Field(max_length=4)
    pairwise_comparisons: list[CampaignPairwiseComparison] = Field(max_length=6)
    quality_eligible_candidate_ids: list[str] = Field(default_factory=list, max_length=4)
    safety_blocked_candidate_ids: list[str] = Field(default_factory=list, max_length=4)
    reliability_blocked_candidate_ids: list[str] = Field(default_factory=list, max_length=4)
    inconclusive_candidate_ids: list[str] = Field(default_factory=list, max_length=4)
    pareto_candidate_ids: list[str] = Field(default_factory=list, max_length=4)
    security_gate_status: SupplementalGateStatus = SupplementalGateStatus.INCONCLUSIVE
    security_gate_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    context_tool_gate_status: SupplementalGateStatus = SupplementalGateStatus.INCONCLUSIVE
    context_tool_gate_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    human_review_eligible_candidate_ids: list[str] = Field(default_factory=list, max_length=2)
    review_status: ReviewStatus = ReviewStatus.NOT_REVIEWED
    report_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_digest(self) -> "CampaignAnalysisReport":
        if self.schema_version != ANALYSIS_SCHEMA_VERSION:
            raise ValueError("unsupported campaign analysis schema")
        payload = self.model_dump(mode="json", exclude={"report_digest"})
        if (
            self.security_gate_status != SupplementalGateStatus.PASS
            or self.context_tool_gate_status != SupplementalGateStatus.PASS
            or self.security_gate_digest is None
            or self.context_tool_gate_digest is None
        ) and (self.pareto_candidate_ids or self.human_review_eligible_candidate_ids):
            raise ValueError("campaign cannot recommend candidates before both separate gates pass")
        if not set(self.human_review_eligible_candidate_ids) <= set(self.pareto_candidate_ids):
            raise ValueError("human-review candidates must be a subset of the security-gated Pareto set")
        if canonical_digest(payload) != self.report_digest:
            raise ValueError("campaign analysis report digest mismatch")
        return self


class SupplementalGateCandidate(CampaignModel):
    candidate_id: str = Field(min_length=1, max_length=128)
    provider: LLMProvider
    model: str = Field(min_length=1, max_length=256)
    system_identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    report_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_path: str = Field(pattern=r"^(security|context_tool)/[a-zA-Z0-9._:-]+\.json$")
    status: SupplementalGateStatus
    metrics: dict[str, int | float | str | bool | None] = Field(max_length=32)


class CampaignSupplementalGateReport(CampaignModel):
    schema_version: str = "live-model-campaign-gate/1.0"
    campaign_id: str = Field(min_length=1, max_length=128)
    plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_revision: str = Field(pattern=r"^[0-9a-f]{40,64}$")
    gate: SupplementalGateKind
    status: SupplementalGateStatus
    candidates: list[SupplementalGateCandidate] = Field(min_length=2, max_length=2)
    resource_usage: dict[str, int | float | str | None] = Field(max_length=24)
    evaluated_at: datetime
    report_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_gate_report(self) -> "CampaignSupplementalGateReport":
        if self.schema_version != "live-model-campaign-gate/1.0":
            raise ValueError("unsupported supplemental campaign gate schema")
        if len({item.candidate_id for item in self.candidates}) != len(self.candidates):
            raise ValueError("supplemental gate candidate IDs must be distinct")
        statuses = {item.status for item in self.candidates}
        expected = (
            SupplementalGateStatus.PASS if statuses == {SupplementalGateStatus.PASS}
            else SupplementalGateStatus.HARD_FAIL if SupplementalGateStatus.HARD_FAIL in statuses
            else SupplementalGateStatus.INVALID if SupplementalGateStatus.INVALID in statuses
            else SupplementalGateStatus.INCONCLUSIVE
        )
        if self.status != expected:
            raise ValueError("aggregate gate status differs from child candidate gates")
        payload = self.model_dump(mode="json", exclude={"report_digest"})
        if canonical_digest(payload) != self.report_digest:
            raise ValueError("supplemental gate report digest mismatch")
        return self


class CampaignReviewSample(CampaignModel):
    schema_version: str = "live-model-campaign-review-sample/1.0"
    campaign_id: str = Field(min_length=1, max_length=128)
    plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_revision: str = Field(pattern=r"^[0-9a-f]{40,64}$")
    candidate_id: str = Field(min_length=1, max_length=128)
    provider: LLMProvider
    model: str = Field(min_length=1, max_length=256)
    system_identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_report_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    case_id: str = Field(min_length=1, max_length=128)
    trial_number: int = Field(ge=1, le=5)
    grade: SystemTrialGrade
    failure_attribution_class: str | None = Field(default=None, max_length=64)
    workflow_trace: list[WorkflowNodeEvent] = Field(max_length=128)
    sample_policy_version: str = "live-model-campaign-review-sample/1.0"
    sample_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_sample(self) -> "CampaignReviewSample":
        if self.grade.case_id != self.case_id or self.grade.trial_number != self.trial_number:
            raise ValueError("review sample trial identity does not match its bounded source")
        payload = self.model_dump(mode="json", exclude={"sample_digest"})
        if canonical_digest(payload) != self.sample_digest:
            raise ValueError("review sample digest mismatch")
        return self


def digest_model(model: BaseModel, *, exclude: set[str] | None = None) -> str:
    return canonical_digest(model.model_dump(mode="json", exclude=exclude or set()))


__all__ = [
    "ANALYSIS_SCHEMA_VERSION", "CampaignAnalysisReport", "CampaignCandidate",
    "CampaignCandidateStatus", "CampaignCandidateSummary", "CampaignExecutionStatus",
    "CampaignPairwiseComparison", "CampaignStage", "CampaignStagePolicy", "CampaignStageReport",
    "CampaignReviewSample",
    "CampaignSupplementalGateReport", "SupplementalGateCandidate", "SupplementalGateKind", "SupplementalGateStatus",
    "CampaignTrialUnit", "CampaignUnitResult", "CampaignUnitStatus", "ModelEvaluationCampaignPlan",
    "ModelStability", "PLAN_SCHEMA_VERSION", "ReviewStatus", "STAGE_REPORT_SCHEMA_VERSION",
    "UsageMetric", "build_digested_model", "canonical_digest", "digest_model", "utc_now",
]
