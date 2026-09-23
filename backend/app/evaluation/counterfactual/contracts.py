"""Content-minimized, integrity-bound replay artifacts."""

from __future__ import annotations

import hashlib
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.evaluation.agent.loader import canonical_json


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _canonicalize(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return _canonicalize(value.model_dump(mode="json"))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _canonicalize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonicalize(item) for item in value]
    return value


class ReplayModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CounterfactualInterventionKind(str, Enum):
    VERIFIER_ACCEPT_MATCHED_FINDING = "VERIFIER_ACCEPT_MATCHED_FINDING"
    VERIFIER_REJECT_UNSUPPORTED_FINDING = "VERIFIER_REJECT_UNSUPPORTED_FINDING"
    REVISION_RESTORE_VALID_CANDIDATE = "REVISION_RESTORE_VALID_CANDIDATE"


class CounterfactualEffect(str, Enum):
    FULL_RESCUE = "FULL_RESCUE"
    PARTIAL_RESCUE = "PARTIAL_RESCUE"
    NO_EFFECT = "NO_EFFECT"
    REGRESSION = "REGRESSION"
    INCONCLUSIVE = "INCONCLUSIVE"
    INVALID_REPLAY = "INVALID_REPLAY"
    NOT_REPLAYABLE = "NOT_REPLAYABLE"


class ReplayMetricStatus(str, Enum):
    MEASURED = "MEASURED"
    NOT_MEASURED = "NOT_MEASURED"


class ReplayMetric(ReplayModel):
    status: ReplayMetricStatus
    value: float | None = None
    unit: str = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def validate_value(self) -> "ReplayMetric":
        if (self.status == ReplayMetricStatus.MEASURED) != (self.value is not None):
            raise ValueError("replay metric value must be present exactly when measured")
        return self


class ReplayOutcomeMetrics(ReplayModel):
    success: bool
    tp: int = Field(ge=0)
    fp: int = Field(ge=0)
    fn: int = Field(ge=0)
    unsupported_claims: int = Field(ge=0)
    invalid_references: int = Field(ge=0)
    hard_safety_violation: bool


class CounterfactualIntervention(ReplayModel):
    schema_version: Literal["counterfactual-intervention/1.0"] = "counterfactual-intervention/1.0"
    intervention_kind: CounterfactualInterventionKind
    case_id: str = Field(min_length=1, max_length=128)
    trial_number: int = Field(ge=1, le=5)
    failure_class: str = Field(min_length=1, max_length=64)
    target_node: Literal["verifier", "revise"]
    target_finding_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_id: str = Field(min_length=1, max_length=128)
    factual_trial_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    checkpoint_id_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    checkpoint_state_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    system_identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    graph_identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    evaluation_contract_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    before_state_projection_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    changed_state_projection_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    state_fields_changed: tuple[
        Literal[
            "verified_findings",
            "rejected_findings",
            "revision_candidates",
            "revision_count",
            "verification_decision",
            "revision_target_ids",
        ], ...
    ] = Field(min_length=1, max_length=6)
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_digest(self) -> "CounterfactualIntervention":
        payload = self.model_dump(mode="json", exclude={"digest"})
        if self.digest != canonical_digest(payload):
            raise ValueError("counterfactual intervention digest does not match its content")
        if len(set(self.state_fields_changed)) != len(self.state_fields_changed):
            raise ValueError("intervention state field inventory must be unique")
        return self


class ReplayTraceEvent(ReplayModel):
    node: str = Field(min_length=1, max_length=64)
    status: Literal["COMPLETED", "COMPLETED_WITH_ERRORS"]
    input_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    output_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    model_calls: int = Field(ge=0)
    tool_calls: int = Field(ge=0)
    failure_codes: tuple[str, ...] = Field(default=(), max_length=16)


class CounterfactualReplayTrialResult(ReplayModel):
    schema_version: Literal["counterfactual-replay-trial/1.0"] = "counterfactual-replay-trial/1.0"
    case_id: str = Field(min_length=1, max_length=128)
    trial_number: int = Field(ge=1, le=5)
    failure_class: str | None = Field(default=None, max_length=64)
    execution_status: Literal["COMPLETED", "NOT_REPLAYABLE", "INCONCLUSIVE", "INVALID_REPLAY"]
    effect: CounterfactualEffect
    reason_code: str = Field(min_length=1, max_length=64)
    intervention: CounterfactualIntervention | None = None
    factual: ReplayOutcomeMetrics | None = None
    counterfactual: ReplayOutcomeMetrics | None = None
    replay_index: int | None = Field(default=None, ge=1, le=3)
    target_finding_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    downstream_nodes: tuple[str, ...] = Field(default=(), max_length=32)
    trace: tuple[ReplayTraceEvent, ...] = Field(default=(), max_length=32)
    model_calls: int = Field(default=0, ge=0)
    tool_calls: int = Field(default=0, ge=0)
    input_tokens: ReplayMetric
    output_tokens: ReplayMetric
    cost_usd: ReplayMetric
    duration_ms: float = Field(default=0.0, ge=0.0)
    result_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_result(self) -> "CounterfactualReplayTrialResult":
        payload = self.model_dump(mode="json", exclude={"result_digest"})
        if self.result_digest != canonical_digest(payload):
            raise ValueError("counterfactual replay result digest does not match its content")
        if self.effect == CounterfactualEffect.NOT_REPLAYABLE:
            if self.execution_status != "NOT_REPLAYABLE" or self.intervention is not None:
                raise ValueError("not-replayable results cannot carry an intervention")
        elif self.effect in {CounterfactualEffect.FULL_RESCUE, CounterfactualEffect.PARTIAL_RESCUE,
                             CounterfactualEffect.NO_EFFECT, CounterfactualEffect.REGRESSION}:
            if self.execution_status != "COMPLETED" or self.intervention is None or self.counterfactual is None:
                raise ValueError("completed replay effects require a completed intervention and grade")
        if self.execution_status in {"INCONCLUSIVE", "INVALID_REPLAY"} and self.effect not in {
            CounterfactualEffect.INCONCLUSIVE, CounterfactualEffect.INVALID_REPLAY,
        }:
            raise ValueError("incomplete replay status must use an incomplete effect")
        return self


class CounterfactualReplayReport(ReplayModel):
    schema_version: Literal["counterfactual-replay-report/1.0"] = "counterfactual-replay-report/1.0"
    factual_report_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    system_identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    graph_identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    evaluation_contract_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    execution_mode: Literal["SCRIPTED_HARNESS_VALIDATION_ONLY", "LIVE_DIAGNOSTIC"]
    policy_version: str = Field(min_length=1, max_length=64)
    # At most one factual record per planned trial plus the six policy-bounded
    # replay branches can appear in the artifact.
    trial_results: tuple[CounterfactualReplayTrialResult, ...] = Field(max_length=326)
    replayable_trials: int = Field(ge=0)
    not_replayable_trials: int = Field(ge=0)
    attempted_branches: int = Field(ge=0, le=6)
    full_rescues: int = Field(ge=0, le=6)
    partial_rescues: int = Field(ge=0, le=6)
    no_effect: int = Field(ge=0, le=6)
    regressions: int = Field(ge=0, le=6)
    inconclusive: int = Field(ge=0, le=326)
    invalid_replays: int = Field(ge=0, le=326)
    rescue_rate: ReplayMetric
    total_model_calls: int = Field(ge=0, le=12)
    total_tool_calls: int = Field(ge=0)
    total_input_tokens: ReplayMetric
    total_output_tokens: ReplayMetric
    total_cost_usd: ReplayMetric
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_report(self) -> "CounterfactualReplayReport":
        completed = [item for item in self.trial_results if item.execution_status == "COMPLETED"]
        derived = {
            "replayable_trials": len({(item.case_id, item.trial_number) for item in completed}),
            "not_replayable_trials": sum(item.effect == CounterfactualEffect.NOT_REPLAYABLE for item in self.trial_results),
            "attempted_branches": sum(item.replay_index is not None for item in self.trial_results),
            "full_rescues": sum(item.effect == CounterfactualEffect.FULL_RESCUE for item in completed),
            "partial_rescues": sum(item.effect == CounterfactualEffect.PARTIAL_RESCUE for item in completed),
            "no_effect": sum(item.effect == CounterfactualEffect.NO_EFFECT for item in completed),
            "regressions": sum(item.effect == CounterfactualEffect.REGRESSION for item in completed),
            "inconclusive": sum(item.effect == CounterfactualEffect.INCONCLUSIVE for item in self.trial_results),
            "invalid_replays": sum(item.effect == CounterfactualEffect.INVALID_REPLAY for item in self.trial_results),
            "total_model_calls": sum(item.model_calls for item in self.trial_results),
            "total_tool_calls": sum(item.tool_calls for item in self.trial_results),
        }
        if any(getattr(self, key) != value for key, value in derived.items()):
            raise ValueError("counterfactual replay aggregate counts disagree with trial records")
        rescue_rate = (
            derived["full_rescues"] / len(completed)
            if completed else None
        )
        if self.rescue_rate.status == ReplayMetricStatus.MEASURED:
            if self.rescue_rate.value != rescue_rate:
                raise ValueError("counterfactual rescue rate disagrees with trial records")
        elif rescue_rate is not None:
            raise ValueError("completed replay branches require a measured rescue rate")
        payload = self.model_dump(mode="json", exclude={"digest"})
        if self.digest != canonical_digest(payload):
            raise ValueError("counterfactual replay report digest does not match its content")
        return self


def make_intervention(**fields: Any) -> CounterfactualIntervention:
    payload = _canonicalize({"schema_version": "counterfactual-intervention/1.0", **fields})
    payload["digest"] = canonical_digest(payload)
    return CounterfactualIntervention.model_validate(payload)


def make_trial_result(**fields: Any) -> CounterfactualReplayTrialResult:
    payload = _canonicalize({"schema_version": "counterfactual-replay-trial/1.0", **fields})
    payload["result_digest"] = canonical_digest(payload)
    return CounterfactualReplayTrialResult.model_validate(payload)


def make_replay_report(**fields: Any) -> CounterfactualReplayReport:
    payload = _canonicalize({"schema_version": "counterfactual-replay-report/1.0", **fields})
    payload["digest"] = canonical_digest(payload)
    return CounterfactualReplayReport.model_validate(payload)
