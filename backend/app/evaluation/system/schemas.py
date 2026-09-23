"""Closed reports and promotion contracts for bounded system evaluations."""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.llm.types import LLMProvider


class SystemEvalModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SystemEvalSuite(str, Enum):
    ALL = "ALL"
    REGRESSION = "REGRESSION"
    CAPABILITY = "CAPABILITY"
    SECURITY = "SECURITY"


class FailureClass(str, Enum):
    """Deterministic, evidence-backed causes for full-graph evaluation failures."""

    VERIFIER_FALSE_REJECTION = "VERIFIER_FALSE_REJECTION"
    VERIFIER_FALSE_CONFIRMATION = "VERIFIER_FALSE_CONFIRMATION"
    INVESTIGATOR_NOT_TRIGGERED = "INVESTIGATOR_NOT_TRIGGERED"
    INVESTIGATOR_INSUFFICIENT_EVIDENCE = "INVESTIGATOR_INSUFFICIENT_EVIDENCE"
    INVESTIGATOR_TOOL_FAILURE = "INVESTIGATOR_TOOL_FAILURE"
    REVISION_FAILED_TO_REPAIR = "REVISION_FAILED_TO_REPAIR"
    MODEL_PROVIDER_FAILURE = "MODEL_PROVIDER_FAILURE"
    BUDGET_EXHAUSTION = "BUDGET_EXHAUSTION"
    STAGNATION = "STAGNATION"
    HARNESS_FAILURE = "HARNESS_FAILURE"
    SECURITY_POLICY_VIOLATION = "SECURITY_POLICY_VIOLATION"
    UNKNOWN_ATTRIBUTION = "UNKNOWN_ATTRIBUTION"


class WorkflowNodeEvent(SystemEvalModel):
    """Content-free event captured at a production graph node boundary."""

    sequence: int = Field(ge=1, le=256)
    node: str = Field(min_length=1, max_length=64)
    superstep: int = Field(ge=0, le=256)
    status: Literal["COMPLETED", "COMPLETED_WITH_ERRORS"]
    duration_ms: float = Field(ge=0.0)
    input_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    output_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_ids: list[str] = Field(default_factory=list, max_length=64)
    verified_ids: list[str] = Field(default_factory=list, max_length=64)
    rejected_ids: list[str] = Field(default_factory=list, max_length=64)
    finding_refs: list[dict[str, Any]] = Field(default_factory=list, max_length=64)
    model_identities: list[str] = Field(default_factory=list, max_length=16)
    model_execution_count: int | None = Field(default=None, ge=0, le=10_000)
    tool_names: list[str] = Field(default_factory=list, max_length=16)
    tool_call_digests: list[Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]] = Field(default_factory=list, max_length=16)
    tool_execution_count: int = Field(default=0, ge=0, le=16)
    evidence_count: int = Field(default=0, ge=0)
    budget_exhausted: bool = False
    failure_codes: list[str] = Field(default_factory=list, max_length=16)


class FailureAttribution(SystemEvalModel):
    """Deterministic causal diagnosis; unknown is preferred over speculation."""

    case_id: str = Field(min_length=1, max_length=128)
    failure_stage: str = Field(min_length=1, max_length=64)
    failure_class: FailureClass
    primary_node: str | None = Field(default=None, max_length=64)
    upstream_condition: str = Field(min_length=1, max_length=256)
    observed_behavior: str = Field(min_length=1, max_length=512)
    expected_behavior: str = Field(min_length=1, max_length=512)
    evidence_refs: list[str] = Field(default_factory=list, max_length=32)
    downstream_effect: str = Field(min_length=1, max_length=512)
    hard_safety_violation: bool = False
    confidence_basis: str = Field(min_length=1, max_length=512)


class FullAnalysisTrialDetail(SystemEvalModel):
    """Bounded workflow trace and structural ground-truth result for one trial."""

    case_id: str = Field(min_length=1, max_length=128)
    trial_number: int = Field(ge=1, le=5)
    workflow_status: str = Field(min_length=1, max_length=32)
    evaluation_stage: Literal["STATIC_FINDING", "ANALYSIS_CANDIDATE", "PUBLISHED_FINDING"]
    tp: int = Field(ge=0)
    fp: int = Field(ge=0)
    fn: int = Field(ge=0)
    clean_case_tn: bool = False
    unknown_abstained: bool | None = None
    category_evaluated_claims: int = Field(default=0, ge=0)
    category_mismatches: int = Field(default=0, ge=0)
    severity_evaluated_claims: int = Field(default=0, ge=0)
    severity_mismatches: int = Field(default=0, ge=0)
    invalid_references: int = Field(default=0, ge=0)
    unsupported_claims: int = Field(default=0, ge=0)
    published_unsupported_confirmations: int = Field(default=0, ge=0)
    security_violation_codes: list[str] = Field(default_factory=list, max_length=32)
    workflow_trace: list[WorkflowNodeEvent] = Field(default_factory=list, max_length=128)
    failure_attribution: FailureAttribution | None = None
    resumed: bool = False
    duration_ms: float = Field(ge=0.0)


class FullAnalysisMetrics(SystemEvalModel):
    case_count: int = Field(ge=0)
    trial_count: int = Field(ge=0)
    tp: int = Field(ge=0)
    fp: int = Field(ge=0)
    fn: int = Field(ge=0)
    true_negatives: int = Field(ge=0)
    category_evaluated_claims: int = Field(default=0, ge=0)
    category_mismatches: int = Field(default=0, ge=0)
    severity_evaluated_claims: int = Field(default=0, ge=0)
    severity_mismatches: int = Field(default=0, ge=0)
    unsupported_confirmations: int = Field(ge=0)
    hard_safety_violations: int = Field(ge=0)
    provider_failures: int = Field(ge=0)
    budget_exhaustions: int = Field(ge=0)
    harness_failures: int = Field(ge=0)
    failed_node_events: int = Field(ge=0)
    investigator_triggered_trials: int = Field(ge=0)
    revision_trials: int = Field(ge=0)
    node_event_count: int = Field(ge=0)
    tool_calls: int = Field(ge=0)
    model_calls: int = Field(ge=0)
    mean_latency_ms: MeasuredMetric
    precision: MeasuredMetric
    recall: MeasuredMetric
    f1: MeasuredMetric
    attribution_counts: dict[str, int] = Field(default_factory=dict)
    branch_counts: dict[str, int] = Field(default_factory=dict)


class FullAnalysisReportDetails(SystemEvalModel):
    """Scope-specific facts for the real production AnalysisState graph."""

    graph_contract_version: str = Field(min_length=1, max_length=64)
    graph_identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    dataset_split: Literal["DEV"] = "DEV"
    target_pipeline: Literal["REPOSITORY_SCAN"] = "REPOSITORY_SCAN"
    dataset_case_count: int = Field(ge=1, le=64)
    trial_details: list[FullAnalysisTrialDetail] = Field(max_length=320)
    metrics: FullAnalysisMetrics


class SystemEvalMode(str, Enum):
    SCRIPTED = "SCRIPTED"
    LIVE = "LIVE"


class EvaluationRunStatus(str, Enum):
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    NOT_EXECUTED = "NOT_EXECUTED"


class TrialOutcome(str, Enum):
    SUCCESS = "SUCCESS"
    TASK_FAILED = "TASK_FAILED"
    PROVIDER_FAILED = "PROVIDER_FAILED"
    HARNESS_FAILED = "HARNESS_FAILED"
    INVALID_OUTPUT = "INVALID_OUTPUT"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    SECURITY_VIOLATION = "SECURITY_VIOLATION"
    NOT_EXECUTED = "NOT_EXECUTED"


class MetricStatus(str, Enum):
    MEASURED = "MEASURED"
    NOT_MEASURED = "NOT_MEASURED"


class MeasuredMetric(SystemEvalModel):
    status: MetricStatus
    value: float | None = None
    unit: str = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def validate_measurement(self) -> "MeasuredMetric":
        if (self.status == MetricStatus.MEASURED) != (self.value is not None):
            raise ValueError("measured values must be present exactly when status is MEASURED")
        return self


class SystemTrajectoryEvent(SystemEvalModel):
    step_number: int = Field(ge=1, le=6)
    action: str | None = Field(default=None, max_length=32)
    tool_name: str | None = Field(default=None, max_length=128)
    argument_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    result_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    status: str = Field(min_length=1, max_length=64)
    provider: str | None = Field(default=None, max_length=64)
    model: str | None = Field(default=None, max_length=256)
    duration_ms: float = Field(default=0.0, ge=0.0)
    context_bytes: int = Field(default=0, ge=0)
    evidence_refs: list[str] = Field(default_factory=list, max_length=32)


class SystemTrialGrade(SystemEvalModel):
    case_id: str = Field(min_length=1, max_length=128)
    trial_number: int = Field(ge=1, le=5)
    outcome: TrialOutcome
    task_success: bool | None = None
    stop_reason: str | None = Field(default=None, max_length=64)
    evidence_valid: bool | None = None
    abstained: bool | None = None
    checkpoint_resumed: bool = False
    trajectory: list[SystemTrajectoryEvent] = Field(default_factory=list, max_length=6)
    tool_calls: int = Field(default=0, ge=0)
    model_calls: int = Field(default=0, ge=0)
    max_context_bytes: int = Field(default=0, ge=0)
    unsafe_tool_requests: int = Field(default=0, ge=0)
    unsafe_tool_executions: int = Field(default=0, ge=0)
    invalid_tool_arguments: int = Field(default=0, ge=0)
    duplicate_tool_calls: int = Field(default=0, ge=0)
    provider: LLMProvider | None = None
    model: str | None = Field(default=None, max_length=256)
    latency_ms: MeasuredMetric
    input_tokens: MeasuredMetric
    output_tokens: MeasuredMetric
    cost_usd: MeasuredMetric
    fallback_count: int | None = Field(default=None, ge=0)
    retry_count: int | None = Field(default=None, ge=0)
    safety_violation_codes: list[str] = Field(default_factory=list, max_length=32)

    @model_validator(mode="after")
    def validate_outcome_consistency(self) -> "SystemTrialGrade":
        if (self.outcome == TrialOutcome.SUCCESS) != (self.task_success is True):
            raise ValueError("successful trial outcomes must agree with task_success")
        if self.outcome == TrialOutcome.SECURITY_VIOLATION and (
            self.task_success is not False or not self.safety_violation_codes
        ):
            raise ValueError("security violations must fail the task and carry a safety code")
        if self.outcome != TrialOutcome.SECURITY_VIOLATION and self.safety_violation_codes and any(
            code in {"UNAUTHORIZED_TOOL_EXECUTED", "CANDIDATE_IDENTITY_MISMATCH"}
            for code in self.safety_violation_codes
        ):
            raise ValueError("hard safety codes require a SECURITY_VIOLATION outcome")
        return self


class SystemCaseResults(SystemEvalModel):
    case_id: str = Field(min_length=1, max_length=128)
    category: str = Field(min_length=1, max_length=128)
    split: Literal["REGRESSION", "CAPABILITY", "DEV", "FROZEN_PUBLIC_EVAL"]
    trials: list[SystemTrialGrade] = Field(min_length=1, max_length=5)

    @model_validator(mode="after")
    def validate_trials(self) -> "SystemCaseResults":
        if any(item.case_id != self.case_id for item in self.trials):
            raise ValueError("nested trial case IDs must match the parent case")
        numbers = [item.trial_number for item in self.trials]
        if len(numbers) != len(set(numbers)):
            raise ValueError("trial numbers must be unique within a case")
        return self


class SystemEvaluationMetrics(SystemEvalModel):
    task_count: int = Field(ge=0)
    trial_count: int = Field(ge=0)
    successful_trials: int = Field(ge=0)
    failed_trials: int = Field(ge=0)
    task_success_rate: MeasuredMetric
    mean_per_case_success_rate: MeasuredMetric
    all_trials_consistency_rate: MeasuredMetric
    required_evidence_trials: int = Field(ge=0)
    evidence_success_rate: MeasuredMetric
    correct_abstentions: int = Field(ge=0)
    correct_abstention_rate: MeasuredMetric
    false_abstentions: int = Field(ge=0)
    false_abstention_rate: MeasuredMetric
    unsafe_tool_requests: int = Field(ge=0)
    unsafe_tool_executions: int = Field(ge=0)
    invalid_tool_arguments: int = Field(ge=0)
    duplicate_tool_calls: int = Field(ge=0)
    provider_failures: int = Field(ge=0)
    harness_failures: int = Field(ge=0)
    budget_exhaustions: int = Field(ge=0)
    context_budget_exhaustions: int = Field(ge=0)
    checkpoint_resumed_trials: int = Field(ge=0)
    checkpoint_duplicate_tool_calls: int = Field(ge=0)
    hard_safety_violations: int = Field(ge=0)
    tool_calls: int = Field(ge=0)
    model_calls: int = Field(ge=0)
    tool_calls_per_trial: MeasuredMetric
    model_calls_per_trial: MeasuredMetric
    tool_calls_per_successful_task: MeasuredMetric
    model_calls_per_successful_task: MeasuredMetric
    latency_ms_per_trial: MeasuredMetric
    input_tokens: MeasuredMetric
    output_tokens: MeasuredMetric
    cost_usd: MeasuredMetric
    fallback_count: MeasuredMetric
    retry_count: MeasuredMetric
    max_context_bytes: MeasuredMetric
    regression_failures: int = Field(ge=0)
    security_case_count: int = Field(ge=0)


class SystemSuiteMetrics(SystemEvalModel):
    suite: SystemEvalSuite
    task_count: int = Field(ge=0)
    trial_count: int = Field(ge=0)
    success_rate: MeasuredMetric
    hard_safety_violations: int = Field(ge=0)


class SystemTrialPolicy(SystemEvalModel):
    trials_per_case: int = Field(ge=1, le=5)
    max_cases: int = Field(ge=1, le=64)
    concurrency: Literal[1] = 1
    fresh_checkpoint_per_trial: Literal[True] = True
    cache_policy: Literal["DISABLED"] = "DISABLED"


class SystemEvaluationReport(SystemEvalModel):
    schema_version: Literal["agent-system-eval-report/1.0", "agent-system-eval-report/1.1"] = "agent-system-eval-report/1.0"
    mode: SystemEvalMode
    scope: Literal["PRODUCTION_EVIDENCE_INVESTIGATOR_GRAPH", "FULL_ANALYSIS_GRAPH"] = "PRODUCTION_EVIDENCE_INVESTIGATOR_GRAPH"
    dataset_version: str = Field(min_length=1, max_length=64)
    dataset_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    evaluation_contract_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    suite: SystemEvalSuite
    expected_case_ids: list[str] = Field(min_length=1, max_length=64)
    evaluated_case_ids: list[str] = Field(max_length=64)
    trial_policy: SystemTrialPolicy
    execution_status: EvaluationRunStatus
    system_identity: "AgentSystemIdentity"
    case_results: list[SystemCaseResults] = Field(default_factory=list, max_length=64)
    suite_metrics: list[SystemSuiteMetrics] = Field(min_length=1, max_length=4)
    metrics: SystemEvaluationMetrics
    full_analysis: FullAnalysisReportDetails | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    report_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_report_shape(self) -> "SystemEvaluationReport":
        if self.schema_version == "agent-system-eval-report/1.0":
            if self.scope != "PRODUCTION_EVIDENCE_INVESTIGATOR_GRAPH" or self.full_analysis is not None:
                raise ValueError("legacy report schema is reserved for investigator-graph scope")
        elif self.scope != "FULL_ANALYSIS_GRAPH" or self.full_analysis is None:
            raise ValueError("report schema 1.1 requires full-analysis scope details")
        ids = [item.case_id for item in self.case_results]
        if len(ids) != len(set(ids)) or ids != self.evaluated_case_ids:
            raise ValueError("case result IDs must uniquely match evaluated_case_ids in order")
        if not set(self.evaluated_case_ids).issubset(set(self.expected_case_ids)):
            raise ValueError("evaluated cases must be a subset of the declared suite")
        expected_status = (
            EvaluationRunStatus.COMPLETED
            if self.evaluated_case_ids == self.expected_case_ids
            and all(len(item.trials) == self.trial_policy.trials_per_case for item in self.case_results)
            else EvaluationRunStatus.PARTIAL
        )
        if self.execution_status != EvaluationRunStatus.NOT_EXECUTED and self.execution_status != expected_status:
            raise ValueError("execution status does not match planned and completed case/trial counts")
        if self.execution_status == EvaluationRunStatus.NOT_EXECUTED and self.case_results:
            raise ValueError("NOT_EXECUTED reports cannot contain case results")
        if self.full_analysis is not None:
            details = self.full_analysis
            if (
                self.system_identity.scope != "FULL_ANALYSIS_GRAPH"
                or self.system_identity.graph_identity_digest != details.graph_identity_digest
                or self.system_identity.graph_contract_version != details.graph_contract_version
                or self.evaluation_contract_hash != self.system_identity.evaluation_contract_hash
            ):
                raise ValueError("full-analysis report, identity, graph, and evaluator contracts disagree")
            if details.dataset_case_count != len(self.expected_case_ids):
                raise ValueError("full-analysis dataset size must match the declared case inventory")
            expected_pairs = {
                (case.case_id, trial.trial_number)
                for case in self.case_results for trial in case.trials
            }
            actual_pairs = {(item.case_id, item.trial_number) for item in details.trial_details}
            if expected_pairs != actual_pairs or len(actual_pairs) != len(details.trial_details):
                raise ValueError("full-analysis trial detail inventory must match graded trial inventory")
            if details.metrics.case_count != len(self.case_results):
                raise ValueError("full-analysis case count disagrees with child case results")
            if details.metrics.trial_count != len(details.trial_details):
                raise ValueError("full-analysis aggregate trial count disagrees with child records")
            if details.metrics.hard_safety_violations != sum(
                bool(item.security_violation_codes) for item in details.trial_details
            ):
                raise ValueError("full-analysis safety aggregate disagrees with child records")
            derived_full = {
                "case_count": len(self.case_results),
                "tp": sum(item.tp for item in details.trial_details),
                "fp": sum(item.fp for item in details.trial_details),
                "fn": sum(item.fn for item in details.trial_details),
                "true_negatives": sum(item.clean_case_tn for item in details.trial_details),
                "category_evaluated_claims": sum(item.category_evaluated_claims for item in details.trial_details),
                "category_mismatches": sum(item.category_mismatches for item in details.trial_details),
                "severity_evaluated_claims": sum(item.severity_evaluated_claims for item in details.trial_details),
                "severity_mismatches": sum(item.severity_mismatches for item in details.trial_details),
                "unsupported_confirmations": sum(
                    item.published_unsupported_confirmations for item in details.trial_details
                ),
                "provider_failures": sum(item.outcome == TrialOutcome.PROVIDER_FAILED for case in self.case_results for item in case.trials),
                "budget_exhaustions": sum(item.outcome == TrialOutcome.BUDGET_EXHAUSTED for case in self.case_results for item in case.trials),
                "harness_failures": sum(item.outcome == TrialOutcome.HARNESS_FAILED for case in self.case_results for item in case.trials),
                "failed_node_events": sum(
                    event.status == "COMPLETED_WITH_ERRORS"
                    for item in details.trial_details for event in item.workflow_trace
                ),
                "investigator_triggered_trials": sum(any(event.node == "investigator_prepare" for event in item.workflow_trace) for item in details.trial_details),
                "revision_trials": sum(any(event.node == "revise" for event in item.workflow_trace) for item in details.trial_details),
                "node_event_count": sum(len(item.workflow_trace) for item in details.trial_details),
                "tool_calls": sum(sum(event.tool_execution_count for event in item.workflow_trace) for item in details.trial_details),
                "model_calls": sum(sum(
                    event.model_execution_count if event.model_execution_count is not None else len(event.model_identities)
                    for event in item.workflow_trace
                ) for item in details.trial_details),
            }
            if any(getattr(details.metrics, name) != value for name, value in derived_full.items()):
                raise ValueError("full-analysis aggregate metrics disagree with child trial details")
            expected_precision = (
                derived_full["tp"] / (derived_full["tp"] + derived_full["fp"])
                if derived_full["tp"] + derived_full["fp"]
                else (1.0 if derived_full["fn"] == 0 else 0.0)
            )
            expected_recall = (
                derived_full["tp"] / (derived_full["tp"] + derived_full["fn"])
                if derived_full["tp"] + derived_full["fn"] else None
            )
            expected_f1 = (
                2 * expected_precision * expected_recall / (expected_precision + expected_recall)
                if expected_recall is not None and expected_precision + expected_recall else None
            )
            for name, expected in (
                ("precision", expected_precision),
                ("recall", expected_recall),
                ("f1", expected_f1),
            ):
                metric = getattr(details.metrics, name)
                if metric.status == MetricStatus.MEASURED:
                    if metric.value != expected:
                        raise ValueError(f"full-analysis {name} disagrees with child trial records")
                elif expected is not None:
                    raise ValueError(f"full-analysis {name} must be measured when derivable")
            expected_attributions: dict[str, int] = {}
            expected_branches: dict[str, int] = {}
            for item in details.trial_details:
                if item.failure_attribution is not None:
                    key = item.failure_attribution.failure_class.value
                    expected_attributions[key] = expected_attributions.get(key, 0) + 1
                for event in item.workflow_trace:
                    expected_branches[event.node] = expected_branches.get(event.node, 0) + 1
            if details.metrics.attribution_counts != expected_attributions or details.metrics.branch_counts != expected_branches:
                raise ValueError("full-analysis attribution/branch metrics disagree with child records")
        trials = [trial for item in self.case_results for trial in item.trials]
        if self.mode == SystemEvalMode.LIVE:
            expected_identity = (
                self.system_identity.model_provider,
                self.system_identity.model_identifier,
            )
            if self.system_identity.model_provider is None:
                raise ValueError("live reports must identify the selected provider")
            for trial in trials:
                actual_identity = (trial.provider, trial.model)
                if trial.task_success is True and actual_identity != expected_identity:
                    raise ValueError("a successful live trial must prove the selected provider/model executed")
                if actual_identity != expected_identity and actual_identity != (None, None) and (
                    trial.outcome != TrialOutcome.SECURITY_VIOLATION
                ):
                    raise ValueError("provider/model drift must be represented as a hard safety violation")
        derived = {
            "task_count": len(self.case_results),
            "trial_count": len(trials),
            "successful_trials": sum(item.task_success is True for item in trials),
            "failed_trials": sum(item.task_success is False for item in trials),
            "unsafe_tool_requests": sum(item.unsafe_tool_requests for item in trials),
            "unsafe_tool_executions": sum(item.unsafe_tool_executions for item in trials),
            "invalid_tool_arguments": sum(item.invalid_tool_arguments for item in trials),
            "duplicate_tool_calls": sum(item.duplicate_tool_calls for item in trials),
            "provider_failures": sum(item.outcome == TrialOutcome.PROVIDER_FAILED for item in trials),
            "harness_failures": sum(item.outcome == TrialOutcome.HARNESS_FAILED for item in trials),
            "budget_exhaustions": sum(item.outcome == TrialOutcome.BUDGET_EXHAUSTED for item in trials),
            "context_budget_exhaustions": sum(
                item.stop_reason == "CONTEXT_BUDGET_EXCEEDED" for item in trials
            ),
            "checkpoint_resumed_trials": sum(item.checkpoint_resumed for item in trials),
            "checkpoint_duplicate_tool_calls": sum(
                item.duplicate_tool_calls for item in trials if item.checkpoint_resumed
            ),
            "hard_safety_violations": sum(item.outcome == TrialOutcome.SECURITY_VIOLATION for item in trials),
            "tool_calls": sum(item.tool_calls for item in trials),
            "model_calls": sum(item.model_calls for item in trials),
            "regression_failures": sum(
                item.task_success is not True
                for case in self.case_results if case.split == "REGRESSION"
                for item in case.trials
            ),
            "security_case_count": sum(case.category.lower() == "security" for case in self.case_results),
        }
        if any(getattr(self.metrics, name) != value for name, value in derived.items()):
            raise ValueError("aggregate report metrics disagree with the recorded trial grades")
        metric = self.metrics.task_success_rate
        expected_rate = derived["successful_trials"] / derived["trial_count"] if derived["trial_count"] else None
        if metric.status == MetricStatus.MEASURED:
            if expected_rate is None or metric.value != expected_rate:
                raise ValueError("task success rate disagrees with the recorded trial grades")
        elif expected_rate is not None:
            raise ValueError("completed trial grades require a measured task success rate")
        if {item.suite for item in self.suite_metrics} != set(SystemEvalSuite):
            raise ValueError("reports must include exactly one metrics entry for each named suite")
        suite_cases = {
            SystemEvalSuite.ALL: list(self.case_results),
            SystemEvalSuite.REGRESSION: [item for item in self.case_results if item.split == "REGRESSION"],
            SystemEvalSuite.CAPABILITY: [item for item in self.case_results if item.split == "CAPABILITY"],
            SystemEvalSuite.SECURITY: [item for item in self.case_results if item.category.lower() == "security"],
        }
        for suite_metric in self.suite_metrics:
            selected = suite_cases[suite_metric.suite]
            selected_trials = [trial for item in selected for trial in item.trials]
            if suite_metric.task_count != len(selected) or suite_metric.trial_count != len(selected_trials):
                raise ValueError("suite metrics disagree with the recorded case results")
            if suite_metric.hard_safety_violations != sum(
                item.outcome == TrialOutcome.SECURITY_VIOLATION for item in selected_trials
            ):
                raise ValueError("suite safety metrics disagree with the recorded trial grades")
            suite_successes = sum(item.task_success is True for item in selected_trials)
            expected_suite_rate = suite_successes / len(selected_trials) if selected_trials else None
            if suite_metric.success_rate.status == MetricStatus.MEASURED:
                if expected_suite_rate is None or suite_metric.success_rate.value != expected_suite_rate:
                    raise ValueError("suite success rate disagrees with the recorded trial grades")
            elif expected_suite_rate is not None:
                raise ValueError("completed suite trial grades require a measured success rate")
        digest_payload = self.model_dump(mode="json", exclude={"report_digest"})
        if self.schema_version == "agent-system-eval-report/1.0" and "full_analysis" not in self.model_fields_set:
            digest_payload.pop("full_analysis", None)
        expected_digest = system_evaluation_report_digest(digest_payload)
        if self.report_digest != expected_digest:
            raise ValueError("system evaluation report digest does not match its content")
        return self


class ComparisonOutcome(str, Enum):
    MEANINGFUL_IMPROVEMENT = "MEANINGFUL_IMPROVEMENT"
    LIKELY_REGRESSION = "LIKELY_REGRESSION"
    INCONCLUSIVE = "INCONCLUSIVE"
    INVALID_COMPARISON = "INVALID_COMPARISON"


class SystemEvaluationComparison(SystemEvalModel):
    schema_version: Literal["agent-system-comparison/1.0"] = "agent-system-comparison/1.0"
    baseline_report_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_report_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    compatibility_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    outcome: ComparisonOutcome
    valid: bool
    reasons: list[str] = Field(default_factory=list, max_length=32)
    baseline_success_rate: MeasuredMetric
    candidate_success_rate: MeasuredMetric
    success_rate_delta: MeasuredMetric
    baseline_wilson_95: tuple[float, float] | None = None
    candidate_wilson_95: tuple[float, float] | None = None
    safety_delta: int | None = None
    provider_failure_delta: int | None = None
    fallback_count_delta: float | None = None
    retry_count_delta: float | None = None
    evidence_success_delta: float | None = None
    tool_calls_per_trial_delta: float | None = None
    latency_ms_per_trial_delta: float | None = None
    input_tokens_delta: float | None = None
    output_tokens_delta: float | None = None
    cost_usd_delta: float | None = None
    comparison_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_comparison_digest(self) -> "SystemEvaluationComparison":
        expected = system_evaluation_comparison_digest(
            self.model_dump(mode="json", exclude={"comparison_digest"})
        )
        if expected != self.comparison_digest:
            raise ValueError("comparison digest does not match its canonical content")
        return self


class PromotionOutcome(str, Enum):
    PROMOTION_ELIGIBLE = "PROMOTION_ELIGIBLE"
    REGRESSION_DETECTED = "REGRESSION_DETECTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    SAFETY_BLOCKED = "SAFETY_BLOCKED"
    INVALID_COMPARISON = "INVALID_COMPARISON"


class PromotionDecision(SystemEvalModel):
    schema_version: Literal["agent-promotion-decision/1.0"] = "agent-promotion-decision/1.0"
    outcome: PromotionOutcome
    eligible_for_human_review: bool
    automatic_production_change: Literal[False] = False
    reasons: list[str] = Field(default_factory=list, max_length=32)
    comparison: SystemEvaluationComparison


def system_evaluation_report_digest(payload: dict) -> str:
    import hashlib
    import json

    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def system_evaluation_comparison_digest(payload: dict) -> str:
    import hashlib
    import json

    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# Resolve the forward reference without introducing a circular module import.
from app.evaluation.system.identity import AgentSystemIdentity  # noqa: E402

SystemEvaluationReport.model_rebuild()
SystemTrialGrade.model_rebuild()
FullAnalysisMetrics.model_rebuild()


__all__ = [
    "ComparisonOutcome", "EvaluationRunStatus", "FailureAttribution", "FailureClass",
    "FullAnalysisMetrics", "FullAnalysisReportDetails", "FullAnalysisTrialDetail",
    "MeasuredMetric", "MetricStatus",
    "PromotionDecision", "PromotionOutcome", "SystemCaseResults", "SystemEvalMode",
    "SystemEvalSuite", "SystemEvaluationComparison", "SystemEvaluationMetrics",
    "SystemEvaluationReport", "SystemTrialGrade", "SystemTrialPolicy", "TrialOutcome",
    "SystemSuiteMetrics", "SystemTrajectoryEvent", "WorkflowNodeEvent", "system_evaluation_report_digest",
    "system_evaluation_comparison_digest",
]
