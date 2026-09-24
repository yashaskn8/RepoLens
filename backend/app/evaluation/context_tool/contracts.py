"""Strict, content-minimized contracts for context/tool experiments."""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

if TYPE_CHECKING:
    from app.evaluation.system.schemas import SystemEvaluationReport


OVERLAY_SCHEMA_VERSION = "context-tool-overlay/1.0"
MANIFEST_SCHEMA_VERSION = "context-presentation-manifest/1.2"
REPORT_SCHEMA_VERSION = "context-tool-experiment-report/1.3"


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _report_metric_sum(reports: list[Any], name: str) -> float | str:
    metrics = [getattr(report.metrics, name, None) for report in reports]
    if not metrics or any(item is None or item.status.value != "MEASURED" for item in metrics):
        return "NOT_MEASURED"
    return sum(float(item.value) for item in metrics)


def _probe_metric_sum(probes: list[Any], name: str) -> float | str:
    values = [getattr(item, name, None) for item in probes]
    if not values or any(item is None for item in values):
        return "NOT_MEASURED"
    return sum(float(item) for item in values)


def _combined_resource_metric(reports: list[Any], probes: list[Any], report_name: str, probe_name: str) -> float | str:
    report_total = _report_metric_sum(reports, report_name)
    probe_total = _probe_metric_sum(probes, probe_name)
    if report_total == "NOT_MEASURED" or probe_total == "NOT_MEASURED":
        return "NOT_MEASURED"
    return report_total + probe_total


class ContextToolModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ContextToolDimension(str, Enum):
    CONTEXT_TOKEN_BUDGET = "CONTEXT_TOKEN_BUDGET"
    MAX_RETRIEVED_CHUNKS = "MAX_RETRIEVED_CHUNKS"
    OPTIONAL_CONTEXT_KIND = "OPTIONAL_CONTEXT_KIND"
    TOOL_VISIBILITY = "TOOL_VISIBILITY"
    TOOL_DESCRIPTION_PRESENTATION = "TOOL_DESCRIPTION_PRESENTATION"


class ContextAblationClass(str, Enum):
    ESSENTIAL_UNDER_TEST = "ESSENTIAL_UNDER_TEST"
    HELPFUL_UNDER_TEST = "HELPFUL_UNDER_TEST"
    NEUTRAL_UNDER_TEST = "NEUTRAL_UNDER_TEST"
    HARMFUL_UNDER_TEST = "HARMFUL_UNDER_TEST"
    EFFICIENCY_IMPROVING_UNDER_TEST = "EFFICIENCY_IMPROVING_UNDER_TEST"
    INCONCLUSIVE = "INCONCLUSIVE"
    INVALID_EXPERIMENT = "INVALID_EXPERIMENT"


class ContextToolRecommendation(str, Enum):
    HUMAN_REVIEW_ELIGIBLE = "HUMAN_REVIEW_ELIGIBLE"
    QUALITY_REGRESSION = "QUALITY_REGRESSION"
    SAFETY_BLOCKED = "SAFETY_BLOCKED"
    EFFICIENCY_NOT_IMPROVED = "EFFICIENCY_NOT_IMPROVED"
    INCONCLUSIVE = "INCONCLUSIVE"
    INVALID_EXPERIMENT = "INVALID_EXPERIMENT"


class ToolSelectionGrade(str, Enum):
    EXPECTED_TOOL = "EXPECTED_TOOL"
    ACCEPTABLE_TOOL = "ACCEPTABLE_TOOL"
    WRONG_TOOL = "WRONG_TOOL"
    NO_TOOL_WHEN_REQUIRED = "NO_TOOL_WHEN_REQUIRED"
    UNNECESSARY_TOOL = "UNNECESSARY_TOOL"
    INVALID_ARGUMENTS = "INVALID_ARGUMENTS"
    FORBIDDEN_TOOL_REQUEST = "FORBIDDEN_TOOL_REQUEST"
    HIDDEN_TOOL_REQUEST = "HIDDEN_TOOL_REQUEST"
    NO_TOOL_EXPECTED = "NO_TOOL_EXPECTED"
    UNLABELED = "UNLABELED"
    INVALID_OUTPUT = "INVALID_OUTPUT"


class ToolSelectionProbe(ContextToolModel):
    case_id: str = Field(min_length=1, max_length=128)
    selected_action: str | None = Field(default=None, max_length=32)
    selected_tool: str | None = Field(default=None, max_length=128)
    argument_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    arguments_valid: bool | None = None
    hidden_tool_request: bool = False
    grade: ToolSelectionGrade
    measured_input_tokens: int | None = Field(default=None, ge=0)
    measured_output_tokens: int | None = Field(default=None, ge=0)
    measured_cost_usd: float | None = Field(default=None, ge=0.0)
    retries: int | None = Field(default=None, ge=0)
    fallbacks: int | None = Field(default=None, ge=0)


class ContextEvidenceReferenceProxy(ContextToolModel):
    """Observable structured-output reference proxy, never a claim about attention."""

    status: Literal["MEASURED", "NOT_MEASURED"] = "NOT_MEASURED"
    packed_evidence_id_count: int = Field(default=0, ge=0, le=100_000)
    downstream_referenced_evidence_id_count: int | None = Field(default=None, ge=0, le=100_000)
    downstream_reference_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    interpretation: Literal[
        "REFERENCED_IN_STRUCTURED_OUTPUT",
        "NOT_REFERENCED_IN_STRUCTURED_OUTPUT",
        "NOT_MEASURED",
    ] = "NOT_MEASURED"

    @model_validator(mode="after")
    def validate_proxy(self) -> "ContextEvidenceReferenceProxy":
        if self.status == "NOT_MEASURED":
            if self.downstream_referenced_evidence_id_count is not None or self.downstream_reference_rate is not None:
                raise ValueError("unavailable structured references must remain NOT_MEASURED")
            if self.interpretation != "NOT_MEASURED":
                raise ValueError("unavailable reference measurements need an explicit NOT_MEASURED interpretation")
        else:
            if self.packed_evidence_id_count <= 0 or self.downstream_referenced_evidence_id_count is None:
                raise ValueError("measured reference rates need a nonempty packed evidence denominator")
            if self.downstream_referenced_evidence_id_count > self.packed_evidence_id_count:
                raise ValueError("downstream references cannot exceed packed evidence identifiers")
            expected = self.downstream_referenced_evidence_id_count / self.packed_evidence_id_count
            if self.downstream_reference_rate != expected:
                raise ValueError("downstream evidence reference rate disagrees with its counts")
            expected_interpretation = (
                "REFERENCED_IN_STRUCTURED_OUTPUT"
                if self.downstream_referenced_evidence_id_count
                else "NOT_REFERENCED_IN_STRUCTURED_OUTPUT"
            )
            if self.interpretation != expected_interpretation:
                raise ValueError("reference interpretation disagrees with structured output counts")
        return self


class ContextToolOverlay(ContextToolModel):
    """One-factor evaluation override; all omitted dimensions stay at baseline."""

    schema_version: str = OVERLAY_SCHEMA_VERSION
    run_id: str = Field(min_length=1, max_length=128)
    candidate_id: str = Field(min_length=1, max_length=128)
    dimension: ContextToolDimension
    target_component: str = Field(min_length=1, max_length=64)
    baseline_system_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    baseline_context_policy_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    baseline_tool_manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    context_budget_fraction: float | None = Field(default=None, gt=0.0, le=1.0)
    max_chunks_reduction: int | None = Field(default=None, ge=1, le=8)
    excluded_context_kind: str | None = Field(default=None, pattern=r"^(chunks|graph_edges|contracts|static_findings)$")
    hidden_tool_name: str | None = Field(default=None, min_length=1, max_length=128)
    description_tool_name: str | None = Field(default=None, min_length=1, max_length=128)
    description_text: str | None = Field(default=None, max_length=600)

    @model_validator(mode="after")
    def validate_single_dimension(self) -> "ContextToolOverlay":
        if self.schema_version != OVERLAY_SCHEMA_VERSION:
            raise ValueError("unsupported context/tool overlay schema version")
        active = {
            ContextToolDimension.CONTEXT_TOKEN_BUDGET: self.context_budget_fraction is not None,
            ContextToolDimension.MAX_RETRIEVED_CHUNKS: self.max_chunks_reduction is not None,
            ContextToolDimension.OPTIONAL_CONTEXT_KIND: self.excluded_context_kind is not None,
            ContextToolDimension.TOOL_VISIBILITY: self.hidden_tool_name is not None,
            ContextToolDimension.TOOL_DESCRIPTION_PRESENTATION: (
                self.description_tool_name is not None and self.description_text is not None
            ),
        }
        if not active[self.dimension] or sum(active.values()) != 1:
            raise ValueError("a context/tool experiment must change exactly one presentation dimension")
        if (self.description_tool_name is None) != (self.description_text is None):
            raise ValueError("tool description experiments require both a tool name and replacement text")
        return self

    @property
    def overlay_digest(self) -> str:
        return canonical_digest(self.model_dump(mode="json"))


class ContextPresentationManifest(ContextToolModel):
    schema_version: str = MANIFEST_SCHEMA_VERSION
    case_id: str = Field(min_length=1, max_length=128)
    trial_number: int = Field(ge=1, le=5)
    evaluation_stage: str = Field(pattern=r"^(BASELINE|SCREEN|FULL_DEV|MICRO_EVAL)$")
    component: str = Field(min_length=1, max_length=64)
    node: str = Field(min_length=1, max_length=64)
    repository_snapshot: str | None = Field(default=None, max_length=128)
    context_policy_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    overlay_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    token_budget: int | None = Field(default=None, ge=1)
    packed_context_bytes: int = Field(ge=0)
    estimated_input_tokens: int = Field(ge=0)
    token_estimate_exact: bool = False
    available_fact_count: int | None = Field(default=None, ge=0)
    included_fact_count: int | None = Field(default=None, ge=0)
    required_fact_count: int | None = Field(default=None, ge=0)
    optional_fact_count: int | None = Field(default=None, ge=0)
    deduplicated_fact_count: int | None = Field(default=None, ge=0)
    deduplicated_bytes: int | None = Field(default=None, ge=0)
    compacted_observation_count: int | None = Field(default=None, ge=0)
    evidence_ids: list[str] = Field(default_factory=list, max_length=256)
    evidence_kind_counts: dict[str, int] = Field(default_factory=dict, max_length=16)
    truncated: bool | None = None
    truncated_candidate_ids: list[str] = Field(default_factory=list, max_length=64)
    context_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    visible_tool_names: list[str] = Field(default_factory=list, max_length=32)
    visible_tool_definition_digests: dict[str, str] = Field(default_factory=dict, max_length=32)
    visible_tool_schema_digests: dict[str, str] = Field(default_factory=dict, max_length=32)
    manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_manifest_digest(self) -> "ContextPresentationManifest":
        if self.schema_version != MANIFEST_SCHEMA_VERSION:
            raise ValueError("unsupported context presentation manifest version")
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("manifest evidence IDs must be unique")
        if self.truncated_candidate_ids != sorted(set(self.truncated_candidate_ids)):
            raise ValueError("truncated candidate IDs must be sorted and unique")
        if self.truncated_candidate_ids and self.truncated is not True:
            raise ValueError("truncated candidate IDs require an explicitly truncated manifest")
        if self.visible_tool_names != sorted(set(self.visible_tool_names)):
            raise ValueError("visible tool names must be sorted and unique")
        payload = self.model_dump(mode="json", exclude={"manifest_digest"})
        if canonical_digest(payload) != self.manifest_digest:
            raise ValueError("context presentation manifest digest mismatch")
        return self


class ContextToolCandidateResult(ContextToolModel):
    candidate_id: str = Field(min_length=1, max_length=128)
    overlay: ContextToolOverlay
    evaluation_report: Any
    screen_report: Any
    evaluation_stage: str = Field(pattern=r"^(SCREEN_ONLY|FULL_DEV)$")
    screen_report_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    screen_case_ids: list[str] = Field(min_length=1, max_length=8)
    screen_passed: bool
    presentation_manifests: list[ContextPresentationManifest] = Field(default_factory=list, max_length=4096)
    tool_selection_probes: list[ToolSelectionProbe] = Field(default_factory=list, max_length=64)
    evidence_reference_proxy: ContextEvidenceReferenceProxy = Field(default_factory=ContextEvidenceReferenceProxy)
    statistical_comparison: dict[str, Any] | None = None
    ablation_class: ContextAblationClass
    recommendation: ContextToolRecommendation
    scripted_security_gate: str = Field(pattern=r"^(PASS|FAIL|NOT_EXECUTED)$")
    efficiency_deltas: dict[str, float | None] = Field(default_factory=dict, max_length=8)
    explanation: str = Field(max_length=2_000)


class ContextToolExperimentReport(ContextToolModel):
    schema_version: str = REPORT_SCHEMA_VERSION
    run_id: str = Field(min_length=1, max_length=128)
    mode: str = Field(pattern=r"^(SCRIPTED|LIVE)$")
    scripted_semantics: str = "HARNESS_VALIDATION_ONLY"
    experiment_policy_version: str = "context-tool-experiment-policy/1.2"
    termination_reason: str = Field(
        default="COMPLETED",
        pattern=r"^(COMPLETED|OPTIMIZATION_BUDGET_EXHAUSTED|PROVIDER_FAILURE|HARNESS_FAILURE|INVALID_EXPERIMENT)$",
    )
    resource_usage: dict[str, int | float | str | None] = Field(default_factory=dict, max_length=32)
    dataset_version: str = Field(min_length=1, max_length=64)
    dataset_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    tool_probe_dataset_version: str = Field(min_length=1, max_length=64)
    tool_probe_dataset_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    baseline_report: Any
    baseline_screen_report: Any
    baseline_evidence_reference_proxy: ContextEvidenceReferenceProxy = Field(default_factory=ContextEvidenceReferenceProxy)
    baseline_screen_manifests: list[ContextPresentationManifest] = Field(default_factory=list, max_length=4096)
    screen_selection_policy_version: str = "context-tool-screen-selection/1.1"
    pareto_policy_version: str = "context-tool-pareto/1.1"
    quality_comparison_policy_version: str = "context-tool-quality-comparison/1.1"
    screen_case_ids: list[str] = Field(min_length=1, max_length=8)
    screen_groups: dict[str, list[str]] = Field(max_length=5)
    screen_selection_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    baseline_manifests: list[ContextPresentationManifest] = Field(default_factory=list, max_length=4096)
    baseline_tool_selection_probes: list[ToolSelectionProbe] = Field(default_factory=list, max_length=64)
    candidates: list[ContextToolCandidateResult] = Field(default_factory=list, max_length=8)
    pareto_candidate_ids: list[str] = Field(default_factory=list, max_length=8)
    scripted_security_gate: str = Field(pattern=r"^(PASS|FAIL|NOT_EXECUTED)$")
    live_security_gate: str = Field(pattern=r"^(PASS|FAIL|NOT_EXECUTED)$")
    report_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_report_integrity(self) -> "ContextToolExperimentReport":
        from app.evaluation.system.schemas import SystemEvaluationReport

        baseline_report = SystemEvaluationReport.model_validate(self.baseline_report)
        baseline_screen_report = SystemEvaluationReport.model_validate(self.baseline_screen_report)
        from app.evaluation.context_tool.comparison import context_evidence_reference_proxy
        from app.evaluation.agent.loader import load_agent_dataset
        from app.evaluation.context_tool.policy import (
            PARETO_POLICY_VERSION,
            POLICY_VERSION,
            QUALITY_COMPARISON_POLICY_VERSION,
            SCREEN_SELECTION_VERSION,
        )

        if self.schema_version != REPORT_SCHEMA_VERSION:
            raise ValueError("unsupported context/tool experiment report schema version")
        if self.experiment_policy_version != POLICY_VERSION:
            raise ValueError("experiment report uses an unsupported context/tool policy")
        if self.screen_selection_policy_version != SCREEN_SELECTION_VERSION:
            raise ValueError("experiment report uses an unsupported screen selection policy")
        if self.pareto_policy_version != PARETO_POLICY_VERSION:
            raise ValueError("Pareto result uses an unsupported optimization ranking policy")
        if self.quality_comparison_policy_version != QUALITY_COMPARISON_POLICY_VERSION:
            raise ValueError("quality result uses an unsupported confidence-interval policy")

        if self.baseline_evidence_reference_proxy != context_evidence_reference_proxy(
            baseline_report, self.baseline_manifests,
        ):
            raise ValueError("baseline evidence-reference proxy disagrees with report and actual-request manifests")
        if self.mode == "SCRIPTED" and self.scripted_semantics != "HARNESS_VALIDATION_ONLY":
            raise ValueError("scripted runs cannot claim model quality evidence")
        if len({item.candidate_id for item in self.candidates}) != len(self.candidates):
            raise ValueError("candidate IDs must be unique")
        candidate_child_reports: list[tuple[Any, Any]] = []
        base = baseline_report.system_identity
        if baseline_screen_report.system_identity.system_digest != base.system_digest:
            raise ValueError("baseline screen system identity differs from the full baseline")
        if baseline_screen_report.evaluated_case_ids != self.screen_case_ids:
            raise ValueError("baseline screen cases disagree with the recorded selection")
        from app.evaluation.context_tool.runner import _screen_selection, _select_public_cases

        selected_public_cases = _select_public_cases(
            baseline_report.evaluated_case_ids,
            max_cases=max(1, len(baseline_report.evaluated_case_ids)),
        )
        derived_screen_ids, derived_screen_groups = _screen_selection(selected_public_cases, baseline_report)
        if derived_screen_ids != self.screen_case_ids or derived_screen_groups != self.screen_groups:
            raise ValueError("recorded screen groups do not match deterministic public-case selection")
        probe_dataset = load_agent_dataset()
        if (
            probe_dataset.manifest.dataset_version != self.tool_probe_dataset_version
            or probe_dataset.dataset_hash != self.tool_probe_dataset_digest
        ):
            raise ValueError("tool-selection probe dataset identity is stale or incompatible")
        probe_case_ids = {case.case_id for case in probe_dataset.cases}
        all_probes = self.baseline_tool_selection_probes + [
            probe for candidate in self.candidates for probe in candidate.tool_selection_probes
        ]
        if any(probe.case_id not in probe_case_ids for probe in all_probes):
            raise ValueError("tool-selection probe references a case outside its bound public dataset")
        if any(
            item.evaluation_stage != "SCREEN" or item.case_id not in self.screen_case_ids
            for item in self.baseline_screen_manifests
        ):
            raise ValueError("baseline screen manifests must describe actual requests in the frozen screen")
        groups = self.screen_groups
        if set(groups) != {"TARGET_FAILURES", "VALIDATION", "SECURITY", "PRESERVE_REGRESSION"}:
            raise ValueError("screen selection must record all four explicit case groups")
        union = sorted({case_id for case_ids in groups.values() for case_id in case_ids})
        if union != self.screen_case_ids or any(len(case_ids) != len(set(case_ids)) for case_ids in groups.values()):
            raise ValueError("screen groups do not exactly describe the selected case inventory")
        if canonical_digest({
            "policy_version": self.screen_selection_policy_version,
            "groups": groups,
            "case_ids": self.screen_case_ids,
        }) != self.screen_selection_digest:
            raise ValueError("screen selection digest mismatch")
        for candidate in self.candidates:
            if candidate.candidate_id != candidate.overlay.candidate_id:
                raise ValueError("candidate artifact and overlay IDs disagree")
            if candidate.overlay.baseline_system_digest != base.system_digest:
                raise ValueError("candidate is not bound to the baseline system identity")
            report = SystemEvaluationReport.model_validate(candidate.evaluation_report)
            screen_report = SystemEvaluationReport.model_validate(candidate.screen_report)
            candidate_child_reports.append((report, screen_report))
            if screen_report.report_digest != candidate.screen_report_digest:
                raise ValueError("candidate screen report digest does not match its recorded artifact")
            if screen_report.evaluated_case_ids != self.screen_case_ids:
                raise ValueError("candidate screen report does not match the frozen screen inventory")
            if (
                screen_report.system_identity.system_digest != base.system_digest
                or screen_report.system_identity.compatibility_digest != base.compatibility_digest
            ):
                raise ValueError("candidate screen changed system identity outside its presentation overlay")
            if report.system_identity.system_digest != base.system_digest:
                raise ValueError("candidate changed system identity outside its evaluation-local overlay")
            if report.system_identity.compatibility_digest != base.compatibility_digest:
                raise ValueError("candidate changed compatibility identity")
            if candidate.evaluation_stage == "SCREEN_ONLY" and candidate.recommendation == ContextToolRecommendation.HUMAN_REVIEW_ELIGIBLE:
                raise ValueError("screen-only evidence cannot be human-review eligible")
            if candidate.evaluation_stage == "SCREEN_ONLY" and report.evaluated_case_ids != self.screen_case_ids:
                raise ValueError("candidate screen cases disagree with the recorded selection")
            if candidate.screen_case_ids != self.screen_case_ids:
                raise ValueError("candidate screen selection differs from the frozen experiment screen")
            if not candidate.presentation_manifests or any(
                manifest.overlay_digest != candidate.overlay.overlay_digest
                for manifest in candidate.presentation_manifests
            ):
                raise ValueError("candidate manifest overlay identity mismatch")
            if candidate.evidence_reference_proxy != context_evidence_reference_proxy(
                report, candidate.presentation_manifests,
            ):
                raise ValueError("candidate evidence-reference proxy disagrees with report and actual-request manifests")
            from app.evaluation.context_tool.comparison import classify_screen, screen_regressions

            screen_target_presented = any(
                manifest.component == candidate.overlay.target_component
                and manifest.overlay_digest == candidate.overlay.overlay_digest
                and manifest.evaluation_stage in {"SCREEN", "MICRO_EVAL"}
                for manifest in candidate.presentation_manifests
            )
            regressions = screen_regressions(
                baseline_screen_report,
                screen_report,
                target_was_presented=screen_target_presented,
            )
            if candidate.screen_passed != (not regressions):
                raise ValueError("candidate screen status disagrees with its full quality/safety metrics")
            if candidate.evaluation_stage == "SCREEN_ONLY":
                if report.report_digest != screen_report.report_digest:
                    raise ValueError("screen-only candidate must identify its actual screen report")
                if candidate.scripted_security_gate == "FAIL":
                    expected_class = ContextAblationClass.ESSENTIAL_UNDER_TEST
                    expected_recommendation = ContextToolRecommendation.SAFETY_BLOCKED
                else:
                    expected_class, expected_recommendation, _ = classify_screen(regressions)
                if (
                    candidate.ablation_class != expected_class
                    or candidate.recommendation != expected_recommendation
                ):
                    raise ValueError("screen-only candidate classification disagrees with deterministic screen results")
            else:
                from app.evaluation.system.comparison import compare_system_reports
                from app.evaluation.system.schemas import SystemEvaluationComparison

                if candidate.statistical_comparison is None:
                    raise ValueError("full-DEV candidates require the canonical paired statistical comparison")
                statistical_comparison = SystemEvaluationComparison.model_validate(candidate.statistical_comparison)
                if statistical_comparison != compare_system_reports(baseline_report, report):
                    raise ValueError("candidate statistical comparison disagrees with canonical report recomputation")
                target_full_presented = any(
                    manifest.component == candidate.overlay.target_component
                    and manifest.overlay_digest == candidate.overlay.overlay_digest
                    and manifest.evaluation_stage == "FULL_DEV"
                    for manifest in candidate.presentation_manifests
                )
                from app.evaluation.context_tool.comparison import compare_experiment
                from app.evaluation.ground_truth.public_dev import PUBLIC_DEV_REPOSITORY_SCAN_CASE_IDS

                expected_class, expected_recommendation, expected_deltas, _ = compare_experiment(
                    baseline_report,
                    report,
                    baseline_manifests=self.baseline_manifests,
                    candidate_manifests=candidate.presentation_manifests,
                    complete_dev=(set(report.evaluated_case_ids) == set(PUBLIC_DEV_REPOSITORY_SCAN_CASE_IDS)),
                    repeated_trials=report.trial_policy.trials_per_case >= 3,
                    security_gate=candidate.scripted_security_gate,
                    scripted=(self.mode == "SCRIPTED"),
                    statistical_outcome=statistical_comparison.outcome.value,
                    statistical_valid=statistical_comparison.valid,
                )
                if not target_full_presented and expected_recommendation != ContextToolRecommendation.SAFETY_BLOCKED:
                    expected_class = ContextAblationClass.INCONCLUSIVE
                    expected_recommendation = ContextToolRecommendation.INCONCLUSIVE
                if (
                    candidate.ablation_class != expected_class
                    or candidate.recommendation != expected_recommendation
                    or candidate.efficiency_deltas != expected_deltas
                ):
                    raise ValueError("full candidate comparison fields disagree with deterministic report recomputation")
            if candidate.recommendation == ContextToolRecommendation.HUMAN_REVIEW_ELIGIBLE and (
                self.mode != "LIVE"
                or candidate.evaluation_stage != "FULL_DEV"
                or candidate.scripted_security_gate != "PASS"
            ):
                raise ValueError("human-review candidates require live full DEV evidence and scripted security PASS")
            if candidate.evaluation_stage == "SCREEN_ONLY" and candidate.statistical_comparison is not None:
                raise ValueError("one-trial elimination screens cannot claim repeated-trial statistical evidence")

        if self.termination_reason == "COMPLETED":
            from app.evaluation.context_tool.policy import (
                MAX_MODEL_CALLS_PER_WORK_UNIT,
                MAX_TRIAL_WORK_UNITS,
                MAX_WALL_CLOCK_SECONDS,
            )

            all_reports = [baseline_report, baseline_screen_report]
            candidate_screen_reports: list[Any] = []
            candidate_full_reports: list[Any] = []
            for candidate, (report, screen_report) in zip(self.candidates, candidate_child_reports, strict=True):
                candidate_screen_reports.append(screen_report)
                all_reports.append(screen_report)
                if candidate.evaluation_stage == "FULL_DEV":
                    candidate_full_reports.append(report)
                    all_reports.append(report)

            baseline_probe_calls = len(self.baseline_tool_selection_probes) if self.mode == "LIVE" else 0
            candidate_probes = [probe for candidate in self.candidates for probe in candidate.tool_selection_probes]
            candidate_probe_calls = len(candidate_probes) if self.mode == "LIVE" else 0
            full_trial_work = len(baseline_report.evaluated_case_ids) * baseline_report.trial_policy.trials_per_case
            screen_trial_work = len(baseline_screen_report.evaluated_case_ids)
            candidate_screen_work = sum(len(item.screen_case_ids) for item in self.candidates)
            candidate_full_work = sum(
                len(report.evaluated_case_ids) * report.trial_policy.trials_per_case
                for report in candidate_full_reports
            )
            security_gate_work = (
                30 * len(candidate_full_reports)
                if self.mode == "LIVE"
                else (30 if self.scripted_security_gate != "NOT_EXECUTED" else 0)
            )
            expected_work_units = (
                full_trial_work + screen_trial_work + len(self.baseline_tool_selection_probes)
                + candidate_screen_work + len(candidate_probes) + candidate_full_work + security_gate_work
            )
            baseline_model_calls = baseline_report.metrics.model_calls + baseline_screen_report.metrics.model_calls
            candidate_model_calls = sum(item.metrics.model_calls for item in candidate_screen_reports + candidate_full_reports)
            expected_usage: dict[str, Any] = {
                "work_units": expected_work_units,
                "case_trial_work_units": expected_work_units,
                "workflow_runs": 2 + len(candidate_screen_reports) + len(candidate_full_reports),
                "baseline_workflows": 2,
                "candidate_screen_workflows": len(candidate_screen_reports),
                "candidate_full_workflows": len(candidate_full_reports),
                "tool_selection_probes": len(self.baseline_tool_selection_probes) + len(candidate_probes),
                "baseline_evaluation_model_executions": baseline_model_calls + baseline_probe_calls,
                "candidate_evaluation_model_executions": candidate_model_calls + candidate_probe_calls,
                "model_calls": baseline_model_calls + candidate_model_calls + baseline_probe_calls + candidate_probe_calls,
                "estimated_context_tokens": sum(
                    item.estimated_input_tokens
                    for item in self.baseline_manifests + self.baseline_screen_manifests
                    + [manifest for candidate in self.candidates for manifest in candidate.presentation_manifests]
                ),
                "case_trial_work_unit_ceiling": MAX_TRIAL_WORK_UNITS,
                "candidate_inventory_count": len(self.candidates),
            }
            if expected_work_units > MAX_TRIAL_WORK_UNITS:
                raise ValueError("completed experiment exceeded its case-trial work-unit ceiling")
            for key, expected_value in expected_usage.items():
                if self.resource_usage.get(key) != expected_value:
                    raise ValueError(
                        f"experiment resource aggregate {key} disagrees with child reports "
                        f"(reported={self.resource_usage.get(key)!r}, derived={expected_value!r})"
                    )
            expected_model_call_reservation = expected_work_units * MAX_MODEL_CALLS_PER_WORK_UNIT
            if self.resource_usage.get("model_call_reservation") != expected_model_call_reservation:
                raise ValueError("model-call reservation disagrees with completed case-trial work")
            budget = baseline_report.system_identity.budget_profile
            for key, expected_value in (
                ("cloud_call_ceiling", expected_work_units * budget.max_workflow_cloud_calls),
                ("cloud_token_reservation_ceiling", expected_work_units * budget.max_workflow_cloud_tokens),
            ):
                if self.resource_usage.get(key) != expected_value:
                    raise ValueError(f"experiment resource ceiling {key} disagrees with system budget profile")

            baseline_probes = self.baseline_tool_selection_probes
            for report_key, usage_key, probe_key in (
                ("input_tokens", "measured_input_tokens", "measured_input_tokens"),
                ("output_tokens", "measured_output_tokens", "measured_output_tokens"),
                ("cost_usd", "measured_cost_usd", "measured_cost_usd"),
                ("retry_count", "retry_count", "retries"),
                ("fallback_count", "fallback_count", "fallbacks"),
            ):
                expected_value: float | str
                if self.mode == "SCRIPTED":
                    expected_value = "NOT_MEASURED"
                else:
                    expected_value = _combined_resource_metric(
                        all_reports,
                        baseline_probes + candidate_probes,
                        report_key,
                        probe_key,
                    )
                if self.resource_usage.get(usage_key) != expected_value:
                    raise ValueError(f"experiment resource aggregate {usage_key} disagrees with child usage metadata")
            for scope, reports, probes in (
                ("baseline", [baseline_report, baseline_screen_report], baseline_probes),
                ("candidate", candidate_screen_reports + candidate_full_reports, candidate_probes),
            ):
                for report_key, usage_key, probe_key in (
                    ("input_tokens", f"{scope}_measured_input_tokens", "measured_input_tokens"),
                    ("output_tokens", f"{scope}_measured_output_tokens", "measured_output_tokens"),
                    ("cost_usd", f"{scope}_measured_cost_usd", "measured_cost_usd"),
                ):
                    expected_value = (
                        "NOT_MEASURED" if self.mode == "SCRIPTED"
                        else _combined_resource_metric(reports, probes, report_key, probe_key)
                    )
                    if self.resource_usage.get(usage_key) != expected_value:
                        raise ValueError(f"experiment resource aggregate {usage_key} disagrees with child usage metadata")
            if self.resource_usage.get("elapsed_wall_clock_seconds", 0) > MAX_WALL_CLOCK_SECONDS:
                raise ValueError("completed experiment exceeded the hard wall-clock ceiling")
        from app.evaluation.context_tool.pareto import pareto_frontier

        if self.pareto_candidate_ids != pareto_frontier(self.candidates):
            raise ValueError("Pareto candidate inventory disagrees with deterministic report recomputation")
        expected = canonical_digest(self.model_dump(mode="json", exclude={"report_digest"}))
        if expected != self.report_digest:
            raise ValueError("context/tool experiment report digest mismatch")
        return self


def build_manifest(**values: Any) -> ContextPresentationManifest:
    payload = dict(values)
    payload.setdefault("schema_version", MANIFEST_SCHEMA_VERSION)
    payload.pop("manifest_digest", None)
    prototype = ContextPresentationManifest.model_construct(**payload, manifest_digest="0" * 64)
    payload = prototype.model_dump(mode="json", exclude={"manifest_digest"})
    payload["manifest_digest"] = canonical_digest(payload)
    return ContextPresentationManifest.model_validate(payload)


def build_experiment_report(**values: Any) -> ContextToolExperimentReport:
    payload = dict(values)
    payload.setdefault("schema_version", REPORT_SCHEMA_VERSION)
    payload.pop("report_digest", None)
    prototype = ContextToolExperimentReport.model_construct(**payload, report_digest="0" * 64)
    payload = prototype.model_dump(mode="json", exclude={"report_digest"})
    payload["report_digest"] = canonical_digest(payload)
    return ContextToolExperimentReport.model_validate(payload)


__all__ = [name for name in globals() if name.startswith("Context") or name in {
    "ToolSelectionGrade", "ToolSelectionProbe", "canonical_digest", "build_manifest",
    "build_experiment_report",
}]
