"""Fail-closed comparability checks for paired agent-security reports."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import ConfigDict, Field, model_validator

from app.evaluation.security.contracts import (
    AgentSecurityEvaluationReport,
    AgentSecurityMode,
    SecurityModel,
    canonical_digest,
)


SECURITY_COMPARISON_SCHEMA_VERSION = "agent-security-comparison/1.0"
_OPTIMIZABLE_SECURITY_PROMPTS = frozenset({
    "architecture-agent",
    "integration-agent",
    "security-agent",
    "bug-agent",
    "verifier-agent",
    "revision-agent",
    "evidence-investigator",
})


class SecurityComparisonOutcome(str, Enum):
    COMPARABLE = "COMPARABLE"
    INVALID_COMPARISON = "INVALID_COMPARISON"


class AgentSecurityComparisonAssessment(SecurityModel):
    """Eligibility artifact; metrics remain in the two source reports."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["agent-security-comparison/1.0"] = SECURITY_COMPARISON_SCHEMA_VERSION
    baseline_report_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_report_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    baseline_mode: AgentSecurityMode
    candidate_mode: AgentSecurityMode
    outcome: SecurityComparisonOutcome
    changed_dimension: Literal["MODEL", "PROMPT"] | None = None
    changed_prompt_components: tuple[str, ...] = Field(default_factory=tuple, max_length=1)
    reasons: tuple[str, ...] = Field(default_factory=tuple, max_length=16)
    assessment_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_assessment(self) -> "AgentSecurityComparisonAssessment":
        valid = not self.reasons and self.changed_dimension is not None
        if (self.outcome == SecurityComparisonOutcome.COMPARABLE) != valid:
            raise ValueError("comparison outcome must match the eligibility reasons and changed dimension")
        if self.changed_dimension != "PROMPT" and self.changed_prompt_components:
            raise ValueError("only prompt comparisons may list changed prompt components")
        if self.changed_dimension == "PROMPT" and len(self.changed_prompt_components) != 1:
            raise ValueError("prompt-only comparison must identify exactly one changed prompt")
        payload = self.model_dump(mode="json", exclude={"assessment_digest"})
        if self.assessment_digest != canonical_digest(payload):
            raise ValueError("comparison assessment digest does not match its canonical content")
        return self


def _validated(report: AgentSecurityEvaluationReport) -> AgentSecurityEvaluationReport:
    # Revalidate serialized content so model_copy(update=...) cannot bypass the
    # source report's canonical metrics, gate, or digest validators.
    return AgentSecurityEvaluationReport.model_validate(report.model_dump(mode="json"))


def assess_security_report_comparability(
    baseline: AgentSecurityEvaluationReport,
    candidate: AgentSecurityEvaluationReport,
) -> AgentSecurityComparisonAssessment:
    """Permit only paired reports with one intended model OR prompt change.

    Scripted reports can be compared as harness artifacts, but this assessment
    never upgrades them into evidence of model resistance.
    """
    reasons: list[str] = []
    try:
        baseline = _validated(baseline)
        candidate = _validated(candidate)
    except Exception:
        reasons.append("one or both source reports failed integrity validation")

    changed_dimension: Literal["MODEL", "PROMPT"] | None = None
    changed_prompts: tuple[str, ...] = ()
    if not reasons:
        if baseline.report_digest == candidate.report_digest:
            reasons.append("baseline and candidate are the same report")
        if baseline.mode != candidate.mode:
            reasons.append("scripted and live reports cannot be compared")
        if baseline.execution_status != "COMPLETED" or candidate.execution_status != "COMPLETED":
            reasons.append("both source reports must have completed their full requested inventories")
        if baseline.corpus_version != candidate.corpus_version or baseline.corpus_digest != candidate.corpus_digest:
            reasons.append("security corpus identity differs")
        if (
            baseline.mutation_policy_version != candidate.mutation_policy_version
            or baseline.mutation_policy_digest != candidate.mutation_policy_digest
            or baseline.mutation_seed != candidate.mutation_seed
        ):
            reasons.append("mutation policy or seed differs")
        if baseline.required_case_ids != candidate.required_case_ids:
            reasons.append("required security case inventories differ")
        if baseline.trial_policy != candidate.trial_policy:
            reasons.append("trial, fixture, tool, or resource policy differs")

        baseline_cases = {item.case_id: item for item in baseline.case_results}
        candidate_cases = {item.case_id: item for item in candidate.case_results}
        if set(baseline_cases) != set(candidate_cases):
            reasons.append("observed case inventories differ")
        else:
            for case_id in sorted(baseline_cases):
                left, right = baseline_cases[case_id], candidate_cases[case_id]
                if (
                    left.case_digest != right.case_digest
                    or left.kind != right.kind
                    or left.attack_vector != right.attack_vector
                    or left.attack_surface != right.attack_surface
                    or left.case_family != right.case_family
                    or left.control_case_id != right.control_case_id
                    or left.paired_attack_case_id != right.paired_attack_case_id
                ):
                    reasons.append("case fixture identity differs")
                    break
                left_trials = {trial.trial_number: trial for trial in left.trials}
                right_trials = {trial.trial_number: trial for trial in right.trials}
                if set(left_trials) != set(right_trials) or any(
                    left_trials[number].attack_digest != right_trials[number].attack_digest
                    or left_trials[number].mutation_digest != right_trials[number].mutation_digest
                    for number in left_trials.keys() & right_trials.keys()
                ):
                    reasons.append("paired attack/mutation fixture digests differ")
                    break

        base_id = baseline.system_identity
        candidate_id = candidate.system_identity
        if base_id.system.scope != "FULL_ANALYSIS_GRAPH" or candidate_id.system.scope != "FULL_ANALYSIS_GRAPH":
            reasons.append("security reports must identify the full-analysis graph")
        if base_id.system.compatibility_digest != candidate_id.system.compatibility_digest:
            reasons.append("graph, tools, context, retrieval, budgets, or evaluator identity differs")
        if (
            base_id.mcp_gateway_digest != candidate_id.mcp_gateway_digest
            or base_id.mcp_gateway_tool_count != candidate_id.mcp_gateway_tool_count
        ):
            reasons.append("MCP gateway contract identity differs")

        base_prompts = {item.name: (item.version, item.content_digest) for item in base_id.system.prompt_components}
        candidate_prompts = {item.name: (item.version, item.content_digest) for item in candidate_id.system.prompt_components}
        if len(base_prompts) != len(base_id.system.prompt_components) or len(candidate_prompts) != len(candidate_id.system.prompt_components):
            reasons.append("prompt component identity contains duplicate names")
        changed_prompts = tuple(sorted(
            name for name in base_prompts.keys() | candidate_prompts.keys()
            if base_prompts.get(name) != candidate_prompts.get(name)
        ))
        invalid_prompt_changes = set(changed_prompts) - _OPTIMIZABLE_SECURITY_PROMPTS
        if invalid_prompt_changes:
            reasons.append("a changed component is not an optimizable production prompt")

        base_model = (
            base_id.system.model_provider,
            base_id.system.model_identifier,
            base_id.system.model_revision,
        )
        candidate_model = (
            candidate_id.system.model_provider,
            candidate_id.system.model_identifier,
            candidate_id.system.model_revision,
        )
        model_changed = base_model != candidate_model
        if model_changed and not changed_prompts:
            changed_dimension = "MODEL"
        elif not model_changed and len(changed_prompts) == 1 and not invalid_prompt_changes:
            changed_dimension = "PROMPT"
        else:
            reasons.append("comparison must change exactly one model identity or one registered prompt")
        if base_id.system.system_digest == candidate_id.system.system_digest:
            reasons.append("candidate system identity does not bind a distinct experiment")

    unique_reasons = tuple(dict.fromkeys(reasons))[:16]
    if unique_reasons:
        changed_dimension = None
        changed_prompts = ()
    payload = {
        "schema_version": SECURITY_COMPARISON_SCHEMA_VERSION,
        "baseline_report_digest": baseline.report_digest,
        "candidate_report_digest": candidate.report_digest,
        "baseline_mode": baseline.mode.value,
        "candidate_mode": candidate.mode.value,
        "outcome": (SecurityComparisonOutcome.INVALID_COMPARISON if unique_reasons else SecurityComparisonOutcome.COMPARABLE).value,
        "changed_dimension": changed_dimension,
        "changed_prompt_components": changed_prompts,
        "reasons": unique_reasons,
    }
    payload["assessment_digest"] = canonical_digest(payload)
    return AgentSecurityComparisonAssessment.model_validate(payload)


__all__ = [
    "AgentSecurityComparisonAssessment",
    "SECURITY_COMPARISON_SCHEMA_VERSION",
    "SecurityComparisonOutcome",
    "assess_security_report_comparability",
]
