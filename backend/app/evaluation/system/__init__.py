"""Opt-in, bounded system identity, comparison and promotion evaluation."""

from app.evaluation.system.comparison import compare_system_reports, promote_check, wilson_interval
from app.evaluation.system.identity import AgentSystemIdentity, build_agent_system_identity
from app.evaluation.system.runner import cases_for_suite, run_system_evaluation
from app.evaluation.system.schemas import (
    ComparisonOutcome,
    EvaluationRunStatus,
    MetricStatus,
    PromotionDecision,
    PromotionOutcome,
    SystemEvalMode,
    SystemEvalSuite,
    SystemEvaluationComparison,
    SystemEvaluationMetrics,
    SystemEvaluationReport,
    SystemSuiteMetrics,
    SystemTrialGrade,
    SystemTrajectoryEvent,
    TrialOutcome,
)

__all__ = [
    "AgentSystemIdentity", "ComparisonOutcome", "EvaluationRunStatus", "MetricStatus",
    "PromotionDecision", "PromotionOutcome", "SystemEvalMode", "SystemEvalSuite",
    "SystemEvaluationComparison", "SystemEvaluationMetrics", "SystemEvaluationReport",
    "SystemSuiteMetrics", "SystemTrialGrade", "SystemTrajectoryEvent", "TrialOutcome", "build_agent_system_identity", "cases_for_suite",
    "compare_system_reports", "promote_check", "run_system_evaluation", "wilson_interval",
]
