"""Evaluation harness package for RepoLens."""

from app.evaluation.fixtures import (
    SyntheticRepoFixture,
    build_synthetic_ecommerce_fixture,
)
from app.evaluation.metrics import (
    compute_finding_metrics,
    compute_mrr,
    compute_recall_at_k,
)
from app.evaluation.remediation_fixtures import (
    RemediationFixtureFinding,
    build_remediation_fixtures,
)
from app.evaluation.remediation_metrics import (
    aggregate_variant_metrics,
    evaluate_single_patch,
)
from app.evaluation.remediation_runner import RemediationEvaluationHarness
from app.evaluation.remediation_schemas import (
    PatchEvaluationMetrics,
    RemediationBenchmarkReport,
    RemediationPipelineVariant,
    VariantAggregateMetrics as RemediationVariantAggregateMetrics,
)
from app.evaluation.runner import DeterministicMockEmbeddingProvider, EvaluationHarness
from app.evaluation.schemas import (
    BenchmarkReport,
    FindingEvaluationResult,
    GroundTruthIssue,
    IssueCategory,
    RetrievalVariant,
    VariantEvaluationResult,
)

__all__ = [
    "BenchmarkReport",
    "DeterministicMockEmbeddingProvider",
    "EvaluationHarness",
    "FindingEvaluationResult",
    "GroundTruthIssue",
    "IssueCategory",
    "PatchEvaluationMetrics",
    "RemediationBenchmarkReport",
    "RemediationEvaluationHarness",
    "RemediationFixtureFinding",
    "RemediationPipelineVariant",
    "RemediationVariantAggregateMetrics",
    "RetrievalVariant",
    "SyntheticRepoFixture",
    "VariantEvaluationResult",
    "aggregate_variant_metrics",
    "build_remediation_fixtures",
    "build_synthetic_ecommerce_fixture",
    "compute_finding_metrics",
    "compute_mrr",
    "compute_recall_at_k",
    "evaluate_single_patch",
]
