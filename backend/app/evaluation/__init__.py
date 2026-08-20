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
    "RetrievalVariant",
    "SyntheticRepoFixture",
    "VariantEvaluationResult",
    "build_synthetic_ecommerce_fixture",
    "compute_finding_metrics",
    "compute_mrr",
    "compute_recall_at_k",
]
