"""Tests for Phase 2G reproducible evaluation harness and ground truth benchmarks."""

import pytest

from app.evaluation.fixtures import build_synthetic_ecommerce_fixture
from app.evaluation.metrics import (
    compute_finding_metrics,
    compute_mrr,
    compute_recall_at_k,
)
from app.evaluation.runner import EvaluationHarness
from app.evaluation.schemas import (
    BenchmarkReport,
    GroundTruthIssue,
    IssueCategory,
    RetrievalVariant,
)
from app.schemas.enums import Severity
from app.schemas.evidence import Evidence
from app.schemas.finding import Finding
from uuid import uuid4


# =========================================================================
# 1. Metric Calculation Tests
# =========================================================================

def test_compute_recall_at_k_deterministic():
    """Verify Recall@K computes exact set intersection fractions."""
    expected = ["c1", "c2"]
    
    # 2 out of 2 in top 3 -> 1.0
    assert compute_recall_at_k(["c1", "c2", "c3"], expected, k=3) == 1.0

    # 1 out of 2 in top 2 -> 0.5
    assert compute_recall_at_k(["c1", "c3"], expected, k=2) == 0.5

    # 0 out of 2 in top 2 -> 0.0
    assert compute_recall_at_k(["c3", "c4"], expected, k=2) == 0.0

    # Empty expected -> 1.0
    assert compute_recall_at_k(["c1"], [], k=5) == 1.0


def test_compute_mrr_deterministic():
    """Verify Mean Reciprocal Rank (MRR) evaluates first relevant rank."""
    expected = ["target"]

    # First rank -> 1/1 = 1.0
    assert compute_mrr(["target", "c2", "c3"], expected) == 1.0

    # Second rank -> 1/2 = 0.5
    assert compute_mrr(["c1", "target", "c3"], expected) == 0.5

    # Fourth rank -> 1/4 = 0.25
    assert compute_mrr(["c1", "c2", "c3", "target"], expected) == 0.25

    # Not found -> 0.0
    assert compute_mrr(["c1", "c2", "c3"], expected) == 0.0


def test_compute_finding_metrics_precision_recall_fpr():
    """Verify precision, recall, false-positive rate, and localization accuracy."""
    gt_issues = [
        GroundTruthIssue(
            issue_id="GT-01",
            category=IssueCategory.SECURITY,
            title="SQL Injection",
            description="SQL Injection in db",
            expected_file="app/db.py",
            expected_start_line=10,
            expected_end_line=15,
            query="sql injection",
        ),
        GroundTruthIssue(
            issue_id="GT-02",
            category=IssueCategory.CORRECTNESS,
            title="Null Pointer",
            description="Null deref",
            expected_file="app/calc.py",
            expected_start_line=20,
            expected_end_line=25,
            query="null deref",
        ),
    ]

    # Finding 1: True Positive (matches GT-01 file and line range)
    f1 = Finding(
        scan_id=uuid4(),
        title="SQL Injection Detected",
        description="Vulnerable query",
        severity=Severity.HIGH,
        evidences=[Evidence(file_path="app/db.py", start_line=12, end_line=14)],
    )

    # Finding 2: False Positive (unknown file)
    f2 = Finding(
        scan_id=uuid4(),
        title="Hallucinated Bug",
        description="Fake issue",
        severity=Severity.LOW,
        evidences=[Evidence(file_path="app/fake.py", start_line=1, end_line=5)],
    )

    res = compute_finding_metrics(
        verified_findings=[f1, f2],
        candidate_findings=[f1, f2],
        ground_truth_issues=gt_issues,
        rejected_findings=[{"finding_id": "fake-1", "reason": "Fabricated file"}],
        line_tolerance=5,
        model_call_count=3,
    )

    # 1 TP, 1 FP out of 2 confirmed
    assert res.total_ground_truth == 2
    assert res.confirmed_findings == 2
    assert res.precision == 0.5  # 1 / 2
    assert res.recall == 0.5     # 1 / 2 (GT-01 matched, GT-02 missed)
    assert res.false_positive_rate == 0.5
    assert res.evidence_localization_accuracy == 1.0  # 1 localized out of 1 TP
    assert res.rejected_findings == 1
    assert res.verifier_rejection_rate == 0.5  # 1 rejected / 2 candidates
    assert res.model_call_count == 3


# =========================================================================
# 2. Synthetic Fixture Tests
# =========================================================================

def test_synthetic_ecommerce_fixture_structure():
    """Verify synthetic fixture contains all 4 documented issue categories and valid graph."""
    fixture = build_synthetic_ecommerce_fixture()

    assert fixture.name == "synth-ecommerce"
    assert len(fixture.manifest.files) == 7
    assert len(fixture.ground_truth_issues) == 4

    categories = {gt.category for gt in fixture.ground_truth_issues}
    assert categories == {
        IssueCategory.ROUTE_MISMATCH,
        IssueCategory.METHOD_MISMATCH,
        IssueCategory.SECURITY,
        IssueCategory.CORRECTNESS,
    }

    # Verify relationship graph has nodes and evaluated contracts
    report = fixture.repository_graph.evaluate_route_contracts()
    assert report.total_frontend_requests == 2
    assert report.total_backend_routes == 2


# =========================================================================
# 3. Retrieval Variant Evaluation Tests
# =========================================================================

@pytest.mark.asyncio
async def test_evaluation_harness_retrieval_variants():
    """Verify all 5 retrieval variants execute and produce measured Recall@K and MRR."""
    fixture = build_synthetic_ecommerce_fixture()
    harness = EvaluationHarness()

    for variant in [
        RetrievalVariant.LEXICAL_ONLY,
        RetrievalVariant.VECTOR_ONLY,
        RetrievalVariant.LEXICAL_VECTOR,
        RetrievalVariant.LEXICAL_VECTOR_GRAPH,
        RetrievalVariant.HYBRID_GRAPH_RERANKER,
    ]:
        res = await harness.evaluate_retrieval_variant(fixture, variant, k=5)
        assert res.variant == variant
        assert 0.0 <= res.recall_at_k <= 1.0
        assert 0.0 <= res.mrr <= 1.0
        assert res.avg_latency_ms >= 0.0
        assert res.total_queries == 4


@pytest.mark.asyncio
async def test_evaluation_harness_full_benchmark_report():
    """Verify complete benchmark execution produces machine-readable JSON and human-readable Markdown."""
    harness = EvaluationHarness()
    report = await harness.run_full_benchmark()

    assert isinstance(report, BenchmarkReport)
    assert len(report.fixtures_evaluated) == 1
    assert len(report.retrieval_results) == 5

    # Check that all 5 variants are in the results
    for variant in RetrievalVariant:
        assert variant.name in report.retrieval_results

    # Verify markdown summary content
    md = report.markdown_summary
    assert "# RepoLens Evaluation Benchmark Report" in md
    assert "Retrieval Variant Comparison" in md
    assert "Multi-Agent Finding & Verification Quality" in md
    assert "Precision" in md
    assert "Recall" in md
    assert "False Positive Rate" in md
