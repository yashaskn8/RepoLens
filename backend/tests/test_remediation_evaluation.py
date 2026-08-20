"""Tests for Phase 3H remediation-quality evaluation harness.

Validates:
- Remediation fixture construction
- Deterministic per-patch metric computation
- Variant aggregation logic
- Full benchmark execution across all 4 pipeline variants
- JSON output serialization and Markdown report generation
"""

import json
import pytest
from uuid import uuid4

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
    VariantAggregateMetrics,
)
from app.patching.schemas import (
    PatchVerificationResult,
    VerificationCheckItem,
    VerificationStatus,
)
from app.planning.schemas import FixPlan, FixScope, OrderedChangeStep
from app.schemas.enums import Severity
from app.schemas.evidence import Evidence
from app.schemas.finding import Finding


# =========================================================================
# 1. Fixture Construction Tests
# =========================================================================


def test_remediation_fixtures_structure():
    """Verify all 4 fixture findings are built with required fields."""
    fixtures = build_remediation_fixtures()

    assert len(fixtures) == 4

    categories = {f.finding.category for f in fixtures}
    assert "security" in categories
    assert "correctness" in categories
    assert "route_mismatch" in categories
    assert "method_mismatch" in categories

    for f in fixtures:
        assert f.finding.title
        assert f.finding.description
        assert f.finding.severity in (Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.CRITICAL)
        assert len(f.expected_files_to_change) >= 1
        assert f.known_good_diff
        assert f.defect_snippet
        assert f.ground_truth.issue_id.startswith("REM-GT-")


def test_remediation_fixtures_known_good_diffs_are_valid():
    """Verify all known-good diffs parse as valid unified diffs."""
    fixtures = build_remediation_fixtures()

    for f in fixtures:
        diff = f.known_good_diff
        assert "--- " in diff, f"Missing --- header in fixture {f.ground_truth.issue_id}"
        assert "+++ " in diff, f"Missing +++ header in fixture {f.ground_truth.issue_id}"
        assert "@@ " in diff, f"Missing @@ hunk header in fixture {f.ground_truth.issue_id}"


# =========================================================================
# 2. Per-Patch Metric Computation Tests
# =========================================================================


def test_evaluate_single_patch_valid_diff():
    """Verify valid diff detection with a well-formed patch."""
    fixtures = build_remediation_fixtures()
    f = fixtures[0]  # SQL injection fixture

    known_files = {"app/db/query.py", "app/core/calculator.py"}

    metrics = evaluate_single_patch(
        fixture=f,
        variant=RemediationPipelineVariant.DIRECT_LLM,
        diff_text=f.known_good_diff,
        known_repo_files=known_files,
    )

    assert metrics.valid_unified_diff is True
    assert metrics.target_finding_resolved is True
    assert metrics.fabricated_path_rate == 0.0
    assert metrics.unnecessary_file_change_rate == 0.0


def test_evaluate_single_patch_fabricated_path():
    """Verify fabricated-path detection when diff references a nonexistent file."""
    fixtures = build_remediation_fixtures()
    f = fixtures[0]

    # Known files do NOT include the file in the diff
    known_files = {"app/other.py"}

    metrics = evaluate_single_patch(
        fixture=f,
        variant=RemediationPipelineVariant.DIRECT_LLM,
        diff_text=f.known_good_diff,
        known_repo_files=known_files,
    )

    assert metrics.valid_unified_diff is True
    assert len(metrics.fabricated_paths) > 0
    assert metrics.fabricated_path_rate > 0.0


def test_evaluate_single_patch_unnecessary_files():
    """Verify unnecessary-file detection when diff modifies files outside expected scope."""
    fixtures = build_remediation_fixtures()
    f = fixtures[0]

    # Patch that changes expected file PLUS an unrelated file
    diff_with_extra = (
        f.known_good_diff +
        "\n--- a/README.md\n"
        "+++ b/README.md\n"
        "@@ -1,1 +1,2 @@\n"
        " # Project\n"
        "+## Fixed\n"
    )

    known_files = {"app/db/query.py", "README.md"}

    metrics = evaluate_single_patch(
        fixture=f,
        variant=RemediationPipelineVariant.DIRECT_LLM,
        diff_text=diff_with_extra,
        known_repo_files=known_files,
    )

    assert len(metrics.unnecessary_files_changed) == 1
    assert "README.md" in metrics.unnecessary_files_changed
    assert metrics.unnecessary_file_change_rate > 0.0


def test_evaluate_single_patch_empty_diff():
    """Verify that empty diff is detected as invalid."""
    fixtures = build_remediation_fixtures()
    f = fixtures[0]

    metrics = evaluate_single_patch(
        fixture=f,
        variant=RemediationPipelineVariant.DIRECT_LLM,
        diff_text="",
        known_repo_files=set(),
    )

    assert metrics.valid_unified_diff is False
    assert metrics.target_finding_resolved is False


def test_evaluate_single_patch_plan_evidence_grounding():
    """Verify plan evidence grounding check against known files."""
    fixtures = build_remediation_fixtures()
    f = fixtures[0]

    plan = FixPlan(
        finding_id=f.finding.id,
        root_cause="Test",
        objective="Test fix",
        files_expected_to_change=["app/db/query.py"],
        ordered_changes=[
            OrderedChangeStep(
                step_number=1,
                target_file="app/db/query.py",
                description="Fix query",
                rationale="Parameterize",
            )
        ],
        validation_plan=["Check snippet removed"],
    )

    known_files = {"app/db/query.py"}

    metrics = evaluate_single_patch(
        fixture=f,
        variant=RemediationPipelineVariant.FIXPLAN_PATCH,
        diff_text=f.known_good_diff,
        known_repo_files=known_files,
        fix_plan=plan,
    )

    assert metrics.plan_evidence_grounded is True


def test_evaluate_single_patch_plan_references_nonexistent_file():
    """Verify plan evidence grounding fails when FixPlan references a nonexistent file."""
    fixtures = build_remediation_fixtures()
    f = fixtures[0]

    plan = FixPlan(
        finding_id=f.finding.id,
        root_cause="Test",
        objective="Test fix",
        files_expected_to_change=["app/db/query.py", "app/nonexistent.py"],
        ordered_changes=[
            OrderedChangeStep(
                step_number=1,
                target_file="app/db/query.py",
                description="Fix query",
                rationale="Parameterize",
            )
        ],
        validation_plan=["Check snippet removed"],
    )

    known_files = {"app/db/query.py"}

    metrics = evaluate_single_patch(
        fixture=f,
        variant=RemediationPipelineVariant.FIXPLAN_PATCH,
        diff_text=f.known_good_diff,
        known_repo_files=known_files,
        fix_plan=plan,
    )

    assert metrics.plan_evidence_grounded is False


# =========================================================================
# 3. Variant Aggregation Tests
# =========================================================================


def test_aggregate_variant_metrics_correct_rates():
    """Verify aggregate metrics computation over multiple per-patch results."""
    variant = RemediationPipelineVariant.DIRECT_LLM

    per_patch = [
        PatchEvaluationMetrics(
            finding_id="GT-1",
            variant=variant,
            valid_unified_diff=True,
            fabricated_path_rate=0.0,
            target_finding_resolved=True,
            unnecessary_file_change_rate=0.5,
            model_calls=1,
            latency_ms=10.0,
        ),
        PatchEvaluationMetrics(
            finding_id="GT-2",
            variant=variant,
            valid_unified_diff=True,
            fabricated_path_rate=0.5,
            target_finding_resolved=False,
            unnecessary_file_change_rate=0.0,
            model_calls=1,
            latency_ms=20.0,
        ),
        PatchEvaluationMetrics(
            finding_id="GT-3",
            variant=variant,
            valid_unified_diff=False,
            fabricated_path_rate=0.0,
            target_finding_resolved=False,
            unnecessary_file_change_rate=0.0,
            model_calls=1,
            latency_ms=5.0,
        ),
    ]

    agg = aggregate_variant_metrics(per_patch, variant)

    assert agg.total_findings == 3
    assert agg.valid_diff_count == 2
    assert abs(agg.valid_diff_rate - 2.0 / 3.0) < 0.01
    assert agg.target_resolution_count == 1
    assert abs(agg.target_resolution_rate - 1.0 / 3.0) < 0.01
    assert abs(agg.avg_model_calls - 1.0) < 0.01
    assert abs(agg.avg_latency_ms - (10.0 + 20.0 + 5.0) / 3.0) < 0.1


def test_aggregate_variant_metrics_empty():
    """Verify aggregation returns zeroes for empty results."""
    agg = aggregate_variant_metrics([], RemediationPipelineVariant.FULL_PIPELINE)

    assert agg.total_findings == 0
    assert agg.valid_diff_rate == 0.0


# =========================================================================
# 4. Full Benchmark Execution Tests
# =========================================================================


@pytest.mark.asyncio
async def test_remediation_harness_full_benchmark():
    """Verify complete benchmark produces results for all 4 variants and all 4 fixtures."""
    harness = RemediationEvaluationHarness()
    report = await harness.run_full_benchmark()

    assert isinstance(report, RemediationBenchmarkReport)
    assert report.fixture_name == "synth-ecommerce-remediation"
    assert report.total_findings_evaluated == 4
    assert len(report.variant_results) == 4

    for variant in RemediationPipelineVariant:
        assert variant.name in report.variant_results
        agg = report.variant_results[variant.name]
        assert agg.total_findings == 4
        assert 0.0 <= agg.valid_diff_rate <= 1.0
        assert 0.0 <= agg.target_resolution_rate <= 1.0


@pytest.mark.asyncio
async def test_remediation_harness_direct_llm_has_unnecessary_files():
    """Verify variant A (Direct LLM) detects unnecessary file changes from README leak."""
    harness = RemediationEvaluationHarness()
    fixtures = build_remediation_fixtures()

    per_patch = await harness.evaluate_variant(
        RemediationPipelineVariant.DIRECT_LLM, fixtures
    )

    # All 4 fixtures should detect the README.md as unnecessary
    for p in per_patch:
        assert p.valid_unified_diff is True
        assert "README.md" in p.unnecessary_files_changed


@pytest.mark.asyncio
async def test_remediation_harness_planned_variants_clean_scope():
    """Verify variants B, C, D produce zero unnecessary file changes."""
    harness = RemediationEvaluationHarness()
    fixtures = build_remediation_fixtures()

    for variant in [
        RemediationPipelineVariant.FIXPLAN_PATCH,
        RemediationPipelineVariant.FIXPLAN_PATCH_VERIFICATION,
        RemediationPipelineVariant.FULL_PIPELINE,
    ]:
        per_patch = await harness.evaluate_variant(variant, fixtures)
        for p in per_patch:
            assert len(p.unnecessary_files_changed) == 0, (
                f"Variant {variant.value} had unnecessary files for {p.finding_id}"
            )


@pytest.mark.asyncio
async def test_remediation_harness_full_pipeline_critic_on_security():
    """Verify full pipeline variant invokes critic only for security findings."""
    harness = RemediationEvaluationHarness()
    fixtures = build_remediation_fixtures()

    per_patch = await harness.evaluate_variant(
        RemediationPipelineVariant.FULL_PIPELINE, fixtures
    )

    security_patches = [p for p in per_patch if p.finding_id == "REM-GT-001"]
    non_security_patches = [p for p in per_patch if p.finding_id != "REM-GT-001"]

    assert len(security_patches) == 1
    assert security_patches[0].critic_invoked is True

    for p in non_security_patches:
        assert p.critic_invoked is False


# =========================================================================
# 5. Report Serialization Tests
# =========================================================================


@pytest.mark.asyncio
async def test_remediation_benchmark_json_serialization():
    """Verify benchmark report serializes to valid JSON."""
    harness = RemediationEvaluationHarness()
    report = await harness.run_full_benchmark()

    json_str = report.model_dump_json(indent=2)
    parsed = json.loads(json_str)

    assert "variant_results" in parsed
    assert "per_patch_results" in parsed
    assert "markdown_summary" in parsed
    assert len(parsed["per_patch_results"]) == 16  # 4 fixtures × 4 variants


@pytest.mark.asyncio
async def test_remediation_benchmark_markdown_report():
    """Verify Markdown report contains comparison table and key observations."""
    harness = RemediationEvaluationHarness()
    report = await harness.run_full_benchmark()

    md = report.markdown_summary
    assert "# RepoLens Remediation Evaluation Benchmark Report" in md
    assert "Pipeline Variant Comparison" in md
    assert "Valid Diff Rate" in md
    assert "Target Resolution Rate" in md
    assert "Direct LLM" in md
    assert "Full Pipeline" in md
    assert "Key Observations" in md
