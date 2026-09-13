"""Integrity test suite for RepoLens Ground-Truth Evaluation Benchmark.

Validates:
- BenchmarkCase schema validation and catalog consistency
- Duplicate case_id rejection
- Invalid version handling
- Family-level split consistency and zero sibling leakage
- RepoLens Canonical Benchmark Serialization v1 bit-for-bit reproducibility
- Wilson score interval boundary conditions
- Family cluster bootstrap resampling with undefined replicate exclusion
- Duplicate prediction raw FP penalty (one-to-one matching)
- Layer metric isolation across stages
- Structural facts exact entailment matching
"""

import json
from pathlib import Path
import pytest
from pydantic import ValidationError

from app.evaluation.ground_truth.catalog import load_capability_catalog
from app.evaluation.ground_truth.loader import (
    BenchmarkDatasetLoader,
    compute_canonical_benchmark_hash,
    load_benchmark_dataset,
)
from app.evaluation.ground_truth.matcher import (
    CaseEvaluationResult,
    EvaluatedFinding,
    IndependentBenchmarkJudge,
)
from app.evaluation.ground_truth.metrics import (
    aggregate_case_metrics,
    compute_family_cluster_bootstrap,
    compute_wilson_ci,
    safe_div,
)
from app.evaluation.ground_truth.schemas import (
    BenchmarkCase,
    BenchmarkCategory,
    BenchmarkDifficulty,
    BenchmarkSplit,
    EvaluationAnnotation,
    EvaluationScope,
    EvaluationStage,
    ExpectedVerdict,
    FindingClaimSpec,
    RepositoryFixture,
    TargetPipeline,
)


@pytest.fixture
def catalog():
    return load_capability_catalog()


@pytest.fixture
def judge(catalog):
    return IndependentBenchmarkJudge(catalog=catalog)


def test_schema_validation_and_catalog_consistency(catalog):
    """All 90 cases in dataset must validate against BenchmarkCase and reference valid catalog rules."""
    loader = BenchmarkDatasetLoader(catalog=catalog)
    cases = loader.load_all_cases()
    assert len(cases) == 90, f"Expected 90 curated cases, got {len(cases)}"

    rule_map = catalog.get_rule_map()
    for case in cases:
        assert isinstance(case, BenchmarkCase)
        assert case.benchmark_version == "1.0.0"
        assert len(case.case_family) > 0
        assert case.category in BenchmarkCategory
        assert case.split in BenchmarkSplit

        # All claimed rule IDs must exist in capability catalog
        for claim in case.annotation.claims:
            assert claim.rule_id in rule_map, f"Rule {claim.rule_id} in {case.case_id} not in catalog"
            catalog_entry = rule_map[claim.rule_id]
            assert catalog_entry.evaluation_stage == case.evaluation_stage, (
                f"Stage mismatch for {claim.rule_id} in {case.case_id}: "
                f"catalog={catalog_entry.evaluation_stage} vs case={case.evaluation_stage}"
            )

        for tr_id in case.annotation.target_rule_ids:
            assert tr_id in rule_map, f"Target rule {tr_id} in {case.case_id} not in catalog"


def test_duplicate_case_id_rejected(tmp_path, catalog):
    """BenchmarkDatasetLoader must reject duplicate case_ids with ValueError."""
    case_data = {
        "case_id": "TEST-DUP-01A",
        "benchmark_version": "1.0.0",
        "case_family": "TEST-DUP-01",
        "category": "SECURITY",
        "difficulty": "EASY",
        "split": "DEV",
        "target_pipeline": "REPOSITORY_SCAN",
        "evaluation_stage": "STATIC_FINDING",
        "benchmark_languages": ["python"],
        "fixture": {"files": {"a.py": "x = 1"}},
        "annotation": {
            "expected_verdict": "CLEAN",
            "evaluation_scope": "RULE_SCOPED",
            "target_rule_ids": ["HARDCODED_CREDENTIAL"],
            "how_established": "audit",
            "fixture_source": "synthetic",
            "human_authored_explanation": "clean",
        },
    }

    f1 = tmp_path / "case1.json"
    f2 = tmp_path / "case2.json"
    f1.write_text(json.dumps(case_data), encoding="utf-8")
    f2.write_text(json.dumps(case_data), encoding="utf-8")

    loader = BenchmarkDatasetLoader(catalog=catalog)
    with pytest.raises(ValueError, match="Duplicate case_id 'TEST-DUP-01A'"):
        loader.load_all_cases(cases_dir=tmp_path)


def test_invalid_version_handling(catalog):
    """Cases with invalid or missing required fields must fail Pydantic validation."""
    with pytest.raises(ValidationError):
        BenchmarkCase.model_validate({
            "case_id": "TEST-INVALID-01",
            "category": "SECURITY",
            # Missing case_family, split, fixture, annotation
        })


def test_split_consistency_and_zero_sibling_leakage(catalog):
    """Case families must be strictly partitioned into DEV or FROZEN_PUBLIC_EVAL with zero sibling leakage."""
    cases = load_benchmark_dataset(catalog=catalog)
    family_splits = {}
    for case in cases:
        if case.case_family in family_splits:
            assert family_splits[case.case_family] == case.split, (
                f"Sibling leakage detected: family {case.case_family} found in both "
                f"{family_splits[case.case_family]} and {case.split}"
            )
        else:
            family_splits[case.case_family] = case.split

    # Verify holdout distribution
    dev_families = [f for f, s in family_splits.items() if s == BenchmarkSplit.DEV]
    holdout_families = [f for f, s in family_splits.items() if s == BenchmarkSplit.FROZEN_PUBLIC_EVAL]
    assert len(dev_families) == 18
    assert len(holdout_families) == 6


def test_canonical_benchmark_serialization_reproducibility(catalog):
    """Canonical serialization must produce identical SHA-256 regardless of case order in input list."""
    cases = load_benchmark_dataset(catalog=catalog)
    hash_forward = compute_canonical_benchmark_hash(cases)
    hash_reversed = compute_canonical_benchmark_hash(list(reversed(cases)))
    assert hash_forward == hash_reversed
    assert len(hash_forward) == 64

    # Verify against manifest
    manifest_path = (
        Path(__file__).resolve().parents[1]
        / "evaluation_data"
        / "ground_truth"
        / "v1"
        / "manifest.json"
    )
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    assert manifest["canonical_dataset_hash"] == hash_forward


def test_wilson_score_ci_boundaries():
    """Wilson interval must stay strictly in [0.0, 1.0] across all edge cases."""
    assert compute_wilson_ci(0, 0) is None

    zero_success = compute_wilson_ci(0, 10)
    assert zero_success is not None
    assert 0.0 <= zero_success[0] <= zero_success[1] <= 1.0
    assert zero_success[0] == 0.0

    all_success = compute_wilson_ci(10, 10)
    assert all_success is not None
    assert 0.0 <= all_success[0] <= all_success[1] <= 1.0
    assert all_success[1] == 1.0

    normal = compute_wilson_ci(7, 10)
    assert normal is not None
    assert 0.0 <= normal[0] <= 0.7 <= normal[1] <= 1.0


def test_family_cluster_bootstrap_resampling(judge):
    """Cluster bootstrap must resample entire families together and handle undefined replicates."""
    case = BenchmarkCase(
        case_id="TEST-SEC-01A",
        benchmark_version="1.0.0",
        case_family="TEST-SEC-01",
        category=BenchmarkCategory.SECURITY,
        difficulty=BenchmarkDifficulty.EASY,
        split=BenchmarkSplit.DEV,
        target_pipeline=TargetPipeline.REPOSITORY_SCAN,
        evaluation_stage=EvaluationStage.STATIC_FINDING,
        benchmark_languages=["python"],
        fixture=RepositoryFixture(files={"app/main.py": "x = 1"}),
        annotation=EvaluationAnnotation(
            expected_verdict=ExpectedVerdict.ISSUE,
            claims=[FindingClaimSpec(
                rule_id="HARDCODED_CREDENTIAL",
                permitted_files=["app/main.py"],
            )],
            how_established="synthetic",
            fixture_source="unit_test",
            human_authored_explanation="test",
        ),
    )

    clean_case = BenchmarkCase(
        case_id="TEST-SEC-02A",
        benchmark_version="1.0.0",
        case_family="TEST-SEC-02",
        category=BenchmarkCategory.SECURITY,
        difficulty=BenchmarkDifficulty.EASY,
        split=BenchmarkSplit.DEV,
        target_pipeline=TargetPipeline.REPOSITORY_SCAN,
        evaluation_stage=EvaluationStage.STATIC_FINDING,
        benchmark_languages=["python"],
        fixture=RepositoryFixture(files={"app/main.py": "x = 1"}),
        annotation=EvaluationAnnotation(
            expected_verdict=ExpectedVerdict.CLEAN,
            target_rule_ids=["HARDCODED_CREDENTIAL"],
            how_established="synthetic",
            fixture_source="unit_test",
            human_authored_explanation="test",
        ),
    )

    res1 = judge.evaluate_case(
        case=case,
        emitted_findings=[EvaluatedFinding(
            rule_id="HARDCODED_CREDENTIAL",
            file_path="app/main.py",
            stage=EvaluationStage.STATIC_FINDING,
        )],
        manifest_files={"app/main.py"},
        file_line_counts={"app/main.py": 10},
    )

    res2 = judge.evaluate_case(
        case=clean_case,
        emitted_findings=[],
        manifest_files={"app/main.py"},
        file_line_counts={"app/main.py": 10},
    )

    intervals = compute_family_cluster_bootstrap([res1, res2], iterations=100)
    assert "precision" in intervals
    assert "recall" in intervals
    assert intervals["precision"].valid_replicates > 0
    assert intervals["precision"].total_replicates == 100


def test_duplicate_prediction_raw_fp_penalty(judge):
    """If detector emits 3 duplicate findings for 1 expected claim: TP=1, raw FP=2, duplicate_fp=2."""
    case = BenchmarkCase(
        case_id="TEST-DUP-FINDING-01A",
        benchmark_version="1.0.0",
        case_family="TEST-DUP-FINDING-01",
        category=BenchmarkCategory.SECURITY,
        difficulty=BenchmarkDifficulty.EASY,
        split=BenchmarkSplit.DEV,
        target_pipeline=TargetPipeline.REPOSITORY_SCAN,
        evaluation_stage=EvaluationStage.STATIC_FINDING,
        benchmark_languages=["python"],
        fixture=RepositoryFixture(files={"app/auth.py": "password = 'secret'"}),
        annotation=EvaluationAnnotation(
            expected_verdict=ExpectedVerdict.ISSUE,
            claims=[FindingClaimSpec(
                rule_id="HARDCODED_CREDENTIAL",
                permitted_files=["app/auth.py"],
            )],
            how_established="synthetic",
            fixture_source="unit_test",
            human_authored_explanation="test",
        ),
    )

    # Detector emits 3 identical findings
    emitted = [
        EvaluatedFinding(
            rule_id="HARDCODED_CREDENTIAL",
            file_path="app/auth.py",
            stage=EvaluationStage.STATIC_FINDING,
        )
        for _ in range(3)
    ]

    res = judge.evaluate_case(
        case=case,
        emitted_findings=emitted,
        manifest_files={"app/auth.py"},
        file_line_counts={"app/auth.py": 10},
    )

    assert res.tp == 1, "Exactly 1 TP must be awarded"
    assert res.fp == 2, "Extra 2 predictions must be penalized as raw FPs"
    assert res.duplicate_fp == 2, "Duplicate FP count must be 2"
    assert res.fn == 0


def test_layer_metric_isolation():
    """Metrics for one evaluation stage must not contaminate another stage."""
    case_results = []
    # Stage 1: STATIC_FINDING result with TP=1, FP=0
    r1 = CaseEvaluationResult(
        case_id="C1",
        case_family="F1",
        split="DEV",
        category="SECURITY",
        difficulty="EASY",
        evaluation_stage=EvaluationStage.STATIC_FINDING,
        expected_verdict=ExpectedVerdict.ISSUE,
        evaluation_scope=EvaluationScope.RULE_SCOPED,
        tp=1,
        fp=0,
        fn=0,
    )
    # Stage 2: CHANGE_FACT result with TP=0, FP=1, FN=1
    r2 = CaseEvaluationResult(
        case_id="C2",
        case_family="F2",
        split="DEV",
        category="CONTRACT",
        difficulty="EASY",
        evaluation_stage=EvaluationStage.CHANGE_FACT,
        expected_verdict=ExpectedVerdict.ISSUE,
        evaluation_scope=EvaluationScope.RULE_SCOPED,
        tp=0,
        fp=1,
        fn=1,
    )
    case_results.extend([r1, r2])

    agg = aggregate_case_metrics(case_results, run_bootstrap=False)
    static_lm = agg.layer_metrics[EvaluationStage.STATIC_FINDING.value]
    change_lm = agg.layer_metrics[EvaluationStage.CHANGE_FACT.value]

    assert static_lm.tp == 1
    assert static_lm.fp == 0
    assert static_lm.precision == 1.0

    assert change_lm.tp == 0
    assert change_lm.fp == 1
    assert change_lm.precision == 0.0


def test_structural_facts_exact_matching(judge):
    """An emitted finding missing required structural facts must be rejected as an unsupported claim."""
    case = BenchmarkCase(
        case_id="TEST-STRUCT-01A",
        benchmark_version="1.0.0",
        case_family="TEST-STRUCT-01",
        category=BenchmarkCategory.CONTRACT,
        difficulty=BenchmarkDifficulty.EASY,
        split=BenchmarkSplit.DEV,
        target_pipeline=TargetPipeline.CHANGE_ANALYSIS,
        evaluation_stage=EvaluationStage.CHANGE_FACT,
        benchmark_languages=["python"],
        fixture=RepositoryFixture(files={"app/routes.py": "x = 1"}),
        annotation=EvaluationAnnotation(
            expected_verdict=ExpectedVerdict.ISSUE,
            claims=[FindingClaimSpec(
                rule_id="ROUTE_PATH_MISMATCH",
                permitted_files=["app/routes.py"],
                required_structural_facts={"change_type": "PATH_CHANGED"},
                forbidden_structural_facts={"change_type": "METHOD_CHANGED"},
            )],
            how_established="synthetic",
            fixture_source="unit_test",
            human_authored_explanation="test",
        ),
    )

    # 1. Matches with correct structural fact
    res_pass = judge.evaluate_case(
        case=case,
        emitted_findings=[EvaluatedFinding(
            rule_id="ROUTE_PATH_MISMATCH",
            file_path="app/routes.py",
            stage=EvaluationStage.CHANGE_FACT,
            structural_facts={"change_type": "PATH_CHANGED"},
        )],
        manifest_files={"app/routes.py"},
        file_line_counts={"app/routes.py": 10},
    )
    assert res_pass.tp == 1
    assert res_pass.fp == 0
    assert res_pass.unsupported_claim_count == 0

    # 2. Fails if structural fact is wrong
    res_fail = judge.evaluate_case(
        case=case,
        emitted_findings=[EvaluatedFinding(
            rule_id="ROUTE_PATH_MISMATCH",
            file_path="app/routes.py",
            stage=EvaluationStage.CHANGE_FACT,
            structural_facts={"change_type": "METHOD_CHANGED"},
        )],
        manifest_files={"app/routes.py"},
        file_line_counts={"app/routes.py": 10},
    )
    assert res_fail.tp == 0
    assert res_fail.fp == 1
    assert res_fail.unsupported_claim_count == 1
    assert any("forbidden structural fact" in r for r in res_fail.mismatch_reasons)
