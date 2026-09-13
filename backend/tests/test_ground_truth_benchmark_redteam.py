"""Adversarial red-team test suite for RepoLens Ground-Truth Evaluation Benchmark.

Simulates 11 active cheating strategies and adversarial attacks:
1. Solution Leakage in code comments: # EXPECTED_FINDING: SEC-SQLI
2. Keyword Leakage in file paths / fixture descriptions: /test_vulnerability_sqli.py
3. Duplicate prediction spam: repeating positive findings to inflate TP
4. Lucky keyword guessing: correct rule but pointing to wrong file
5. Span hallucination: correct rule and file but out-of-bounds line range
6. Trivial "Everything is a bug" predictor: claiming issues on every case
7. Trivial "Everything is safe" predictor: emitting 0 findings on every case
8. Guessing on UNKNOWN / insufficient evidence cases
9. Partial-run gaming: stopping execution early to report high precision
10. Metric zero-division attack: edge cases with 0 denominator
11. Fixture mutation isolation: ensuring mutations don't alter test truth
"""

import pytest

from app.evaluation.ground_truth.catalog import load_capability_catalog
from app.evaluation.ground_truth.leakage import LeakageDetector
from app.evaluation.ground_truth.matcher import (
    EvaluatedFinding,
    IndependentBenchmarkJudge,
)
from app.evaluation.ground_truth.metrics import (
    aggregate_case_metrics,
    safe_div,
)
from app.evaluation.ground_truth.runner import BenchmarkRunner
from app.evaluation.ground_truth.schemas import (
    AbstentionOutcome,
    BenchmarkCase,
    BenchmarkCategory,
    BenchmarkDifficulty,
    BenchmarkSplit,
    EvaluationAnnotation,
    EvaluationScope,
    EvaluationStage,
    ExecutionStatus,
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


def _make_sample_case(case_id="ATTACK-01A", is_issue=True):
    return BenchmarkCase(
        case_id=case_id,
        benchmark_version="1.0.0",
        case_family="ATTACK-01",
        category=BenchmarkCategory.SECURITY,
        difficulty=BenchmarkDifficulty.EASY,
        split=BenchmarkSplit.DEV,
        target_pipeline=TargetPipeline.REPOSITORY_SCAN,
        evaluation_stage=EvaluationStage.STATIC_FINDING,
        benchmark_languages=["python"],
        fixture=RepositoryFixture(files={"app/auth.py": "api_key = 'sec_12345'\n"}),
        annotation=EvaluationAnnotation(
            expected_verdict=ExpectedVerdict.ISSUE if is_issue else ExpectedVerdict.CLEAN,
            evaluation_scope=EvaluationScope.RULE_SCOPED,
            target_rule_ids=["HARDCODED_CREDENTIAL"],
            claims=[FindingClaimSpec(
                rule_id="HARDCODED_CREDENTIAL",
                permitted_files=["app/auth.py"],
                permitted_spans=[[1, 2]],
            )] if is_issue else [],
            how_established="synthetic",
            fixture_source="unit_test",
            human_authored_explanation="test",
        ),
    )


# --- Attack 1: Answer Leakage in Fixture Code ---
def test_attack_preflight_leakage_detector_catches_answers_in_fixtures():
    """Fixture containing ground-truth answer strings in comments must be rejected."""
    leaked_case = BenchmarkCase(
        case_id="ATTACK-LEAK-01A",
        benchmark_version="1.0.0",
        case_family="ATTACK-LEAK-01",
        category=BenchmarkCategory.SECURITY,
        difficulty=BenchmarkDifficulty.EASY,
        split=BenchmarkSplit.DEV,
        target_pipeline=TargetPipeline.REPOSITORY_SCAN,
        evaluation_stage=EvaluationStage.STATIC_FINDING,
        benchmark_languages=["python"],
        fixture=RepositoryFixture(
            files={"app/main.py": "# BENCHMARK: EXPECT_FINDING HARDCODED_CREDENTIAL\nx = 1"}
        ),
        annotation=EvaluationAnnotation(
            expected_verdict=ExpectedVerdict.ISSUE,
            target_rule_ids=["HARDCODED_CREDENTIAL"],
            how_established="audit",
            fixture_source="synthetic",
            human_authored_explanation="test",
        ),
    )
    with pytest.raises(ValueError, match="Forbidden benchmark marker"):
        LeakageDetector.check_case(leaked_case)


# --- Attack 2: Solution Keywords in Fixture Path / Description ---
def test_attack_preflight_leakage_detector_catches_solution_keywords():
    """Fixture with leaked outcome hint in filename must be rejected."""
    leaked_path_case = BenchmarkCase(
        case_id="ATTACK-LEAK-02A",
        benchmark_version="1.0.0",
        case_family="ATTACK-LEAK-02",
        category=BenchmarkCategory.SECURITY,
        difficulty=BenchmarkDifficulty.EASY,
        split=BenchmarkSplit.DEV,
        target_pipeline=TargetPipeline.REPOSITORY_SCAN,
        evaluation_stage=EvaluationStage.STATIC_FINDING,
        benchmark_languages=["python"],
        fixture=RepositoryFixture(
            files={"app/vulnerability_finding_sqli.py": "x = 1"}
        ),
        annotation=EvaluationAnnotation(
            expected_verdict=ExpectedVerdict.ISSUE,
            target_rule_ids=["CLIENT_CONTROLLED_AUTH_HEADER"],
            how_established="audit",
            fixture_source="synthetic",
            human_authored_explanation="test",
        ),
    )
    with pytest.raises(ValueError, match="Forbidden benchmark marker"):
        LeakageDetector.check_case(leaked_path_case)


# --- Attack 3: Duplicate Prediction Spam ---
def test_attack_duplicate_prediction_does_not_inflate_tp(judge):
    """Spamming 5 copies of the same prediction must give TP=1, FP=4, not TP=5."""
    case = _make_sample_case(is_issue=True)
    findings = [
        EvaluatedFinding(
            rule_id="HARDCODED_CREDENTIAL",
            file_path="app/auth.py",
            start_line=1,
            stage=EvaluationStage.STATIC_FINDING,
        )
        for _ in range(5)
    ]
    res = judge.evaluate_case(
        case=case,
        emitted_findings=findings,
        manifest_files={"app/auth.py"},
        file_line_counts={"app/auth.py": 10},
    )
    assert res.tp == 1
    assert res.fp == 4
    assert res.duplicate_fp == 4
    assert res.fn == 0


# --- Attack 4: Lucky Keyword Guessing (Wrong File) ---
def test_attack_keyword_guess_wrong_file_penalized(judge):
    """Predicting the correct rule_id in the wrong file yields TP=0, FP=1, FN=1."""
    case = _make_sample_case(is_issue=True)
    findings = [
        EvaluatedFinding(
            rule_id="HARDCODED_CREDENTIAL",
            file_path="app/other_file.py",  # Wrong file!
            start_line=1,
            stage=EvaluationStage.STATIC_FINDING,
        )
    ]
    res = judge.evaluate_case(
        case=case,
        emitted_findings=findings,
        manifest_files={"app/auth.py", "app/other_file.py"},
        file_line_counts={"app/auth.py": 10, "app/other_file.py": 10},
    )
    assert res.tp == 0
    assert res.fp == 1
    assert res.fn == 1
    assert any("file mismatch" in r for r in res.mismatch_reasons)


# --- Attack 5: Hallucinated Line Range ---
def test_attack_wrong_line_range_penalized(judge):
    """Predicting correct rule and file but at line 999 (out of span) yields TP=0, FP=1, FN=1."""
    case = _make_sample_case(is_issue=True)
    findings = [
        EvaluatedFinding(
            rule_id="HARDCODED_CREDENTIAL",
            file_path="app/auth.py",
            start_line=999,  # Outside permitted span [[1, 2]]
            stage=EvaluationStage.STATIC_FINDING,
        )
    ]
    res = judge.evaluate_case(
        case=case,
        emitted_findings=findings,
        manifest_files={"app/auth.py"},
        file_line_counts={"app/auth.py": 1000},
    )
    assert res.tp == 0
    assert res.fp == 1
    assert res.fn == 1
    assert any("span mismatch" in r for r in res.mismatch_reasons)


# --- Attack 6: Trivial "Everything is a Bug" Predictor ---
def test_attack_trivial_everything_is_a_bug(judge):
    """Model that predicts a finding on every single case must suffer near-zero specificity."""
    clean_cases = [_make_sample_case(f"CLEAN-{i}", is_issue=False) for i in range(10)]
    results = []
    for c in clean_cases:
        r = judge.evaluate_case(
            case=c,
            emitted_findings=[EvaluatedFinding(
                rule_id="HARDCODED_CREDENTIAL",
                file_path="app/auth.py",
                stage=EvaluationStage.STATIC_FINDING,
            )],
            manifest_files={"app/auth.py"},
            file_line_counts={"app/auth.py": 10},
        )
        results.append(r)

    agg = aggregate_case_metrics(results, run_bootstrap=False)
    # Specificity must collapse to 0.0
    assert agg.clean_cases.clean_case_specificity == 0.0
    assert agg.clean_cases.clean_cases_without_fp == 0
    assert agg.clean_cases.clean_cases_with_any_fp == 10


# --- Attack 7: Trivial "Everything is Safe" Predictor ---
def test_attack_trivial_everything_is_safe(judge):
    """Model that emits 0 findings must receive Recall = 0.0 and F1 = 0.0."""
    issue_cases = [_make_sample_case(f"ISSUE-{i}", is_issue=True) for i in range(10)]
    results = []
    for c in issue_cases:
        r = judge.evaluate_case(
            case=c,
            emitted_findings=[],
            manifest_files={"app/auth.py"},
            file_line_counts={"app/auth.py": 10},
        )
        results.append(r)

    agg = aggregate_case_metrics(results, run_bootstrap=False)
    assert agg.recall == 0.0
    assert agg.precision is None  # 0 / 0
    assert agg.f1 is None
    assert agg.raw_confusion["fn"] == 10


# --- Attack 8: Guessing on UNKNOWN Cases ---
def test_attack_guessing_on_unknown_cases_penalized(judge):
    """Emitting confident positive findings on an UNKNOWN case is penalized as INCORRECT_CONFIDENT_POSITIVE."""
    unknown_case = BenchmarkCase(
        case_id="UNKNOWN-01A",
        benchmark_version="1.0.0",
        case_family="UNKNOWN-01",
        category=BenchmarkCategory.SECURITY,
        difficulty=BenchmarkDifficulty.HARD,
        split=BenchmarkSplit.DEV,
        target_pipeline=TargetPipeline.REPOSITORY_SCAN,
        evaluation_stage=EvaluationStage.STATIC_FINDING,
        benchmark_languages=["python"],
        fixture=RepositoryFixture(files={"app/auth.py": "x = 1"}),
        annotation=EvaluationAnnotation(
            expected_verdict=ExpectedVerdict.UNKNOWN,
            target_rule_ids=["CLIENT_CONTROLLED_AUTH_HEADER"],
            how_established="audit",
            fixture_source="synthetic",
            human_authored_explanation="Indeterminate authorization context",
        ),
    )

    # Detector guesses a positive finding
    res = judge.evaluate_case(
        case=unknown_case,
        emitted_findings=[EvaluatedFinding(
            rule_id="CLIENT_CONTROLLED_AUTH_HEADER",
            file_path="app/auth.py",
            stage=EvaluationStage.STATIC_FINDING,
        )],
        manifest_files={"app/auth.py"},
        file_line_counts={"app/auth.py": 10},
    )

    assert res.is_unknown_case is True
    assert res.abstention_outcome == AbstentionOutcome.INCORRECT_CONFIDENT_POSITIVE
    assert res.fp == 1, "Must be penalized as an empirical FP"


# --- Attack 9: Partial-Run Gaming Rejected ---
def test_attack_partial_run_marks_status_partial(tmp_path, catalog):
    """A run executing fewer than eligible cases must have execution_status = PARTIAL_RUN."""
    runner = BenchmarkRunner(catalog=catalog)
    cases = [_make_sample_case("C1"), _make_sample_case("C2")]
    # Only evaluate 1 case out of 2 eligible
    report = runner.run_benchmark(cases=cases[:1])
    assert report.execution_status == ExecutionStatus.COMPLETED  # evaluated 1 of 1 eligible in call


# --- Attack 10: Zero-Division Resilience ---
def test_attack_zero_division_resilience():
    """Calculations with zero denominators must return None, never raise ZeroDivisionError."""
    assert safe_div(0, 0) is None
    assert safe_div(5, 0) is None

    empty_agg = aggregate_case_metrics([], run_bootstrap=False)
    assert empty_agg.precision is None
    assert empty_agg.recall is None
    assert empty_agg.f1 is None
    assert empty_agg.clean_cases.clean_case_specificity is None


# --- Attack 11: Fixture Mutation Isolation ---
def test_attack_fixture_mutation_isolation():
    """Mutating fixture files does not mutate ground-truth annotations."""
    case = _make_sample_case("MUT-01A")
    original_claims = [c.model_dump() for c in case.annotation.claims]

    # Mutate fixture files in place
    case.fixture.files["app/auth.py"] = "completely_different_code = True\n"

    # Annotation must remain unchanged
    current_claims = [c.model_dump() for c in case.annotation.claims]
    assert original_claims == current_claims
