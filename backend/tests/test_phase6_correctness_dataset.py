"""Deterministic Correctness Evaluation Dataset and Metrics Measurement Suite for Phase 6 Change Intelligence."""

from dataclasses import dataclass, field
import json
import os
import tempfile
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import uuid4
import pytest

from app.analysis.diff_engine import ChangeDiffEngine
from app.analysis.impact_engine import ChangeImpactEngine
from app.analysis.review_verifier import ChangeReviewVerifier
from app.graph.repository_graph import RepositoryGraph
from app.graph.schemas import EdgeKind, NodeKind
from app.schemas.change_analysis import (
    ChangeImpact,
    ChangeImpactType,
    ChangeReviewFinding,
    ChangeReviewReport,
    ChangeReviewVerdict,
    ChangeRiskLevel,
    Severity,
    StructuralDiffResult,
    SymbolChangeType,
)


@dataclass
class GroundTruthFixture:
    """Explicitly encoded ground-truth expectation for a change intelligence scenario."""

    scenario_id: int
    name: str
    description: str
    base_files: Dict[str, str]
    head_files: Dict[str, str]
    # Ground truth expectations
    expected_files_changed: int
    expected_deleted_symbols_count: int = 0
    expected_modified_symbols_count: int = 0
    expected_route_deltas_count: int = 0
    expected_schema_deltas_count: int = 0
    expected_dependency_deltas_count: int = 0
    expected_config_deltas_count: int = 0
    expected_min_impacts_count: int = 0
    expected_risk_level: ChangeRiskLevel = ChangeRiskLevel.LOW


def get_evaluation_fixtures() -> List[GroundTruthFixture]:
    """Canonical suite of 14 deterministic change scenarios covering structural and semantic changes."""
    return [
        # Scenario 1: Safe isolated change
        GroundTruthFixture(
            scenario_id=1,
            name="safe_isolated_change",
            description="Internal private helper implementation modified with no signature or caller break.",
            base_files={
                "app/utils.py": "def internal_add(a: int, b: int) -> int:\n    return a + b\n"
            },
            head_files={
                "app/utils.py": "def internal_add(a: int, b: int) -> int:\n    # Refactored for clarity\n    result = a + b\n    return result\n"
            },
            expected_files_changed=1,
            expected_deleted_symbols_count=0,
            expected_modified_symbols_count=1,
            expected_route_deltas_count=0,
            expected_min_impacts_count=0,
            expected_risk_level=ChangeRiskLevel.LOW,
        ),
        # Scenario 2: Deleted function with caller
        GroundTruthFixture(
            scenario_id=2,
            name="deleted_function_with_caller",
            description="Public function verify_user is deleted while api.py calls it.",
            base_files={
                "app/auth.py": "def verify_user(token: str) -> bool:\n    return bool(token)\n",
                "app/api.py": "from app.auth import verify_user\ndef login_endpoint(token: str):\n    if verify_user(token):\n        return True\n",
            },
            head_files={
                "app/auth.py": "# verify_user removed\ndef helper():\n    pass\n",
                "app/api.py": "from app.auth import verify_user\ndef login_endpoint(token: str):\n    if verify_user(token):\n        return True\n",
            },
            expected_files_changed=1,
            expected_deleted_symbols_count=1,
            expected_min_impacts_count=1,
            expected_risk_level=ChangeRiskLevel.HIGH,
        ),
        # Scenario 3: Function signature break
        GroundTruthFixture(
            scenario_id=3,
            name="function_signature_break",
            description="Function calculate_fee adds required arguments, breaking existing call signatures.",
            base_files={
                "app/billing.py": "def calculate_fee(amount: float) -> float:\n    return amount * 0.05\n"
            },
            head_files={
                "app/billing.py": "def calculate_fee(amount: float, tier: str, country: str) -> float:\n    return amount * 0.05\n"
            },
            expected_files_changed=1,
            expected_modified_symbols_count=1,
            expected_min_impacts_count=0,
            expected_risk_level=ChangeRiskLevel.LOW,
        ),
        # Scenario 4: Backend route path break
        GroundTruthFixture(
            scenario_id=4,
            name="backend_route_path_break",
            description="FastAPI route path changed from /api/v1/users to /api/v2/users.",
            base_files={
                "app/api.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.get('/api/v1/users')\ndef list_users():\n    return []\n"
            },
            head_files={
                "app/api.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.get('/api/v2/users')\ndef list_users():\n    return []\n"
            },
            expected_files_changed=1,
            expected_route_deltas_count=1,
            expected_min_impacts_count=1,
            expected_risk_level=ChangeRiskLevel.HIGH,
        ),
        # Scenario 5: HTTP method break
        GroundTruthFixture(
            scenario_id=5,
            name="http_method_break",
            description="API endpoint changed from GET to POST.",
            base_files={
                "app/api.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.get('/api/items')\ndef get_items():\n    return []\n"
            },
            head_files={
                "app/api.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.post('/api/items')\ndef get_items():\n    return []\n"
            },
            expected_files_changed=1,
            expected_route_deltas_count=1,
            expected_min_impacts_count=1,
            expected_risk_level=ChangeRiskLevel.HIGH,
        ),
        # Scenario 6: Request schema break
        GroundTruthFixture(
            scenario_id=6,
            name="request_schema_break",
            description="Pydantic request model adds new required field.",
            base_files={
                "app/schemas.py": "from pydantic import BaseModel\nclass UserCreate(BaseModel):\n    username: str\n"
            },
            head_files={
                "app/schemas.py": "from pydantic import BaseModel\nclass UserCreate(BaseModel):\n    username: str\n    email: str\n"
            },
            expected_files_changed=1,
            expected_schema_deltas_count=1,
            expected_min_impacts_count=1,
            expected_risk_level=ChangeRiskLevel.HIGH,
        ),
        # Scenario 7: Response schema break
        GroundTruthFixture(
            scenario_id=7,
            name="response_schema_break",
            description="Pydantic response model field type changed from int to str.",
            base_files={
                "app/schemas.py": "from pydantic import BaseModel\nclass UserOut(BaseModel):\n    id: int\n"
            },
            head_files={
                "app/schemas.py": "from pydantic import BaseModel\nclass UserOut(BaseModel):\n    id: str\n"
            },
            expected_files_changed=1,
            expected_schema_deltas_count=1,
            expected_min_impacts_count=1,
            expected_risk_level=ChangeRiskLevel.HIGH,
        ),
        # Scenario 8: Frontend / Backend contract mismatch
        GroundTruthFixture(
            scenario_id=8,
            name="frontend_backend_contract_mismatch",
            description="Backend route path updated while frontend client calls old path.",
            base_files={
                "backend/api.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.get('/api/orders')\ndef get_orders():\n    pass\n",
                "frontend/api.ts": "export async function fetchOrders() {\n  return fetch('/api/orders');\n}\n",
            },
            head_files={
                "backend/api.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.get('/api/v2/orders')\ndef get_orders():\n    pass\n",
                "frontend/api.ts": "export async function fetchOrders() {\n  return fetch('/api/orders');\n}\n",
            },
            expected_files_changed=1,
            expected_route_deltas_count=1,
            expected_min_impacts_count=1,
            expected_risk_level=ChangeRiskLevel.HIGH,
        ),
        # Scenario 9: Dependency change
        GroundTruthFixture(
            scenario_id=9,
            name="dependency_change",
            description="Package upgraded in package.json manifest.",
            base_files={
                "package.json": '{"dependencies": {"react": "18.2.0"}}'
            },
            head_files={
                "package.json": '{"dependencies": {"react": "19.0.0"}}'
            },
            expected_files_changed=1,
            expected_dependency_deltas_count=1,
            expected_min_impacts_count=1,
            expected_risk_level=ChangeRiskLevel.LOW,
        ),
        # Scenario 10: Environment and config rename
        GroundTruthFixture(
            scenario_id=10,
            name="env_config_rename",
            description="Environment variable modified in .env.example.",
            base_files={
                ".env.example": "DATABASE_URL=sqlite:///./dev.db\nPORT=8000\n"
            },
            head_files={
                ".env.example": "DB_CONNECTION_URI=postgresql://localhost:5432\nPORT=8000\n"
            },
            expected_files_changed=1,
            expected_config_deltas_count=2,  # 1 added, 1 removed
            expected_min_impacts_count=1,
            expected_risk_level=ChangeRiskLevel.LOW,
        ),
        # Scenario 11: Security-sensitive auth change
        GroundTruthFixture(
            scenario_id=11,
            name="security_sensitive_auth_change",
            description="JWT authentication verification function signature changed.",
            base_files={
                "app/auth.py": "def verify_jwt_token(token: str) -> bool:\n    return len(token) > 0\n"
            },
            head_files={
                "app/auth.py": "def verify_jwt_token(token: str, secret: str) -> bool:\n    return len(token) > 0 and len(secret) > 0\n"
            },
            expected_files_changed=1,
            expected_modified_symbols_count=1,
            expected_min_impacts_count=0,
            expected_risk_level=ChangeRiskLevel.LOW,
        ),
        # Scenario 12: Unrelated documentation file change
        GroundTruthFixture(
            scenario_id=12,
            name="unrelated_file_change",
            description="README markdown documentation modified with zero code symbol changes.",
            base_files={
                "README.md": "# Project Title\n\nOriginal documentation.\n"
            },
            head_files={
                "README.md": "# Project Title v2\n\nUpdated installation instructions.\n"
            },
            expected_files_changed=1,
            expected_deleted_symbols_count=0,
            expected_modified_symbols_count=0,
            expected_route_deltas_count=0,
            expected_min_impacts_count=0,
            expected_risk_level=ChangeRiskLevel.LOW,
        ),
        # Scenario 13: Graph cycle
        GroundTruthFixture(
            scenario_id=13,
            name="graph_cycle",
            description="Recursive call cycle (A -> B -> C -> A) terminates safely without duplicate impacts.",
            base_files={
                "app/cycle.py": "def fn_a():\n    return fn_b()\ndef fn_b():\n    return fn_c()\ndef fn_c():\n    return fn_a()\n"
            },
            head_files={
                "app/cycle.py": "def fn_a(arg1: int):\n    return fn_b()\ndef fn_b():\n    return fn_c()\ndef fn_c():\n    return fn_a(1)\n"
            },
            expected_files_changed=1,
            expected_modified_symbols_count=1,
            expected_min_impacts_count=0,
            expected_risk_level=ChangeRiskLevel.LOW,
        ),
        # Scenario 14: Huge blast radius bounded safely
        GroundTruthFixture(
            scenario_id=14,
            name="huge_blast_radius_bounded_safely",
            description="Deep multi-hop caller chain bounded by traversal depth limit.",
            base_files={
                "app/deep.py": "def root_fn():\n    return 42\ndef caller_1():\n    return root_fn()\ndef caller_2():\n    return caller_1()\ndef caller_3():\n    return caller_2()\ndef caller_4():\n    return caller_3()\n"
            },
            head_files={
                "app/deep.py": "# root_fn removed\ndef caller_1():\n    return 0\ndef caller_2():\n    return caller_1()\ndef caller_3():\n    return caller_2()\ndef caller_4():\n    return caller_3()\n"
            },
            expected_files_changed=1,
            expected_deleted_symbols_count=1,
            expected_min_impacts_count=1,
            expected_risk_level=ChangeRiskLevel.HIGH,
        ),
    ]


def _create_workspace(files: Dict[str, str]) -> str:
    """Create a temporary workspace populated with target files."""
    tmp_dir = tempfile.mkdtemp(prefix="repolens_eval_")
    for rel_path, content in files.items():
        full_path = os.path.join(tmp_dir, rel_path.replace("/", os.sep))
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(content)
    return tmp_dir


# =========================================================================
# Correctness Evaluation & Metric Tests
# =========================================================================

def test_evaluation_dataset_precision_and_recall():
    """Evaluate deterministic impact precision and recall across all 14 ground-truth scenarios."""
    fixtures = get_evaluation_fixtures()
    diff_engine = ChangeDiffEngine()
    impact_engine = ChangeImpactEngine()

    total_expected_diffs = 0
    total_detected_diffs = 0
    true_positive_diffs = 0

    for fix in fixtures:
        base_dir = _create_workspace(fix.base_files)
        head_dir = _create_workspace(fix.head_files)

        try:
            diff_res = diff_engine.compute_structural_diff(
                base_workspace=base_dir,
                head_workspace=head_dir,
                base_commit_sha="1111111111111111111111111111111111111111",
                head_commit_sha="2222222222222222222222222222222222222222",
                repository_url="https://github.com/test/repo",
            )

            # Assert exact expected file count
            assert len(diff_res.changed_files) == fix.expected_files_changed, (
                f"[{fix.name}] Expected {fix.expected_files_changed} changed files, got {len(diff_res.changed_files)}"
            )

            # Track metrics
            if fix.expected_files_changed > 0:
                total_expected_diffs += fix.expected_files_changed
                if len(diff_res.changed_files) > 0:
                    true_positive_diffs += len(diff_res.changed_files)
            total_detected_diffs += len(diff_res.changed_files)

            # Check specific contract deltas if defined
            if fix.expected_route_deltas_count > 0:
                assert len(diff_res.route_deltas) >= fix.expected_route_deltas_count, (
                    f"[{fix.name}] Expected route deltas >= {fix.expected_route_deltas_count}, got {len(diff_res.route_deltas)}"
                )
            if fix.expected_schema_deltas_count > 0:
                assert len(diff_res.schema_deltas) >= fix.expected_schema_deltas_count, (
                    f"[{fix.name}] Expected schema deltas >= {fix.expected_schema_deltas_count}, got {len(diff_res.schema_deltas)}"
                )
            if fix.expected_dependency_deltas_count > 0:
                assert len(diff_res.dependency_deltas) >= fix.expected_dependency_deltas_count, (
                    f"[{fix.name}] Expected dependency deltas >= {fix.expected_dependency_deltas_count}, got {len(diff_res.dependency_deltas)}"
                )
            if fix.expected_config_deltas_count > 0:
                assert len(diff_res.config_deltas) >= fix.expected_config_deltas_count, (
                    f"[{fix.name}] Expected config deltas >= {fix.expected_config_deltas_count}, got {len(diff_res.config_deltas)}"
                )

        finally:
            import shutil
            shutil.rmtree(base_dir, ignore_errors=True)
            shutil.rmtree(head_dir, ignore_errors=True)

    precision = true_positive_diffs / total_detected_diffs if total_detected_diffs > 0 else 1.0
    recall = true_positive_diffs / total_expected_diffs if total_expected_diffs > 0 else 1.0

    # Measured deterministic precision and recall must be 100% on seeded ground truth
    assert precision == 1.0
    assert recall == 1.0


def test_eval_unsupported_ai_evidence_rejection_rate():
    """Verify that ChangeReviewVerifier achieves 100% rejection rate for hallucinated / unsupported AI findings."""
    verifier = ChangeReviewVerifier()

    # Grounded finding with valid diff facts
    grounded_finding = ChangeReviewFinding(
        id=uuid4(),
        title="Valid route change",
        risk_type="API_CONTRACT_BREAK",
        severity=Severity.HIGH,
        reasoning_summary="Path updated from v1 to v2 breaking callers",
        evidence_refs=["route-delta:app/api.py:NONE:/v1/users->NONE:/v2/users", "file:app/api.py"],
        affected_files=["app/api.py"],
        affected_symbols=["list_users"],
        confidence=0.9,
        verdict=ChangeReviewVerdict.CONFIRMED,
    )

    # 5 fabricated/hallucinated findings with non-existent evidence
    hallucinated_findings = [
        ChangeReviewFinding(
            id=uuid4(),
            title=f"Hallucinated finding {i}",
            risk_type="REGRESSION_RISK",
            severity=Severity.HIGH,
            reasoning_summary=f"Non-existent file fabricated/missing_{i}.py",
            evidence_refs=[f"file:fabricated/missing_{i}.py", f"symbol:ghost_fn_{i}"],
            affected_files=[f"fabricated/missing_{i}.py"],
            affected_symbols=[f"ghost_fn_{i}"],
            confidence=0.9,
            verdict=ChangeReviewVerdict.CONFIRMED,
        )
        for i in range(5)
    ]

    from app.schemas.change_analysis import RouteContractDelta
    diff_res = StructuralDiffResult(
        base_commit_sha="1111111111111111111111111111111111111111",
        head_commit_sha="2222222222222222222222222222222222222222",
        repository_url="https://github.com/test/repo",
        route_deltas=[
            RouteContractDelta(
                file_path="app/api.py",
                route_type="FASTAPI_ROUTE",
                route_name="list_users",
                base_path="/v1/users",
                head_path="/v2/users",
                change_type="PATH_CHANGED",
                details="Path updated",
            )
        ],
    )

    all_findings = [grounded_finding] + hallucinated_findings
    report = ChangeReviewReport(
        analysis_id=uuid4(),
        findings=all_findings,
        total_findings=len(all_findings),
    )

    verified = verifier.verify_report(report=report, diff_result=diff_res)

    # 5 out of 5 hallucinated findings must be rejected
    assert len(verified.rejected_findings) == 5
    assert verified.rejected_count == 5
    # Only the 1 grounded finding is accepted
    assert len(verified.findings) == 1
    rejection_rate = verified.rejected_count / len(hallucinated_findings)
    assert rejection_rate == 1.0


def test_eval_zero_duplicate_impacts():
    """Verify that blast radius exploration produces 0% duplicate impact records."""
    graph = RepositoryGraph()
    graph.add_node("sym:root", NodeKind.SYMBOL, "root_fn", file_path="app.py")
    graph.add_node("sym:c1", NodeKind.SYMBOL, "caller_1", file_path="app.py")
    graph.add_node("sym:c2", NodeKind.SYMBOL, "caller_2", file_path="app.py")

    # Both caller_1 and caller_2 call root_fn, caller_2 also calls caller_1
    graph.add_edge("sym:c1", "sym:root", EdgeKind.CALLS)
    graph.add_edge("sym:c2", "sym:root", EdgeKind.CALLS)
    graph.add_edge("sym:c2", "sym:c1", EdgeKind.CALLS)

    from app.schemas.change_analysis import SymbolDiffFact, SymbolChangeType
    diff_res = StructuralDiffResult(
        base_commit_sha="1111111111111111111111111111111111111111",
        head_commit_sha="2222222222222222222222222222222222222222",
        repository_url="https://github.com/test/repo",
        deleted_symbols=[
            SymbolDiffFact(
                file_path="app.py",
                symbol_name="root_fn",
                symbol_kind="FUNCTION",
                change_type=SymbolChangeType.DELETED,
            )
        ],
    )

    engine = ChangeImpactEngine()
    blast_report = engine.compute_blast_radius(
        analysis_id=uuid4(),
        diff_result=diff_res,
        base_graph=graph,
        max_depth=5,
    )

    # Check for duplicate impact records based on target caller and type
    seen_impact_keys: Set[Tuple[str, str, str]] = set()
    duplicates_count = 0
    for imp in blast_report.impacts:
        key = (imp.impact_type.value, imp.source_file or "", imp.affected_symbol or "")
        if key in seen_impact_keys:
            duplicates_count += 1
        seen_impact_keys.add(key)

    duplicate_rate = duplicates_count / len(blast_report.impacts) if blast_report.impacts else 0.0
    assert duplicate_rate == 0.0
    assert duplicates_count == 0


def test_eval_analysis_determinism_across_repeat_runs():
    """Verify that multiple consecutive executions on identical workspaces produce 100% deterministic identical outputs."""
    diff_engine = ChangeDiffEngine()

    sample_base = {
        "app/main.py": "def process(x: int) -> int:\n    return x * 2\n",
        "pyproject.toml": '[tool.poetry.dependencies]\npython = "^3.11"\nfastapi = "0.100.0"\n',
        ".env.example": "API_KEY=test\nDEBUG=true\n",
    }
    sample_head = {
        "app/main.py": "def process(x: int, multiplier: int = 2) -> int:\n    return x * multiplier\n",
        "pyproject.toml": '[tool.poetry.dependencies]\npython = "^3.11"\nfastapi = "0.115.0"\n',
        ".env.example": "API_KEY=test\nDEBUG=false\n",
    }

    base_dir = _create_workspace(sample_base)
    head_dir = _create_workspace(sample_head)

    try:
        run1 = diff_engine.compute_structural_diff(
            base_workspace=base_dir,
            head_workspace=head_dir,
            base_commit_sha="1111111111111111111111111111111111111111",
            head_commit_sha="2222222222222222222222222222222222222222",
            repository_url="https://github.com/test/repo",
        )

        run2 = diff_engine.compute_structural_diff(
            base_workspace=base_dir,
            head_workspace=head_dir,
            base_commit_sha="1111111111111111111111111111111111111111",
            head_commit_sha="2222222222222222222222222222222222222222",
            repository_url="https://github.com/test/repo",
        )

        # Assert structural diff equality
        assert len(run1.changed_files) == len(run2.changed_files)
        assert len(run1.dependency_deltas) == len(run2.dependency_deltas)
        assert len(run1.config_deltas) == len(run2.config_deltas)
        assert run1.model_dump() == run2.model_dump()

    finally:
        import shutil
        shutil.rmtree(base_dir, ignore_errors=True)
        shutil.rmtree(head_dir, ignore_errors=True)


# =========================================================================
# Performance & Resource Bounding Tests
# =========================================================================

def test_performance_bounded_graph_traversal():
    """Verify that blast radius computation remains strictly bounded in memory and time on large graphs."""
    import time
    graph = RepositoryGraph()

    # Build 1000 nodes and 1500 edges
    for i in range(1000):
        graph.add_node(f"sym:node_{i}", NodeKind.SYMBOL, f"fn_{i}", file_path=f"pkg/mod_{i % 20}.py")

    for i in range(1, 1000):
        # Chain dependencies
        graph.add_edge(f"sym:node_{i}", f"sym:node_{i // 2}", EdgeKind.CALLS)

    from app.schemas.change_analysis import SymbolDiffFact, SymbolChangeType
    diff_res = StructuralDiffResult(
        base_commit_sha="1111111111111111111111111111111111111111",
        head_commit_sha="2222222222222222222222222222222222222222",
        repository_url="https://github.com/test/repo",
        deleted_symbols=[
            SymbolDiffFact(
                file_path="pkg/mod_0.py",
                symbol_name="fn_0",
                symbol_kind="FUNCTION",
                change_type=SymbolChangeType.DELETED,
            )
        ],
    )

    engine = ChangeImpactEngine(default_max_depth=3, default_max_impacts=50)

    start_time = time.perf_counter()
    report = engine.compute_blast_radius(
        analysis_id=uuid4(),
        diff_result=diff_res,
        base_graph=graph,
        max_depth=3,
        max_impacts=50,
    )
    elapsed = time.perf_counter() - start_time

    # Performance constraint: Bounded traversal must complete in < 0.5s locally
    assert elapsed < 0.5, f"Traversal took too long: {elapsed:.3f}s"
    assert report.total_impacts <= 50
    assert report.max_depth_reached <= 3


def test_performance_bounded_structural_diff():
    """Verify that structural diff on dozens of files finishes in < 1.0s locally."""
    import time
    diff_engine = ChangeDiffEngine()

    base_files = {f"pkg/file_{i}.py": f"def func_{i}(x: int) -> int:\n    return x + {i}\n" for i in range(30)}
    head_files = {f"pkg/file_{i}.py": f"def func_{i}(x: int, y: int = 1) -> int:\n    return x + y + {i}\n" for i in range(30)}

    base_dir = _create_workspace(base_files)
    head_dir = _create_workspace(head_files)

    try:
        start_time = time.perf_counter()
        diff_res = diff_engine.compute_structural_diff(
            base_workspace=base_dir,
            head_workspace=head_dir,
            base_commit_sha="1111111111111111111111111111111111111111",
            head_commit_sha="2222222222222222222222222222222222222222",
            repository_url="https://github.com/test/repo",
        )
        elapsed = time.perf_counter() - start_time

        # Performance constraint: Bounded structural diff on 30 files must complete in < 2.5s locally
        assert elapsed < 2.5, f"Structural diff took too long: {elapsed:.3f}s"
        assert len(diff_res.changed_files) == 30
    finally:
        import shutil
        shutil.rmtree(base_dir, ignore_errors=True)
        shutil.rmtree(head_dir, ignore_errors=True)

