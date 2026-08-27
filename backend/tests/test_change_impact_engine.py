"""Comprehensive tests for Phase 6D: Graph-Aware Change Impact Engine."""

from uuid import uuid4
import pytest

from app.analysis.impact_engine import ChangeImpactEngine, get_impact_engine
from app.graph.repository_graph import RepositoryGraph
from app.graph.schemas import EdgeKind, NodeKind
from app.schemas.change_analysis import (
    BlastRadiusReport,
    ConfigDelta,
    DependencyDelta,
    FileChangeType,
    FileDiffFact,
    RouteContractDelta,
    SchemaModelDelta,
    StructuralDiffResult,
    SymbolChangeType,
    SymbolDiffFact,
)
from app.schemas.enums import (
    ChangeImpactType,
    ChangeRiskLevel,
    ImpactVerificationStatus,
    Severity,
)


@pytest.fixture
def base_and_head_graphs():
    """Create a populated RepositoryGraph with callers, multi-hop chains, cycles, routes, and schemas."""
    graph = RepositoryGraph()

    # 1. File nodes
    graph.add_node("file:app/services/auth.py", NodeKind.FILE, "auth.py", file_path="app/services/auth.py")
    graph.add_node("file:app/api/auth.py", NodeKind.FILE, "auth.py", file_path="app/api/auth.py")
    graph.add_node("file:app/api/users.py", NodeKind.FILE, "users.py", file_path="app/api/users.py")
    graph.add_node("file:app/main.py", NodeKind.FILE, "main.py", file_path="app/main.py")
    graph.add_node("file:app/unrelated.py", NodeKind.FILE, "unrelated.py", file_path="app/unrelated.py")
    graph.add_node("file:frontend/src/api.ts", NodeKind.FILE, "api.ts", file_path="frontend/src/api.ts")
    graph.add_node("file:app/schemas/user.py", NodeKind.FILE, "user.py", file_path="app/schemas/user.py")

    # 2. Symbol nodes
    # Target Callee (to be deleted or signature changed)
    graph.add_node(
        "symbol:app/services/auth.py:FUNCTION:verify_token:10",
        NodeKind.SYMBOL,
        "verify_token",
        file_path="app/services/auth.py",
        start_line=10,
        end_line=15,
        metadata={"kind": "FUNCTION"},
    )
    # Direct Caller (Depth 1)
    graph.add_node(
        "symbol:app/api/auth.py:FUNCTION:login_endpoint:20",
        NodeKind.SYMBOL,
        "login_endpoint",
        file_path="app/api/auth.py",
        start_line=20,
        end_line=30,
        metadata={"kind": "FUNCTION"},
    )
    # Transitive Caller (Depth 2)
    graph.add_node(
        "symbol:app/api/users.py:FUNCTION:get_current_user:40",
        NodeKind.SYMBOL,
        "get_current_user",
        file_path="app/api/users.py",
        start_line=40,
        end_line=50,
        metadata={"kind": "FUNCTION"},
    )
    # Transitive Caller (Depth 3)
    graph.add_node(
        "symbol:app/main.py:FUNCTION:init_middleware:60",
        NodeKind.SYMBOL,
        "init_middleware",
        file_path="app/main.py",
        start_line=60,
        end_line=70,
        metadata={"kind": "FUNCTION"},
    )
    # Unrelated Symbol
    graph.add_node(
        "symbol:app/unrelated.py:FUNCTION:unrelated_func:80",
        NodeKind.SYMBOL,
        "unrelated_func",
        file_path="app/unrelated.py",
        start_line=80,
        end_line=90,
        metadata={"kind": "FUNCTION"},
    )

    # 3. Call Edges:
    # login_endpoint -> verify_token (Direct Caller)
    graph.add_edge(
        "symbol:app/api/auth.py:FUNCTION:login_endpoint:20",
        "symbol:app/services/auth.py:FUNCTION:verify_token:10",
        EdgeKind.CALLS,
    )
    # get_current_user -> login_endpoint (Depth 2 Transitive)
    graph.add_edge(
        "symbol:app/api/users.py:FUNCTION:get_current_user:40",
        "symbol:app/api/auth.py:FUNCTION:login_endpoint:20",
        EdgeKind.CALLS,
    )
    # init_middleware -> get_current_user (Depth 3 Transitive)
    graph.add_edge(
        "symbol:app/main.py:FUNCTION:init_middleware:60",
        "symbol:app/api/users.py:FUNCTION:get_current_user:40",
        EdgeKind.CALLS,
    )

    # 4. Cycle: login_endpoint -> helper_a -> helper_b -> login_endpoint
    graph.add_node(
        "symbol:app/api/auth.py:FUNCTION:helper_a:100",
        NodeKind.SYMBOL,
        "helper_a",
        file_path="app/api/auth.py",
        start_line=100,
        end_line=105,
    )
    graph.add_node(
        "symbol:app/api/auth.py:FUNCTION:helper_b:110",
        NodeKind.SYMBOL,
        "helper_b",
        file_path="app/api/auth.py",
        start_line=110,
        end_line=115,
    )
    graph.add_edge("symbol:app/api/auth.py:FUNCTION:helper_a:100", "symbol:app/api/auth.py:FUNCTION:login_endpoint:20", EdgeKind.CALLS)
    graph.add_edge("symbol:app/api/auth.py:FUNCTION:helper_b:110", "symbol:app/api/auth.py:FUNCTION:helper_a:100", EdgeKind.CALLS)
    graph.add_edge("symbol:app/api/auth.py:FUNCTION:login_endpoint:20", "symbol:app/api/auth.py:FUNCTION:helper_b:110", EdgeKind.CALLS)

    # 5. Route and Frontend Client Match
    graph.add_node(
        "route:POST:/api/v1/auth/login",
        NodeKind.ROUTE,
        "POST /api/v1/auth/login",
        file_path="app/api/auth.py",
        metadata={"http_method": "POST", "path": "/api/v1/auth/login"},
    )
    graph.add_node(
        "req:frontend/src/api.ts:15:POST:/api/v1/auth/login",
        NodeKind.FRONTEND_REQUEST,
        "POST /api/v1/auth/login",
        file_path="frontend/src/api.ts",
        start_line=15,
        metadata={"http_method": "POST", "url": "/api/v1/auth/login"},
    )
    # Frontend matches route
    graph.add_edge(
        "req:frontend/src/api.ts:15:POST:/api/v1/auth/login",
        "route:POST:/api/v1/auth/login",
        EdgeKind.MATCHES_ROUTE,
    )

    # 6. Schema and Importer
    graph.add_node(
        "symbol:app/schemas/user.py:CLASS:UserProfile:5",
        NodeKind.SYMBOL,
        "UserProfile",
        file_path="app/schemas/user.py",
        metadata={"kind": "CLASS"},
    )
    # app/api/users.py imports app/schemas/user.py
    graph.add_edge("file:app/api/users.py", "file:app/schemas/user.py", EdgeKind.IMPORTS)

    return graph


def test_direct_and_multi_hop_caller_blast_radius(base_and_head_graphs):
    """Verify that direct and multi-hop callers are traced with correct depth and severity."""
    engine = ChangeImpactEngine(default_max_depth=3)
    analysis_id = uuid4()

    diff_result = StructuralDiffResult(
        base_commit_sha="1111111111111111111111111111111111111111",
        head_commit_sha="2222222222222222222222222222222222222222",
        repository_url="https://github.com/fastapi/fastapi",
        deleted_symbols=[
            SymbolDiffFact(
                file_path="app/services/auth.py",
                symbol_name="verify_token",
                symbol_kind="FUNCTION",
                change_type=SymbolChangeType.DELETED,
                base_location={"start_line": 10, "end_line": 15},
                head_location=None,
                evidence={},
            )
        ],
    )

    report: BlastRadiusReport = engine.compute_blast_radius(
        analysis_id=analysis_id,
        diff_result=diff_result,
        base_graph=base_and_head_graphs,
    )

    assert report.analysis_id == analysis_id
    assert report.total_impacts >= 3
    assert report.is_truncated is False

    # 1. Direct Caller: login_endpoint (Depth 1, Critical/High due to auth)
    direct_impact = next(
        (i for i in report.impacts if i.affected_symbol == "login_endpoint" and i.evidence_payload.get("depth") == 1),
        None,
    )
    assert direct_impact is not None
    assert direct_impact.severity in (Severity.CRITICAL, Severity.HIGH)
    assert direct_impact.verification_status == ImpactVerificationStatus.FACT
    assert direct_impact.confidence == 1.0

    # 2. Transitive Caller: get_current_user (Depth 2, Medium)
    hop2_impact = next(
        (i for i in report.impacts if i.affected_symbol == "get_current_user" and i.evidence_payload.get("depth") == 2),
        None,
    )
    assert hop2_impact is not None
    assert hop2_impact.severity == Severity.MEDIUM

    # 3. Transitive Caller: init_middleware (Depth 3, Low)
    hop3_impact = next(
        (i for i in report.impacts if i.affected_symbol == "init_middleware" and i.evidence_payload.get("depth") == 3),
        None,
    )
    assert hop3_impact is not None
    assert hop3_impact.severity == Severity.LOW

    # 4. Unrelated Symbol MUST NOT be in impacts
    assert not any(i.affected_symbol == "unrelated_func" for i in report.impacts)


def test_cycle_handling_and_no_infinite_loop(base_and_head_graphs):
    """Verify that circular dependency cycles (A -> B -> A) do not cause infinite recursion."""
    engine = ChangeImpactEngine(default_max_depth=5)
    analysis_id = uuid4()

    diff_result = StructuralDiffResult(
        base_commit_sha="1111111111111111111111111111111111111111",
        head_commit_sha="2222222222222222222222222222222222222222",
        repository_url="https://github.com/fastapi/fastapi",
        deleted_symbols=[
            SymbolDiffFact(
                file_path="app/services/auth.py",
                symbol_name="verify_token",
                symbol_kind="FUNCTION",
                change_type=SymbolChangeType.DELETED,
                base_location={"start_line": 10, "end_line": 15},
                head_location=None,
                evidence={},
            )
        ],
    )

    # Should finish promptly without recursion error
    report = engine.compute_blast_radius(
        analysis_id=analysis_id,
        diff_result=diff_result,
        base_graph=base_and_head_graphs,
    )
    assert report.total_impacts > 0


def test_bounded_depth_truncation(base_and_head_graphs):
    """Verify that traversal bounds truncate properly when max_depth is reached."""
    engine = ChangeImpactEngine(default_max_depth=1)  # Limit to 1 hop
    analysis_id = uuid4()

    diff_result = StructuralDiffResult(
        base_commit_sha="1111111111111111111111111111111111111111",
        head_commit_sha="2222222222222222222222222222222222222222",
        repository_url="https://github.com/fastapi/fastapi",
        deleted_symbols=[
            SymbolDiffFact(
                file_path="app/services/auth.py",
                symbol_name="verify_token",
                symbol_kind="FUNCTION",
                change_type=SymbolChangeType.DELETED,
                base_location={"start_line": 10, "end_line": 15},
                head_location=None,
                evidence={},
            )
        ],
    )

    report = engine.compute_blast_radius(
        analysis_id=analysis_id,
        diff_result=diff_result,
        base_graph=base_and_head_graphs,
        max_depth=1,
    )

    assert report.is_truncated is True
    assert report.truncation_reason == "MAX_DEPTH_REACHED"
    # init_middleware at depth 3 should NOT be present
    assert not any(i.affected_symbol == "init_middleware" for i in report.impacts)


def test_frontend_backend_contract_break(base_and_head_graphs):
    """Verify that frontend API clients referencing changed backend routes are marked HIGH/CRITICAL."""
    engine = ChangeImpactEngine()
    analysis_id = uuid4()

    diff_result = StructuralDiffResult(
        base_commit_sha="1111111111111111111111111111111111111111",
        head_commit_sha="2222222222222222222222222222222222222222",
        repository_url="https://github.com/fastapi/fastapi",
        route_deltas=[
            RouteContractDelta(
                file_path="app/api/auth.py",
                route_type="FASTAPI_ROUTE",
                route_name="POST /api/v1/auth/login",
                base_http_method="POST",
                head_http_method="PUT",
                base_path="/api/v1/auth/login",
                head_path="/api/v1/auth/login",
                change_type="METHOD_CHANGED",
                details="Method changed from POST to PUT",
            )
        ],
    )

    report = engine.compute_blast_radius(
        analysis_id=analysis_id,
        diff_result=diff_result,
        base_graph=base_and_head_graphs,
    )

    fe_impact = next((i for i in report.impacts if i.affected_file == "frontend/src/api.ts"), None)
    assert fe_impact is not None
    assert fe_impact.impact_type == ChangeImpactType.API_CONTRACT_CHANGE
    assert fe_impact.severity in (Severity.CRITICAL, Severity.HIGH)
    assert fe_impact.evidence_payload.get("edge_type") == EdgeKind.MATCHES_ROUTE.value


def test_schema_consumer_impact(base_and_head_graphs):
    """Verify that files importing modified/removed schema fields are marked as impacted consumers."""
    engine = ChangeImpactEngine()
    analysis_id = uuid4()

    diff_result = StructuralDiffResult(
        base_commit_sha="1111111111111111111111111111111111111111",
        head_commit_sha="2222222222222222222222222222222222222222",
        repository_url="https://github.com/fastapi/fastapi",
        schema_deltas=[
            SchemaModelDelta(
                file_path="app/schemas/user.py",
                model_name="UserProfile",
                model_kind="PYDANTIC_MODEL",
                field_name="email",
                base_type="str",
                head_type=None,
                change_type="REMOVED_FIELD",
                details="Removed field email",
            )
        ],
    )

    report = engine.compute_blast_radius(
        analysis_id=analysis_id,
        diff_result=diff_result,
        base_graph=base_and_head_graphs,
    )

    schema_consumer = next((i for i in report.impacts if i.affected_file == "app/api/users.py"), None)
    assert schema_consumer is not None
    assert schema_consumer.impact_type == ChangeImpactType.SCHEMA_CHANGE
    assert schema_consumer.severity == Severity.HIGH


def test_dependency_and_config_impacts(base_and_head_graphs):
    """Verify dependency and config deltas generate evidence-backed impact records."""
    engine = ChangeImpactEngine()
    analysis_id = uuid4()

    diff_result = StructuralDiffResult(
        base_commit_sha="1111111111111111111111111111111111111111",
        head_commit_sha="2222222222222222222222222222222222222222",
        repository_url="https://github.com/fastapi/fastapi",
        dependency_deltas=[
            DependencyDelta(
                manifest_file="package.json",
                package_name="react",
                base_version="18.2.0",
                head_version="19.0.0",
                change_type="UPDATED",
            )
        ],
        config_deltas=[
            ConfigDelta(
                file_path=".env.example",
                key="DATABASE_URL",
                base_value="sqlite:///./dev.db",
                head_value=None,
                change_type="REMOVED",
            )
        ],
    )

    report = engine.compute_blast_radius(
        analysis_id=analysis_id,
        diff_result=diff_result,
        base_graph=base_and_head_graphs,
    )

    assert any(i.impact_type == ChangeImpactType.DEPENDENCY_CHANGE and i.source_symbol == "react" for i in report.impacts)
    db_impact = next(i for i in report.impacts if i.impact_type == ChangeImpactType.CONFIG_CHANGE and i.source_symbol == "DATABASE_URL")
    assert db_impact.severity == Severity.HIGH


def test_duplicate_path_deduplication():
    """Verify that multiple call paths to the same caller symbol produce a single deduplicated impact."""
    graph = RepositoryGraph()
    graph.add_node("symbol:app/utils.py:FUNCTION:format_date:5", NodeKind.SYMBOL, "format_date", file_path="app/utils.py", start_line=5)
    graph.add_node("symbol:app/helper.py:FUNCTION:helper_fn:10", NodeKind.SYMBOL, "helper_fn", file_path="app/helper.py", start_line=10)
    graph.add_node("symbol:app/main.py:FUNCTION:caller_fn:20", NodeKind.SYMBOL, "caller_fn", file_path="app/main.py", start_line=20)

    # Path 1: caller_fn -> format_date
    graph.add_edge("symbol:app/main.py:FUNCTION:caller_fn:20", "symbol:app/utils.py:FUNCTION:format_date:5", EdgeKind.CALLS)
    # Path 2: caller_fn -> helper_fn -> format_date
    graph.add_edge("symbol:app/main.py:FUNCTION:caller_fn:20", "symbol:app/helper.py:FUNCTION:helper_fn:10", EdgeKind.CALLS)
    graph.add_edge("symbol:app/helper.py:FUNCTION:helper_fn:10", "symbol:app/utils.py:FUNCTION:format_date:5", EdgeKind.CALLS)

    engine = ChangeImpactEngine()
    analysis_id = uuid4()
    diff_result = StructuralDiffResult(
        base_commit_sha="1111111111111111111111111111111111111111",
        head_commit_sha="2222222222222222222222222222222222222222",
        repository_url="https://github.com/fastapi/fastapi",
        deleted_symbols=[
            SymbolDiffFact(
                file_path="app/utils.py",
                symbol_name="format_date",
                symbol_kind="FUNCTION",
                change_type=SymbolChangeType.DELETED,
                base_location={"start_line": 5},
                head_location=None,
                evidence={},
            )
        ],
    )

    report = engine.compute_blast_radius(
        analysis_id=analysis_id,
        diff_result=diff_result,
        base_graph=graph,
    )

    # caller_fn should only appear once
    caller_impacts = [i for i in report.impacts if i.affected_symbol == "caller_fn"]
    assert len(caller_impacts) == 1
    # Depth 1 (direct path) is preferred over depth 2
    assert caller_impacts[0].evidence_payload.get("depth") == 1


def test_max_impacts_bound_truncation():
    """Verify that exceeding max_impacts triggers is_truncated=True and MAX_IMPACTS_REACHED."""
    graph = RepositoryGraph()
    graph.add_node("symbol:app/core.py:FUNCTION:target_fn:1", NodeKind.SYMBOL, "target_fn", file_path="app/core.py", start_line=1)

    for idx in range(10):
        sym_id = f"symbol:app/caller_{idx}.py:FUNCTION:caller_{idx}:{idx*10}"
        graph.add_node(sym_id, NodeKind.SYMBOL, f"caller_{idx}", file_path=f"app/caller_{idx}.py", start_line=idx*10)
        graph.add_edge(sym_id, "symbol:app/core.py:FUNCTION:target_fn:1", EdgeKind.CALLS)

    engine = ChangeImpactEngine()
    analysis_id = uuid4()
    diff_result = StructuralDiffResult(
        base_commit_sha="1111111111111111111111111111111111111111",
        head_commit_sha="2222222222222222222222222222222222222222",
        repository_url="https://github.com/fastapi/fastapi",
        deleted_symbols=[
            SymbolDiffFact(
                file_path="app/core.py",
                symbol_name="target_fn",
                symbol_kind="FUNCTION",
                change_type=SymbolChangeType.DELETED,
                base_location={"start_line": 1},
                head_location=None,
                evidence={},
            )
        ],
    )

    report = engine.compute_blast_radius(
        analysis_id=analysis_id,
        diff_result=diff_result,
        base_graph=graph,
        max_impacts=3,  # strict bound
    )

    assert len(report.impacts) == 3
    assert report.is_truncated is True
    assert report.truncation_reason == "MAX_IMPACTS_REACHED"


def test_deterministic_ordering_and_singleton(base_and_head_graphs):
    """Verify deterministic ordering and singleton accessor."""
    e1 = get_impact_engine()
    e2 = get_impact_engine()
    assert e1 is e2
    assert isinstance(e1, ChangeImpactEngine)

