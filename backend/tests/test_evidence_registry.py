from datetime import datetime, timezone
from uuid import uuid4
import pytest

from app.analysis.evidence_ids import (
    make_config_evidence_id,
    make_dependency_evidence_id,
    make_edge_evidence_id,
    make_file_evidence_id,
    make_impact_evidence_id,
    make_line_evidence_id,
    make_route_delta_evidence_id,
    make_schema_delta_evidence_id,
    make_symbol_evidence_id,
    normalize_path,
)
from app.analysis.evidence_registry import (
    EvidenceDescriptor,
    EvidenceRegistry,
    build_evidence_registry,
)
from app.graph.repository_graph import RepositoryGraph
from app.graph.schemas import EdgeKind, GraphEdge, GraphNode, NodeKind
from app.schemas.change_analysis import (
    BlastRadiusReport,
    ChangeImpact,
    ConfigDelta,
    DependencyDelta,
    FileDiffFact,
    RouteContractDelta,
    SchemaModelDelta,
    StructuralDiffResult,
    SymbolChangeType,
    SymbolDiffFact,
)
from app.schemas.enums import ChangeImpactType, ChangeRiskLevel, Severity


def test_evidence_id_normalization():
    assert normalize_path("backend\\app\\api.py") == "backend/app/api.py"
    assert normalize_path("/app/api.py") == "app/api.py"
    assert make_file_evidence_id("backend\\app\\api.py") == "file:backend/app/api.py"
    assert make_symbol_evidence_id("app/auth.py", "FUNCTION", "login", 42) == "symbol:app/auth.py:FUNCTION:login:42"
    assert make_config_evidence_id(".env", "DATABASE_URL") == "config:.env:DATABASE_URL"
    assert make_dependency_evidence_id("package.json", "react") == "dependency:package.json:react"
    assert make_edge_evidence_id("CALLS", "node1", "node2") == "edge:CALLS:node1->node2"
    assert make_schema_delta_evidence_id("models.py", "User", "email", "REMOVED") == "schema-delta:models.py:User:email:REMOVED"
    assert make_route_delta_evidence_id("api.py", "POST", "/users", "PUT", "/users") == "route-delta:api.py:POST:/users->PUT:/users"


def test_evidence_registry_builder():
    impact_id = uuid4()
    diff_res = StructuralDiffResult(
        analysis_id=uuid4(),
        base_commit_sha="1111111111111111111111111111111111111111",
        head_commit_sha="2222222222222222222222222222222222222222",
        repository_url="https://github.com/test/repo",
        changed_files=[
            FileDiffFact(file_path="app/main.py", change_type=SymbolChangeType.MODIFIED, base_lines=10, head_lines=15),
        ],
        modified_files=["app/main.py"],
        changed_symbols=[
            SymbolDiffFact(file_path="app/main.py", symbol_name="start_app", symbol_kind="FUNCTION", change_type=SymbolChangeType.MODIFIED, head_location={"start_line": 5, "end_line": 12}),
        ],
        route_deltas=[
            RouteContractDelta(file_path="app/main.py", route_type="FASTAPI_ROUTE", route_name="health", change_type="ROUTE_ADDED", base_http_method=None, base_path=None, head_http_method="GET", head_path="/health"),
        ],
        config_deltas=[
            ConfigDelta(file_path=".env", key="APP_PORT", change_type="MODIFIED", base_value="8000", head_value="8080"),
        ],
        dependency_deltas=[
            DependencyDelta(manifest_file="requirements.txt", package_name="pydantic", change_type="MODIFIED", base_version="2.0", head_version="2.1"),
        ],
        schema_deltas=[
            SchemaModelDelta(file_path="app/schemas.py", model_name="Item", field_name="price", change_type="MODIFIED_TYPE", base_type="int", head_type="float"),
        ],
    )

    graph = RepositoryGraph()
    n1 = graph.add_node(node_id="symbol:app/main.py:SYMBOL:start_app:5", label="start_app", kind=NodeKind.SYMBOL, file_path="app/main.py", start_line=5)
    n2 = graph.add_node(node_id="symbol:app/main.py:SYMBOL:helper:20", label="helper", kind=NodeKind.SYMBOL, file_path="app/main.py", start_line=20)
    graph.add_edge(source_id=n1.id, target_id=n2.id, kind=EdgeKind.CALLS)

    analysis_id = uuid4()
    blast_radius = BlastRadiusReport(
        analysis_id=analysis_id,
        total_impacts=1,
        overall_risk_level=ChangeRiskLevel.LOW,
        impacts=[
            ChangeImpact(
                id=impact_id,
                analysis_id=analysis_id,
                impact_type=ChangeImpactType.CALLER_IMPACT,
                severity=Severity.LOW,
                title="Caller impact",
                description="Caller impacted by modification",
                source_file="app/main.py",
                source_symbol="helper",
                affected_file="app/main.py",
                affected_symbol="start_app",
                evidence_payload={"caller_node_id": n1.id, "callee_node_id": n2.id, "edge_type": "CALLS"},
                created_at=datetime.now(timezone.utc),
            )
        ],
    )

    registry = build_evidence_registry(
        diff_result=diff_res,
        blast_radius=blast_radius,
        base_graph=graph,
    )

    # 1. Check file lookup
    assert registry.contains_file("app/main.py")
    assert registry.contains_file(".env")
    assert registry.contains_file("requirements.txt")
    assert registry.contains_file("app/schemas.py")
    assert not registry.contains_file("nonexistent.py")

    # 2. Check symbol lookup
    assert registry.contains_symbol("start_app")
    assert registry.contains_symbol("start_app", "app/main.py")
    assert registry.contains_symbol("helper")
    assert not registry.contains_symbol("fake_symbol")

    # 3. Check exact evidence ID retrieval
    assert registry.get("file:app/main.py") is not None
    assert registry.get("symbol:app/main.py:SYMBOL:start_app:5") is not None
    assert registry.get(f"impact:{str(impact_id).lower()}") is not None
    assert registry.get(f"edge:CALLS:{n1.id}->{n2.id}") is not None
    assert registry.get("config:.env:APP_PORT") is not None
    assert registry.get("dependency:requirements.txt:pydantic") is not None
    assert registry.get("schema-delta:app/schemas.py:Item:price:MODIFIED_TYPE") is not None
    assert registry.get("route-delta:app/main.py:NONE:NONE->GET:/health") is not None

    # 4. Unknown/fuzzy aliases return None
    assert registry.get("diff:app/main.py") is None
    assert registry.get("symbol:start_app") is None
    assert registry.get("config:APP_PORT") is None
    assert registry.get("dependency:pydantic") is None
