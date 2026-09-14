"""Targeted tests for Phase A final boundary invariants:
A. CALL_RELATIONSHIP exact-one endpoint semantics.
B. Bounded, snapshot-bound public graph entity identities.
C. Path admission consistency with MAX_PUBLIC_PATH_LENGTH = 1024.
"""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4
import pytest
from pydantic import ValidationError

from app.agent_tools import (
    AgentToolContext,
    RepositorySnapshot,
    ToolResourceLimits,
    create_agent_tool_registry,
)
from app.agent_tools.context import public_graph_entity_identity
from app.agent_tools.schemas import (
    CallRelationshipClaim,
    ClaimType,
    EvidenceRecord,
    EvidenceType,
    GraphEntityRecord,
    MAX_PUBLIC_PATH_LENGTH,
    ToolResultStatus,
    VerificationVerdict,
)
from app.analysis.store import EvidenceStore
from app.graph.repository_graph import RepositoryGraph
from app.graph.schemas import EdgeKind, GraphNode, NodeKind
from app.ingestion.schemas import AnalysisScope, FileEntry, RepositoryManifest
from app.schemas.enums import Severity
from app.schemas.evidence import Evidence
from app.schemas.static_finding import ScannerResult, StaticFinding, ToolStatus
from tests.test_agent_tool_layer import _snapshot


# ======================================================================
# DEFECT A: CALL_RELATIONSHIP exact-one endpoint semantics
# ======================================================================

def test_defect_a_1_source_symbol_and_target_symbol_valid():
    """1. source_symbol_id only + target_symbol_id only => valid."""
    claim = CallRelationshipClaim(
        claim_type=ClaimType.CALL_RELATIONSHIP,
        snapshot_id="a" * 40,
        source_symbol_id="symbol:source_123",
        target_symbol_id="symbol:target_456",
        evidence_refs=["evidence:edge_1"],
    )
    assert claim.source_symbol_id == "symbol:source_123"
    assert claim.target_symbol_id == "symbol:target_456"
    assert claim.source_entity_id is None
    assert claim.target_entity_id is None


def test_defect_a_2_source_entity_and_target_entity_valid():
    """2. source_entity_id only + target_entity_id only => valid."""
    claim = CallRelationshipClaim(
        claim_type=ClaimType.CALL_RELATIONSHIP,
        snapshot_id="a" * 40,
        source_entity_id="entity:source_789",
        target_entity_id="entity:target_012",
        evidence_refs=["evidence:edge_1"],
    )
    assert claim.source_entity_id == "entity:source_789"
    assert claim.target_entity_id == "entity:target_012"
    assert claim.source_symbol_id is None
    assert claim.target_symbol_id is None


def test_defect_a_mixed_symbol_and_entity_valid():
    """Mixed coordinates (source_symbol + target_entity, or source_entity + target_symbol) => valid."""
    c1 = CallRelationshipClaim(
        claim_type=ClaimType.CALL_RELATIONSHIP,
        snapshot_id="a" * 40,
        source_symbol_id="symbol:source",
        target_entity_id="entity:target",
        evidence_refs=["evidence:edge_1"],
    )
    assert c1.source_symbol_id == "symbol:source"
    assert c1.target_entity_id == "entity:target"

    c2 = CallRelationshipClaim(
        claim_type=ClaimType.CALL_RELATIONSHIP,
        snapshot_id="a" * 40,
        source_entity_id="entity:source",
        target_symbol_id="symbol:target",
        evidence_refs=["evidence:edge_1"],
    )
    assert c2.source_entity_id == "entity:source"
    assert c2.target_symbol_id == "symbol:target"


def test_defect_a_3_both_source_fields_rejected():
    """3. source_symbol_id + source_entity_id simultaneously => rejected."""
    with pytest.raises(ValidationError, match="cannot contain both source_symbol_id and source_entity_id"):
        CallRelationshipClaim(
            claim_type=ClaimType.CALL_RELATIONSHIP,
            snapshot_id="a" * 40,
            source_symbol_id="symbol:source",
            source_entity_id="entity:source",
            target_symbol_id="symbol:target",
            evidence_refs=["evidence:edge_1"],
        )


def test_defect_a_4_both_target_fields_rejected():
    """4. target_symbol_id + target_entity_id simultaneously => rejected."""
    with pytest.raises(ValidationError, match="cannot contain both target_symbol_id and target_entity_id"):
        CallRelationshipClaim(
            claim_type=ClaimType.CALL_RELATIONSHIP,
            snapshot_id="a" * 40,
            source_symbol_id="symbol:source",
            target_symbol_id="symbol:target",
            target_entity_id="entity:target",
            evidence_refs=["evidence:edge_1"],
        )


def test_defect_a_5_neither_source_field_rejected():
    """5. neither source field => rejected."""
    with pytest.raises(ValidationError, match="must contain exactly one of source_symbol_id or source_entity_id"):
        CallRelationshipClaim(
            claim_type=ClaimType.CALL_RELATIONSHIP,
            snapshot_id="a" * 40,
            target_symbol_id="symbol:target",
            evidence_refs=["evidence:edge_1"],
        )


def test_defect_a_6_neither_target_field_rejected():
    """6. neither target field => rejected."""
    with pytest.raises(ValidationError, match="must contain exactly one of target_symbol_id or target_entity_id"):
        CallRelationshipClaim(
            claim_type=ClaimType.CALL_RELATIONSHIP,
            snapshot_id="a" * 40,
            source_symbol_id="symbol:source",
            evidence_refs=["evidence:edge_1"],
        )


def test_defect_a_7_contradictory_source_never_reaches_supported(tmp_path: Path):
    """7. correct source_symbol_id + contradictory source_entity_id => must NEVER reach SUPPORTED."""
    code = "def worker(): return 42\nworker()\n"
    snap = _snapshot(tmp_path / "contra-source", "a" * 40, {"main.py": code})
    ctx = AgentToolContext(snapshots={snap.snapshot_id: snap}, default_snapshot_id=snap.snapshot_id)
    reg = create_agent_tool_registry(ctx)

    worker_id = reg.invoke("search_symbol", {"query": "worker"}).result["matches"][0]["symbol_id"]
    callers = reg.invoke("find_callers", {"symbol_id": worker_id})
    file_entity = callers.result["relationships"][0]["source"]["entity_id"]
    evidence_id = callers.evidence[0].evidence_id

    # Passing both source fields to verify_finding must fail at schema validation before verification
    res = reg.invoke("verify_finding", {
        "claim": {
            "claim_type": "CALL_RELATIONSHIP",
            "snapshot_id": snap.snapshot_id,
            "source_symbol_id": worker_id,
            "source_entity_id": file_entity,
            "target_symbol_id": worker_id,
            "evidence_refs": [evidence_id],
        }
    })
    assert res.status == ToolResultStatus.INVALID_INPUT
    assert "verdict" not in (res.result or {})


def test_defect_a_8_contradictory_target_never_reaches_supported(tmp_path: Path):
    """8. correct target_symbol_id + contradictory target_entity_id => must NEVER reach SUPPORTED."""
    code = "def helper(): return 1\ndef caller(): return helper()\n"
    snap = _snapshot(tmp_path / "contra-target", "b" * 40, {"svc.py": code})
    ctx = AgentToolContext(snapshots={snap.snapshot_id: snap}, default_snapshot_id=snap.snapshot_id)
    reg = create_agent_tool_registry(ctx)

    caller_id = reg.invoke("search_symbol", {"query": "caller"}).result["matches"][0]["symbol_id"]
    helper_id = reg.invoke("search_symbol", {"query": "helper"}).result["matches"][0]["symbol_id"]
    callees = reg.invoke("find_callees", {"symbol_id": caller_id})
    target_entity = callees.result["relationships"][0]["target"]["entity_id"]
    evidence_id = callees.evidence[0].evidence_id

    # Passing both target fields to verify_finding must fail at schema validation
    res = reg.invoke("verify_finding", {
        "claim": {
            "claim_type": "CALL_RELATIONSHIP",
            "snapshot_id": snap.snapshot_id,
            "source_symbol_id": caller_id,
            "target_symbol_id": helper_id,
            "target_entity_id": target_entity,
            "evidence_refs": [evidence_id],
        }
    })
    assert res.status == ToolResultStatus.INVALID_INPUT
    assert "verdict" not in (res.result or {})


# ======================================================================
# DEFECT B: Deterministic, bounded, snapshot-bound public graph entity IDs
# ======================================================================

def test_defect_b_1_symbol_node_uses_public_symbol_id(tmp_path: Path):
    """1. SYMBOL graph node => public symbol ID (starts with 'symbol:')."""
    code = "def alpha(): return 1\n"
    snap = _snapshot(tmp_path / "sym-test", "c" * 40, {"mod.py": code})
    reg = create_agent_tool_registry(AgentToolContext.from_snapshot(snap))

    search = reg.invoke("search_symbol", {"query": "alpha"})
    sym_id = search.result["matches"][0]["symbol_id"]
    assert sym_id.startswith("symbol:")
    assert len(sym_id) == 71  # "symbol:" + 64 hex chars


def test_defect_b_2_file_node_uses_bounded_public_entity_id(tmp_path: Path):
    """2. FILE graph node => bounded public entity ID (starts with 'entity:', len=71)."""
    code = "def run(): pass\nrun()\n"
    snap = _snapshot(tmp_path / "file-node-test", "d" * 40, {"main.py": code})
    reg = create_agent_tool_registry(AgentToolContext.from_snapshot(snap))

    run_id = reg.invoke("search_symbol", {"query": "run"}).result["matches"][0]["symbol_id"]
    callers = reg.invoke("find_callers", {"symbol_id": run_id})
    rel = callers.result["relationships"][0]

    assert rel["source"]["kind"] == "FILE"
    entity_id = rel["source"]["entity_id"]
    assert entity_id.startswith("entity:")
    assert len(entity_id) == 71  # "entity:" + 64 hex chars
    assert rel["source"]["file_path"] == "main.py"


def test_defect_b_3_route_node_exceeding_2048_chars_produces_bounded_id(tmp_path: Path):
    """3. ROUTE node with route string >2048 characters => GraphEntityRecord still serializes."""
    code = "def dummy(): pass\n"
    snap = _snapshot(tmp_path / "long-route", "e" * 40, {"app.py": code})
    long_route_path = "/api/v1/" + "segment/" * 300  # > 2400 chars
    long_internal_id = f"route:GET:{long_route_path}"

    # Construct graph with this long route node
    graph = RepositoryGraph()
    for n in snap.graph.get_nodes():
        graph.add_node(n.id, n.kind, n.label, file_path=n.file_path, start_line=n.start_line, end_line=n.end_line, metadata=n.metadata)
    graph.add_node(
        node_id=long_internal_id,
        kind=NodeKind.ROUTE,
        label=f"GET {long_route_path}",
        file_path="app.py",
        start_line=1,
        end_line=1,
        metadata={"http_method": "GET", "path": long_route_path},
    )

    custom_snap = RepositorySnapshot.create(
        snapshot_id=snap.snapshot_id,
        repository_root=snap.repository_root,
        evidence_store=snap.evidence_store,
        graph=graph,
    )

    pub_id = custom_snap.public_graph_entity_id(long_internal_id)
    assert pub_id is not None
    assert pub_id.startswith("entity:")
    assert len(pub_id) == 71

    # Verify GraphEntityRecord serializes without failing 2048 bound
    node = graph.get_node(long_internal_id)
    rec = GraphEntityRecord(
        entity_id=pub_id,
        kind=node.kind.value,
        label="test route",
        file_path=node.file_path,
    )
    json_str = rec.model_dump_json()
    assert isinstance(json_str, str)
    assert len(rec.entity_id) <= 2048


def test_defect_b_4_request_node_with_long_target_is_bounded(tmp_path: Path):
    """4. REQUEST node with extremely long target => public entity ID remains bounded."""
    code = "def dummy(): pass\n"
    snap = _snapshot(tmp_path / "long-req", "f" * 40, {"client.py": code})
    long_target = "https://example.com/api/" + "query/" * 300
    long_req_id = f"req:POST:{long_target}"

    graph = RepositoryGraph()
    for n in snap.graph.get_nodes():
        graph.add_node(n.id, n.kind, n.label, file_path=n.file_path, start_line=n.start_line, end_line=n.end_line, metadata=n.metadata)
    graph.add_node(
        node_id=long_req_id,
        kind=NodeKind.FRONTEND_REQUEST,
        label="POST request",
        file_path="client.py",
        start_line=1,
        end_line=1,
    )

    custom_snap = RepositorySnapshot.create(
        snapshot_id=snap.snapshot_id,
        repository_root=snap.repository_root,
        evidence_store=snap.evidence_store,
        graph=graph,
    )
    pub_id = custom_snap.public_graph_entity_id(long_req_id)
    assert pub_id is not None
    assert pub_id.startswith("entity:")
    assert len(pub_id) == 71


def test_defect_b_5_dependency_node_with_long_id_is_bounded(tmp_path: Path):
    """5. DEPENDENCY node with long internal ID => bounded public ID."""
    code = "def dummy(): pass\n"
    snap = _snapshot(tmp_path / "long-dep", "1" * 40, {"dep.py": code})
    long_dep_id = "dep:" + "library-" * 300

    graph = RepositoryGraph()
    for n in snap.graph.get_nodes():
        graph.add_node(n.id, n.kind, n.label, file_path=n.file_path, start_line=n.start_line, end_line=n.end_line, metadata=n.metadata)
    graph.add_node(
        node_id=long_dep_id,
        kind=NodeKind.DEPENDENCY,
        label="dep",
        file_path="dep.py",
    )

    custom_snap = RepositorySnapshot.create(
        snapshot_id=snap.snapshot_id,
        repository_root=snap.repository_root,
        evidence_store=snap.evidence_store,
        graph=graph,
    )
    pub_id = custom_snap.public_graph_entity_id(long_dep_id)
    assert pub_id is not None
    assert pub_id.startswith("entity:")
    assert len(pub_id) == 71


def test_defect_b_6_same_node_same_snapshot_deterministic(tmp_path: Path):
    """6. same graph node + same snapshot => same public ID."""
    code = "def f(): pass\nf()\n"
    snap = _snapshot(tmp_path / "det-test", "2" * 40, {"main.py": code})
    id1 = snap.public_graph_entity_id("file:main.py")
    id2 = snap.public_graph_entity_id("file:main.py")
    assert id1 is not None
    assert id1 == id2


def test_defect_b_7_same_node_different_snapshots_distinct(tmp_path: Path):
    """7. same internal graph node coordinates + different snapshot => different public ID."""
    code = "def f(): pass\nf()\n"
    snap1 = _snapshot(tmp_path / "snap1", "3" * 40, {"main.py": code})
    snap2 = _snapshot(tmp_path / "snap2", "4" * 40, {"main.py": code})

    id1 = snap1.public_graph_entity_id("file:main.py")
    id2 = snap2.public_graph_entity_id("file:main.py")
    assert id1 is not None
    assert id2 is not None
    assert id1 != id2


def test_defect_b_8_foreign_snapshot_entity_id_rejected(tmp_path: Path):
    """8. foreign snapshot entity ID => rejected."""
    code = "def f(): pass\nf()\n"
    snap1 = _snapshot(tmp_path / "foreign-snap1", "5" * 40, {"main.py": code})
    snap2 = _snapshot(tmp_path / "foreign-snap2", "6" * 40, {"main.py": code})
    ctx = AgentToolContext(snapshots={snap1.snapshot_id: snap1, snap2.snapshot_id: snap2}, default_snapshot_id=snap1.snapshot_id)
    reg = create_agent_tool_registry(ctx)

    id2 = snap2.public_graph_entity_id("file:main.py")
    f_sym = reg.invoke("search_symbol", {"snapshot_id": snap1.snapshot_id, "query": "f"}).result["matches"][0]["symbol_id"]

    res = reg.invoke("verify_finding", {
        "claim": {
            "claim_type": "CALL_RELATIONSHIP",
            "snapshot_id": snap1.snapshot_id,
            "source_entity_id": id2,
            "target_symbol_id": f_sym,
            "evidence_refs": ["edge:dummy"],
        }
    })
    assert res.result["verdict"] == VerificationVerdict.INVALID_CLAIM
    assert res.result["reason_code"] == "SOURCE_OR_TARGET_UNRESOLVED"


def test_defect_b_9_invented_and_raw_entity_id_rejected(tmp_path: Path):
    """9. invented entity ID and raw internal ID => rejected."""
    code = "def f(): pass\nf()\n"
    snap = _snapshot(tmp_path / "invented-id", "7" * 40, {"main.py": code})
    reg = create_agent_tool_registry(AgentToolContext.from_snapshot(snap))
    f_sym = reg.invoke("search_symbol", {"query": "f"}).result["matches"][0]["symbol_id"]

    # Invented public entity ID
    res_fake = reg.invoke("verify_finding", {
        "claim": {
            "claim_type": "CALL_RELATIONSHIP",
            "snapshot_id": snap.snapshot_id,
            "source_entity_id": "entity:" + "0" * 64,
            "target_symbol_id": f_sym,
            "evidence_refs": ["edge:dummy"],
        }
    })
    assert res_fake.result["verdict"] == VerificationVerdict.INVALID_CLAIM
    assert res_fake.result["reason_code"] == "SOURCE_OR_TARGET_UNRESOLVED"

    # Raw internal node ID (e.g. file:main.py) must be rejected
    res_raw = reg.invoke("verify_finding", {
        "claim": {
            "claim_type": "CALL_RELATIONSHIP",
            "snapshot_id": snap.snapshot_id,
            "source_entity_id": "file:main.py",
            "target_symbol_id": f_sym,
            "evidence_refs": ["edge:dummy"],
        }
    })
    assert res_raw.result["verdict"] == VerificationVerdict.INVALID_CLAIM
    assert res_raw.result["reason_code"] == "SOURCE_OR_TARGET_UNRESOLVED"


def test_defect_b_10_find_callers_entity_id_round_trips(tmp_path: Path):
    """10. find_callers -> returned entity ID -> verify_finding => round trips."""
    code = "def worker(): return 42\nworker()\n"
    snap = _snapshot(tmp_path / "callers-rt", "8" * 40, {"main.py": code})
    reg = create_agent_tool_registry(AgentToolContext.from_snapshot(snap))

    worker_id = reg.invoke("search_symbol", {"query": "worker"}).result["matches"][0]["symbol_id"]
    callers = reg.invoke("find_callers", {"symbol_id": worker_id})
    assert callers.status == ToolResultStatus.SUCCESS
    rel = callers.result["relationships"][0]
    evidence_id = callers.evidence[0].evidence_id

    verify_res = reg.invoke("verify_finding", {
        "claim": {
            "claim_type": "CALL_RELATIONSHIP",
            "snapshot_id": snap.snapshot_id,
            "source_entity_id": rel["source"]["entity_id"],
            "target_entity_id": rel["target"]["entity_id"],
            "evidence_refs": [evidence_id],
        }
    })
    assert verify_res.status == ToolResultStatus.SUCCESS
    assert verify_res.result["verdict"] == VerificationVerdict.SUPPORTED
    assert verify_res.result["reason_code"] == "EXACT_GRAPH_EDGE"


def test_defect_b_11_find_callees_entity_id_round_trips(tmp_path: Path):
    """11. find_callees -> returned entity ID -> verify_finding => round trips."""
    code = "def helper(): return 1\ndef caller(): return helper()\n"
    snap = _snapshot(tmp_path / "callees-rt", "9" * 40, {"service.py": code})
    reg = create_agent_tool_registry(AgentToolContext.from_snapshot(snap))

    caller_id = reg.invoke("search_symbol", {"query": "caller"}).result["matches"][0]["symbol_id"]
    callees = reg.invoke("find_callees", {"symbol_id": caller_id})
    assert callees.status == ToolResultStatus.SUCCESS
    rel = callees.result["relationships"][0]
    evidence_id = callees.evidence[0].evidence_id

    verify_res = reg.invoke("verify_finding", {
        "claim": {
            "claim_type": "CALL_RELATIONSHIP",
            "snapshot_id": snap.snapshot_id,
            "source_entity_id": rel["source"]["entity_id"],
            "target_entity_id": rel["target"]["entity_id"],
            "evidence_refs": [evidence_id],
        }
    })
    assert verify_res.status == ToolResultStatus.SUCCESS
    assert verify_res.result["verdict"] == VerificationVerdict.SUPPORTED
    assert verify_res.result["reason_code"] == "EXACT_GRAPH_EDGE"


def test_defect_b_12_inspect_symbol_relationship_model_dump_json_succeeds(tmp_path: Path):
    """12. inspect_symbol relationship involving non-symbol entity => model_dump_json succeeds."""
    code = "def worker(): return 42\nworker()\n"
    snap = _snapshot(tmp_path / "inspect-sym", "a" * 40, {"main.py": code})
    reg = create_agent_tool_registry(AgentToolContext.from_snapshot(snap))

    worker_id = reg.invoke("search_symbol", {"query": "worker"}).result["matches"][0]["symbol_id"]
    inspect_res = reg.invoke("inspect_symbol", {"symbol_id": worker_id})
    assert inspect_res.status == ToolResultStatus.SUCCESS

    # model_dump_json must succeed without schema validation errors
    json_str = inspect_res.model_dump_json()
    assert isinstance(json_str, str)
    assert len(json_str) > 0


# ======================================================================
# DEFECT C: Path admission consistency with MAX_PUBLIC_PATH_LENGTH
# ======================================================================

def test_defect_c_1_path_at_limit_admitted(monkeypatch, tmp_path: Path):
    """1. path exactly at accepted public limit (1024 chars) => admitted."""
    code = "x = 1\n"
    snap = _snapshot(tmp_path / "limit-path", "b" * 40, {"main.py": code})

    # Exact 1024-character normalized path
    exact_1024_path = "a" * 1021 + ".py"
    assert len(exact_1024_path) == 1024

    entry = FileEntry(
        path=exact_1024_path,
        language="python",
        size_bytes=len(code.encode()),
        lines_count=1,
    )
    manifest = RepositoryManifest(
        repository_url=snap.manifest.repository_url,
        commit_hash=snap.manifest.commit_hash,
        commit_sha=snap.manifest.commit_sha,
        total_files=1,
        total_size_bytes=len(code.encode()),
        files=[entry],
        analysis_scope=AnalysisScope(
            truncated=False,
            files_processed=1,
            source_bytes_processed=len(code.encode()),
            total_observed_files=1,
            total_observed_bytes=len(code.encode()),
        ),
    )
    store = EvidenceStore(manifest, {})

    # Mock _confined_relative to return the exact 1024-char relative path without filesystem syscall
    monkeypatch.setattr("app.agent_tools.context._confined_relative", lambda root, p: p)

    new_snap = RepositorySnapshot.create(
        snapshot_id=snap.snapshot_id,
        repository_root=snap.repository_root,
        evidence_store=store,
    )
    assert exact_1024_path in new_snap.manifest_paths


def test_defect_c_2_path_above_limit_rejected(monkeypatch, tmp_path: Path):
    """2. path above public limit (>1024 chars) => RepositorySnapshot.create rejects it."""
    code = "x = 1\n"
    snap = _snapshot(tmp_path / "oversized-path", "c" * 40, {"main.py": code})

    oversized_path = "a" * 1022 + ".py"
    assert len(oversized_path) == 1025

    entry = FileEntry(
        path=oversized_path,
        language="python",
        size_bytes=len(code.encode()),
        lines_count=1,
    )
    manifest = RepositoryManifest(
        repository_url=snap.manifest.repository_url,
        commit_hash=snap.manifest.commit_hash,
        commit_sha=snap.manifest.commit_sha,
        total_files=1,
        total_size_bytes=len(code.encode()),
        files=[entry],
    )
    store = EvidenceStore(manifest, {})

    monkeypatch.setattr("app.agent_tools.context._confined_relative", lambda root, p: p)

    with pytest.raises(ValueError, match="repository manifest path exceeds Phase-A public path limit"):
        RepositorySnapshot.create(
            snapshot_id=snap.snapshot_id,
            repository_root=snap.repository_root,
            evidence_store=store,
        )


def test_defect_c_3_scanner_evidence_cannot_introduce_oversized_path(monkeypatch, tmp_path: Path):
    """3. scanner evidence cannot introduce an oversized non-manifest path."""
    code = "x = 1\n"
    snap = _snapshot(tmp_path / "scan-oversized", "d" * 40, {"main.py": code})

    oversized_finding_path = "bad/" + "x" * 1030 + ".py"
    finding = StaticFinding(
        id=uuid4(),
        tool="semgrep",
        rule_id="test-rule",
        title="test finding",
        description="test finding description",
        severity=Severity.HIGH,
        evidence=Evidence(file_path=oversized_finding_path, start_line=1, end_line=1),
    )
    scanner_result = ScannerResult(
        tool="semgrep",
        status=ToolStatus.COMPLETED,
        findings=[finding],
    )
    store = EvidenceStore(snap.manifest, {"semgrep": scanner_result})

    with pytest.raises(ValueError, match="scanner finding is not authorized by the repository manifest"):
        RepositorySnapshot.create(
            snapshot_id=snap.snapshot_id,
            repository_root=snap.repository_root,
            evidence_store=store,
        )


def test_defect_c_4_graph_call_site_cannot_introduce_oversized_path(tmp_path: Path):
    """4. graph call_site_file cannot introduce an oversized non-manifest path."""
    code = "def f(): pass\n"
    snap = _snapshot(tmp_path / "callsite-oversized", "e" * 40, {"app.py": code})

    oversized_callsite = "unauthorized/" + "y" * 1030 + ".py"
    graph = RepositoryGraph()
    for n in snap.graph.get_nodes():
        graph.add_node(n.id, n.kind, n.label, file_path=n.file_path, start_line=n.start_line, end_line=n.end_line, metadata=n.metadata)
    nodes = list(graph.get_nodes())
    if len(nodes) >= 2:
        graph.add_edge(nodes[0].id, nodes[1].id, EdgeKind.CALLS, metadata={"call_site_file": oversized_callsite})

    with pytest.raises(ValueError, match="graph call site is not authorized by the repository manifest"):
        RepositorySnapshot.create(
            snapshot_id=snap.snapshot_id,
            repository_root=snap.repository_root,
            evidence_store=snap.evidence_store,
            graph=graph,
        )


def test_defect_c_5_evidence_record_file_path_never_exceeds_contract():
    """5. public EvidenceRecord file_path never exceeds MAX_PUBLIC_PATH_LENGTH."""
    valid_rec = EvidenceRecord(
        evidence_id="evidence:123",
        evidence_type=EvidenceType.GRAPH_EDGE,
        source_component="test",
        file_path="a" * MAX_PUBLIC_PATH_LENGTH,
    )
    assert len(valid_rec.file_path) == MAX_PUBLIC_PATH_LENGTH

    with pytest.raises(ValidationError):
        EvidenceRecord(
            evidence_id="evidence:123",
            evidence_type=EvidenceType.GRAPH_EDGE,
            source_component="test",
            file_path="a" * (MAX_PUBLIC_PATH_LENGTH + 1),
        )
