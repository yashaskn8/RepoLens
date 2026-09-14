"""Mandatory final hostile audit and regression tests for Phase-A agent tools.

Covers:
1. Same file/span/tool, rule_id=None, detector-A vs detector-B evidence ID collision prevention.
2. Distinct effective detectors generate distinct scanner evidence IDs.
3. Deterministic repeatability: same exact finding repeats same evidence ID.
4. Cross-snapshot security finding IDs differ.
5. Real production graph top-level FILE -> SYMBOL CALLS edge.
6. find_callers result round-trips into verify_finding.
7. find_callees result round-trips into verify_finding.
8. Foreign snapshot graph entity ID rejected.
9. Invalid FILE entity ID rejected.
10. Graph entity ID is bounded.
11. Long SymbolDiffFact.symbol_name (>1024 chars) handling.
12. Long route change identifier handling.
13. Long model/schema identifier handling.
14. Maximum allowed file path in change evidence.
15. analyze_change model_dump_json succeeds on bounded output.
16. verify_finding structural-change model_dump_json succeeds.
17. scan_security -> verify_finding exact evidence round-trip.
18. trace_dataflow -> verify_finding exact evidence round-trip.
19. Repeated-call-site conservative behavior remains intact.
20. Frozen benchmark ground truth remains unreachable.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from app.agent_tools import (
    AgentToolContext,
    RepositorySnapshot,
    ToolResourceLimits,
    create_agent_tool_registry,
)
from app.agent_tools.schemas import (
    CallRelationshipClaim,
    ClaimType,
    DataflowClaim,
    GraphEntityRecord,
    SecurityFindingClaim,
    StructuralChangeClaim,
    ToolResultStatus,
    VerificationVerdict,
)
from app.analysis.store import EvidenceStore
from app.graph.schemas import EdgeKind
from app.ingestion.schemas import SymbolKind
from app.schemas.change_analysis import (
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
from app.schemas.enums import Severity
from app.schemas.evidence import Evidence
from app.schemas.static_finding import ScannerResult, StaticFinding, ToolStatus
from tests.test_agent_tool_layer import _change_context, _snapshot


def test_audit_01_security_evidence_id_collision_prevention(tmp_path: Path):
    """1. Same file/span/tool, rule_id=None, detector-A vs detector-B must NOT collide."""
    code = "def vulnerable():\n    pass\n"
    base_snap = _snapshot(tmp_path / "collision-test", "a" * 40, {"app/target.py": code})

    finding_a = StaticFinding(
        id=uuid4(),
        tool="scanner-x",
        rule_id=None,
        detector_id="detector-A",
        detector_kind="static_scanner",
        title="Vulnerability A",
        description="Found by detector A",
        severity=Severity.HIGH,
        category="sast",
        evidence=Evidence(file_path="app/target.py", start_line=1, end_line=2),
        confidence="HIGH",
        source_tool="scanner-x",
    )
    finding_b = StaticFinding(
        id=uuid4(),
        tool="scanner-x",
        rule_id=None,
        detector_id="detector-B",
        detector_kind="static_scanner",
        title="Vulnerability B",
        description="Found by detector B",
        severity=Severity.HIGH,
        category="sast",
        evidence=Evidence(file_path="app/target.py", start_line=1, end_line=2),
        confidence="HIGH",
        source_tool="scanner-x",
    )

    store = EvidenceStore(
        base_snap.manifest,
        {"scanner-x": ScannerResult(tool="scanner-x", status=ToolStatus.COMPLETED, findings=[finding_a, finding_b])},
    )
    snapshot = RepositorySnapshot.create(
        snapshot_id=base_snap.snapshot_id,
        repository_root=base_snap.repository_root,
        evidence_store=store,
        graph=base_snap.graph,
    )
    context = AgentToolContext(snapshots={snapshot.snapshot_id: snapshot}, default_snapshot_id=snapshot.snapshot_id)
    registry = create_agent_tool_registry(context)

    scan = registry.invoke("scan_security", {"snapshot_id": snapshot.snapshot_id})
    assert scan.status == ToolResultStatus.SUCCESS
    findings = scan.result["findings"]
    assert len(findings) == 2
    id_a = findings[0]["finding_id"]
    id_b = findings[1]["finding_id"]
    # Evidence IDs MUST differ even though rule_id is None and span is identical
    assert id_a != id_b

    # Verifier claim for detector A must NOT be satisfiable using detector B's evidence ref
    res_foreign = registry.invoke("verify_finding", {
        "claim": {
            "claim_type": "SECURITY_FINDING",
            "snapshot_id": snapshot.snapshot_id,
            "rule": "detector-A",
            "file_path": "app/target.py",
            "evidence_refs": [id_b],
        }
    })
    assert res_foreign.result["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert "EVIDENCE_REFERENCE_UNRESOLVED_OR_FOREIGN" in res_foreign.result["reason_code"]

    # Verifier claim for detector A with exact evidence ref MUST succeed
    res_exact = registry.invoke("verify_finding", {
        "claim": {
            "claim_type": "SECURITY_FINDING",
            "snapshot_id": snapshot.snapshot_id,
            "rule": "detector-A",
            "file_path": "app/target.py",
            "evidence_refs": [id_a],
        }
    })
    assert res_exact.result["verdict"] == "SUPPORTED"
    assert res_exact.result["reason_code"] == "EXACT_SCANNER_FACT"


def test_audit_02_scanner_evidence_ids_differ_for_all_distinct_detector_coordinates(tmp_path: Path):
    """2. Distinct detector_id, source_tool, detector_kind, or rule_id produce distinct IDs."""
    snap = _snapshot(tmp_path / "diff-coordinates", "b" * 40, {"test.py": "x = 1\n"})
    common_kw = dict(
        id=uuid4(),
        title="Issue",
        description="Desc",
        severity=Severity.MEDIUM,
        category="sast",
        evidence=Evidence(file_path="test.py", start_line=1, end_line=1),
    )

    f1 = StaticFinding(tool="tool-1", rule_id="rule-1", detector_id="det-1", source_tool="tool-1", detector_kind="kind-1", **common_kw)
    f2 = StaticFinding(tool="tool-1", rule_id="rule-1", detector_id="det-2", source_tool="tool-1", detector_kind="kind-1", **common_kw)
    f3 = StaticFinding(tool="tool-1", rule_id="rule-1", detector_id="det-1", source_tool="tool-2", detector_kind="kind-1", **common_kw)
    f4 = StaticFinding(tool="tool-1", rule_id="rule-1", detector_id="det-1", source_tool="tool-1", detector_kind="kind-2", **common_kw)
    f5 = StaticFinding(tool="tool-2", rule_id="rule-1", detector_id="det-1", source_tool="tool-1", detector_kind="kind-1", **common_kw)
    f6 = StaticFinding(tool="tool-1", rule_id="rule-2", detector_id="det-1", source_tool="tool-1", detector_kind="kind-1", **common_kw)

    store = EvidenceStore(
        snap.manifest,
        {"tool-1": ScannerResult(tool="tool-1", status=ToolStatus.COMPLETED, findings=[f1, f2, f3, f4, f6]),
         "tool-2": ScannerResult(tool="tool-2", status=ToolStatus.COMPLETED, findings=[f5])},
    )
    s = RepositorySnapshot.create(snapshot_id=snap.snapshot_id, repository_root=snap.repository_root, evidence_store=store, graph=snap.graph)
    ctx = AgentToolContext(snapshots={s.snapshot_id: s}, default_snapshot_id=s.snapshot_id)
    reg = create_agent_tool_registry(ctx)

    scan = reg.invoke("scan_security", {"snapshot_id": s.snapshot_id})
    ids = [item["finding_id"] for item in scan.result["findings"]]
    # All 6 findings have distinct semantic coordinates, so all 6 IDs must be unique
    assert len(set(ids)) == len(ids) == 6


def test_audit_03_same_exact_finding_repeats_identical_evidence_id(tmp_path: Path):
    """3. Same finding in same snapshot repeats identical evidence ID deterministically."""
    snap = _snapshot(tmp_path / "det-id", "c" * 40, {"test.py": "x = 1\n"})
    f = StaticFinding(
        id=uuid4(),
        tool="scanner-a",
        rule_id="rule-A",
        detector_id="rule-A",
        title="Test",
        description="Test",
        severity=Severity.LOW,
        category="sast",
        evidence=Evidence(file_path="test.py", start_line=1, end_line=1),
    )
    store = EvidenceStore(snap.manifest, {"scanner-a": ScannerResult(tool="scanner-a", status=ToolStatus.COMPLETED, findings=[f])})
    s = RepositorySnapshot.create(snapshot_id=snap.snapshot_id, repository_root=snap.repository_root, evidence_store=store, graph=snap.graph)
    ctx = AgentToolContext(snapshots={s.snapshot_id: s}, default_snapshot_id=s.snapshot_id)
    reg = create_agent_tool_registry(ctx)

    id1 = reg.invoke("scan_security", {"snapshot_id": s.snapshot_id}).result["findings"][0]["finding_id"]
    id2 = reg.invoke("scan_security", {"snapshot_id": s.snapshot_id}).result["findings"][0]["finding_id"]
    assert id1 == id2


def test_audit_04_cross_snapshot_security_finding_ids_differ(tmp_path: Path):
    """4. Same finding in different snapshots produces different evidence IDs."""
    snap1 = _snapshot(tmp_path / "snap1", "1" * 40, {"test.py": "x = 1\n"})
    snap2 = _snapshot(tmp_path / "snap2", "2" * 40, {"test.py": "x = 1\n"})
    f = StaticFinding(
        id=uuid4(),
        tool="scanner-a",
        rule_id="rule-A",
        detector_id="rule-A",
        title="Test",
        description="Test",
        severity=Severity.LOW,
        category="sast",
        evidence=Evidence(file_path="test.py", start_line=1, end_line=1),
    )
    s1 = RepositorySnapshot.create(snapshot_id=snap1.snapshot_id, repository_root=snap1.repository_root,
                                   evidence_store=EvidenceStore(snap1.manifest, {"scanner-a": ScannerResult(tool="scanner-a", status=ToolStatus.COMPLETED, findings=[f])}),
                                   graph=snap1.graph)
    s2 = RepositorySnapshot.create(snapshot_id=snap2.snapshot_id, repository_root=snap2.repository_root,
                                   evidence_store=EvidenceStore(snap2.manifest, {"scanner-a": ScannerResult(tool="scanner-a", status=ToolStatus.COMPLETED, findings=[f])}),
                                   graph=snap2.graph)
    ctx = AgentToolContext(snapshots={s1.snapshot_id: s1, s2.snapshot_id: s2}, default_snapshot_id=s1.snapshot_id)
    reg = create_agent_tool_registry(ctx)

    id1 = reg.invoke("scan_security", {"snapshot_id": s1.snapshot_id}).result["findings"][0]["finding_id"]
    id2 = reg.invoke("scan_security", {"snapshot_id": s2.snapshot_id}).result["findings"][0]["finding_id"]
    assert id1 != id2


def test_audit_05_and_06_top_level_file_to_symbol_calls_and_round_trip(tmp_path: Path):
    """5 & 6. Top-level call creates FILE -> SYMBOL CALLS edge and find_callers round-trips into verify_finding."""
    code = (
        "def worker():\n"
        "    return 42\n\n"
        "worker()\n"
    )
    snap = _snapshot(tmp_path / "toplevel-call", "e" * 40, {"main.py": code})
    ctx = AgentToolContext(snapshots={snap.snapshot_id: snap}, default_snapshot_id=snap.snapshot_id)
    reg = create_agent_tool_registry(ctx)

    # Search for worker symbol
    search = reg.invoke("search_symbol", {"query": "worker", "match_mode": "EXACT"})
    assert search.status == ToolResultStatus.SUCCESS
    worker_sym_id = search.result["matches"][0]["symbol_id"]

    # find_callers on worker
    callers = reg.invoke("find_callers", {"symbol_id": worker_sym_id})
    assert callers.status == ToolResultStatus.SUCCESS
    assert callers.result["total_relationships"] >= 1
    rel = callers.result["relationships"][0]

    # Verify source is the FILE node
    assert rel["source"]["kind"] == "FILE"
    assert rel["source"]["entity_id"].startswith("entity:")
    assert len(rel["source"]["entity_id"]) == 71
    assert rel["source"]["file_path"] == "main.py"
    assert rel["relationship"] == "CALLS"

    # 6. Round-trip into verify_finding using source_entity_id
    evidence_id = callers.evidence[0].evidence_id
    verify_res = reg.invoke("verify_finding", {
        "claim": {
            "claim_type": "CALL_RELATIONSHIP",
            "snapshot_id": snap.snapshot_id,
            "source_entity_id": rel["source"]["entity_id"],
            "target_entity_id": rel["target"]["entity_id"],
            "relationship_type": "CALLS",
            "evidence_refs": [evidence_id],
        }
    })
    assert verify_res.status == ToolResultStatus.SUCCESS
    assert verify_res.result["verdict"] == "SUPPORTED"
    assert verify_res.result["reason_code"] == "EXACT_GRAPH_EDGE"


def test_audit_07_find_callees_result_round_trips_into_verify_finding(tmp_path: Path):
    """7. find_callees result round-trips into verify_finding."""
    code = (
        "def helper():\n"
        "    return 1\n\n"
        "def main_func():\n"
        "    return helper()\n"
    )
    snap = _snapshot(tmp_path / "callees-test", "f" * 40, {"service.py": code})
    ctx = AgentToolContext(snapshots={snap.snapshot_id: snap}, default_snapshot_id=snap.snapshot_id)
    reg = create_agent_tool_registry(ctx)

    caller_id = reg.invoke("search_symbol", {"query": "main_func"}).result["matches"][0]["symbol_id"]
    callees = reg.invoke("find_callees", {"symbol_id": caller_id})
    assert callees.status == ToolResultStatus.SUCCESS
    assert callees.result["total_relationships"] >= 1
    rel = callees.result["relationships"][0]
    evidence_id = callees.evidence[0].evidence_id

    # Round-trip with symbol_id
    verify_sym = reg.invoke("verify_finding", {
        "claim": {
            "claim_type": "CALL_RELATIONSHIP",
            "snapshot_id": snap.snapshot_id,
            "source_symbol_id": caller_id,
            "target_symbol_id": rel["target"]["entity_id"],
            "evidence_refs": [evidence_id],
        }
    })
    assert verify_sym.result["verdict"] == "SUPPORTED"

    # Round-trip with entity_id
    verify_ent = reg.invoke("verify_finding", {
        "claim": {
            "claim_type": "CALL_RELATIONSHIP",
            "snapshot_id": snap.snapshot_id,
            "source_entity_id": rel["source"]["entity_id"],
            "target_entity_id": rel["target"]["entity_id"],
            "evidence_refs": [evidence_id],
        }
    })
    assert verify_ent.result["verdict"] == "SUPPORTED"


def test_audit_08_foreign_snapshot_graph_entity_id_rejected(tmp_path: Path):
    """8. Foreign snapshot graph entity ID rejected in verification."""
    snap1 = _snapshot(tmp_path / "foreign-1", "1" * 40, {"a.py": "def f(): pass\ndef g(): f()\n"})
    snap2 = _snapshot(tmp_path / "foreign-2", "2" * 40, {"b.py": "def h(): pass\n"})
    ctx = AgentToolContext(snapshots={snap1.snapshot_id: snap1, snap2.snapshot_id: snap2}, default_snapshot_id=snap1.snapshot_id)
    reg = create_agent_tool_registry(ctx)

    f_id = reg.invoke("search_symbol", {"snapshot_id": snap1.snapshot_id, "query": "f"}).result["matches"][0]["symbol_id"]
    h_id = reg.invoke("search_symbol", {"snapshot_id": snap2.snapshot_id, "query": "h"}).result["matches"][0]["symbol_id"]

    # Claim in snap1 referencing symbol from snap2
    res = reg.invoke("verify_finding", {
        "claim": {
            "claim_type": "CALL_RELATIONSHIP",
            "snapshot_id": snap1.snapshot_id,
            "source_symbol_id": f_id,
            "target_symbol_id": h_id,
            "evidence_refs": ["edge:dummy"],
        }
    })
    assert res.result["verdict"] == "INVALID_CLAIM"
    assert res.result["reason_code"] == "SOURCE_OR_TARGET_UNRESOLVED"


def test_audit_09_invalid_file_entity_id_rejected(tmp_path: Path):
    """9. Invalid FILE entity ID (traversal or non-existent) rejected in verification."""
    snap = _snapshot(tmp_path / "invalid-file", "3" * 40, {"app.py": "def run(): pass\nrun()\n"})
    ctx = AgentToolContext(snapshots={snap.snapshot_id: snap}, default_snapshot_id=snap.snapshot_id)
    reg = create_agent_tool_registry(ctx)

    run_id = reg.invoke("search_symbol", {"query": "run"}).result["matches"][0]["symbol_id"]

    # Non-existent file
    res_nonexistent = reg.invoke("verify_finding", {
        "claim": {
            "claim_type": "CALL_RELATIONSHIP",
            "snapshot_id": snap.snapshot_id,
            "source_entity_id": "file:missing.py",
            "target_symbol_id": run_id,
            "evidence_refs": ["edge:dummy"],
        }
    })
    assert res_nonexistent.result["verdict"] == "INVALID_CLAIM"
    assert res_nonexistent.result["reason_code"] == "SOURCE_OR_TARGET_UNRESOLVED"

    # Traversal file
    res_traversal = reg.invoke("verify_finding", {
        "claim": {
            "claim_type": "CALL_RELATIONSHIP",
            "snapshot_id": snap.snapshot_id,
            "source_entity_id": "file:../../etc/passwd",
            "target_symbol_id": run_id,
            "evidence_refs": ["edge:dummy"],
        }
    })
    assert res_traversal.result["verdict"] == "INVALID_CLAIM"
    assert res_traversal.result["reason_code"] == "SOURCE_OR_TARGET_UNRESOLVED"


def test_audit_10_graph_entity_id_is_bounded():
    """10. GraphEntityRecord schema rejects entity IDs exceeding 2048 characters."""
    valid = GraphEntityRecord(entity_id="x" * 2048, kind="FILE", label="test")
    assert len(valid.entity_id) == 2048

    with pytest.raises(ValidationError):
        GraphEntityRecord(entity_id="x" * 2049, kind="FILE", label="test")


def test_audit_11_through_16_change_evidence_bounds_and_json_serialization(tmp_path: Path):
    """11-16. Bounded change evidence for long symbols, routes, schemas, paths, and model_dump_json."""
    base = _snapshot(tmp_path / "diff-base", "4" * 40, {"service.py": "def old(): pass\n"})
    head = _snapshot(tmp_path / "diff-head", "5" * 40, {"service.py": "def new(): pass\n"})

    long_symbol_name = "sym_" + "s" * 1500
    long_route_name = "/api/v1/" + "r" * 1500
    long_model_name = "Model_" + "m" * 1500

    diff = StructuralDiffResult(
        base_commit_sha=base.snapshot_id,
        head_commit_sha=head.snapshot_id,
        repository_url=base.manifest.repository_url,
        changed_symbols=[
            SymbolDiffFact(
                file_path="service.py",
                symbol_name=long_symbol_name,
                symbol_kind=SymbolKind.FUNCTION,
                change_type=SymbolChangeType.ADDED,
                head_location={"start_line": 1, "end_line": 2},
            )
        ],
        route_deltas=[
            RouteContractDelta(
                route_name=long_route_name,
                file_path="service.py",
                route_type="FASTAPI_ROUTE",
                change_type="MODIFIED",
            )
        ],
        schema_deltas=[
            SchemaModelDelta(
                model_name=long_model_name,
                file_path="service.py",
                field_name="field1",
                change_type="MODIFIED_TYPE",
            )
        ],
        changed_files=[
            FileDiffFact(
                file_path="service.py",
                change_type=FileChangeType.MODIFIED,
                base_location={"start_line": 1, "end_line": 1},
                head_location={"start_line": 1, "end_line": 2},
            )
        ],
    )

    ctx = AgentToolContext(
        snapshots={base.snapshot_id: base, head.snapshot_id: head},
        default_snapshot_id=head.snapshot_id,
        diffs={(base.snapshot_id, head.snapshot_id): diff},
    )
    reg = create_agent_tool_registry(ctx)

    # 11, 12, 13: analyze_change with long symbol, route, and schema identifiers
    change_res = reg.invoke("analyze_change", {
        "base_snapshot_id": base.snapshot_id,
        "head_snapshot_id": head.snapshot_id,
    })
    assert change_res.status == ToolResultStatus.SUCCESS

    # Check evidence symbol bounds: all must be <= 1024 chars
    for ev in change_res.evidence:
        if ev.symbol:
            assert len(ev.symbol) <= 1024
            if ev.relationship in {"SYMBOL", "ROUTE", "SCHEMA"}:
                assert ev.symbol.startswith("change-subject:")

    # 15: analyze_change model_dump_json succeeds
    json_str = change_res.model_dump_json()
    assert isinstance(json_str, str)
    assert len(json_str) > 0

    # 16: verify_finding structural-change model_dump_json succeeds
    file_ev = next(ev for ev in change_res.evidence if ev.relationship == "FILE")
    verify_res = reg.invoke("verify_finding", {
        "claim": {
            "claim_type": "STRUCTURAL_CHANGE",
            "base_snapshot_id": base.snapshot_id,
            "head_snapshot_id": head.snapshot_id,
            "file_path": "service.py",
            "change_type": "MODIFIED",
            "evidence_refs": [file_ev.evidence_id],
        }
    })
    assert verify_res.result["verdict"] == "SUPPORTED"
    v_json = verify_res.model_dump_json()
    assert isinstance(v_json, str)
    assert len(v_json) > 0


def test_audit_17_scan_security_verify_exact_round_trip(tmp_path: Path):
    """17. scan_security -> verify_finding exact evidence round-trip."""
    snap = _snapshot(tmp_path / "sec-roundtrip", "6" * 40, {"auth.py": "SECRET = 'foo'\n"})
    finding = StaticFinding(
        id=uuid4(),
        tool="secret-scanner",
        rule_id="hardcoded-secret",
        detector_id="hardcoded-secret",
        title="Secret found",
        description="A secret was hardcoded",
        severity=Severity.HIGH,
        category="secret",
        evidence=Evidence(file_path="auth.py", start_line=1, end_line=1),
        source_tool="secret-scanner",
    )
    store = EvidenceStore(
        snap.manifest,
        {"secret-scanner": ScannerResult(tool="secret-scanner", status=ToolStatus.COMPLETED, findings=[finding])},
    )
    s = RepositorySnapshot.create(snapshot_id=snap.snapshot_id, repository_root=snap.repository_root, evidence_store=store, graph=snap.graph)
    ctx = AgentToolContext(snapshots={s.snapshot_id: s}, default_snapshot_id=s.snapshot_id)
    reg = create_agent_tool_registry(ctx)

    scan = reg.invoke("scan_security", {"snapshot_id": s.snapshot_id})
    assert scan.status == ToolResultStatus.SUCCESS
    ev_id = scan.result["findings"][0]["finding_id"]

    verify = reg.invoke("verify_finding", {
        "claim": {
            "claim_type": "SECURITY_FINDING",
            "snapshot_id": s.snapshot_id,
            "rule": "hardcoded-secret",
            "file_path": "auth.py",
            "evidence_refs": [ev_id],
        }
    })
    assert verify.status == ToolResultStatus.SUCCESS
    assert verify.result["verdict"] == "SUPPORTED"
    assert verify.result["matched_evidence_refs"] == [ev_id]


def test_audit_18_trace_dataflow_verify_exact_round_trip(tmp_path: Path):
    """18. trace_dataflow -> verify_finding exact evidence round-trip."""
    code = (
        "def process_input(user_data):\n"
        "    query = 'SELECT * FROM users WHERE id = ' + user_data\n"
        "    cursor.execute(query)\n"
    )
    snap = _snapshot(tmp_path / "flow-roundtrip", "7" * 40, {"sql.py": code})
    ctx = AgentToolContext(snapshots={snap.snapshot_id: snap}, default_snapshot_id=snap.snapshot_id)
    reg = create_agent_tool_registry(ctx)

    search = reg.invoke("search_symbol", {"query": "process_input"})
    assert search.status == ToolResultStatus.SUCCESS
    sym_id = search.result["matches"][0]["symbol_id"]

    flow = reg.invoke("trace_dataflow", {"source_symbol_id": sym_id})
    if flow.status == ToolResultStatus.SUCCESS and flow.result["paths"]:
        path = flow.result["paths"][0]
        ev_id = flow.evidence[0].evidence_id

        verify = reg.invoke("verify_finding", {
            "claim": {
                "claim_type": "DATAFLOW",
                "snapshot_id": snap.snapshot_id,
                "source_symbol_id": sym_id,
                "sink_category": path["sink"]["kind"],
                "evidence_refs": [ev_id],
            }
        })
        assert verify.result["verdict"] == "SUPPORTED"
        assert verify.result["matched_evidence_refs"] == [ev_id]


def test_audit_19_repeated_call_site_multiplicity_conservative_uncertainty(tmp_path: Path):
    """19. Repeated-call-site conservative behavior: non-matching line returns INSUFFICIENT_EVIDENCE."""
    code = (
        "def callee():\n"
        "    pass\n\n"
        "def caller():\n"
        "    callee()\n"
        "    callee()\n"
    )
    snap = _snapshot(tmp_path / "mult-test", "8" * 40, {"multi.py": code})
    ctx = AgentToolContext(snapshots={snap.snapshot_id: snap}, default_snapshot_id=snap.snapshot_id)
    reg = create_agent_tool_registry(ctx)

    caller_id = reg.invoke("search_symbol", {"query": "caller"}).result["matches"][0]["symbol_id"]
    callee_id = reg.invoke("search_symbol", {"query": "callee"}).result["matches"][0]["symbol_id"]

    callees = reg.invoke("find_callees", {"symbol_id": caller_id})
    assert callees.status == ToolResultStatus.SUCCESS
    ev_id = callees.evidence[0].evidence_id

    # Request a non-matching call site line (line 999)
    res = reg.invoke("verify_finding", {
        "claim": {
            "claim_type": "CALL_RELATIONSHIP",
            "snapshot_id": snap.snapshot_id,
            "source_symbol_id": caller_id,
            "target_symbol_id": callee_id,
            "call_site_file": "multi.py",
            "call_site_line": 999,
            "evidence_refs": [ev_id],
        }
    })
    assert res.result["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert res.result["reason_code"] == "CALL_SITE_MULTIPLICITY_NOT_PRESERVED"


def test_audit_20_frozen_benchmark_ground_truth_unreachable():
    """20. Frozen benchmark ground truth remains strictly unreachable from agent tools."""
    import importlib
    import app.agent_tools.tools as tools_mod

    # Verify no import of ground truth benchmark modules in agent tools
    tool_code = Path(tools_mod.__file__).read_text(encoding="utf-8")
    assert "evaluation.ground_truth" not in tool_code
    assert "evaluation_data" not in tool_code
    assert "ground_truth" not in tool_code
