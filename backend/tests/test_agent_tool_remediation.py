"""Hostile regressions for the Phase-A deterministic tool trust boundary."""

from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone
import os
import subprocess
from uuid import uuid4

import pytest
import json

from app.agent_tools import AgentToolContext, RepositorySnapshot, ToolResourceLimits, create_agent_tool_registry
from app.agent_tools.schemas import GraphEntityRecord, GraphRelationship, ToolResultStatus
from app.analysis.store import EvidenceStore
from app.graph.schemas import EdgeKind, NodeKind
from app.schemas.static_finding import ScannerResult, ToolStatus
from app.semantics.flow import FlowResults
from app.agent_tools.tools import _edge_evidence
from app.analysis.diff_engine import get_diff_engine
from tests.test_agent_tool_layer import _change_context, _snapshot


@pytest.fixture
def tool_fixture(tmp_path: Path):
    snapshot = _snapshot(
        tmp_path / "observability",
        "9" * 40,
        {"app/routes.py": "def route(value):\n    return open(value).read()\n"},
    )
    return create_agent_tool_registry(AgentToolContext.from_snapshot(snapshot)), snapshot


def _symbol(registry, name: str, snapshot_id: str | None = None) -> str:
    arguments = {"query": name}
    if snapshot_id:
        arguments["snapshot_id"] = snapshot_id
    result = registry.invoke("search_symbol", arguments)
    return result.result["matches"][0]["symbol_id"]


def test_change_tools_never_recompute_from_mutable_live_files(tmp_path: Path):
    context, base, head = _change_context(tmp_path)
    registry = create_agent_tool_registry(context)
    first = registry.invoke("analyze_change", {
        "base_snapshot_id": base.snapshot_id,
        "head_snapshot_id": head.snapshot_id,
    })
    (head.repository_root / "app/service.py").write_text("def injected():\n    return False\n", encoding="utf-8")
    second = registry.invoke("analyze_change", {
        "base_snapshot_id": base.snapshot_id,
        "head_snapshot_id": head.snapshot_id,
    })
    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_untrusted_direct_diff_is_not_used_even_with_symlink_escape(tmp_path: Path):
    context, base, head = _change_context(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_text("secret = True\n", encoding="utf-8")
    link = head.repository_root / "escape.py"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    result = create_agent_tool_registry(context).invoke("analyze_change", {
        "base_snapshot_id": base.snapshot_id,
        "head_snapshot_id": head.snapshot_id,
    })
    assert result.status == ToolResultStatus.INSUFFICIENT_EVIDENCE
    assert result.errors[0].code == "PRECOMPUTED_DIFF_REQUIRED"


def test_post_registration_symlink_swap_fails_closed(tmp_path: Path):
    snapshot = _snapshot(tmp_path / "swap", "2" * 40, {"safe.py": "def safe():\n    return True\n"})
    registry = create_agent_tool_registry(AgentToolContext.from_snapshot(snapshot))
    outside = tmp_path / "outside.py"
    outside.write_text("secret = True\n", encoding="utf-8")
    materialized = snapshot.repository_root / "safe.py"
    materialized.unlink()
    try:
        materialized.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    result = registry.invoke("inspect_file", {"file_path": "safe.py"})
    assert result.status == ToolResultStatus.INVALID_INPUT
    assert result.errors[0].code == "PATH_OUTSIDE_REPOSITORY"


@pytest.mark.skipif(os.name != "nt", reason="Windows reparse-point regression")
def test_directory_junction_escape_fails_closed(tmp_path: Path):
    snapshot = _snapshot(tmp_path / "junction-repo", "3" * 40, {"safe.py": "def safe():\n    return True\n"})
    registry = create_agent_tool_registry(AgentToolContext.from_snapshot(snapshot))
    outside = tmp_path / "junction-outside"
    outside.mkdir()
    (outside / "secret.py").write_text("secret = True\n", encoding="utf-8")
    junction = snapshot.repository_root / "linked"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
        capture_output=True,
        text=True,
        check=False,
    )
    if created.returncode != 0:
        pytest.skip("directory junction creation is unavailable")
    result = registry.invoke("inspect_file", {"file_path": "linked/secret.py"})
    assert result.status == ToolResultStatus.INVALID_INPUT
    assert result.errors[0].code == "PATH_OUTSIDE_REPOSITORY"


def test_scanner_fact_for_in_root_non_manifest_file_is_rejected(tmp_path: Path):
    original = _snapshot(tmp_path / "scanner", "1" * 40, {"app/routes.py": "def route():\n    pass\n"})
    hidden = original.repository_root / "hidden.py"
    hidden.write_text("hidden = True\n", encoding="utf-8")
    result = next(iter(original.evidence_store.scanner_results.values())).model_copy(deep=True)
    poisoned = result.findings[0].model_copy(deep=True)
    poisoned.evidence.file_path = "hidden.py"
    store = EvidenceStore(original.manifest, {"poisoned": ScannerResult(
        tool="poisoned", status=ToolStatus.COMPLETED, findings=[poisoned]
    )})
    with pytest.raises(ValueError, match="manifest"):
        RepositorySnapshot.create(
            snapshot_id=original.snapshot_id,
            repository_root=original.repository_root,
            evidence_store=store,
        )


def test_graph_fact_for_in_root_non_manifest_file_is_rejected(tmp_path: Path):
    original = _snapshot(tmp_path / "graph", "3" * 40, {"safe.py": "def safe():\n    pass\n"})
    (original.repository_root / "hidden.py").write_text("hidden = True\n", encoding="utf-8")
    original.graph.add_node("symbol:hidden", NodeKind.SYMBOL, "hidden", file_path="hidden.py", start_line=1, end_line=1)
    with pytest.raises(ValueError, match="manifest"):
        RepositorySnapshot.create(
            snapshot_id=original.snapshot_id,
            repository_root=original.repository_root,
            evidence_store=original.evidence_store,
            graph=original.graph,
        )


def test_precomputed_diff_top_level_paths_require_snapshot_manifest_membership(tmp_path: Path):
    context, base, head = _change_context(tmp_path)
    diff = context.get_diff(base.snapshot_id, head.snapshot_id)
    poisoned = diff.model_copy(update={"added_files": ["hidden.py"]})
    with pytest.raises(ValueError, match="manifest"):
        AgentToolContext(
            snapshots={base.snapshot_id: base, head.snapshot_id: head},
            default_snapshot_id=head.snapshot_id,
            diffs={(base.snapshot_id, head.snapshot_id): poisoned},
        )


def test_registered_snapshot_isolated_from_retained_graph_and_scanner_references(tmp_path: Path):
    snapshot = _snapshot(tmp_path / "immutable", "4" * 40, {
        "a.py": "def target(value):\n    return value\n\ndef caller(value):\n    return target(value)\n",
        "b.py": "def other(value):\n    return value\n",
    })
    context = AgentToolContext.from_snapshot(snapshot)
    registry = create_agent_tool_registry(context)
    target = _symbol(registry, "target")
    before_callers = registry.invoke("find_callers", {"symbol_id": target}).model_dump(mode="json")
    before_scan = registry.invoke("scan_security", {}).model_dump(mode="json")
    other = next(node for node in snapshot.graph.get_nodes() if node.label == "other")
    snapshot.graph.add_edge(other.id, target, EdgeKind.CALLS, {"call_site_file": "b.py", "call_site_line": 1})
    snapshot.evidence_store.add_scanner_result(ScannerResult(tool="late", status=ToolStatus.COMPLETED, findings=[]))
    assert registry.invoke("find_callers", {"symbol_id": target}).model_dump(mode="json") == before_callers
    assert registry.invoke("scan_security", {}).model_dump(mode="json") == before_scan


def test_mutation_through_registered_snapshot_fails_closed(tmp_path: Path):
    snapshot = _snapshot(tmp_path / "tamper", "4" * 40, {"a.py": "def target(v):\n    return v\n"})
    context = AgentToolContext.from_snapshot(snapshot)
    registered = context.get_snapshot(snapshot.snapshot_id)
    registered.manifest.files[0].path = "tampered.py"
    result = create_agent_tool_registry(context).invoke("search_symbol", {"query": "target"})
    assert result.status == ToolResultStatus.INTERNAL_ERROR
    assert result.errors[0].code == "SNAPSHOT_ARTIFACT_INTEGRITY_FAILED"


def test_graph_evidence_ids_are_snapshot_bound(tmp_path: Path):
    contents = {"a.py": "def target(v):\n    return v\n\ndef caller(v):\n    return target(v)\n"}
    first = _snapshot(tmp_path / "one", "5" * 40, contents)
    second = _snapshot(tmp_path / "two", "6" * 40, contents)
    context = AgentToolContext(
        snapshots={first.snapshot_id: first, second.snapshot_id: second},
        default_snapshot_id=first.snapshot_id,
    )
    registry = create_agent_tool_registry(context)
    first_target = _symbol(registry, "target", first.snapshot_id)
    second_target = _symbol(registry, "target", second.snapshot_id)
    first_edge = registry.invoke("find_callers", {"snapshot_id": first.snapshot_id, "symbol_id": first_target})
    second_edge = registry.invoke("find_callers", {"snapshot_id": second.snapshot_id, "symbol_id": second_target})
    assert first_edge.evidence[0].evidence_id != second_edge.evidence[0].evidence_id
    assert len(first_edge.evidence[0].evidence_id) <= 80


def test_same_relation_at_different_call_sites_has_distinct_evidence_ids(tool_fixture):
    _, snapshot = tool_fixture
    source = GraphEntityRecord(entity_id="s" * 2048, kind="SYMBOL", label="source")
    target = GraphEntityRecord(entity_id="t" * 2048, kind="SYMBOL", label="target")
    first = GraphRelationship(
        relationship="CALLS", source=source, target=target, evidence_file="app/routes.py", evidence_line=10
    )
    second = first.model_copy(update={"evidence_line": 11})
    assert _edge_evidence(snapshot, first).evidence_id != _edge_evidence(snapshot, second).evidence_id
    assert len(_edge_evidence(snapshot, first).evidence_id) <= 128


def test_verifier_rejects_irrelevant_coordinates_and_non_call_relationship(tmp_path: Path):
    snapshot = _snapshot(tmp_path / "claims", "7" * 40, {
        "a.py": "def target(v):\n    return v\n\ndef caller(v):\n    return target(v)\n",
    })
    registry = create_agent_tool_registry(AgentToolContext.from_snapshot(snapshot))
    target = _symbol(registry, "target")
    callers = registry.invoke("find_callers", {"symbol_id": target})
    caller = callers.result["relationships"][0]["source"]["entity_id"]
    irrelevant = registry.invoke("verify_finding", {"claim": {
        "claim_type": "DATAFLOW", "snapshot_id": snapshot.snapshot_id,
        "source_symbol_id": target, "sink_category": "INPUT_TO_DATABASE",
        "target_symbol_id": caller, "evidence_refs": [callers.evidence[0].evidence_id],
    }})
    assert irrelevant.status == ToolResultStatus.INVALID_INPUT
    imports = registry.invoke("verify_finding", {"claim": {
        "claim_type": "CALL_RELATIONSHIP", "snapshot_id": snapshot.snapshot_id,
        "source_symbol_id": caller, "target_symbol_id": target,
        "relationship_type": "IMPORTS", "evidence_refs": [callers.evidence[0].evidence_id],
    }})
    assert imports.status == ToolResultStatus.INVALID_INPUT


def test_structural_symbol_verification_is_exact_and_rejects_suffix_collisions(tmp_path: Path):
    context, base, head = _change_context(tmp_path)
    registry = create_agent_tool_registry(context)
    changed = registry.invoke("analyze_change", {
        "base_snapshot_id": base.snapshot_id, "head_snapshot_id": head.snapshot_id,
    })
    evidence = next(item for item in changed.evidence if item.relationship == "SYMBOL")
    result = registry.invoke("verify_finding", {"claim": {
        "claim_type": "STRUCTURAL_CHANGE", "base_snapshot_id": base.snapshot_id,
        "head_snapshot_id": head.snapshot_id, "file_path": "app/service.py",
        "change_type": "DELETED", "symbol_id": "symbol:other.py:FUNCTION:legacy:1",
        "evidence_refs": [evidence.evidence_id],
    }})
    assert result.result["verdict"] == "INVALID_CLAIM"


def test_structural_symbol_verification_does_not_cross_same_named_methods(tmp_path: Path):
    base = _snapshot(tmp_path / "collision-base", "c" * 40, {
        "api.py": (
            "class A:\n"
            "    def same(self, value):\n"
            "        return value\n\n"
            "class B:\n"
            "    def same(self, value):\n"
            "        return value\n"
        ),
    })
    head = _snapshot(tmp_path / "collision-head", "d" * 40, {
        "api.py": (
            "class A:\n"
            "    def same(self, value, required):\n"
            "        return value\n\n"
            "class B:\n"
            "    def same(self, value):\n"
            "        return value\n"
        ),
    })
    from app.schemas.change_analysis import FileChangeType, FileDiffFact, StructuralDiffResult, SymbolChangeType, SymbolDiffFact
    diff = StructuralDiffResult(
        base_commit_sha=base.snapshot_id,
        head_commit_sha=head.snapshot_id,
        repository_url=base.manifest.repository_url,
        changed_files=[FileDiffFact(file_path="api.py", change_type=FileChangeType.MODIFIED)],
        modified_files=["api.py"],
        changed_symbols=[SymbolDiffFact(
            file_path="api.py", symbol_name="same", symbol_kind="METHOD",
            change_type=SymbolChangeType.SIGNATURE_CHANGED,
            base_location={"start_line": 2, "end_line": 3},
            head_location={"start_line": 2, "end_line": 3},
        )],
        modified_symbols=[SymbolDiffFact(
            file_path="api.py", symbol_name="same", symbol_kind="METHOD",
            change_type=SymbolChangeType.SIGNATURE_CHANGED,
            base_location={"start_line": 2, "end_line": 3},
            head_location={"start_line": 2, "end_line": 3},
        )],
    )
    context = AgentToolContext(
        snapshots={base.snapshot_id: base, head.snapshot_id: head},
        default_snapshot_id=head.snapshot_id,
        diffs={(base.snapshot_id, head.snapshot_id): diff},
    )
    registry = create_agent_tool_registry(context)
    changed = registry.invoke("analyze_change", {
        "base_snapshot_id": base.snapshot_id, "head_snapshot_id": head.snapshot_id,
    })
    symbol_fact = next(item for item in changed.result["diff"]["changed_symbols"] if item["symbol_name"] == "same")
    evidence = next(item for item in changed.evidence if item.relationship == "SYMBOL")
    b_symbol = next(
        item["symbol_id"] for item in registry.invoke("search_symbol", {
            "snapshot_id": head.snapshot_id, "query": "same", "max_results": 10,
        }).result["matches"] if item["start_line"] == 6
    )
    bogus = registry.invoke("verify_finding", {"claim": {
        "claim_type": "STRUCTURAL_CHANGE", "base_snapshot_id": base.snapshot_id,
        "head_snapshot_id": head.snapshot_id, "file_path": "api.py",
        "change_type": symbol_fact["change_type"], "symbol_id": b_symbol,
        "evidence_refs": [evidence.evidence_id],
    }})
    assert bogus.result["verdict"] != "SUPPORTED"


def test_wrong_snapshot_evidence_never_supports_a_claim(tmp_path: Path):
    first = _snapshot(tmp_path / "first", "a" * 40, {"app/routes.py": "def route(value):\n    return open(value).read()\n"})
    second = _snapshot(tmp_path / "second", "b" * 40, {"app/routes.py": "def route(value):\n    return open(value).read()\n"})
    registry = create_agent_tool_registry(AgentToolContext(
        snapshots={first.snapshot_id: first, second.snapshot_id: second}, default_snapshot_id=first.snapshot_id,
    ))
    evidence = registry.invoke("scan_security", {"snapshot_id": first.snapshot_id}).evidence[0].evidence_id
    result = registry.invoke("verify_finding", {"claim": {
        "claim_type": "SECURITY_FINDING", "snapshot_id": second.snapshot_id,
        "rule": "python.security.path-input", "file_path": "app/routes.py",
        "evidence_refs": [evidence],
    }})
    assert result.result["verdict"] != "SUPPORTED"


def test_supported_claim_rejects_any_fake_or_foreign_evidence(tool_fixture):
    registry, snapshot = tool_fixture
    scan = registry.invoke("scan_security", {"file_path": "app/routes.py"})
    result = registry.invoke("verify_finding", {"claim": {
        "claim_type": "SECURITY_FINDING", "snapshot_id": snapshot.snapshot_id,
        "rule": "python.security.path-input", "file_path": "app/routes.py",
        "evidence_refs": [scan.evidence[0].evidence_id, "evidence:fake"],
    }})
    assert result.result["verdict"] != "SUPPORTED"


def test_alias_budget_is_reported_as_resource_limit(tmp_path: Path, monkeypatch):
    snapshot = _snapshot(tmp_path / "flow", "8" * 40, {"a.py": "def source(value):\n    return value\n"})
    registry = create_agent_tool_registry(AgentToolContext.from_snapshot(snapshot))
    source = _symbol(registry, "source")
    monkeypatch.setattr(
        "app.agent_tools.tools.analyze_security_flows",
        lambda *args, **kwargs: FlowResults([], coverage={
            "complete": False, "stop_reasons": ["alias_budget"], "states_examined": 1,
        }),
    )
    result = registry.invoke("trace_dataflow", {"source_symbol_id": source})
    assert result.status == ToolResultStatus.RESOURCE_LIMIT


def test_inspect_file_enforces_symbol_result_boundary(tmp_path: Path):
    body = "\n".join(f"def f{i}():\n    pass" for i in range(8)) + "\n"
    snapshot = _snapshot(tmp_path / "many", "9" * 40, {"many.py": body})
    registry = create_agent_tool_registry(AgentToolContext.from_snapshot(
        snapshot, limits=ToolResourceLimits(max_results=2)
    ))
    result = registry.invoke("inspect_file", {"file_path": "many.py"})
    assert result.status == ToolResultStatus.RESOURCE_LIMIT
    assert len(result.result["symbols"]) == 2
    assert result.result["truncated"] is True


def test_inspect_symbol_enforces_high_degree_boundary(tmp_path: Path):
    body = "def target(v):\n    return v\n\n" + "\n".join(
        f"def caller{i}(v):\n    return target(v)\n" for i in range(6)
    )
    snapshot = _snapshot(tmp_path / "degree", "a" * 40, {"many.py": body})
    registry = create_agent_tool_registry(AgentToolContext.from_snapshot(
        snapshot, limits=ToolResourceLimits(max_results=2)
    ))
    target = _symbol(registry, "target")
    result = registry.invoke("inspect_symbol", {"symbol_id": target})
    assert result.status == ToolResultStatus.RESOURCE_LIMIT
    assert result.result["truncated"] is True
    assert result.result["returned_relationships"] <= 2


def test_snapshot_registration_enforces_file_count_and_size_limits(tmp_path: Path):
    snapshot = _snapshot(tmp_path / "limits", "c" * 40, {
        "a.py": "def a():\n    pass\n", "b.py": "def b():\n    pass\n",
    })
    with pytest.raises(ValueError, match="max_files"):
        RepositorySnapshot.create(
            snapshot_id=snapshot.snapshot_id, repository_root=snapshot.repository_root,
            evidence_store=snapshot.evidence_store, graph=snapshot.graph,
            limits=ToolResourceLimits(max_files=1),
        )
    large = _snapshot(tmp_path / "large", "d" * 40, {"large.py": "12345"})
    with pytest.raises(ValueError, match="max_file_size"):
        RepositorySnapshot.create(
            snapshot_id=large.snapshot_id, repository_root=large.repository_root,
            evidence_store=large.evidence_store, graph=large.graph,
            limits=ToolResourceLimits(max_file_size_bytes=2),
        )


def test_partial_diff_and_graph_coverage_never_prove_zero_impact(tmp_path: Path):
    context, base, head = _change_context(tmp_path)
    diff = context.get_diff(base.snapshot_id, head.snapshot_id)
    partial_diff = diff.model_copy(update={"discovery_coverage": {"complete": False, "stop_reasons": ["max_files"]}})
    partial_context = AgentToolContext(
        snapshots={base.snapshot_id: base, head.snapshot_id: head}, default_snapshot_id=head.snapshot_id,
        diffs={(base.snapshot_id, head.snapshot_id): partial_diff},
    )
    partial_result = create_agent_tool_registry(partial_context).invoke("analyze_impact", {
        "base_snapshot_id": base.snapshot_id, "head_snapshot_id": head.snapshot_id,
    })
    assert partial_result.status in {ToolResultStatus.INSUFFICIENT_EVIDENCE, ToolResultStatus.RESOURCE_LIMIT}
    assert partial_result.result["coverage"]["structural_diff_complete"] is False

    base_partial = _snapshot(tmp_path / "base-partial", "e" * 40, {"service.py": "def old():\n    pass\n"}, truncated=True)
    head_partial = _snapshot(tmp_path / "head-partial", "f" * 40, {"service.py": "def new():\n    pass\n"}, truncated=True)
    partial_diff = get_diff_engine().compute_structural_diff(
        base_workspace=str(base_partial.repository_root), head_workspace=str(head_partial.repository_root),
        base_commit_sha=base_partial.snapshot_id, head_commit_sha=head_partial.snapshot_id,
        repository_url=base_partial.manifest.repository_url,
    )
    graph_context = AgentToolContext(
        snapshots={base_partial.snapshot_id: base_partial, head_partial.snapshot_id: head_partial},
        default_snapshot_id=head_partial.snapshot_id, diffs={(base_partial.snapshot_id, head_partial.snapshot_id): partial_diff},
    )
    graph_result = create_agent_tool_registry(graph_context).invoke("analyze_impact", {
        "base_snapshot_id": base_partial.snapshot_id, "head_snapshot_id": head_partial.snapshot_id,
    })
    assert graph_result.status == ToolResultStatus.INSUFFICIENT_EVIDENCE
    assert graph_result.result["coverage"]["base_graph_complete"] is False

    zero_diff = partial_diff.model_copy(update={
        "changed_files": [], "added_files": [], "deleted_files": [], "renamed_files": [],
        "modified_files": [], "changed_symbols": [], "added_symbols": [], "deleted_symbols": [],
        "modified_symbols": [], "dependency_deltas": [], "config_deltas": [],
        "route_deltas": [], "schema_deltas": [], "summary": {"total_facts": 0},
        "discovery_coverage": {"complete": False, "stop_reasons": ["max_files"]},
    })
    zero_context = AgentToolContext(
        snapshots={base_partial.snapshot_id: base_partial, head_partial.snapshot_id: head_partial},
        default_snapshot_id=head_partial.snapshot_id,
        diffs={(base_partial.snapshot_id, head_partial.snapshot_id): zero_diff},
    )
    zero_result = create_agent_tool_registry(zero_context).invoke("analyze_impact", {
        "base_snapshot_id": base_partial.snapshot_id, "head_snapshot_id": head_partial.snapshot_id,
    })
    assert zero_result.result["total_impacts"] == 0
    assert zero_result.status == ToolResultStatus.INSUFFICIENT_EVIDENCE


def test_structural_verification_reports_missing_diff_as_insufficient_evidence(tmp_path: Path):
    base = _snapshot(tmp_path / "missing-diff-base", "1" * 40, {"service.py": "def old():\n    pass\n"})
    head = _snapshot(tmp_path / "missing-diff-head", "2" * 40, {"service.py": "def new():\n    pass\n"})
    registry = create_agent_tool_registry(AgentToolContext(
        snapshots={base.snapshot_id: base, head.snapshot_id: head},
        default_snapshot_id=head.snapshot_id,
    ))
    result = registry.invoke("verify_finding", {"claim": {
        "claim_type": "STRUCTURAL_CHANGE",
        "base_snapshot_id": base.snapshot_id,
        "head_snapshot_id": head.snapshot_id,
        "file_path": "service.py",
        "change_type": "MODIFIED",
        "evidence_refs": ["change:missing"],
    }})
    assert result.status == ToolResultStatus.SUCCESS
    assert result.result["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert result.result["reason_code"] == "PRECOMPUTED_DIFF_REQUIRED"


def test_every_registered_tool_result_is_json_serializable(tool_fixture):
    registry, snapshot = tool_fixture
    arguments = {
        "inspect_file": {"file_path": "app/routes.py"},
        "search_symbol": {"query": "route"},
        "inspect_symbol": {"symbol_id": _symbol(registry, "route")},
        "find_callers": {"symbol_id": _symbol(registry, "route")},
        "find_callees": {"symbol_id": _symbol(registry, "route")},
        "trace_dataflow": {"source_symbol_id": _symbol(registry, "route")},
        "scan_security": {},
        "analyze_change": {"base_snapshot_id": snapshot.snapshot_id, "head_snapshot_id": "0" * 40},
        "analyze_impact": {"base_snapshot_id": snapshot.snapshot_id, "head_snapshot_id": "0" * 40},
        "verify_finding": {"claim": {
            "claim_type": "SECURITY_FINDING", "snapshot_id": snapshot.snapshot_id,
            "rule": "x", "file_path": "app/routes.py", "evidence_refs": ["fake"],
        }},
    }
    for metadata in registry.list_tools():
        result = registry.invoke(metadata.tool_name, arguments[metadata.tool_name])
        payload = result.model_dump_json()
        assert isinstance(json.loads(payload), dict)


def test_adversarial_valid_metadata_is_stable_json_safe_and_redacted(tmp_path: Path):
    snapshot = _snapshot(tmp_path / "metadata", "e" * 40, {"a.py": "def target(v):\n    return v\n"})
    node = next(item for item in snapshot.graph.get_nodes() if item.label == "target")
    snapshot.graph.update_node_metadata(node.id, {
        "host_path": Path("C:/private/repository/secret.py"),
        "unordered": {"beta", "alpha"},
        "created": datetime(2025, 1, 1, tzinfo=timezone.utc),
        "opaque_identifier": uuid4(),
        "credential": "token=super-secret-value",
    })
    registry = create_agent_tool_registry(AgentToolContext.from_snapshot(snapshot))
    symbol_id = _symbol(registry, "target")
    first = registry.invoke("inspect_symbol", {"symbol_id": symbol_id})
    second = registry.invoke("inspect_symbol", {"symbol_id": symbol_id})
    encoded = first.model_dump_json()
    assert json.loads(encoded) == json.loads(second.model_dump_json())
    assert "C:/private" not in encoded
    assert "super-secret-value" not in encoded


def test_provenance_marks_caller_component_versions_as_declared(tool_fixture):
    registry, _ = tool_fixture
    result = registry.invoke("inspect_file", {"file_path": "app/routes.py"})
    assert result.provenance.component_version_trust == "DECLARED"
    assert result.provenance.snapshot_artifact_digest
