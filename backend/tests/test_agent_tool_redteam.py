"""Additional adversarial and semantic contract tests for Phase A."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from app.agent_tools import AgentToolContext, RepositorySnapshot, ToolResourceLimits, create_agent_tool_registry
from app.analysis.store import EvidenceStore
from app.agent_tools.schemas import ToolResultStatus
from app.graph.schemas import EdgeKind
from app.schemas.static_finding import ToolStatus
from tests.test_agent_tool_layer import _change_context, _snapshot


@pytest.fixture
def tool_fixture(tmp_path: Path):
    snapshot = _snapshot(
        tmp_path / "observability",
        "9" * 40,
        {"sample.py": "def sample(value):\n    return value\n"},
    )
    return create_agent_tool_registry(AgentToolContext.from_snapshot(snapshot)), snapshot


def test_empty_repository_fails_closed_without_fabricated_results(tmp_path: Path):
    snapshot = _snapshot(tmp_path / "empty", "1" * 40, {})
    registry = create_agent_tool_registry(AgentToolContext.from_snapshot(snapshot))
    search = registry.invoke("search_symbol", {"query": "anything"})
    assert search.status == ToolResultStatus.NOT_FOUND
    assert search.result["matches"] == []
    scan = registry.invoke("scan_security", {})
    assert scan.status == ToolResultStatus.SUCCESS
    assert scan.result["findings"] == []
    callers = registry.invoke("find_callers", {"symbol_id": "symbol:nope"})
    assert callers.status == ToolResultStatus.NOT_FOUND


def test_graph_cycle_is_bounded_and_direction_remains_upstream(tmp_path: Path):
    context, base, head = _change_context(tmp_path)
    legacy = next(node for node in base.graph.get_nodes() if node.label == "legacy")
    caller = next(node for node in base.graph.get_nodes() if node.label == "use")
    base.graph.add_edge(legacy.id, caller.id, EdgeKind.CALLS, {"call_site_file": "app/service.py", "call_site_line": 1})
    context = AgentToolContext(
        snapshots={base.snapshot_id: base, head.snapshot_id: head},
        default_snapshot_id=head.snapshot_id,
        diffs=context.diffs,
        limits=context.limits,
    )
    registry = create_agent_tool_registry(context)
    result = registry.invoke("analyze_impact", {
        "base_snapshot_id": base.snapshot_id,
        "head_snapshot_id": head.snapshot_id,
        "max_depth": 8,
        "max_results": 50,
    })
    assert result.status in {ToolResultStatus.INSUFFICIENT_EVIDENCE, ToolResultStatus.RESOURCE_LIMIT}
    assert 0 < result.result["returned_impacts"] < 10
    assert all(item["direction"] == "UPSTREAM_CALLER" for item in result.result["impacts"] if item["impact_type"] == "CALLER_IMPACT")


def test_flow_preserves_sanitizer_and_opaque_call_markers(tmp_path: Path):
    contents = {
        "flow.py": (
            "def sanitized(value):\n"
            "    clean = resolve_safe_path(value)\n"
            "    return open(clean)\n\n"
            "def opaque(value):\n"
            "    changed = mystery_transform(value)\n"
            "    return open(changed)\n"
        ),
    }
    snapshot = _snapshot(tmp_path / "flow", "2" * 40, contents)
    registry = create_agent_tool_registry(AgentToolContext.from_snapshot(snapshot))
    sanitized_id = registry.invoke("search_symbol", {"query": "sanitized"}).result["matches"][0]["symbol_id"]
    sanitized = registry.invoke("trace_dataflow", {"source_symbol_id": sanitized_id, "sink_category": "INPUT_TO_FILESYSTEM"})
    assert sanitized.result["paths"][0]["sanitizers"][0]["kind"] == "PATH_CONFINEMENT"
    assert sanitized.result["paths"][0]["certainty"] == "POSSIBLE"
    opaque_id = registry.invoke("search_symbol", {"query": "opaque"}).result["matches"][0]["symbol_id"]
    opaque = registry.invoke("trace_dataflow", {"source_symbol_id": opaque_id, "sink_category": "INPUT_TO_FILESYSTEM"})
    assert opaque.result["paths"][0]["opaque_calls"] == ["OPAQUE_CALL:mystery_transform"]
    assert opaque.result["paths"][0]["certainty"] == "POSSIBLE"


def test_change_facts_preserve_breaking_and_nonbreaking_signature_classification(tmp_path: Path):
    base = _snapshot(
        tmp_path / "sig-base",
        "3" * 40,
        {"api.py": "def breaking(value):\n    return value\n\ndef compatible(value):\n    return value\n"},
    )
    head = _snapshot(
        tmp_path / "sig-head",
        "4" * 40,
        {"api.py": "def breaking(value, required):\n    return value\n\ndef compatible(value, optional=True):\n    return value\n"},
    )
    from app.analysis.diff_engine import get_diff_engine
    diff = get_diff_engine().compute_structural_diff(
        base_workspace=str(base.repository_root), head_workspace=str(head.repository_root),
        base_commit_sha=base.snapshot_id, head_commit_sha=head.snapshot_id,
        repository_url=base.manifest.repository_url,
    )
    context = AgentToolContext(
        snapshots={base.snapshot_id: base, head.snapshot_id: head},
        default_snapshot_id=head.snapshot_id,
        diffs={(base.snapshot_id, head.snapshot_id): diff},
    )
    result = create_agent_tool_registry(context).invoke("analyze_change", {
        "base_snapshot_id": base.snapshot_id,
        "head_snapshot_id": head.snapshot_id,
    })
    changes = {item["symbol_name"]: item for item in result.result["diff"]["modified_symbols"]}
    assert changes["breaking"]["change_type"] == "SIGNATURE_CHANGED"
    assert changes["breaking"]["evidence"]["is_breaking"] is True
    assert changes["compatible"]["change_type"] == "SIGNATURE_CHANGED"
    assert changes["compatible"]["evidence"]["is_breaking"] is False


def test_call_and_structural_claim_verification_use_exact_evidence(tmp_path: Path):
    context, base, head = _change_context(tmp_path)
    registry = create_agent_tool_registry(context)
    legacy = registry.invoke("search_symbol", {"snapshot_id": base.snapshot_id, "query": "legacy"}).result["matches"][0]
    callers = registry.invoke("find_callers", {"snapshot_id": base.snapshot_id, "symbol_id": legacy["symbol_id"]})
    relation = callers.result["relationships"][0]
    call = registry.invoke("verify_finding", {"claim": {
        "claim_type": "CALL_RELATIONSHIP",
        "snapshot_id": base.snapshot_id,
        "source_symbol_id": relation["source"]["entity_id"],
        "target_symbol_id": relation["target"]["entity_id"],
        "relationship_type": "CALLS",
        "evidence_refs": [callers.evidence[0].evidence_id],
    }})
    assert call.result["verdict"] == "SUPPORTED"

    changed = registry.invoke("analyze_change", {"base_snapshot_id": base.snapshot_id, "head_snapshot_id": head.snapshot_id})
    file_evidence = next(item for item in changed.evidence if item.relationship == "FILE" and item.file_path == "app/service.py")
    structural = registry.invoke("verify_finding", {"claim": {
        "claim_type": "STRUCTURAL_CHANGE",
        "base_snapshot_id": base.snapshot_id,
        "head_snapshot_id": head.snapshot_id,
        "file_path": "app/service.py",
        "change_type": "MODIFIED",
        "evidence_refs": [file_evidence.evidence_id],
    }})
    assert structural.result["verdict"] == "SUPPORTED"


def test_partial_graph_never_proves_no_callers(tmp_path: Path):
    snapshot = _snapshot(
        tmp_path / "partial",
        "5" * 40,
        {"partial.py": "def target(value):\n    return value\n\ndef unknown(value):\n    return dynamic.target(value)\n"},
        truncated=True,
    )
    registry = create_agent_tool_registry(AgentToolContext.from_snapshot(snapshot))
    target_id = registry.invoke("search_symbol", {"query": "target"}).result["matches"][0]["symbol_id"]
    callers = registry.invoke("find_callers", {"symbol_id": target_id})
    assert callers.status == ToolResultStatus.INSUFFICIENT_EVIDENCE
    assert callers.result["graph_complete"] is False


def test_repository_file_scope_limit_is_explicit(tool_fixture):
    _, snapshot = tool_fixture
    registry = create_agent_tool_registry(AgentToolContext.from_snapshot(
        snapshot,
        limits=ToolResourceLimits(max_files=1),
    ))
    limited = registry.invoke("search_symbol", {"query": "sample"})
    assert limited.status == ToolResultStatus.SUCCESS

    larger = _snapshot(
        snapshot.repository_root.parent / "larger",
        "8" * 40,
        {"a.py": "def a():\n    pass\n", "b.py": "def b():\n    pass\n"},
    )
    bounded = create_agent_tool_registry(AgentToolContext.from_snapshot(
        larger,
        limits=ToolResourceLimits(max_files=1),
    )).invoke("search_symbol", {"query": "a"})
    assert bounded.status == ToolResultStatus.RESOURCE_LIMIT
    assert bounded.errors[0].code == "FILE_SCOPE_LIMIT_REACHED"


def test_context_reuses_manifest_graph_semantics_and_emits_observability(tool_fixture, caplog):
    registry, snapshot = tool_fixture
    assert 0 <= snapshot.initialization_duration_ms < 1_000
    assert snapshot.evidence_store.manifest is snapshot.manifest
    graph_identity = id(snapshot.graph)
    program_identity = id(snapshot.semantic_program)
    caplog.set_level(logging.INFO, logger="app.agent_tools.registry")
    registry.invoke("search_symbol", {"query": "read_file"})
    assert id(snapshot.graph) == graph_identity
    assert id(snapshot.semantic_program) == program_identity
    record = next(item for item in caplog.records if item.message == "agent_tool_invocation")
    assert record.invocation_id
    assert 0 <= record.duration_ms < 1_000
    assert record.status
    assert record.repository_snapshot == snapshot.snapshot_id


def test_agent_tool_sources_have_no_network_shell_mcp_or_benchmark_dependency():
    source_dir = Path(__file__).parents[1] / "app" / "agent_tools"
    combined = "\n".join(path.read_text(encoding="utf-8") for path in source_dir.glob("*.py"))
    for forbidden in (
        "subprocess.", "os.system", "requests.", "httpx.", "mcp.server",
        "evaluation_data", "ground_truth", "benchmark matcher",
    ):
        assert forbidden not in combined


def test_agent_visible_symbol_metadata_redacts_source_secrets(tmp_path: Path):
    raw_secret = "sk-abcdefghijklmnopqrstuvwxyz123456"
    snapshot = _snapshot(
        tmp_path / "redaction",
        "7" * 40,
        {"config.py": f"def configure(api_key='{raw_secret}'):\n    return True\n"},
    )
    result = create_agent_tool_registry(AgentToolContext.from_snapshot(snapshot)).invoke(
        "inspect_file", {"file_path": "config.py"}
    )
    assert result.status == ToolResultStatus.SUCCESS
    assert raw_secret not in result.model_dump_json()
    assert "REDACTED" in result.model_dump_json()


def test_precomputed_manifest_provenance_cannot_escape_repository(tmp_path: Path):
    original = _snapshot(
        tmp_path / "safe-root",
        "6" * 40,
        {"safe.py": "def safe():\n    return True\n"},
    )
    poisoned_manifest = original.manifest.model_copy(deep=True)
    poisoned_manifest.files[0].path = "../../outside.py"
    poisoned_store = EvidenceStore(poisoned_manifest, {})
    with pytest.raises(ValueError, match="outside the repository"):
        RepositorySnapshot.create(
            snapshot_id=poisoned_manifest.commit_hash,
            repository_root=original.repository_root,
            evidence_store=poisoned_store,
        )
