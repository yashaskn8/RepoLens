"""Final hostile regressions for the public Phase-A agent-tool contract."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest

from app.agent_tools import AgentToolContext, RepositorySnapshot, ToolResourceLimits, create_agent_tool_registry
from app.analysis.store import EvidenceStore
from app.ingestion.schemas import AnalysisScope, FileEntry, ParsedSymbol, RepositoryManifest, SymbolKind
from app.schemas.enums import Severity
from app.schemas.evidence import Evidence
from app.schemas.change_analysis import FileChangeType, FileDiffFact, StructuralDiffResult, SymbolChangeType, SymbolDiffFact
from app.schemas.static_finding import ScannerResult, StaticFinding, ToolStatus
from tests.test_agent_tool_layer import _change_context, _snapshot


def _search_id(registry, name: str, *, snapshot_id: str | None = None) -> str:
    arguments: dict[str, object] = {"query": name[:128], "match_mode": "PREFIX"}
    if snapshot_id is not None:
        arguments["snapshot_id"] = snapshot_id
    result = registry.invoke("search_symbol", arguments)
    assert result.status.value == "SUCCESS"
    return result.result["matches"][0]["symbol_id"]


def _many_security_snapshot(tmp_path: Path, *, count: int = 202) -> RepositorySnapshot:
    body = "\n\n".join(f"def finding_{index}(value):\n    return value" for index in range(count)) + "\n"
    original = _snapshot(tmp_path / "many-security", "7" * 40, {"app/routes.py": body})
    symbols = [item for item in original.manifest.files[0].symbols if item.kind == SymbolKind.FUNCTION]
    findings = [
        StaticFinding(
            id=UUID(int=index + 1),
            tool="repolens-core",
            rule_id="python.security.mass-finding",
            title=f"Finding {index}",
            description="Deterministic mass-finding fixture.",
            severity=Severity.HIGH,
            category="sast",
            evidence=Evidence(file_path="app/routes.py", start_line=symbol.start_line, end_line=symbol.end_line),
            confidence="HIGH",
            source_tool="repolens-core",
            detector_id="python.security.mass-finding",
            detector_kind="static_scanner",
        )
        for index, symbol in enumerate(symbols)
    ]
    store = EvidenceStore(
        original.manifest,
        {"repolens-core": ScannerResult(tool="repolens-core", status=ToolStatus.COMPLETED, findings=findings)},
    )
    return RepositorySnapshot.create(
        snapshot_id=original.snapshot_id,
        repository_root=original.repository_root,
        evidence_store=store,
        graph=original.graph,
    )


def _replace_repository(snapshot: RepositorySnapshot, repository_url: str) -> RepositorySnapshot:
    manifest = snapshot.manifest.model_copy(deep=True)
    manifest.repository_url = repository_url
    store = EvidenceStore(
        manifest,
        {name: result.model_copy(deep=True) for name, result in snapshot.evidence_store.scanner_results.items()},
    )
    return RepositorySnapshot.create(
        snapshot_id=snapshot.snapshot_id,
        repository_root=snapshot.repository_root,
        evidence_store=store,
        graph=snapshot.graph,
        semantic_program=snapshot.semantic_program,
    )


def test_public_symbol_id_round_trips_for_extreme_name_and_is_snapshot_bound(tmp_path: Path):
    name = "symbol_" + ("x" * 3_000)
    contents = {"app/routes.py": f"def {name}(value):\n    return open(value).read()\n"}
    first = _snapshot(tmp_path / "long-first", "1" * 40, contents)
    second = _snapshot(tmp_path / "long-second", "2" * 40, contents)
    registry = create_agent_tool_registry(AgentToolContext(
        snapshots={first.snapshot_id: first, second.snapshot_id: second},
        default_snapshot_id=first.snapshot_id,
        limits=ToolResourceLimits(max_results=200),
    ))

    symbol_id = _search_id(registry, name, snapshot_id=first.snapshot_id)
    other_id = _search_id(registry, name, snapshot_id=second.snapshot_id)
    assert len(symbol_id) <= 128
    assert symbol_id != other_id

    assert registry.invoke("inspect_symbol", {"snapshot_id": first.snapshot_id, "symbol_id": symbol_id}).status.value == "SUCCESS"
    assert registry.invoke("find_callers", {"snapshot_id": first.snapshot_id, "symbol_id": symbol_id}).status.value != "INVALID_INPUT"
    assert registry.invoke("find_callees", {"snapshot_id": first.snapshot_id, "symbol_id": symbol_id}).status.value != "INVALID_INPUT"
    assert registry.invoke("trace_dataflow", {"snapshot_id": first.snapshot_id, "source_symbol_id": symbol_id}).status.value != "INVALID_INPUT"
    scan = registry.invoke("scan_security", {"snapshot_id": first.snapshot_id, "symbol_id": symbol_id})
    assert scan.status.value == "SUCCESS"
    verified = registry.invoke("verify_finding", {"claim": {
        "claim_type": "SECURITY_FINDING",
        "snapshot_id": first.snapshot_id,
        "rule": "python.security.path-input",
        "file_path": "app/routes.py",
        "symbol_id": symbol_id,
        "evidence_refs": [scan.evidence[0].evidence_id],
    }})
    assert verified.result["verdict"] == "SUPPORTED"
    verified.model_dump_json()


def test_public_symbol_id_round_trips_for_maximum_path_and_unicode(tmp_path: Path):
    root = tmp_path / "maximum-path"
    root.mkdir()
    prefix = "/".join(["a" * 100] * 10) + "/"
    path = prefix + ("b" * (1024 - len(prefix) - 3)) + ".py"
    assert len(path) == 1024
    symbol = ParsedSymbol(name="Δοκιμή", kind=SymbolKind.FUNCTION, start_line=1, end_line=2)
    manifest = RepositoryManifest(
        repository_url="https://github.com/fixture/agent-tools",
        commit_hash="3" * 40,
        commit_sha="3" * 40,
        total_files=1,
        total_size_bytes=1,
        files=[FileEntry(path=path, language="python", size_bytes=1, lines_count=2, symbols=[symbol])],
        analysis_scope=AnalysisScope(files_processed=1, source_bytes_processed=1, total_observed_files=1, total_observed_bytes=1),
    )
    snapshot = RepositorySnapshot.create(
        snapshot_id="3" * 40,
        repository_root=root,
        evidence_store=EvidenceStore(manifest),
    )
    registry = create_agent_tool_registry(AgentToolContext.from_snapshot(snapshot))
    symbol_id = _search_id(registry, symbol.name)
    assert len(symbol_id) <= 128
    assert registry.invoke("inspect_symbol", {"symbol_id": symbol_id}).result["symbol"]["name"] == symbol.name


def test_public_symbol_ids_are_collision_resistant_and_repeatable(tmp_path: Path):
    body = "\n\n".join(f"def symbol_{index}(value):\n    return value" for index in range(128)) + "\n"
    snapshot = _snapshot(tmp_path / "identity-set", "6" * 40, {"symbols.py": body})
    registry = create_agent_tool_registry(AgentToolContext.from_snapshot(
        snapshot, limits=ToolResourceLimits(max_results=200)
    ))
    first = registry.invoke("search_symbol", {"query": "symbol_", "match_mode": "PREFIX", "max_results": 200})
    second = registry.invoke("search_symbol", {"query": "symbol_", "match_mode": "PREFIX", "max_results": 200})
    first_ids = [item["symbol_id"] for item in first.result["matches"]]
    second_ids = [item["symbol_id"] for item in second.result["matches"]]
    assert first_ids == second_ids
    assert len(first_ids) == len(set(first_ids)) == 128
    assert all(len(value) == 71 for value in first_ids)


def test_public_symbol_id_is_repository_bound_even_for_equal_commit(tmp_path: Path):
    commit = "0" * 40
    first = _snapshot(tmp_path / "repo-a", commit, {"app.py": "def target():\n    return 1\n"})
    second = _replace_repository(
        _snapshot(tmp_path / "repo-b", commit, {"app.py": "def target():\n    return 1\n"}),
        "https://github.com/other-owner/agent-tools",
    )
    first_id = _search_id(create_agent_tool_registry(AgentToolContext.from_snapshot(first)), "target")
    second_id = _search_id(create_agent_tool_registry(AgentToolContext.from_snapshot(second)), "target")
    assert first_id != second_id


def test_security_verifier_scopes_before_result_bounding(tmp_path: Path):
    snapshot = _many_security_snapshot(tmp_path)
    registry = create_agent_tool_registry(AgentToolContext.from_snapshot(
        snapshot, limits=ToolResourceLimits(max_results=200)
    ))
    target = _search_id(registry, "finding_201")
    scoped = registry.invoke("scan_security", {"symbol_id": target, "rules": ["python.security.mass-finding"]})
    assert scoped.status.value == "SUCCESS"
    result = registry.invoke("verify_finding", {"claim": {
        "claim_type": "SECURITY_FINDING",
        "snapshot_id": snapshot.snapshot_id,
        "rule": "python.security.mass-finding",
        "file_path": "app/routes.py",
        "symbol_id": target,
        "evidence_refs": [scoped.evidence[0].evidence_id],
    }})
    assert result.result["verdict"] == "SUPPORTED"


def test_security_verifier_distinguishes_complete_partial_and_bounded_absence(tmp_path: Path):
    snapshot = _many_security_snapshot(tmp_path / "complete")
    registry = create_agent_tool_registry(AgentToolContext.from_snapshot(
        snapshot, limits=ToolResourceLimits(max_results=200)
    ))
    target = _search_id(registry, "finding_201")
    absent = registry.invoke("verify_finding", {"claim": {
        "claim_type": "SECURITY_FINDING", "snapshot_id": snapshot.snapshot_id,
        "rule": "missing.rule", "file_path": "app/routes.py", "symbol_id": target,
        "evidence_refs": ["finding:absent"],
    }})
    assert absent.result["verdict"] == "UNSUPPORTED"
    assert absent.result["unresolved_evidence_refs"] == ["finding:absent"]

    partial_snapshot = _snapshot(
        tmp_path / "partial",
        "8" * 40,
        {"app/routes.py": "def target(value):\n    return value\n"},
        scanner_status=ToolStatus.UNAVAILABLE,
    )
    partial_registry = create_agent_tool_registry(AgentToolContext.from_snapshot(partial_snapshot))
    partial_target = _search_id(partial_registry, "target")
    partial = partial_registry.invoke("verify_finding", {"claim": {
        "claim_type": "SECURITY_FINDING", "snapshot_id": partial_snapshot.snapshot_id,
        "rule": "missing.rule", "file_path": "app/routes.py", "symbol_id": partial_target,
        "evidence_refs": ["finding:unavailable"],
    }})
    assert partial.result["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert partial.result["unresolved_evidence_refs"] == ["finding:unavailable"]

    bounded_original = _snapshot(
        tmp_path / "bounded",
        "9" * 40,
        {"app/routes.py": "def target(value):\n    return value\n"},
    )
    symbol = next(item for item in bounded_original.manifest.files[0].symbols if item.name == "target")
    findings = [
        StaticFinding(
            id=UUID(int=index + 1), tool="repolens-core", rule_id="python.security.overlap",
            title=f"Overlap {index}", description="Overlapping deterministic evidence.",
            severity=Severity.HIGH, category="sast",
            evidence=Evidence(file_path="app/routes.py", start_line=symbol.start_line, end_line=symbol.end_line),
            confidence="HIGH", source_tool="repolens-core", detector_id="python.security.overlap",
            detector_kind="static_scanner",
        )
        for index in range(201)
    ]
    bounded = RepositorySnapshot.create(
        snapshot_id=bounded_original.snapshot_id,
        repository_root=bounded_original.repository_root,
        evidence_store=EvidenceStore(bounded_original.manifest, {
            "repolens-core": ScannerResult(tool="repolens-core", status=ToolStatus.COMPLETED, findings=findings)
        }),
        graph=bounded_original.graph,
    )
    bounded_registry = create_agent_tool_registry(AgentToolContext.from_snapshot(
        bounded, limits=ToolResourceLimits(max_results=200)
    ))
    bounded_target = _search_id(bounded_registry, "target")
    bounded_result = bounded_registry.invoke("verify_finding", {"claim": {
        "claim_type": "SECURITY_FINDING", "snapshot_id": bounded.snapshot_id,
        "rule": "python.security.overlap", "file_path": "app/routes.py", "symbol_id": bounded_target,
        "evidence_refs": ["finding:not-returned"],
    }})
    assert bounded_result.status.value == "RESOURCE_LIMIT"
    assert bounded_result.result["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert bounded_result.result["reason_code"] == "EVIDENCE_REFERENCE_UNRESOLVED_OR_FOREIGN"


def test_security_verifier_rejects_file_and_rule_symbol_mismatches(tmp_path: Path):
    snapshot = _snapshot(
        tmp_path / "scope-mismatch",
        "a" * 40,
        {
            "app/routes.py": "def route(value):\n    return open(value).read()\n",
            "app/other.py": "def other(value):\n    return value\n",
        },
    )
    registry = create_agent_tool_registry(AgentToolContext.from_snapshot(snapshot))
    route = _search_id(registry, "route")
    other = _search_id(registry, "other")
    scan = registry.invoke("scan_security", {"symbol_id": route})
    mismatched_file = registry.invoke("verify_finding", {"claim": {
        "claim_type": "SECURITY_FINDING", "snapshot_id": snapshot.snapshot_id,
        "rule": "python.security.path-input", "file_path": "app/other.py", "symbol_id": route,
        "evidence_refs": [scan.evidence[0].evidence_id],
    }})
    assert mismatched_file.result["verdict"] == "INVALID_CLAIM"
    assert mismatched_file.result["unresolved_evidence_refs"] == [scan.evidence[0].evidence_id]
    wrong_rule = registry.invoke("verify_finding", {"claim": {
        "claim_type": "SECURITY_FINDING", "snapshot_id": snapshot.snapshot_id,
        "rule": "missing.rule", "file_path": "app/other.py", "symbol_id": other,
        "evidence_refs": [scan.evidence[0].evidence_id],
    }})
    assert wrong_rule.result["verdict"] == "UNSUPPORTED"
    assert wrong_rule.result["unresolved_evidence_refs"] == [scan.evidence[0].evidence_id]


def test_verifier_accounts_for_invalid_evidence_on_all_semantic_verdicts(tmp_path: Path):
    snapshot = _snapshot(
        tmp_path / "evidence-accounting",
        "4" * 40,
        {"app/routes.py": "def route(value):\n    return open(value).read()\n"},
    )
    registry = create_agent_tool_registry(AgentToolContext.from_snapshot(snapshot))
    scan = registry.invoke("scan_security", {})
    correct = scan.evidence[0].evidence_id
    supported = registry.invoke("verify_finding", {"claim": {
        "claim_type": "SECURITY_FINDING", "snapshot_id": snapshot.snapshot_id,
        "rule": "python.security.path-input", "file_path": "app/routes.py",
        "evidence_refs": [correct, "evidence:fake", correct],
    }})
    assert supported.result["matched_evidence_refs"] == [correct]
    assert supported.result["unresolved_evidence_refs"] == ["evidence:fake"]
    assert supported.result["duplicate_evidence_refs"] == [correct]
    assert supported.result["verdict"] == "INSUFFICIENT_EVIDENCE"

    unsupported = registry.invoke("verify_finding", {"claim": {
        "claim_type": "SECURITY_FINDING", "snapshot_id": snapshot.snapshot_id,
        "rule": "missing.rule", "file_path": "app/routes.py",
        "evidence_refs": ["foreign:finding"],
    }})
    assert unsupported.result["verdict"] == "UNSUPPORTED"
    assert unsupported.result["unresolved_evidence_refs"] == ["foreign:finding"]
    assert any(item.code == "EVIDENCE_REFERENCE_UNRESOLVED_OR_FOREIGN" for item in unsupported.warnings)


def test_evidence_accounting_detects_foreign_unrelated_insufficient_and_invalid_refs(tmp_path: Path):
    first = _snapshot(
        tmp_path / "first-evidence", "b" * 40,
        {"app/routes.py": "def route(value):\n    return open(value).read()\n"},
    )
    second = _snapshot(
        tmp_path / "second-evidence", "c" * 40,
        {"app/routes.py": "def route(value):\n    return open(value).read()\n"},
    )
    registry = create_agent_tool_registry(AgentToolContext(
        snapshots={first.snapshot_id: first, second.snapshot_id: second},
        default_snapshot_id=first.snapshot_id,
    ))
    first_ref = registry.invoke("scan_security", {"snapshot_id": first.snapshot_id}).evidence[0].evidence_id
    second_ref = registry.invoke("scan_security", {"snapshot_id": second.snapshot_id}).evidence[0].evidence_id
    foreign = registry.invoke("verify_finding", {"claim": {
        "claim_type": "SECURITY_FINDING", "snapshot_id": second.snapshot_id,
        "rule": "python.security.path-input", "file_path": "app/routes.py",
        "evidence_refs": [first_ref],
    }})
    assert foreign.result["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert foreign.result["matched_evidence_refs"] == []
    assert foreign.result["unresolved_evidence_refs"] == [first_ref]

    correct = registry.invoke("verify_finding", {"claim": {
        "claim_type": "SECURITY_FINDING", "snapshot_id": second.snapshot_id,
        "rule": "python.security.path-input", "file_path": "app/routes.py",
        "evidence_refs": [second_ref],
    }})
    assert correct.result["verdict"] == "SUPPORTED"
    assert correct.result["evidence_refs_complete"] is True

    invalid = registry.invoke("verify_finding", {"claim": {
        "claim_type": "SECURITY_FINDING", "snapshot_id": second.snapshot_id,
        "rule": "python.security.path-input", "file_path": "app/routes.py",
        "symbol_id": "symbol:not-registered", "evidence_refs": [second_ref],
    }})
    assert invalid.result["verdict"] == "INVALID_CLAIM"
    assert invalid.result["unresolved_evidence_refs"] == [second_ref]


def test_precomputed_change_context_requires_one_canonical_repository(tmp_path: Path):
    context, base, head = _change_context(tmp_path)
    diff = context.get_diff(base.snapshot_id, head.snapshot_id)
    foreign_head = _replace_repository(head, "https://github.com/other-owner/agent-tools")
    with pytest.raises(ValueError, match="repository"):
        AgentToolContext(
            snapshots={base.snapshot_id: base, foreign_head.snapshot_id: foreign_head},
            default_snapshot_id=foreign_head.snapshot_id,
            diffs={(base.snapshot_id, foreign_head.snapshot_id): diff},
        )

    other_repository_head = _replace_repository(head, "https://github.com/fixture/other-repository")
    with pytest.raises(ValueError, match="repository"):
        AgentToolContext(
            snapshots={base.snapshot_id: base, other_repository_head.snapshot_id: other_repository_head},
            default_snapshot_id=other_repository_head.snapshot_id,
            diffs={(base.snapshot_id, other_repository_head.snapshot_id): diff},
        )

    cosmetic_head = _replace_repository(head, "https://www.github.com/FIXTURE/AGENT-TOOLS.git/")
    AgentToolContext(
        snapshots={base.snapshot_id: base, cosmetic_head.snapshot_id: cosmetic_head},
        default_snapshot_id=cosmetic_head.snapshot_id,
        diffs={(base.snapshot_id, cosmetic_head.snapshot_id): diff},
    )

    foreign_diff = diff.model_copy(update={"repository_url": "https://github.com/other-owner/agent-tools"})
    with pytest.raises(ValueError, match="repository"):
        AgentToolContext(
            snapshots={base.snapshot_id: base, head.snapshot_id: head},
            default_snapshot_id=head.snapshot_id,
            diffs={(base.snapshot_id, head.snapshot_id): foreign_diff},
        )
    wrong_commit = diff.model_copy(update={"head_commit_sha": "f" * 40})
    with pytest.raises(ValueError, match="identity"):
        AgentToolContext(
            snapshots={base.snapshot_id: base, head.snapshot_id: head},
            default_snapshot_id=head.snapshot_id,
            diffs={(base.snapshot_id, head.snapshot_id): wrong_commit},
        )


def test_repeated_call_site_absence_is_not_overclaimed(tmp_path: Path):
    snapshot = _snapshot(
        tmp_path / "repeated-calls",
        "5" * 40,
        {"calls.py": "def target(value):\n    return value\n\ndef caller(value):\n    first = target(value)\n    return target(first)\n"},
    )
    registry = create_agent_tool_registry(AgentToolContext.from_snapshot(snapshot))
    target = _search_id(registry, "target")
    callers = registry.invoke("find_callers", {"symbol_id": target})
    assert callers.result["total_relationships"] == 1
    relationship = callers.result["relationships"][0]
    retained_line = relationship["evidence_line"]
    collapsed_line = 5 if retained_line == 6 else 6
    result = registry.invoke("verify_finding", {"claim": {
        "claim_type": "CALL_RELATIONSHIP",
        "snapshot_id": snapshot.snapshot_id,
        "source_symbol_id": relationship["source"]["entity_id"],
        "target_symbol_id": relationship["target"]["entity_id"],
        "relationship_type": "CALLS",
        "call_site_file": "calls.py",
        "call_site_line": collapsed_line,
        "evidence_refs": [callers.evidence[0].evidence_id],
    }})
    assert result.result["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert result.result["reason_code"] == "CALL_SITE_MULTIPLICITY_NOT_PRESERVED"

    retained = registry.invoke("verify_finding", {"claim": {
        "claim_type": "CALL_RELATIONSHIP",
        "snapshot_id": snapshot.snapshot_id,
        "source_symbol_id": relationship["source"]["entity_id"],
        "target_symbol_id": relationship["target"]["entity_id"],
        "relationship_type": "CALLS",
        "call_site_file": "calls.py",
        "call_site_line": retained_line,
        "evidence_refs": [callers.evidence[0].evidence_id],
    }})
    assert retained.result["verdict"] == "SUPPORTED"


def test_impact_symbol_scope_does_not_cross_same_named_methods(tmp_path: Path):
    base = _snapshot(tmp_path / "impact-base", "d" * 40, {
        "api.py": (
            "class A:\n"
            "    def same(self, value):\n"
            "        return value\n\n"
            "class B:\n"
            "    def same(self, value):\n"
            "        return value\n"
        ),
    })
    head = _snapshot(tmp_path / "impact-head", "e" * 40, {
        "api.py": (
            "class A:\n"
            "    def same(self, value, required):\n"
            "        return value\n\n"
            "class B:\n"
            "    def same(self, value):\n"
            "        return value\n"
        ),
    })
    changed_method = SymbolDiffFact(
        file_path="api.py", symbol_name="same", symbol_kind="METHOD",
        change_type=SymbolChangeType.SIGNATURE_CHANGED,
        base_location={"start_line": 2, "end_line": 3},
        head_location={"start_line": 2, "end_line": 3},
    )
    diff = StructuralDiffResult(
        base_commit_sha=base.snapshot_id,
        head_commit_sha=head.snapshot_id,
        repository_url=base.manifest.repository_url,
        changed_files=[FileDiffFact(file_path="api.py", change_type=FileChangeType.MODIFIED)],
        modified_files=["api.py"],
        changed_symbols=[changed_method],
        modified_symbols=[changed_method],
    )
    registry = create_agent_tool_registry(AgentToolContext(
        snapshots={base.snapshot_id: base, head.snapshot_id: head},
        default_snapshot_id=head.snapshot_id,
        diffs={(base.snapshot_id, head.snapshot_id): diff},
    ))
    unchanged_b = next(
        item["symbol_id"]
        for item in registry.invoke("search_symbol", {
            "snapshot_id": head.snapshot_id, "query": "same", "max_results": 10,
        }).result["matches"]
        if item["start_line"] == 6
    )
    result = registry.invoke("analyze_impact", {
        "base_snapshot_id": base.snapshot_id,
        "head_snapshot_id": head.snapshot_id,
        "changed_symbol_id": unchanged_b,
    })
    assert result.status.value == "NOT_FOUND"
    assert result.errors[0].code == "CHANGED_SYMBOL_NOT_FOUND"
