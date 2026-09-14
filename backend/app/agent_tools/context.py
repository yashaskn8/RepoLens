"""Immutable analysis-session context shared by all deterministic agent tools."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import time
from types import MappingProxyType
from typing import Iterable, Mapping

from app.analysis.store import EvidenceStore
from app.core.path_confinement import PathTraversalError, resolve_safe_path
from app.graph.builder import build_repository_graph
from app.graph.repository_graph import RepositoryGraph
from app.graph.schemas import NodeKind
from app.indexing.schemas import CodeChunk
from app.ingestion.schemas import ParsedSymbol, RepositoryManifest
from app.schemas.change_analysis import StructuralDiffResult
from app.semantics import SemanticProgram, build_semantic_program


def _confined_relative(root: Path, value: str) -> str:
    try:
        resolved = resolve_safe_path(root, value)
        normalized = resolved.relative_to(root).as_posix()
    except (PathTraversalError, ValueError) as exc:
        raise ValueError("analysis component contains a path outside the repository root") from exc
    if normalized in {"", "."}:
        raise ValueError("analysis component must reference a repository-relative file")
    return normalized


@dataclass(frozen=True, slots=True)
class ToolResourceLimits:
    max_file_size_bytes: int = 1_048_576
    max_files: int = 100_000
    max_results: int = 200
    max_graph_depth: int = 5
    max_dataflow_paths: int = 16
    max_flow_nodes: int = 256
    max_aliases: int = 64

    def __post_init__(self) -> None:
        if min(
            self.max_file_size_bytes,
            self.max_files,
            self.max_results,
            self.max_graph_depth,
            self.max_dataflow_paths,
            self.max_flow_nodes,
            self.max_aliases,
        ) < 1:
            raise ValueError("all agent tool resource limits must be positive")


@dataclass(frozen=True, slots=True)
class RepositorySnapshot:
    """Authorized, already-ingested repository snapshot; no mutation methods."""

    snapshot_id: str
    repository_root: Path
    manifest: RepositoryManifest
    evidence_store: EvidenceStore
    graph: RepositoryGraph | None = None
    semantic_program: SemanticProgram | None = None
    component_versions: Mapping[str, str] = field(default_factory=dict)
    symbol_index: Mapping[str, tuple[str, ParsedSymbol]] = field(default_factory=dict, repr=False)
    initialization_duration_ms: float = field(default=0.0, compare=False)

    @classmethod
    def create(
        cls,
        *,
        snapshot_id: str,
        repository_root: str | Path,
        evidence_store: EvidenceStore,
        graph: RepositoryGraph | None = None,
        chunks: Iterable[CodeChunk] | None = None,
        semantic_program: SemanticProgram | None = None,
        component_versions: Mapping[str, str] | None = None,
    ) -> "RepositorySnapshot":
        started = time.perf_counter()
        root = Path(repository_root).resolve()
        if not root.is_dir():
            raise ValueError("repository root does not exist or is not a directory")
        if not snapshot_id or not snapshot_id.strip():
            raise ValueError("snapshot_id is required")
        manifest = evidence_store.manifest
        if snapshot_id != (manifest.commit_sha or manifest.commit_hash):
            raise ValueError("snapshot_id must match the manifest commit identity")
        authorized_paths: set[str] = set()
        for entry in manifest.files:
            normalized = _confined_relative(root, entry.path)
            if normalized in authorized_paths:
                raise ValueError("repository manifest contains duplicate normalized file paths")
            authorized_paths.add(normalized)
        for result in evidence_store.scanner_results.values():
            for finding in result.findings:
                _confined_relative(root, finding.evidence.file_path)
        built_graph = graph if graph is not None else build_repository_graph(manifest, evidence_store)
        for node in built_graph.get_nodes():
            if node.file_path:
                _confined_relative(root, node.file_path)
        for edge in built_graph.get_edges():
            call_site_file = (edge.metadata or {}).get("call_site_file")
            if call_site_file:
                _confined_relative(root, str(call_site_file))
        chunk_values = tuple(chunks) if chunks is not None else None
        for chunk in chunk_values or ():
            normalized = _confined_relative(root, chunk.file_path)
            if normalized not in authorized_paths:
                raise ValueError("semantic chunk is not authorized by the repository manifest")
        program = semantic_program
        if program is None and chunk_values is not None:
            program = build_semantic_program(manifest, chunk_values)
        if program is not None:
            for field_name in SemanticProgram.model_fields:
                values = getattr(program, field_name)
                if isinstance(values, list):
                    for fact in values:
                        file_path = getattr(fact, "file_path", None)
                        if file_path:
                            normalized = _confined_relative(root, file_path)
                            if normalized not in authorized_paths:
                                raise ValueError("semantic fact is not authorized by the repository manifest")
        symbol_index: dict[str, tuple[str, ParsedSymbol]] = {}
        for entry in manifest.files:
            path = entry.path.replace("\\", "/")
            for symbol in entry.symbols:
                identity = f"symbol:{path}:{symbol.kind.value}:{symbol.name}:{symbol.start_line}"
                symbol_index[identity] = (path, symbol)
        return cls(
            snapshot_id=snapshot_id,
            repository_root=root,
            manifest=manifest,
            evidence_store=evidence_store,
            graph=built_graph,
            semantic_program=program,
            component_versions=MappingProxyType(dict(component_versions or {})),
            symbol_index=MappingProxyType(symbol_index),
            initialization_duration_ms=(time.perf_counter() - started) * 1000.0,
        )

    @property
    def manifest_complete(self) -> bool:
        scope = self.manifest.analysis_scope
        return bool(scope is None or not scope.truncated)

    @property
    def graph_complete(self) -> bool:
        if self.graph is None or not self.manifest_complete:
            return False
        file_nodes = self.graph.get_nodes_by_kind(NodeKind.FILE)
        return bool(file_nodes) and not any((node.metadata or {}).get("unresolved_calls") for node in file_nodes)

    def normalize_path(self, relative_path: str, *, require_manifest_entry: bool = False) -> str:
        """Validate traversal/symlink boundaries and return a normalized repo-relative path."""
        try:
            resolved = resolve_safe_path(self.repository_root, relative_path)
        except (PathTraversalError, ValueError) as exc:
            raise PathTraversalError("repository path is outside the authorized snapshot") from exc
        try:
            normalized = resolved.relative_to(self.repository_root).as_posix()
        except ValueError as exc:  # defense in depth around platform path behavior
            raise PathTraversalError("repository path is outside the authorized snapshot") from exc
        if normalized in {"", "."}:
            raise PathTraversalError("a repository file path is required")
        if require_manifest_entry and normalized not in {
            entry.path.replace("\\", "/") for entry in self.manifest.files
        }:
            raise FileNotFoundError(normalized)
        return normalized

    def symbol_records(self):
        """Yield manifest symbols with their containing file; no source reads."""
        for identity in sorted(self.symbol_index):
            yield self.symbol_index[identity]


@dataclass(frozen=True, slots=True)
class AgentToolContext:
    """Read-only collection of reusable snapshots and precomputed diffs."""

    snapshots: Mapping[str, RepositorySnapshot]
    default_snapshot_id: str
    diffs: Mapping[tuple[str, str], StructuralDiffResult] = field(default_factory=dict)
    limits: ToolResourceLimits = field(default_factory=ToolResourceLimits)

    def __post_init__(self) -> None:
        snapshots = MappingProxyType(dict(self.snapshots))
        diffs = MappingProxyType(dict(self.diffs))
        if not snapshots:
            raise ValueError("at least one repository snapshot is required")
        if self.default_snapshot_id not in snapshots:
            raise ValueError("default snapshot is not registered")
        for (base_id, head_id), diff in diffs.items():
            if base_id not in snapshots or head_id not in snapshots:
                raise ValueError("precomputed diff references an unregistered snapshot")
            if diff.base_commit_sha != base_id or diff.head_commit_sha != head_id:
                raise ValueError("precomputed diff identity does not match its registered snapshots")
            if diff.repository_url != snapshots[base_id].manifest.repository_url:
                raise ValueError("precomputed diff repository does not match its registered snapshots")
            paths = [
                *(item.file_path for item in diff.changed_files),
                *(item.old_path for item in diff.changed_files if item.old_path),
                *(item.file_path for item in diff.changed_symbols),
                *(item.manifest_file for item in diff.dependency_deltas),
                *(item.file_path for item in diff.config_deltas),
                *(item.file_path for item in diff.route_deltas),
                *(item.file_path for item in diff.schema_deltas),
            ]
            for value in paths:
                snapshots[head_id].normalize_path(value, require_manifest_entry=False)
        object.__setattr__(self, "snapshots", snapshots)
        object.__setattr__(self, "diffs", diffs)

    @classmethod
    def from_snapshot(
        cls,
        snapshot: RepositorySnapshot,
        *,
        limits: ToolResourceLimits | None = None,
    ) -> "AgentToolContext":
        return cls(
            snapshots={snapshot.snapshot_id: snapshot},
            default_snapshot_id=snapshot.snapshot_id,
            limits=limits or ToolResourceLimits(),
        )

    def get_snapshot(self, snapshot_id: str | None = None) -> RepositorySnapshot:
        key = snapshot_id or self.default_snapshot_id
        try:
            return self.snapshots[key]
        except KeyError as exc:
            raise KeyError("repository snapshot is not registered") from exc

    def get_diff(self, base_snapshot_id: str, head_snapshot_id: str) -> StructuralDiffResult | None:
        return self.diffs.get((base_snapshot_id, head_snapshot_id))


__all__ = ["AgentToolContext", "RepositorySnapshot", "ToolResourceLimits"]
