"""Immutable analysis-session context shared by all deterministic agent tools."""

from __future__ import annotations

from dataclasses import dataclass, field
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import time
from types import MappingProxyType
from typing import Iterable, Mapping
from urllib.parse import urlparse

from app.analysis.store import EvidenceStore
from app.core.path_confinement import PathTraversalError, resolve_safe_path
from app.graph.builder import build_repository_graph
from app.graph.repository_graph import RepositoryGraph
from app.graph.schemas import GraphNode, NodeKind
from app.agent_tools.schemas import MAX_PUBLIC_PATH_LENGTH
from app.indexing.schemas import CodeChunk
from app.ingestion.schemas import ParsedSymbol, RepositoryManifest
from app.schemas.change_analysis import StructuralDiffResult
from app.semantics import SemanticProgram, build_semantic_program


_GITHUB_REPOSITORY_SEGMENT = re.compile(r"^[A-Za-z0-9_.-]+$")


def _is_filesystem_indirection(path: Path) -> bool:
    """Return whether *path* is a symlink or Windows junction/reparse directory."""
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction and is_junction())


def canonical_repository_identity(value: str) -> str:
    """Return a comparison-only GitHub identity without trusting cosmetic URL form."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("repository identity must be a non-empty GitHub HTTPS URL")
    parsed = urlparse(value.strip())
    if (
        parsed.scheme.lower() != "https"
        or (parsed.hostname or "").lower() not in {"github.com", "www.github.com"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("repository identity must be an uncredentialed GitHub HTTPS URL")
    parts = [part for part in parsed.path.rstrip("/").split("/") if part]
    if len(parts) != 2:
        raise ValueError("repository identity must contain exactly an owner and repository")
    owner, repository = parts
    if repository.lower().endswith(".git"):
        repository = repository[:-4]
    if not owner or not repository or not all(
        _GITHUB_REPOSITORY_SEGMENT.fullmatch(part) for part in (owner, repository)
    ):
        raise ValueError("repository identity contains an invalid owner or repository")
    return f"github.com/{owner.lower()}/{repository.lower()}"


def internal_symbol_identity(file_path: str, symbol: ParsedSymbol) -> str:
    """Return the frozen analyzer's exact manifest/graph symbol identity."""
    return f"symbol:{file_path}:{symbol.kind.value}:{symbol.name}:{symbol.start_line}"


def public_symbol_identity(
    repository_identity: str,
    snapshot_id: str,
    file_path: str,
    symbol: ParsedSymbol,
) -> str:
    """Return a bounded, snapshot-bound public identity for one exact manifest symbol."""
    material = json.dumps(
        {
            "repository": repository_identity,
            "snapshot": snapshot_id,
            "file": file_path,
            "kind": symbol.kind.value,
            "name": symbol.name,
            "start_line": symbol.start_line,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"symbol:{hashlib.sha256(material.encode('utf-8')).hexdigest()}"


def public_graph_entity_identity(
    repository_identity: str,
    snapshot_id: str,
    node: GraphNode,
) -> str:
    """Return a bounded, snapshot-bound public identity for one non-symbol graph node."""
    kind_value = node.kind.value if hasattr(node.kind, "value") else str(node.kind)
    material = json.dumps(
        {
            "internal_id": node.id,
            "kind": kind_value,
            "repository": repository_identity,
            "snapshot": snapshot_id,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"entity:{hashlib.sha256(material.encode('utf-8')).hexdigest()}"


def _confined_relative(root: Path, value: str) -> str:
    try:
        resolved = resolve_safe_path(root, value)
        normalized = resolved.relative_to(root).as_posix()
    except (PathTraversalError, ValueError) as exc:
        raise ValueError("analysis component contains a path outside the repository root") from exc
    if normalized in {"", "."}:
        raise ValueError("analysis component must reference a repository-relative file")
    return normalized


def _clone_graph(graph: RepositoryGraph) -> RepositoryGraph:
    cloned = RepositoryGraph()
    for node in sorted(graph.get_nodes(), key=lambda item: item.id):
        cloned.add_node(
            node.id,
            node.kind,
            node.label,
            file_path=node.file_path,
            start_line=node.start_line,
            end_line=node.end_line,
            metadata=copy.deepcopy(node.metadata),
        )
    for edge in sorted(graph.get_edges(), key=lambda item: (item.source, item.target, item.kind.value)):
        cloned.add_edge(edge.source, edge.target, edge.kind, copy.deepcopy(edge.metadata))
    return cloned


def _digest_payload(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _diff_digest(diff: StructuralDiffResult) -> str:
    return _digest_payload(diff.model_dump(mode="json"))


def _snapshot_artifact_payload(
    snapshot_id: str,
    manifest: RepositoryManifest,
    evidence_store: EvidenceStore,
    graph: RepositoryGraph | None,
    semantic_program: SemanticProgram | None,
    component_versions: Mapping[str, str],
) -> dict[str, object]:
    return {
        "snapshot_id": snapshot_id,
        "manifest": manifest.model_dump(mode="json"),
        "scanners": {
            name: result.model_dump(mode="json")
            for name, result in sorted(evidence_store.scanner_results.items())
        },
        "graph_nodes": [
            item.model_dump(mode="json")
            for item in sorted(graph.get_nodes(), key=lambda value: value.id)
        ] if graph is not None else [],
        "graph_edges": [
            item.model_dump(mode="json")
            for item in sorted(graph.get_edges(), key=lambda value: (value.source, value.target, value.kind.value))
        ] if graph is not None else [],
        "semantic_program": semantic_program.model_dump(mode="json") if semantic_program is not None else None,
        "component_versions": dict(sorted(component_versions.items())),
    }


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
    symbol_internal_ids: Mapping[str, str] = field(default_factory=dict, repr=False)
    public_symbol_ids: Mapping[str, str] = field(default_factory=dict, repr=False)
    graph_entity_internal_ids: Mapping[str, str] = field(default_factory=dict, repr=False)
    graph_entity_public_ids: Mapping[str, str] = field(default_factory=dict, repr=False)
    manifest_paths: frozenset[str] = field(default_factory=frozenset, repr=False)
    repository_identity: str = field(default="", repr=False)
    artifact_digest: str = field(default="", repr=False)
    admission_limits: ToolResourceLimits = field(default_factory=ToolResourceLimits, repr=False, compare=False)
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
        limits: ToolResourceLimits | None = None,
    ) -> "RepositorySnapshot":
        started = time.perf_counter()
        root = Path(repository_root).resolve()
        if not root.is_dir():
            raise ValueError("repository root does not exist or is not a directory")
        if not snapshot_id or not snapshot_id.strip():
            raise ValueError("snapshot_id is required")
        manifest = evidence_store.manifest.model_copy(deep=True)
        registration_limits = limits or ToolResourceLimits()
        if len(manifest.files) > registration_limits.max_files:
            raise ValueError("repository manifest exceeds the configured max_files limit")
        if any(
            entry.size_bytes > registration_limits.max_file_size_bytes and not entry.skipped_reason
            for entry in manifest.files
        ):
            raise ValueError("repository manifest contains an unbounded file larger than max_file_size_bytes")
        if snapshot_id != (manifest.commit_sha or manifest.commit_hash):
            raise ValueError("snapshot_id must match the manifest commit identity")
        repository_identity = canonical_repository_identity(manifest.repository_url)
        authorized_paths: set[str] = set()
        for entry in manifest.files:
            normalized = _confined_relative(root, entry.path)
            if len(normalized) > MAX_PUBLIC_PATH_LENGTH:
                raise ValueError("repository manifest path exceeds Phase-A public path limit")
            if normalized in authorized_paths:
                raise ValueError("repository manifest contains duplicate normalized file paths")
            authorized_paths.add(normalized)
        scanner_results = {
            str(name): result.model_copy(deep=True)
            for name, result in sorted(evidence_store.scanner_results.items())
        }
        frozen_store = EvidenceStore(manifest, scanner_results)
        for result in frozen_store.scanner_results.values():
            for finding in result.findings:
                normalized = _confined_relative(root, finding.evidence.file_path)
                if normalized not in authorized_paths:
                    raise ValueError("scanner finding is not authorized by the repository manifest")
        built_graph = _clone_graph(graph) if graph is not None else build_repository_graph(manifest, frozen_store)
        for node in built_graph.get_nodes():
            if node.file_path:
                normalized = _confined_relative(root, node.file_path)
                if normalized not in authorized_paths:
                    raise ValueError("graph node is not authorized by the repository manifest")
        for edge in built_graph.get_edges():
            call_site_file = (edge.metadata or {}).get("call_site_file")
            if call_site_file:
                normalized = _confined_relative(root, str(call_site_file))
                if normalized not in authorized_paths:
                    raise ValueError("graph call site is not authorized by the repository manifest")
        chunk_values = tuple(chunks) if chunks is not None else None
        for chunk in chunk_values or ():
            normalized = _confined_relative(root, chunk.file_path)
            if normalized not in authorized_paths:
                raise ValueError("semantic chunk is not authorized by the repository manifest")
        program = semantic_program.model_copy(deep=True) if semantic_program is not None else None
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
                        commit_sha = getattr(fact, "commit_sha", snapshot_id)
                        if commit_sha != snapshot_id:
                            raise ValueError("semantic fact snapshot identity does not match the repository snapshot")
        symbol_index: dict[str, tuple[str, ParsedSymbol]] = {}
        symbol_internal_ids: dict[str, str] = {}
        public_symbol_ids: dict[str, str] = {}
        for entry in manifest.files:
            path = entry.path.replace("\\", "/")
            for symbol in entry.symbols:
                internal_identity = internal_symbol_identity(path, symbol)
                public_identity = public_symbol_identity(
                    repository_identity,
                    snapshot_id,
                    path,
                    symbol,
                )
                if internal_identity in public_symbol_ids or public_identity in symbol_index:
                    raise ValueError("repository manifest contains a duplicate symbol identity")
                symbol_index[public_identity] = (path, symbol)
                symbol_internal_ids[public_identity] = internal_identity
                public_symbol_ids[internal_identity] = public_identity
        graph_entity_internal_ids: dict[str, str] = {}
        graph_entity_public_ids: dict[str, str] = {}
        if built_graph is not None:
            for node in sorted(built_graph.get_nodes(), key=lambda item: item.id):
                if node.id in public_symbol_ids:
                    pub_id = public_symbol_ids[node.id]
                else:
                    pub_id = public_graph_entity_identity(
                        repository_identity,
                        snapshot_id,
                        node,
                    )
                graph_entity_internal_ids[pub_id] = node.id
                graph_entity_public_ids[node.id] = pub_id
        versions = {str(key): str(value) for key, value in sorted((component_versions or {}).items())}
        artifact_payload = _snapshot_artifact_payload(
            snapshot_id, manifest, frozen_store, built_graph, program, versions
        )
        return cls(
            snapshot_id=snapshot_id,
            repository_root=root,
            manifest=manifest,
            evidence_store=frozen_store,
            graph=built_graph,
            semantic_program=program,
            component_versions=MappingProxyType(versions),
            symbol_index=MappingProxyType(symbol_index),
            symbol_internal_ids=MappingProxyType(symbol_internal_ids),
            public_symbol_ids=MappingProxyType(public_symbol_ids),
            graph_entity_internal_ids=MappingProxyType(graph_entity_internal_ids),
            graph_entity_public_ids=MappingProxyType(graph_entity_public_ids),
            manifest_paths=frozenset(authorized_paths),
            repository_identity=repository_identity,
            artifact_digest=_digest_payload(artifact_payload),
            admission_limits=registration_limits,
            initialization_duration_ms=(time.perf_counter() - started) * 1000.0,
        )

    def detached_copy(self) -> "RepositorySnapshot":
        """Copy all caller-owned mutable artifacts before registry registration."""
        return RepositorySnapshot.create(
            snapshot_id=self.snapshot_id,
            repository_root=self.repository_root,
            evidence_store=self.evidence_store,
            graph=self.graph,
            semantic_program=self.semantic_program,
            component_versions=self.component_versions,
            limits=self.admission_limits,
        )

    def integrity_valid(self) -> bool:
        return _digest_payload(_snapshot_artifact_payload(
            self.snapshot_id,
            self.manifest,
            self.evidence_store,
            self.graph,
            self.semantic_program,
            self.component_versions,
        )) == self.artifact_digest

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
        if len(normalized) > MAX_PUBLIC_PATH_LENGTH:
            raise ValueError("repository path exceeds Phase-A public path limit")
        if require_manifest_entry and normalized not in self.manifest_paths:
            raise FileNotFoundError(normalized)
        return normalized

    def assert_change_workspace_confined(self) -> None:
        """Fail closed if the materialized namespace contains an untrusted indirection.

        Change tools never read source contents, but this check prevents a caller from
        presenting a post-registration symlink/junction escape alongside a supposedly
        trusted precomputed diff. Directory indirections are never traversed.
        """
        root = self.repository_root.resolve(strict=True)
        pending = [root]
        inspected = 0
        max_entries = self.admission_limits.max_files * 2
        while pending:
            directory = pending.pop()
            try:
                entries = sorted(os.scandir(directory), key=lambda item: item.name)
            except OSError as exc:
                raise PathTraversalError("repository namespace cannot be verified") from exc
            for entry in entries:
                inspected += 1
                if inspected > max_entries:
                    raise PathTraversalError("repository namespace exceeds the verification limit")
                candidate = Path(entry.path)
                try:
                    if _is_filesystem_indirection(candidate):
                        resolved = candidate.resolve(strict=True)
                        resolved.relative_to(root)
                        relative_link = candidate.relative_to(root).as_posix()
                        if relative_link not in self.manifest_paths:
                            raise PathTraversalError(
                                "repository indirection is not authorized by the snapshot manifest"
                            )
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        pending.append(candidate)
                except (OSError, ValueError) as exc:
                    raise PathTraversalError(
                        "repository indirection escapes the authorized snapshot"
                    ) from exc

    def symbol_records(self):
        """Yield manifest symbols with their containing file; no source reads."""
        for identity in sorted(self.symbol_index):
            yield self.symbol_index[identity]

    def internal_symbol_id(self, public_id: str) -> str:
        try:
            return self.symbol_internal_ids[public_id]
        except KeyError as exc:
            raise KeyError("public symbol identity is not registered") from exc

    def public_symbol_id(self, internal_id: str) -> str | None:
        return self.public_symbol_ids.get(internal_id)

    def internal_graph_entity_id(self, public_id: str) -> str:
        try:
            return self.graph_entity_internal_ids[public_id]
        except KeyError as exc:
            raise KeyError("public graph entity identity is not registered") from exc

    def public_graph_entity_id(self, internal_id: str) -> str | None:
        return self.graph_entity_public_ids.get(internal_id)


@dataclass(frozen=True, slots=True)
class AgentToolContext:
    """Read-only collection of reusable snapshots and precomputed diffs."""

    snapshots: Mapping[str, RepositorySnapshot]
    default_snapshot_id: str
    diffs: Mapping[tuple[str, str], StructuralDiffResult] = field(default_factory=dict)
    limits: ToolResourceLimits = field(default_factory=ToolResourceLimits)
    diff_digests: Mapping[tuple[str, str], str] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        snapshots = MappingProxyType({
            key: snapshot.detached_copy() for key, snapshot in sorted(self.snapshots.items())
        })
        diff_values = {
            key: diff.model_copy(deep=True) for key, diff in sorted(self.diffs.items())
        }
        if not snapshots:
            raise ValueError("at least one repository snapshot is required")
        if any(key != snapshot.snapshot_id for key, snapshot in snapshots.items()):
            raise ValueError("snapshot registry key does not match snapshot identity")
        if self.default_snapshot_id not in snapshots:
            raise ValueError("default snapshot is not registered")
        for (base_id, head_id), diff in diff_values.items():
            if base_id not in snapshots or head_id not in snapshots:
                raise ValueError("precomputed diff references an unregistered snapshot")
            if diff.base_commit_sha != base_id or diff.head_commit_sha != head_id:
                raise ValueError("precomputed diff identity does not match its registered snapshots")
            base_repository = snapshots[base_id].repository_identity
            head_repository = snapshots[head_id].repository_identity
            diff_repository = canonical_repository_identity(diff.repository_url)
            if len({base_repository, head_repository, diff_repository}) != 1:
                raise ValueError("precomputed diff repository does not match its registered snapshots")
            base_paths = snapshots[base_id].manifest_paths
            head_paths = snapshots[head_id].manifest_paths

            def require(value: str, *, base: bool, head: bool) -> None:
                normalized = snapshots[head_id if head else base_id].normalize_path(
                    value, require_manifest_entry=False
                )
                if base and normalized not in base_paths:
                    raise ValueError("precomputed diff path is not authorized by the base manifest")
                if head and normalized not in head_paths:
                    raise ValueError("precomputed diff path is not authorized by the head manifest")

            for value in diff.added_files:
                require(value, base=False, head=True)
            for value in diff.deleted_files:
                require(value, base=True, head=False)
            for value in diff.modified_files:
                require(value, base=True, head=True)
            for pair in diff.renamed_files:
                if len(pair) != 2:
                    raise ValueError("renamed precomputed diff path must contain old and new paths")
                require(pair[0], base=True, head=False)
                require(pair[1], base=False, head=True)

            for item in diff.changed_files:
                kind = item.change_type.value
                if kind == "ADDED":
                    require(item.file_path, base=False, head=True)
                elif kind == "DELETED":
                    require(item.file_path, base=True, head=False)
                elif kind == "RENAMED":
                    if not item.old_path:
                        raise ValueError("renamed precomputed diff fact requires an old path")
                    require(item.old_path, base=True, head=False)
                    require(item.file_path, base=False, head=True)
                else:
                    require(item.file_path, base=True, head=True)
            for item in diff.changed_symbols:
                kind = item.change_type.value
                require(item.file_path, base=kind != "ADDED", head=kind != "DELETED")
            for collection, path_attr, change_attr in (
                (diff.dependency_deltas, "manifest_file", "change_type"),
                (diff.config_deltas, "file_path", "change_type"),
                (diff.route_deltas, "file_path", "change_type"),
                (diff.schema_deltas, "file_path", "change_type"),
            ):
                for item in collection:
                    kind = str(getattr(item, change_attr)).upper()
                    require(
                        str(getattr(item, path_attr)),
                        base=not kind.startswith("ADD"),
                        head=not (kind.startswith("REMOV") or kind.startswith("DELET")),
                    )
        diffs = MappingProxyType(diff_values)
        diff_digests = MappingProxyType({key: _diff_digest(value) for key, value in diff_values.items()})
        object.__setattr__(self, "snapshots", snapshots)
        object.__setattr__(self, "diffs", diffs)
        object.__setattr__(self, "diff_digests", diff_digests)

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
        key = (base_snapshot_id, head_snapshot_id)
        value = self.diffs.get(key)
        if value is not None and _diff_digest(value) != self.diff_digests[key]:
            raise ValueError("registered precomputed diff integrity check failed")
        return value


__all__ = [
    "AgentToolContext",
    "MAX_PUBLIC_PATH_LENGTH",
    "RepositorySnapshot",
    "ToolResourceLimits",
    "canonical_repository_identity",
    "internal_symbol_identity",
    "public_graph_entity_identity",
    "public_symbol_identity",
]
