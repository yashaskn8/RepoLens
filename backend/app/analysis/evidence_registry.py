"""Canonical Deterministic Evidence Registry for RepoLens Change Intelligence.

Builds and stores the authoritative, immutable universe of typed deterministic
evidence descriptors derived strictly from:
1. StructuralDiffResult (files, symbols, route deltas, schema deltas, dependency deltas, config deltas)
2. BlastRadiusReport (impact UUIDs, graph impact payloads)
3. RepositoryGraph (exact directional edges and symbol nodes)

Guarantees:
- Zero fuzzy aliases or substring matching.
- Exact literal equality on canonical evidence IDs.
- Complete provenance metadata on every registered evidence item.
"""

from dataclasses import dataclass, field
import logging
from typing import Any, Dict, List, Optional, Set
from uuid import UUID

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
from app.graph.repository_graph import RepositoryGraph
from app.graph.schemas import EdgeKind, NodeKind
from app.schemas.change_analysis import (
    BlastRadiusReport,
    ChangeImpact,
    ConfigDelta,
    DependencyDelta,
    FileDiffFact,
    RouteContractDelta,
    SchemaModelDelta,
    StructuralDiffResult,
    SymbolDiffFact,
)
from app.schemas.enums import ChangeImpactType, Severity

logger = logging.getLogger(__name__)


@dataclass
class EvidenceDescriptor:
    """Authoritative typed descriptor for a deterministic evidence fact."""

    evidence_id: str
    evidence_type: str  # FILE, SYMBOL, IMPACT, EDGE, CONFIG, DEPENDENCY, LINE, SCHEMA_DELTA, ROUTE_DELTA
    file_path: Optional[str] = None
    symbol_name: Optional[str] = None
    symbol_kind: Optional[str] = None
    symbol_start_line: Optional[int] = None
    impact_id: Optional[str] = None
    impact_type: Optional[ChangeImpactType] = None
    severity: Optional[Severity] = None
    edge_kind: Optional[str] = None
    edge_source: Optional[str] = None
    edge_target: Optional[str] = None
    change_type: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    source_object: Optional[Any] = None


class EvidenceRegistry:
    """Canonical Registry containing all verified deterministic evidence descriptors for an analysis."""

    def __init__(self):
        self._descriptors: Dict[str, EvidenceDescriptor] = {}
        self._known_files: Set[str] = set()
        self._known_symbols: Set[str] = set()
        self._symbols_by_file: Dict[str, Set[str]] = {}
        self._impacts_by_id: Dict[str, EvidenceDescriptor] = {}

    def register(self, descriptor: EvidenceDescriptor) -> None:
        """Register a canonical evidence descriptor into the registry."""
        self._descriptors[descriptor.evidence_id] = descriptor

        if descriptor.file_path:
            norm_f = normalize_path(descriptor.file_path)
            self._known_files.add(norm_f)
            if descriptor.symbol_name:
                if norm_f not in self._symbols_by_file:
                    self._symbols_by_file[norm_f] = set()
                self._symbols_by_file[norm_f].add(descriptor.symbol_name)

        if descriptor.symbol_name:
            self._known_symbols.add(descriptor.symbol_name)

        if descriptor.impact_id:
            self._impacts_by_id[descriptor.impact_id.lower()] = descriptor

    def get(self, evidence_id: str) -> Optional[EvidenceDescriptor]:
        """Look up an exact canonical evidence descriptor by ID (exact literal match only)."""
        return self._descriptors.get(evidence_id.strip())

    def contains_file(self, file_path: str) -> bool:
        """Check if file exists in the canonical universe."""
        return normalize_path(file_path) in self._known_files

    def contains_symbol(self, symbol_name: str, file_path: Optional[str] = None) -> bool:
        """Check if symbol exists globally or in a specific file."""
        if file_path:
            norm_f = normalize_path(file_path)
            return symbol_name in self._symbols_by_file.get(norm_f, set())
        return symbol_name in self._known_symbols

    def get_descriptors_for_file(self, file_path: str) -> List[EvidenceDescriptor]:
        """Retrieve all descriptors associated with a specific file."""
        norm_f = normalize_path(file_path)
        return [d for d in self._descriptors.values() if d.file_path and normalize_path(d.file_path) == norm_f]

    def get_descriptors_for_symbol(self, symbol_name: str, file_path: Optional[str] = None) -> List[EvidenceDescriptor]:
        """Retrieve all descriptors referencing a specific symbol (optionally bound to file)."""
        norm_f = normalize_path(file_path) if file_path else None
        matches = []
        for d in self._descriptors.values():
            if d.symbol_name == symbol_name:
                if norm_f is None or (d.file_path and normalize_path(d.file_path) == norm_f):
                    matches.append(d)
        return matches

    @property
    def all_descriptors(self) -> Dict[str, EvidenceDescriptor]:
        """Return shallow copy of all registered descriptors."""
        return dict(self._descriptors)

    @property
    def known_files(self) -> Set[str]:
        return set(self._known_files)

    @property
    def known_symbols(self) -> Set[str]:
        return set(self._known_symbols)


def build_evidence_registry(
    diff_result: StructuralDiffResult,
    blast_radius: Optional[BlastRadiusReport] = None,
    base_graph: Optional[RepositoryGraph] = None,
    head_graph: Optional[RepositoryGraph] = None,
    base_workspace: Optional[str] = None,
    head_workspace: Optional[str] = None,
) -> EvidenceRegistry:
    """Deterministically construct canonical EvidenceRegistry from all Phase 6 analysis artifacts."""
    registry = EvidenceRegistry()

    # 1. Register all Files
    all_files: Set[str] = set()
    for f in diff_result.changed_files:
        all_files.add(normalize_path(f.file_path))
        if f.old_path:
            all_files.add(normalize_path(f.old_path))
    for f in diff_result.added_files + diff_result.deleted_files + diff_result.modified_files:
        all_files.add(normalize_path(f))
    for ren in diff_result.renamed_files:
        for r in ren:
            all_files.add(normalize_path(r))
    for delta in diff_result.dependency_deltas:
        all_files.add(normalize_path(delta.manifest_file))
    for delta in diff_result.config_deltas:
        all_files.add(normalize_path(delta.file_path))
    for delta in diff_result.route_deltas:
        all_files.add(normalize_path(delta.file_path))
    for delta in diff_result.schema_deltas:
        all_files.add(normalize_path(delta.file_path))

    for g in (base_graph, head_graph):
        if g:
            for n in g.get_nodes():
                if n.file_path:
                    all_files.add(normalize_path(n.file_path))

    if blast_radius:
        for imp in blast_radius.impacts:
            if imp.source_file:
                all_files.add(normalize_path(imp.source_file))
            if imp.affected_file:
                all_files.add(normalize_path(imp.affected_file))

    for fp in sorted(all_files):
        ev_id = make_file_evidence_id(fp)
        registry.register(
            EvidenceDescriptor(
                evidence_id=ev_id,
                evidence_type="FILE",
                file_path=fp,
            )
        )

    # 2. Register Symbols from Structural Diff
    for s in (
        diff_result.changed_symbols
        + diff_result.added_symbols
        + diff_result.deleted_symbols
        + diff_result.modified_symbols
    ):
        norm_f = normalize_path(s.file_path)
        start_l = s.head_location.get("start_line") if s.head_location else (s.base_location.get("start_line") if s.base_location else 1)
        ev_id = make_symbol_evidence_id(norm_f, s.symbol_kind, s.symbol_name, start_l)
        registry.register(
            EvidenceDescriptor(
                evidence_id=ev_id,
                evidence_type="SYMBOL",
                file_path=norm_f,
                symbol_name=s.symbol_name,
                symbol_kind=s.symbol_kind,
                symbol_start_line=start_l,
                change_type=s.change_type,
                source_object=s,
            )
        )

    # 3. Register Symbols from Repository Graphs
    for g in (base_graph, head_graph):
        if g:
            for n in g.get_nodes():
                if n.file_path:
                    norm_f = normalize_path(n.file_path)
                    start_l = n.start_line if n.start_line is not None else 1
                    kind_str = n.kind.value.upper() if hasattr(n.kind, "value") else str(n.kind).upper()
                    ev_id = make_symbol_evidence_id(norm_f, kind_str, n.label, start_l)
                    registry.register(
                        EvidenceDescriptor(
                            evidence_id=ev_id,
                            evidence_type="SYMBOL",
                            file_path=norm_f,
                            symbol_name=n.label,
                            symbol_kind=kind_str,
                            symbol_start_line=start_l,
                            source_object=n,
                        )
                    )
                    # Also register exact node ID if matching canonical format
                    if n.id.startswith("symbol:"):
                        registry.register(
                            EvidenceDescriptor(
                                evidence_id=n.id,
                                evidence_type="SYMBOL",
                                file_path=norm_f,
                                symbol_name=n.label,
                                symbol_kind=kind_str,
                                symbol_start_line=start_l,
                                source_object=n,
                            )
                        )

    # 4. Register Route Deltas
    for r in diff_result.route_deltas:
        norm_f = normalize_path(r.file_path)
        ev_id = make_route_delta_evidence_id(
            norm_f,
            r.base_http_method,
            r.base_path,
            r.head_http_method,
            r.head_path,
        )
        registry.register(
            EvidenceDescriptor(
                evidence_id=ev_id,
                evidence_type="ROUTE_DELTA",
                file_path=norm_f,
                symbol_name=r.route_name,
                change_type=r.change_type,
                details={
                    "base_method": r.base_http_method,
                    "base_path": r.base_path,
                    "head_method": r.head_http_method,
                    "head_path": r.head_path,
                    "details": r.details,
                },
                source_object=r,
            )
        )
        # Register single route evidence for base and head if present
        if r.base_http_method and r.base_path:
            base_route_id = f"route:{r.base_http_method.upper()}:{r.base_path}"
            registry.register(
                EvidenceDescriptor(
                    evidence_id=base_route_id,
                    evidence_type="ROUTE_DELTA",
                    file_path=norm_f,
                    symbol_name=r.route_name,
                    change_type=r.change_type,
                    source_object=r,
                )
            )
        if r.head_http_method and r.head_path:
            head_route_id = f"route:{r.head_http_method.upper()}:{r.head_path}"
            registry.register(
                EvidenceDescriptor(
                    evidence_id=head_route_id,
                    evidence_type="ROUTE_DELTA",
                    file_path=norm_f,
                    symbol_name=r.route_name,
                    change_type=r.change_type,
                    source_object=r,
                )
            )

    # 5. Register Schema Deltas
    for s in diff_result.schema_deltas:
        norm_f = normalize_path(s.file_path)
        ev_id = make_schema_delta_evidence_id(norm_f, s.model_name, s.field_name, s.change_type)
        registry.register(
            EvidenceDescriptor(
                evidence_id=ev_id,
                evidence_type="SCHEMA_DELTA",
                file_path=norm_f,
                symbol_name=s.model_name,
                change_type=s.change_type,
                details={
                    "field_name": s.field_name,
                    "model_kind": s.model_kind,
                    "base_type": s.base_type,
                    "head_type": s.head_type,
                    "details": s.details,
                },
                source_object=s,
            )
        )

    # 6. Register Config Deltas
    for c in diff_result.config_deltas:
        norm_f = normalize_path(c.file_path)
        ev_id = make_config_evidence_id(norm_f, c.key)
        registry.register(
            EvidenceDescriptor(
                evidence_id=ev_id,
                evidence_type="CONFIG",
                file_path=norm_f,
                symbol_name=c.key,
                change_type=c.change_type,
                source_object=c,
            )
        )

    # 7. Register Dependency Deltas
    for d in diff_result.dependency_deltas:
        norm_f = normalize_path(d.manifest_file)
        ev_id = make_dependency_evidence_id(norm_f, d.package_name)
        registry.register(
            EvidenceDescriptor(
                evidence_id=ev_id,
                evidence_type="DEPENDENCY",
                file_path=norm_f,
                symbol_name=d.package_name,
                change_type=d.change_type,
                details={
                    "base_version": d.base_version,
                    "head_version": d.head_version,
                },
                source_object=d,
            )
        )

    # 8. Register Graph Edges (Exact Directional Wiring)
    for g in (base_graph, head_graph):
        if g:
            for e in g.get_edges():
                kind_str = e.kind.value.upper() if hasattr(e.kind, "value") else str(e.kind).upper()
                ev_id = make_edge_evidence_id(kind_str, e.source, e.target)
                registry.register(
                    EvidenceDescriptor(
                        evidence_id=ev_id,
                        evidence_type="EDGE",
                        edge_kind=kind_str,
                        edge_source=e.source,
                        edge_target=e.target,
                        source_object=e,
                    )
                )

    # 9. Register Blast Radius Impacts and Edge Payloads
    if blast_radius:
        for imp in blast_radius.impacts:
            imp_id_str = str(imp.id).lower()
            ev_id = make_impact_evidence_id(imp_id_str)
            registry.register(
                EvidenceDescriptor(
                    evidence_id=ev_id,
                    evidence_type="IMPACT",
                    impact_id=imp_id_str,
                    impact_type=imp.impact_type,
                    severity=imp.severity,
                    file_path=imp.affected_file or imp.source_file,
                    symbol_name=imp.affected_symbol or imp.source_symbol,
                    details=imp.evidence_payload or {},
                    source_object=imp,
                )
            )

            # Register exact edge if stored in impact payload
            payload = imp.evidence_payload or {}
            edge_type = payload.get("edge_type")
            c_node = payload.get("caller_node_id")
            t_node = payload.get("callee_node_id")
            if edge_type and c_node and t_node:
                edge_ev_id = make_edge_evidence_id(str(edge_type).upper(), str(c_node), str(t_node))
                registry.register(
                    EvidenceDescriptor(
                        evidence_id=edge_ev_id,
                        evidence_type="EDGE",
                        edge_kind=str(edge_type).upper(),
                        edge_source=str(c_node),
                        edge_target=str(t_node),
                        source_object=imp,
                    )
                )

    return registry
