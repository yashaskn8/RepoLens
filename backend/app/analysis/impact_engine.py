"""Deterministic Graph-Aware Change Impact and Blast Radius Engine.

Given deterministic changed symbols, contracts, schemas, dependencies, and configs,
computes the bounded repository blast radius using RepoLens' canonical RepositoryGraph.

Guarantees:
- Deterministic-first (zero LLM reasoning or arbitrary percentages).
- Bounded traversal with depth limits, visited-node tracking, and maximum result bounds.
- Exact epistemic facts with evidence payloads for every impact.
- Deterministic severity classification and stable ordering.
"""

from collections import Counter, deque
from datetime import datetime, timezone
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import UUID, uuid4

from app.graph.repository_graph import RepositoryGraph
from app.graph.schemas import EdgeKind, NodeKind
from app.schemas.change_analysis import (
    BlastRadiusReport,
    ChangeImpact,
    ChangeImpactEvidence,
    ConfigDelta,
    DependencyDelta,
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

_SECURITY_KEYWORDS = {
    "auth",
    "token",
    "jwt",
    "password",
    "crypto",
    "permission",
    "security",
    "credential",
    "secret",
    "oauth",
    "apikey",
    "api_key",
}

_CRITICAL_CONFIG_KEYS = {
    "DATABASE_URL",
    "SECRET_KEY",
    "JWT_SECRET",
    "API_KEY",
    "AUTH_TOKEN",
    "ENCRYPTION_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "GITHUB_TOKEN",
}

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def _is_security_sensitive(file_path: Optional[str], symbol_name: Optional[str]) -> bool:
    """Deterministically check if file path or symbol name corresponds to security/auth logic."""
    target_str = f"{file_path or ''} {symbol_name or ''}".lower()
    return any(k in target_str for k in _SECURITY_KEYWORDS)


def _compute_risk_level(severities: List[Severity]) -> ChangeRiskLevel:
    """Compute aggregate risk rating from observed impact severities."""
    if Severity.CRITICAL in severities:
        return ChangeRiskLevel.CRITICAL
    if Severity.HIGH in severities:
        return ChangeRiskLevel.HIGH
    if Severity.MEDIUM in severities:
        return ChangeRiskLevel.MEDIUM
    return ChangeRiskLevel.LOW


class ChangeImpactEngine:
    """Deterministic blast radius computation engine operating on RepositoryGraph."""

    def __init__(self, default_max_depth: int = 3, default_max_impacts: int = 100):
        self.default_max_depth = default_max_depth
        self.default_max_impacts = default_max_impacts

    def compute_blast_radius(
        self,
        analysis_id: UUID,
        diff_result: StructuralDiffResult,
        base_graph: RepositoryGraph,
        head_graph: Optional[RepositoryGraph] = None,
        max_depth: Optional[int] = None,
        max_impacts: Optional[int] = None,
    ) -> BlastRadiusReport:
        """Trace deterministic blast radius across RepositoryGraph for all changed symbols & contracts."""
        depth_limit = max_depth if max_depth is not None else self.default_max_depth
        impacts_limit = max_impacts if max_impacts is not None else self.default_max_impacts

        impacts: List[ChangeImpact] = []
        is_truncated = False
        truncation_reason: Optional[str] = None
        max_depth_reached = 0

        # Build symbol lookup for base graph: (file_path, name) -> List[node_id]
        base_symbol_nodes: Dict[Tuple[str, str], List[str]] = {}
        for n in base_graph.get_nodes_by_kind(NodeKind.SYMBOL):
            if n.file_path:
                clean_f = n.file_path.replace("\\", "/")
                base_symbol_nodes.setdefault((clean_f, n.label), []).append(n.id)

        # ---------------------------------------------------------------------
        # 1. Trace Deleted Symbols & Direct / Transitive Callers
        # ---------------------------------------------------------------------
        for del_sym in diff_result.deleted_symbols:
            clean_f = del_sym.file_path.replace("\\", "/")
            matched_node_ids = base_symbol_nodes.get((clean_f, del_sym.symbol_name), [])

            # Also check if exact node ID exists
            if not matched_node_ids and del_sym.base_location:
                start_l = del_sym.base_location.get("start_line", 0)
                cand_id = f"symbol:{clean_f}:{del_sym.symbol_kind}:{del_sym.symbol_name}:{start_l}"
                if base_graph.get_node(cand_id):
                    matched_node_ids = [cand_id]

            for start_node_id in matched_node_ids:
                # Traverse upstream callers in base graph
                queue = deque([(start_node_id, 1, [start_node_id])])
                visited: Set[str] = {start_node_id}

                while queue:
                    curr_id, depth, path = queue.popleft()
                    max_depth_reached = max(max_depth_reached, depth)

                    if len(impacts) >= impacts_limit:
                        is_truncated = True
                        truncation_reason = "MAX_IMPACTS_REACHED"
                        break

                    incoming = base_graph.get_incoming_edges(curr_id)
                    for edge in incoming:
                        if edge.kind != EdgeKind.CALLS:
                            continue

                        caller_id = edge.source
                        caller_node = base_graph.get_node(caller_id)
                        if not caller_node:
                            continue

                        if caller_id in path:
                            # Cycle detected!
                            continue

                        is_security = _is_security_sensitive(del_sym.file_path, del_sym.symbol_name)
                        if depth == 1:
                            sev = Severity.CRITICAL if is_security else Severity.HIGH
                            title = f"Direct caller '{caller_node.label}' broken by deleted symbol '{del_sym.symbol_name}'"
                            desc = (
                                f"Direct caller '{caller_node.label}' in {caller_node.file_path} invokes "
                                f"'{del_sym.symbol_name}' which was deleted in the head revision."
                            )
                        else:
                            sev = Severity.MEDIUM if depth == 2 else Severity.LOW
                            title = f"Transitive caller '{caller_node.label}' affected by deleted symbol '{del_sym.symbol_name}' ({depth} hops)"
                            desc = (
                                f"Transitive caller '{caller_node.label}' at hop distance {depth} depends on "
                                f"'{del_sym.symbol_name}' which was deleted in the head revision."
                            )

                        impacts.append(
                            ChangeImpact(
                                id=uuid4(),
                                analysis_id=analysis_id,
                                impact_type=ChangeImpactType.CALLER_IMPACT,
                                severity=sev,
                                title=title,
                                description=desc,
                                source_file=del_sym.file_path,
                                source_symbol=del_sym.symbol_name,
                                affected_file=caller_node.file_path,
                                affected_symbol=caller_node.label,
                                evidence_payload={
                                    "edge_type": EdgeKind.CALLS.value,
                                    "depth": depth,
                                    "caller_file": caller_node.file_path,
                                    "caller_symbol": caller_node.label,
                                    "callee_file": del_sym.file_path,
                                    "callee_symbol": del_sym.symbol_name,
                                    "call_path": path + [caller_id],
                                    "change_type": del_sym.change_type.value,
                                },
                                confidence=1.0,
                                verification_status=ImpactVerificationStatus.FACT,
                                created_at=datetime.now(timezone.utc),
                            )
                        )

                        if caller_id not in visited:
                            visited.add(caller_id)
                            if depth < depth_limit:
                                queue.append((caller_id, depth + 1, path + [caller_id]))
                            else:
                                # Check if caller has further unvisited incoming callers
                                if any(e.kind == EdgeKind.CALLS and e.source not in path for e in base_graph.get_incoming_edges(caller_id)):
                                    is_truncated = True
                                    truncation_reason = "MAX_DEPTH_REACHED"


        # ---------------------------------------------------------------------
        # 2. Trace Signature-Changed Symbols & Direct / Transitive Callers
        # ---------------------------------------------------------------------
        for mod_sym in diff_result.modified_symbols:
            if mod_sym.change_type != SymbolChangeType.SIGNATURE_CHANGED:
                continue

            clean_f = mod_sym.file_path.replace("\\", "/")
            matched_node_ids = base_symbol_nodes.get((clean_f, mod_sym.symbol_name), [])

            for start_node_id in matched_node_ids:
                queue = deque([(start_node_id, 1, [start_node_id])])
                visited: Set[str] = {start_node_id}

                while queue:
                    curr_id, depth, path = queue.popleft()
                    max_depth_reached = max(max_depth_reached, depth)

                    if len(impacts) >= impacts_limit:
                        is_truncated = True
                        truncation_reason = "MAX_IMPACTS_REACHED"
                        break

                    incoming = base_graph.get_incoming_edges(curr_id)
                    for edge in incoming:
                        if edge.kind != EdgeKind.CALLS:
                            continue

                        caller_id = edge.source
                        caller_node = base_graph.get_node(caller_id)
                        if not caller_node:
                            continue

                        if caller_id in path:
                            continue

                        is_security = _is_security_sensitive(mod_sym.file_path, mod_sym.symbol_name)
                        if depth == 1:
                            sev = Severity.HIGH if is_security else Severity.MEDIUM
                            title = f"Direct caller '{caller_node.label}' affected by signature change in '{mod_sym.symbol_name}'"
                            desc = (
                                f"Direct caller '{caller_node.label}' in {caller_node.file_path} invokes "
                                f"'{mod_sym.symbol_name}' whose parameter list or return type changed: "
                                f"{mod_sym.evidence.get('diff', '')}"
                            )
                        else:
                            sev = Severity.LOW
                            title = f"Transitive caller '{caller_node.label}' affected by signature change in '{mod_sym.symbol_name}' ({depth} hops)"
                            desc = (
                                f"Transitive caller '{caller_node.label}' in {caller_node.file_path} at depth {depth} "
                                f"depends on '{mod_sym.symbol_name}'."
                            )

                        impacts.append(
                            ChangeImpact(
                                id=uuid4(),
                                analysis_id=analysis_id,
                                impact_type=ChangeImpactType.CALLER_IMPACT,
                                severity=sev,
                                title=title,
                                description=desc,
                                source_file=mod_sym.file_path,
                                source_symbol=mod_sym.symbol_name,
                                affected_file=caller_node.file_path,
                                affected_symbol=caller_node.label,
                                evidence_payload={
                                    "edge_type": EdgeKind.CALLS.value,
                                    "depth": depth,
                                    "caller_file": caller_node.file_path,
                                    "caller_symbol": caller_node.label,
                                    "callee_file": mod_sym.file_path,
                                    "callee_symbol": mod_sym.symbol_name,
                                    "call_path": path + [caller_id],
                                    "signature_diff": mod_sym.evidence.get("diff", ""),
                                },
                                confidence=1.0,
                                verification_status=ImpactVerificationStatus.FACT,
                                created_at=datetime.now(timezone.utc),
                            )
                        )

                        if caller_id not in visited:
                            visited.add(caller_id)
                            if depth < depth_limit:
                                queue.append((caller_id, depth + 1, path + [caller_id]))
                            else:
                                if any(e.kind == EdgeKind.CALLS and e.source not in path for e in base_graph.get_incoming_edges(caller_id)):
                                    is_truncated = True
                                    truncation_reason = "MAX_DEPTH_REACHED"


        # ---------------------------------------------------------------------
        # 3. Trace Route & Cross-Layer Frontend Contract Deltas
        # ---------------------------------------------------------------------
        # Pre-evaluate base contracts to locate frontend client requests referencing routes
        for route_delta in diff_result.route_deltas:
            is_breaking = route_delta.change_type in ("REMOVED", "PATH_CHANGED", "METHOD_CHANGED", "TARGET_CHANGED", "METHOD_AND_PATH_CHANGED")
            is_security = _is_security_sensitive(route_delta.file_path, route_delta.route_name)

            # Look up matching frontend requests in base graph
            affected_clients: List[Dict[str, Any]] = []
            if route_delta.base_path and route_delta.base_http_method:
                route_node_id = f"route:{route_delta.base_http_method}:{route_delta.base_path}"
                incoming_to_route = base_graph.get_incoming_edges(route_node_id)
                for edge in incoming_to_route:
                    if edge.kind == EdgeKind.MATCHES_ROUTE:
                        fe_req_node = base_graph.get_node(edge.source)
                        if fe_req_node:
                            affected_clients.append({
                                "file": fe_req_node.file_path,
                                "line": fe_req_node.start_line,
                                "label": fe_req_node.label,
                                "method": fe_req_node.metadata.get("http_method"),
                                "url": fe_req_node.metadata.get("url"),
                            })

            if affected_clients and is_breaking:
                for client in affected_clients:
                    sev = Severity.CRITICAL if is_security else Severity.HIGH
                    title = f"Frontend client broken by {route_delta.change_type} on '{route_delta.route_name}'"
                    desc = (
                        f"Frontend client in {client['file']}:{client['line']} invokes '{client['label']}' "
                        f"which is broken by backend contract change: {route_delta.details}"
                    )
                    impacts.append(
                        ChangeImpact(
                            id=uuid4(),
                            analysis_id=analysis_id,
                            impact_type=ChangeImpactType.API_CONTRACT_CHANGE,
                            severity=sev,
                            title=title,
                            description=desc,
                            source_file=route_delta.file_path,
                            source_symbol=route_delta.route_name,
                            affected_file=client["file"],
                            affected_symbol=client["label"],
                            evidence_payload={
                                "edge_type": EdgeKind.MATCHES_ROUTE.value,
                                "route_type": route_delta.route_type,
                                "change_type": route_delta.change_type,
                                "base_method": route_delta.base_http_method,
                                "head_method": route_delta.head_http_method,
                                "base_path": route_delta.base_path,
                                "head_path": route_delta.head_path,
                                "frontend_file": client["file"],
                                "frontend_line": client["line"],
                            },
                            confidence=1.0,
                            verification_status=ImpactVerificationStatus.FACT,
                            created_at=datetime.now(timezone.utc),
                        )
                    )
            else:
                sev = Severity.HIGH if (is_breaking and is_security) else (Severity.MEDIUM if is_breaking else Severity.LOW)
                title = f"API route definition changed: {route_delta.route_name}"
                desc = f"API route '{route_delta.route_name}' in {route_delta.file_path} underwent {route_delta.change_type}: {route_delta.details}"
                impacts.append(
                    ChangeImpact(
                        id=uuid4(),
                        analysis_id=analysis_id,
                        impact_type=ChangeImpactType.API_CONTRACT_CHANGE,
                        severity=sev,
                        title=title,
                        description=desc,
                        source_file=route_delta.file_path,
                        source_symbol=route_delta.route_name,
                        affected_file=route_delta.file_path,
                        affected_symbol=route_delta.route_name,
                        evidence_payload={
                            "route_type": route_delta.route_type,
                            "change_type": route_delta.change_type,
                            "base_method": route_delta.base_http_method,
                            "head_method": route_delta.head_http_method,
                            "base_path": route_delta.base_path,
                            "head_path": route_delta.head_path,
                            "details": route_delta.details,
                        },
                        confidence=1.0,
                        verification_status=ImpactVerificationStatus.FACT,
                        created_at=datetime.now(timezone.utc),
                    )
                )

        # ---------------------------------------------------------------------
        # 4. Trace Data Model and Schema Deltas
        # ---------------------------------------------------------------------
        for schema_delta in diff_result.schema_deltas:
            is_breaking = schema_delta.change_type in ("REMOVED_FIELD", "MODIFIED_TYPE")
            sev = Severity.HIGH if schema_delta.change_type == "REMOVED_FIELD" else (
                Severity.MEDIUM if schema_delta.change_type == "MODIFIED_TYPE" else Severity.LOW
            )

            # Find consumers/importing files of the schema model
            consumer_files: Set[str] = set()
            clean_schema_file = schema_delta.file_path.replace("\\", "/")
            schema_file_node_id = f"file:{clean_schema_file}"
            for edge in base_graph.get_incoming_edges(schema_file_node_id):
                if edge.kind == EdgeKind.IMPORTS:
                    importer_node = base_graph.get_node(edge.source)
                    if importer_node and importer_node.file_path:
                        consumer_files.add(importer_node.file_path)

            if consumer_files and is_breaking:
                for c_file in sorted(consumer_files):
                    title = f"Schema consumer '{c_file}' affected by {schema_delta.change_type} in '{schema_delta.model_name}'"
                    desc = (
                        f"File '{c_file}' imports '{clean_schema_file}' which altered field "
                        f"'{schema_delta.field_name}' in model '{schema_delta.model_name}': {schema_delta.details}"
                    )
                    impacts.append(
                        ChangeImpact(
                            id=uuid4(),
                            analysis_id=analysis_id,
                            impact_type=ChangeImpactType.SCHEMA_CHANGE,
                            severity=sev,
                            title=title,
                            description=desc,
                            source_file=schema_delta.file_path,
                            source_symbol=schema_delta.model_name,
                            affected_file=c_file,
                            affected_symbol=schema_delta.model_name,
                            evidence_payload={
                                "model_name": schema_delta.model_name,
                                "field_name": schema_delta.field_name,
                                "base_type": schema_delta.base_type,
                                "head_type": schema_delta.head_type,
                                "change_type": schema_delta.change_type,
                            },
                            confidence=1.0,
                            verification_status=ImpactVerificationStatus.FACT,
                            created_at=datetime.now(timezone.utc),
                        )
                    )
            else:
                title = f"Data model '{schema_delta.model_name}' field '{schema_delta.field_name}' changed"
                desc = f"Model '{schema_delta.model_name}' in {schema_delta.file_path}: {schema_delta.details}"
                impacts.append(
                    ChangeImpact(
                        id=uuid4(),
                        analysis_id=analysis_id,
                        impact_type=ChangeImpactType.SCHEMA_CHANGE,
                        severity=sev,
                        title=title,
                        description=desc,
                        source_file=schema_delta.file_path,
                        source_symbol=schema_delta.model_name,
                        affected_file=schema_delta.file_path,
                        affected_symbol=schema_delta.model_name,
                        evidence_payload={
                            "model_name": schema_delta.model_name,
                            "field_name": schema_delta.field_name,
                            "base_type": schema_delta.base_type,
                            "head_type": schema_delta.head_type,
                            "change_type": schema_delta.change_type,
                        },
                        confidence=1.0,
                        verification_status=ImpactVerificationStatus.FACT,
                        created_at=datetime.now(timezone.utc),
                    )
                )

        # ---------------------------------------------------------------------
        # 5. Trace Dependency Manifest Deltas
        # ---------------------------------------------------------------------
        for dep_delta in diff_result.dependency_deltas:
            sev = Severity.HIGH if dep_delta.change_type == "REMOVED" else (
                Severity.MEDIUM if dep_delta.change_type == "UPDATED" else Severity.LOW
            )
            title = f"Dependency '{dep_delta.package_name}' {dep_delta.change_type.lower()}"
            desc = (
                f"Package '{dep_delta.package_name}' in {dep_delta.manifest_file} was "
                f"{dep_delta.change_type.lower()} (Base: {dep_delta.base_version or 'none'}, "
                f"Head: {dep_delta.head_version or 'none'})."
            )
            impacts.append(
                ChangeImpact(
                    id=uuid4(),
                    analysis_id=analysis_id,
                    impact_type=ChangeImpactType.DEPENDENCY_CHANGE,
                    severity=sev,
                    title=title,
                    description=desc,
                    source_file=dep_delta.manifest_file,
                    source_symbol=dep_delta.package_name,
                    affected_file=dep_delta.manifest_file,
                    affected_symbol=dep_delta.package_name,
                    evidence_payload={
                        "manifest_file": dep_delta.manifest_file,
                        "package_name": dep_delta.package_name,
                        "base_version": dep_delta.base_version,
                        "head_version": dep_delta.head_version,
                        "change_type": dep_delta.change_type,
                    },
                    confidence=1.0,
                    verification_status=ImpactVerificationStatus.FACT,
                    created_at=datetime.now(timezone.utc),
                )
            )

        # ---------------------------------------------------------------------
        # 6. Trace Config & Environment Variable Deltas
        # ---------------------------------------------------------------------
        for config_delta in diff_result.config_deltas:
            is_critical = config_delta.key in _CRITICAL_CONFIG_KEYS or any(k in config_delta.key.lower() for k in _SECURITY_KEYWORDS)
            if is_critical and config_delta.change_type == "REMOVED":
                sev = Severity.HIGH
            elif config_delta.change_type in ("REMOVED", "MODIFIED"):
                sev = Severity.MEDIUM
            else:
                sev = Severity.LOW

            title = f"Configuration '{config_delta.key}' {config_delta.change_type.lower()}"
            desc = (
                f"Configuration key '{config_delta.key}' in {config_delta.file_path} was "
                f"{config_delta.change_type.lower()}."
            )
            impacts.append(
                ChangeImpact(
                    id=uuid4(),
                    analysis_id=analysis_id,
                    impact_type=ChangeImpactType.CONFIG_CHANGE,
                    severity=sev,
                    title=title,
                    description=desc,
                    source_file=config_delta.file_path,
                    source_symbol=config_delta.key,
                    affected_file=config_delta.file_path,
                    affected_symbol=config_delta.key,
                    evidence_payload={
                        "file_path": config_delta.file_path,
                        "key": config_delta.key,
                        "base_value": config_delta.base_value,
                        "head_value": config_delta.head_value,
                        "change_type": config_delta.change_type,
                    },
                    confidence=1.0,
                    verification_status=ImpactVerificationStatus.FACT,
                    created_at=datetime.now(timezone.utc),
                )
            )

        # ---------------------------------------------------------------------
        # 7. Deduplicate and Order Deterministically
        # ---------------------------------------------------------------------
        deduped: Dict[Tuple[str, str, str, str, str], ChangeImpact] = {}
        for imp in impacts:
            key = (
                imp.impact_type.value,
                imp.source_file or "",
                imp.source_symbol or "",
                imp.affected_file or "",
                imp.affected_symbol or "",
            )
            if key not in deduped:
                deduped[key] = imp
            else:
                existing = deduped[key]
                existing_depth = existing.evidence_payload.get("depth", 999) if isinstance(existing.evidence_payload, dict) else 999
                imp_depth = imp.evidence_payload.get("depth", 999) if isinstance(imp.evidence_payload, dict) else 999

                # Prefer higher severity first, then shorter depth
                if _SEVERITY_ORDER[imp.severity] < _SEVERITY_ORDER[existing.severity]:
                    deduped[key] = imp
                elif _SEVERITY_ORDER[imp.severity] == _SEVERITY_ORDER[existing.severity] and imp_depth < existing_depth:
                    deduped[key] = imp


        unique_impacts = list(deduped.values())

        # Sort deterministically
        def sort_key(imp: ChangeImpact):
            sev_prio = _SEVERITY_ORDER[imp.severity]
            depth_val = imp.evidence_payload.get("depth", 1) if isinstance(imp.evidence_payload, dict) else 1
            return (
                sev_prio,
                depth_val,
                imp.source_file or "",
                imp.affected_file or "",
                imp.title,
            )

        unique_impacts.sort(key=sort_key)

        # Enforce impacts limit if total exceeds bound
        if len(unique_impacts) > impacts_limit:
            unique_impacts = unique_impacts[:impacts_limit]
            is_truncated = True
            truncation_reason = "MAX_IMPACTS_REACHED"

        # Summary telemetry
        direct_count = sum(
            1 for i in unique_impacts
            if i.evidence_payload.get("depth", 1) == 1
        )
        transitive_count = len(unique_impacts) - direct_count

        summary_by_type = dict(Counter(i.impact_type.value for i in unique_impacts))
        summary_by_severity = dict(Counter(i.severity.value for i in unique_impacts))
        overall_risk = _compute_risk_level([i.severity for i in unique_impacts])

        return BlastRadiusReport(
            analysis_id=analysis_id,
            impacts=unique_impacts,
            total_impacts=len(unique_impacts),
            direct_impacts_count=direct_count,
            transitive_impacts_count=transitive_count,
            is_truncated=is_truncated,
            truncation_reason=truncation_reason,
            max_depth_reached=max_depth_reached,
            overall_risk_level=overall_risk,
            summary_by_type=summary_by_type,
            summary_by_severity=summary_by_severity,
        )


# Global singleton instance
_default_impact_engine: Optional[ChangeImpactEngine] = None


def get_impact_engine() -> ChangeImpactEngine:
    """Retrieve singleton ChangeImpactEngine."""
    global _default_impact_engine
    if _default_impact_engine is None:
        _default_impact_engine = ChangeImpactEngine()
    return _default_impact_engine
