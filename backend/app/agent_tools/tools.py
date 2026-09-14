"""Thin adapters from the public agent-tool contract to frozen RepoLens services."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable
from uuid import NAMESPACE_URL, uuid5

from pydantic import BaseModel

from app.agent_tools.context import AgentToolContext, RepositorySnapshot
from app.agent_tools.schemas import (
    AnalyzeChangeInput,
    AnalyzeChangeOutput,
    AnalyzeImpactInput,
    AnalyzeImpactOutput,
    ClaimType,
    DataflowEdge,
    DataflowEndpoint,
    DataflowPath,
    DataflowSupportingFact,
    EvidenceRecord,
    EvidenceType,
    FileInspectionOutput,
    FlowOutcome,
    GraphEntityRecord,
    GraphRelationship,
    ImpactRecord,
    InspectFileInput,
    InspectSymbolInput,
    ProposedFinding,
    RelationshipInput,
    RelationshipOutput,
    ScanSecurityInput,
    SearchMode,
    SearchSymbolInput,
    SecurityFindingRecord,
    SecurityScanOutput,
    SymbolInspectionOutput,
    SymbolRecord,
    SymbolSearchOutput,
    ToolError,
    ToolProvenance,
    ToolResultStatus,
    TraceDataflowInput,
    TraceDataflowOutput,
    VerificationVerdict,
    VerifyFindingInput,
    VerifyFindingOutput,
)
from app.analysis.diff_engine import get_diff_engine
from app.analysis.impact_engine import get_impact_engine
from app.core.path_confinement import PathTraversalError
from app.graph.schemas import EdgeKind, GraphEdge, GraphNode, NodeKind
from app.ingestion.schemas import ParsedSymbol, SymbolKind
from app.schemas.change_analysis import StructuralDiffResult, SymbolChangeType
from app.schemas.static_finding import ToolStatus
from app.security.redaction import redact_secrets
from app.semantics import FlowLimits, SemanticFlow, analyze_security_flows


@dataclass(frozen=True, slots=True)
class ToolExecution:
    status: ToolResultStatus
    output: BaseModel | None
    snapshot: RepositorySnapshot | None
    components: tuple[str, ...]
    stage: str
    evidence: tuple[EvidenceRecord, ...] = ()
    warnings: tuple[ToolError, ...] = ()


class ToolFailure(Exception):
    def __init__(self, status: ToolResultStatus, code: str, message: str, **details: Any):
        super().__init__(message)
        self.status = status
        self.error = ToolError(code=code, message=message, details=details)


def _snapshot(context: AgentToolContext, snapshot_id: str | None) -> RepositorySnapshot:
    try:
        return context.get_snapshot(snapshot_id)
    except KeyError as exc:
        raise ToolFailure(
            ToolResultStatus.NOT_FOUND,
            "SNAPSHOT_NOT_FOUND",
            "The requested repository snapshot is not registered.",
        ) from exc


def _normalize_path(snapshot: RepositorySnapshot, path: str, *, require_entry: bool = True) -> str:
    try:
        return snapshot.normalize_path(path, require_manifest_entry=require_entry)
    except PathTraversalError as exc:
        raise ToolFailure(
            ToolResultStatus.INVALID_INPUT,
            "PATH_OUTSIDE_REPOSITORY",
            "The supplied path is outside the authorized repository snapshot.",
        ) from exc
    except FileNotFoundError as exc:
        raise ToolFailure(
            ToolResultStatus.NOT_FOUND,
            "FILE_NOT_FOUND",
            "The supplied file is not present in the repository manifest.",
        ) from exc


def _json(value: Any, depth: int = 0) -> Any:
    if depth > 6:
        return "[truncated: max depth exceeded]"
    if isinstance(value, BaseModel):
        return _json(value.model_dump(mode="json"), depth + 1)
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda pair: str(pair[0]))
        result = {str(key): _json(item, depth + 1) for key, item in items[:100]}
        if len(items) > 100:
            result["_truncated"] = True
        return result
    if isinstance(value, (list, tuple)):
        items = [_json(item, depth + 1) for item in value[:100]]
        if len(value) > 100:
            items.append("[truncated: max items exceeded]")
        return items
    if isinstance(value, set):
        return [_json(item, depth + 1) for item in sorted(value, key=str)[:100]]
    if isinstance(value, str):
        cleaned = redact_secrets(value)
        return cleaned if len(cleaned) <= 2_048 else f"{cleaned[:2_048]}...[truncated]"
    return value


def _symbol_id(file_path: str, symbol: ParsedSymbol) -> str:
    return f"symbol:{file_path}:{symbol.kind.value}:{symbol.name}:{symbol.start_line}"


def _symbol_record(file_path: str, symbol: ParsedSymbol) -> SymbolRecord:
    details = _json(symbol.details)
    signature = details.get("parameters")
    return SymbolRecord(
        symbol_id=_symbol_id(file_path, symbol),
        qualified_name=f"{file_path}::{symbol.name}",
        name=symbol.name,
        kind=symbol.kind,
        file_path=file_path,
        start_line=symbol.start_line,
        end_line=symbol.end_line,
        start_column=symbol.start_column,
        end_column=symbol.end_column,
        signature=str(signature) if signature not in (None, "") else None,
        return_type=str(details.get("return_type")) if details.get("return_type") not in (None, "") else None,
        details=details,
    )


def _all_symbols(snapshot: RepositorySnapshot) -> list[SymbolRecord]:
    records = [_symbol_record(path, symbol) for path, symbol in snapshot.symbol_records()]
    return sorted(records, key=lambda item: (item.file_path, item.start_line, item.kind.value, item.name))


def _find_symbol(snapshot: RepositorySnapshot, symbol_id: str) -> SymbolRecord:
    found = snapshot.symbol_index.get(symbol_id)
    if found is None:
        raise ToolFailure(
            ToolResultStatus.NOT_FOUND,
            "SYMBOL_NOT_FOUND",
            "No symbol matched the supplied stable symbol identity.",
        )
    return _symbol_record(*found)


def _entity(node: GraphNode) -> GraphEntityRecord:
    return GraphEntityRecord(
        entity_id=node.id,
        kind=node.kind.value,
        label=node.label,
        file_path=node.file_path,
        start_line=node.start_line,
        end_line=node.end_line,
        metadata=_json(node.metadata),
    )


def _relationship(snapshot: RepositorySnapshot, edge: GraphEdge) -> GraphRelationship | None:
    if snapshot.graph is None:
        return None
    source = snapshot.graph.get_node(edge.source)
    target = snapshot.graph.get_node(edge.target)
    if source is None or target is None:
        return None
    metadata = _json(edge.metadata)
    return GraphRelationship(
        relationship=edge.kind.value,
        source=_entity(source),
        target=_entity(target),
        evidence_file=metadata.get("call_site_file") or source.file_path,
        evidence_line=metadata.get("call_site_line") or source.start_line,
        metadata=metadata,
    )


def _location_evidence(
    snapshot: RepositorySnapshot,
    *,
    component: str,
    evidence_type: EvidenceType,
    file_path: str,
    start_line: int | None,
    end_line: int | None,
    symbol: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> EvidenceRecord:
    material = "\0".join(
        [snapshot.snapshot_id, component, file_path, str(start_line or ""), str(end_line or ""), symbol or ""]
    )
    return EvidenceRecord(
        evidence_id=f"evidence:{hashlib.sha256(material.encode()).hexdigest()[:24]}",
        evidence_type=evidence_type,
        source_component=component,
        file_path=file_path,
        symbol=symbol,
        start_line=start_line,
        end_line=end_line,
        metadata=_json(metadata or {}),
    )


def _edge_evidence(snapshot: RepositorySnapshot, relationship: GraphRelationship) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=f"edge:{relationship.relationship}:{relationship.source.entity_id}->{relationship.target.entity_id}",
        evidence_type=(
            EvidenceType.CALL_RELATIONSHIP
            if relationship.relationship == EdgeKind.CALLS.value
            else EvidenceType.GRAPH_EDGE
        ),
        source_component="repository_graph",
        file_path=relationship.evidence_file,
        start_line=relationship.evidence_line,
        end_line=relationship.evidence_line,
        relationship=relationship.relationship,
        source_id=relationship.source.entity_id,
        target_id=relationship.target.entity_id,
        metadata={"repository_snapshot": snapshot.snapshot_id},
    )


def _warning(code: str, message: str, **details: Any) -> ToolError:
    return ToolError(code=code, message=message, details=details)


def inspect_file(arguments: InspectFileInput, context: AgentToolContext) -> ToolExecution:
    snapshot = _snapshot(context, arguments.snapshot_id)
    path = _normalize_path(snapshot, arguments.file_path)
    entry = snapshot.evidence_store.get_file_entry(path)
    if entry is None:
        raise ToolFailure(ToolResultStatus.NOT_FOUND, "FILE_NOT_FOUND", "File is not present in the manifest.")
    records = sorted(
        (_symbol_record(path, symbol) for symbol in entry.symbols),
        key=lambda item: (item.start_line, item.kind.value, item.name),
    )
    evidence = tuple(
        _location_evidence(
            snapshot,
            component="repository_manifest",
            evidence_type=EvidenceType.AST_FACT,
            file_path=path,
            start_line=record.start_line,
            end_line=record.end_line,
            symbol=record.symbol_id,
        )
        for record in records
    )
    warnings = ()
    if entry.skipped_reason:
        warnings = (_warning("FILE_NOT_PARSED", "The manifest records this file as unparsed.", reason=entry.skipped_reason),)
    return ToolExecution(
        status=ToolResultStatus.SUCCESS,
        output=FileInspectionOutput(
            file_path=path,
            language=entry.language,
            size_bytes=entry.size_bytes,
            lines_count=entry.lines_count,
            is_binary=entry.is_binary,
            skipped_reason=entry.skipped_reason,
            symbols=records,
            imports=[item for item in records if item.kind == SymbolKind.IMPORT],
            manifest_scope_complete=snapshot.manifest_complete,
        ),
        snapshot=snapshot,
        components=("repository_manifest", "tree_sitter_parser"),
        stage="file_inspection",
        evidence=evidence,
        warnings=warnings,
    )


def search_symbol(arguments: SearchSymbolInput, context: AgentToolContext) -> ToolExecution:
    snapshot = _snapshot(context, arguments.snapshot_id)
    if len(snapshot.manifest.files) > context.limits.max_files:
        raise ToolFailure(
            ToolResultStatus.RESOURCE_LIMIT,
            "FILE_SCOPE_LIMIT_REACHED",
            "Symbol search cannot exhaustively inspect this snapshot within the configured file limit.",
            observed_files=len(snapshot.manifest.files),
            max_files=context.limits.max_files,
        )
    scope = _normalize_path(snapshot, arguments.file_path) if arguments.file_path else None
    query = arguments.query

    def matches(name: str) -> bool:
        if arguments.match_mode == SearchMode.EXACT:
            return name == query
        if arguments.match_mode == SearchMode.PREFIX:
            return name.startswith(query)
        return query in name

    found = [
        record for record in _all_symbols(snapshot)
        if (scope is None or record.file_path == scope)
        and (arguments.kind is None or record.kind == arguments.kind)
        and matches(record.name)
    ]
    effective = min(arguments.max_results, context.limits.max_results)
    returned = found[:effective]
    truncated = len(found) > effective
    status = ToolResultStatus.RESOURCE_LIMIT if truncated else (
        ToolResultStatus.NOT_FOUND if not found else ToolResultStatus.SUCCESS
    )
    evidence = tuple(
        _location_evidence(
            snapshot,
            component="repository_manifest",
            evidence_type=EvidenceType.AST_FACT,
            file_path=item.file_path,
            start_line=item.start_line,
            end_line=item.end_line,
            symbol=item.symbol_id,
        ) for item in returned
    )
    return ToolExecution(
        status=status,
        output=SymbolSearchOutput(
            query=query,
            match_mode=arguments.match_mode,
            matches=returned,
            total_matches=len(found),
            returned_matches=len(returned),
            truncated=truncated,
        ),
        snapshot=snapshot,
        components=("repository_manifest", "tree_sitter_parser"),
        stage="symbol_search",
        evidence=evidence,
        warnings=(
            (_warning("RESULT_LIMIT_REACHED", "Symbol results were truncated.", limit=effective),)
            if truncated else ()
        ),
    )


def inspect_symbol(arguments: InspectSymbolInput, context: AgentToolContext) -> ToolExecution:
    snapshot = _snapshot(context, arguments.snapshot_id)
    symbol = _find_symbol(snapshot, arguments.symbol_id)
    parents = [
        candidate for candidate in _all_symbols(snapshot)
        if candidate.file_path == symbol.file_path
        and candidate.kind == SymbolKind.CLASS
        and candidate.symbol_id != symbol.symbol_id
        and candidate.start_line <= symbol.start_line
        and candidate.end_line >= symbol.end_line
    ]
    parents.sort(key=lambda item: (item.end_line - item.start_line, item.start_line, item.symbol_id))
    incoming: list[GraphRelationship] = []
    outgoing: list[GraphRelationship] = []
    if snapshot.graph is not None and snapshot.graph.get_node(symbol.symbol_id) is not None:
        incoming = [item for edge in snapshot.graph.get_incoming_edges(symbol.symbol_id) if (item := _relationship(snapshot, edge))]
        outgoing = [item for edge in snapshot.graph.get_outgoing_edges(symbol.symbol_id) if (item := _relationship(snapshot, edge))]
    incoming.sort(key=lambda item: (item.relationship, item.source.entity_id, item.target.entity_id))
    outgoing.sort(key=lambda item: (item.relationship, item.source.entity_id, item.target.entity_id))
    relationships = [*incoming, *outgoing]
    evidence = [
        _location_evidence(
            snapshot,
            component="repository_manifest",
            evidence_type=EvidenceType.AST_FACT,
            file_path=symbol.file_path,
            start_line=symbol.start_line,
            end_line=symbol.end_line,
            symbol=symbol.symbol_id,
        )
    ]
    evidence.extend(_edge_evidence(snapshot, item) for item in relationships)
    warnings = () if snapshot.graph is not None else (
        _warning("GRAPH_UNAVAILABLE", "Call and dependency relationships were not available."),
    )
    return ToolExecution(
        status=ToolResultStatus.SUCCESS,
        output=SymbolInspectionOutput(
            symbol=symbol,
            parents=parents,
            incoming=incoming,
            outgoing=outgoing,
            graph_complete=snapshot.graph_complete,
        ),
        snapshot=snapshot,
        components=("repository_manifest", "repository_graph"),
        stage="symbol_inspection",
        evidence=tuple(evidence),
        warnings=warnings,
    )


def _find_relationships(
    arguments: RelationshipInput,
    context: AgentToolContext,
    *,
    incoming: bool,
) -> ToolExecution:
    snapshot = _snapshot(context, arguments.snapshot_id)
    symbol = _find_symbol(snapshot, arguments.symbol_id)
    if snapshot.graph is None:
        raise ToolFailure(
            ToolResultStatus.INSUFFICIENT_EVIDENCE,
            "GRAPH_UNAVAILABLE",
            "The repository graph is unavailable for this snapshot.",
        )
    if snapshot.graph.get_node(symbol.symbol_id) is None:
        raise ToolFailure(
            ToolResultStatus.INSUFFICIENT_EVIDENCE,
            "SYMBOL_NOT_INDEXED_IN_GRAPH",
            "The symbol exists in the manifest but has no graph identity.",
        )
    edges = snapshot.graph.get_incoming_edges(symbol.symbol_id) if incoming else snapshot.graph.get_outgoing_edges(symbol.symbol_id)
    relationships = [
        relationship for edge in edges
        if edge.kind == EdgeKind.CALLS and (relationship := _relationship(snapshot, edge)) is not None
    ]
    relationships.sort(key=lambda item: (item.source.entity_id, item.target.entity_id, item.evidence_line or 0))
    effective = min(arguments.max_results, context.limits.max_results)
    returned = relationships[:effective]
    truncated = len(relationships) > effective
    if truncated:
        status = ToolResultStatus.RESOURCE_LIMIT
    elif relationships:
        status = ToolResultStatus.SUCCESS
    elif snapshot.graph_complete:
        status = ToolResultStatus.SUCCESS
    else:
        status = ToolResultStatus.INSUFFICIENT_EVIDENCE
    return ToolExecution(
        status=status,
        output=RelationshipOutput(
            symbol=symbol,
            relationships=returned,
            total_relationships=len(relationships),
            returned_relationships=len(returned),
            graph_complete=snapshot.graph_complete,
            truncated=truncated,
        ),
        snapshot=snapshot,
        components=("repository_graph",),
        stage="caller_lookup" if incoming else "callee_lookup",
        evidence=tuple(_edge_evidence(snapshot, item) for item in returned),
        warnings=(
            (_warning("GRAPH_PARTIAL", "Unresolved graph relationships may hide additional calls."),)
            if not snapshot.graph_complete else ()
        ),
    )


def find_callers(arguments: RelationshipInput, context: AgentToolContext) -> ToolExecution:
    return _find_relationships(arguments, context, incoming=True)


def find_callees(arguments: RelationshipInput, context: AgentToolContext) -> ToolExecution:
    return _find_relationships(arguments, context, incoming=False)


def _endpoint(fact, kind: str) -> DataflowEndpoint:
    return DataflowEndpoint(
        fact_id=fact.fact_id,
        kind=kind,
        name=fact.name,
        file_path=fact.file_path,
        symbol=fact.symbol,
        start_line=fact.start_line,
        end_line=fact.end_line,
        certainty=fact.certainty.value,
    )


def _supporting_fact(fact, kind: str) -> DataflowSupportingFact:
    return DataflowSupportingFact(
        fact_id=fact.fact_id,
        kind=kind,
        name=getattr(fact, "name", getattr(fact, "expression", kind)),
        file_path=fact.file_path,
        symbol=fact.symbol,
        start_line=fact.start_line,
        end_line=fact.end_line,
    )


def _flow_path(flow: SemanticFlow) -> DataflowPath:
    opaque = sorted(item for item in flow.transformations if item.startswith("OPAQUE_CALL:"))
    return DataflowPath(
        source=_endpoint(flow.source, flow.source.source_kind),
        sink=_endpoint(flow.sink, flow.sink.sink_kind),
        transformations=list(flow.transformations),
        sanitizers=[_supporting_fact(item, item.sanitizer_kind) for item in flow.sanitizers],
        guards=[_supporting_fact(item, item.guard_kind) for item in flow.guards],
        edges=[DataflowEdge(**edge.model_dump(mode="json")) for edge in flow.edges],
        opaque_calls=opaque,
        certainty=flow.certainty.value,
        evidence_refs=sorted(flow.evidence_refs),
        call_depth=flow.call_depth,
    )


def _flow_evidence(snapshot: RepositorySnapshot, path: DataflowPath) -> EvidenceRecord:
    material = "\0".join([
        snapshot.snapshot_id,
        path.source.fact_id,
        path.sink.fact_id,
        *path.evidence_refs,
    ])
    return EvidenceRecord(
        evidence_id=f"flow:{hashlib.sha256(material.encode()).hexdigest()[:24]}",
        evidence_type=EvidenceType.DATAFLOW_PATH,
        source_component="semantic_flow_analysis",
        file_path=path.sink.file_path,
        symbol=path.source.symbol,
        start_line=path.source.start_line,
        end_line=path.sink.end_line,
        relationship=f"{path.source.kind}->{path.sink.kind}",
        source_id=path.source.fact_id,
        target_id=path.sink.fact_id,
        metadata={"certainty": path.certainty, "opaque_calls": path.opaque_calls},
    )


def trace_dataflow(arguments: TraceDataflowInput, context: AgentToolContext) -> ToolExecution:
    snapshot = _snapshot(context, arguments.snapshot_id)
    source_symbol = _find_symbol(snapshot, arguments.source_symbol_id)
    if snapshot.semantic_program is None:
        raise ToolFailure(
            ToolResultStatus.INSUFFICIENT_EVIDENCE,
            "SEMANTIC_PROGRAM_UNAVAILABLE",
            "No production semantic program is registered for this snapshot.",
        )
    depth = min(arguments.max_depth, context.limits.max_graph_depth)
    path_limit = min(arguments.max_paths, context.limits.max_dataflow_paths)
    raw = analyze_security_flows(
        snapshot.semantic_program,
        limits=FlowLimits(
            max_call_depth=depth,
            max_paths=path_limit,
            max_flow_nodes=context.limits.max_flow_nodes,
            max_aliases=context.limits.max_aliases,
        ),
    )
    semantic_symbol = f"{source_symbol.file_path}:{source_symbol.name}:{source_symbol.start_line}"
    paths = [_flow_path(flow) for flow in raw if flow.source.symbol == semantic_symbol]
    if arguments.sink_category:
        paths = [path for path in paths if path.sink.kind == arguments.sink_category]
    paths.sort(key=lambda item: (item.source.fact_id, item.sink.fact_id, tuple(item.evidence_refs)))
    coverage = _json(getattr(raw, "coverage", snapshot.semantic_program.coverage))
    resource_reasons = {"path_budget", "flow_budget", "flow_nodes", "call_depth"}
    resource_hit = any(reason in resource_reasons for reason in coverage.get("stop_reasons", []))
    truncated = resource_hit or not bool(coverage.get("complete", False))
    if paths:
        outcome = FlowOutcome.FOUND
    elif coverage.get("complete") is True:
        outcome = FlowOutcome.NOT_FOUND
    else:
        outcome = FlowOutcome.INSUFFICIENT_EVIDENCE
    if resource_hit:
        status = ToolResultStatus.RESOURCE_LIMIT
    elif outcome == FlowOutcome.NOT_FOUND:
        status = ToolResultStatus.NOT_FOUND
    elif outcome == FlowOutcome.INSUFFICIENT_EVIDENCE:
        status = ToolResultStatus.INSUFFICIENT_EVIDENCE
    else:
        status = ToolResultStatus.SUCCESS
    evidence = tuple(_flow_evidence(snapshot, path) for path in paths)
    return ToolExecution(
        status=status,
        output=TraceDataflowOutput(
            outcome=outcome,
            source_symbol_id=source_symbol.symbol_id,
            paths=paths,
            total_paths=len(paths),
            returned_paths=len(paths),
            coverage=coverage,
            truncated=truncated,
        ),
        snapshot=snapshot,
        components=("semantic_program_builder", "semantic_flow_analysis"),
        stage="dataflow_trace",
        evidence=evidence,
        warnings=(
            (_warning("FLOW_COVERAGE_PARTIAL", "Flow coverage is incomplete; absence is not proven.", coverage=coverage),)
            if not coverage.get("complete", False) else ()
        ),
    )


def _finding_id(snapshot: RepositorySnapshot, finding) -> str:
    evidence = finding.evidence
    material = "\0".join([
        snapshot.snapshot_id,
        finding.tool,
        finding.rule_id or "",
        evidence.file_path,
        str(evidence.start_line or ""),
        str(evidence.end_line or ""),
    ])
    return f"finding:{hashlib.sha256(material.encode()).hexdigest()[:24]}"


def _finding_record(snapshot: RepositorySnapshot, finding) -> SecurityFindingRecord:
    return SecurityFindingRecord(
        finding_id=_finding_id(snapshot, finding),
        analyzer=finding.tool,
        rule=finding.rule_id or finding.detector_id,
        title=redact_secrets(finding.title)[:512],
        description=redact_secrets(finding.description)[:2_048],
        severity=finding.severity.value,
        category=finding.category,
        file_path=finding.evidence.file_path.replace("\\", "/"),
        start_line=finding.evidence.start_line,
        end_line=finding.evidence.end_line,
        certainty=finding.confidence,
        source_analyzer=finding.source_tool or finding.tool,
        detector_kind=finding.detector_kind,
    )


def _finding_evidence(snapshot: RepositorySnapshot, record: SecurityFindingRecord) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=record.finding_id,
        evidence_type=EvidenceType.SCANNER_FINDING,
        source_component=record.source_analyzer,
        file_path=record.file_path,
        start_line=record.start_line,
        end_line=record.end_line,
        metadata={"rule": record.rule, "analyzer": record.analyzer, "certainty": record.certainty},
    )


def scan_security(arguments: ScanSecurityInput, context: AgentToolContext) -> ToolExecution:
    snapshot = _snapshot(context, arguments.snapshot_id)
    path = _normalize_path(snapshot, arguments.file_path) if arguments.file_path else None
    symbol = _find_symbol(snapshot, arguments.symbol_id) if arguments.symbol_id else None
    if path and symbol and symbol.file_path != path:
        raise ToolFailure(
            ToolResultStatus.INVALID_INPUT,
            "SCOPE_MISMATCH",
            "The symbol is not defined in the supplied file scope.",
        )
    selected_names = {name.lower() for name in arguments.analyzers}
    known_names = {name.lower(): name for name in snapshot.evidence_store.scanner_results}
    unknown = sorted(selected_names - set(known_names))
    if unknown:
        raise ToolFailure(
            ToolResultStatus.UNSUPPORTED,
            "ANALYZER_NOT_REGISTERED",
            "One or more requested deterministic analyzers are not registered.",
            analyzers=unknown,
        )
    selected = [
        name for name in sorted(snapshot.evidence_store.scanner_results)
        if not selected_names or name.lower() in selected_names
    ]
    statuses = {
        name: snapshot.evidence_store.scanner_results[name].status.value for name in selected
    }
    findings = []
    rules = set(arguments.rules)
    categories = {category.lower() for category in arguments.categories}
    for name in selected:
        result = snapshot.evidence_store.scanner_results[name]
        if result.status != ToolStatus.COMPLETED:
            continue
        for finding in result.findings:
            record = _finding_record(snapshot, finding)
            if path and record.file_path != path:
                continue
            if symbol and not (
                record.file_path == symbol.file_path
                and record.start_line is not None
                and record.end_line is not None
                and record.start_line <= symbol.end_line
                and record.end_line >= symbol.start_line
            ):
                continue
            if rules and record.rule not in rules:
                continue
            if categories and record.category.lower() not in categories:
                continue
            findings.append(record)
    findings.sort(key=lambda item: (item.file_path, item.start_line or 0, item.rule or "", item.finding_id))
    effective = min(arguments.max_results, context.limits.max_results)
    returned = findings[:effective]
    truncated = len(findings) > effective
    coverage_complete = snapshot.manifest_complete and bool(selected) and all(
        snapshot.evidence_store.scanner_results[name].status == ToolStatus.COMPLETED for name in selected
    )
    if truncated:
        status = ToolResultStatus.RESOURCE_LIMIT
    elif not coverage_complete and not findings:
        status = ToolResultStatus.INSUFFICIENT_EVIDENCE
    else:
        status = ToolResultStatus.SUCCESS
    warnings = []
    if not coverage_complete:
        warnings.append(_warning("SECURITY_COVERAGE_PARTIAL", "One or more scanner or manifest scopes are incomplete.", analyzer_status=statuses))
    if truncated:
        warnings.append(_warning("RESULT_LIMIT_REACHED", "Security findings were truncated.", limit=effective))
    return ToolExecution(
        status=status,
        output=SecurityScanOutput(
            findings=returned,
            total_findings=len(findings),
            returned_findings=len(returned),
            analyzer_status=statuses,
            coverage_complete=coverage_complete,
            truncated=truncated,
        ),
        snapshot=snapshot,
        components=tuple(f"static_scanner:{name}" for name in selected) or ("evidence_store",),
        stage="security_scan_query",
        evidence=tuple(_finding_evidence(snapshot, item) for item in returned),
        warnings=tuple(warnings),
    )


def _authorize_change_scope(
    base: RepositorySnapshot,
    head: RepositorySnapshot,
    scope_paths: Iterable[str],
) -> list[str]:
    normalized = []
    for path in scope_paths:
        base_path = _normalize_path(base, path, require_entry=False)
        head_path = _normalize_path(head, path, require_entry=False)
        if base_path != head_path:
            raise ToolFailure(ToolResultStatus.INVALID_INPUT, "PATH_NORMALIZATION_MISMATCH", "Snapshot paths normalized inconsistently.")
        normalized.append(base_path)
    return sorted(set(normalized))


def _obtain_diff(
    context: AgentToolContext,
    base_id: str,
    head_id: str,
) -> tuple[RepositorySnapshot, RepositorySnapshot, StructuralDiffResult]:
    if base_id == head_id:
        raise ToolFailure(ToolResultStatus.INVALID_INPUT, "IDENTICAL_SNAPSHOTS", "Base and head snapshots must differ.")
    base = _snapshot(context, base_id)
    head = _snapshot(context, head_id)
    if base.manifest.repository_url != head.manifest.repository_url:
        raise ToolFailure(ToolResultStatus.INVALID_INPUT, "REPOSITORY_MISMATCH", "Base and head snapshots belong to different repositories.")
    existing = context.get_diff(base_id, head_id)
    if existing is not None:
        return base, head, existing
    if (base.repository_root / ".git").exists() or (head.repository_root / ".git").exists():
        raise ToolFailure(
            ToolResultStatus.UNSUPPORTED,
            "MATERIALIZED_SNAPSHOTS_REQUIRED",
            "Diff computation requires precomputed facts or materialized snapshots without Git metadata; tool execution never invokes Git.",
        )
    diff = get_diff_engine().compute_structural_diff(
        base_workspace=str(base.repository_root),
        head_workspace=str(head.repository_root),
        base_commit_sha=base.snapshot_id,
        head_commit_sha=head.snapshot_id,
        repository_url=base.manifest.repository_url,
    )
    return base, head, diff


def _in_scope(path: str, scopes: list[str]) -> bool:
    normalized = path.replace("\\", "/")
    return not scopes or any(normalized == scope or normalized.startswith(f"{scope}/") for scope in scopes)


def _bounded_diff(diff: StructuralDiffResult, scopes: list[str], limit: int) -> tuple[StructuralDiffResult, int, int]:
    file_facts = sorted(
        [item for item in diff.changed_files if _in_scope(item.file_path, scopes) or (item.old_path and _in_scope(item.old_path, scopes))],
        key=lambda item: (item.file_path, item.change_type.value, item.old_path or ""),
    )
    symbol_facts = sorted(
        [item for item in diff.changed_symbols if _in_scope(item.file_path, scopes)],
        key=lambda item: (item.file_path, item.symbol_name, item.symbol_kind, item.change_type.value),
    )
    dependency = sorted(
        [item for item in diff.dependency_deltas if _in_scope(item.manifest_file, scopes)],
        key=lambda item: (item.manifest_file, item.package_name, item.change_type),
    )
    config = sorted(
        [item for item in diff.config_deltas if _in_scope(item.file_path, scopes)],
        key=lambda item: (item.file_path, item.key, item.change_type),
    )
    routes = sorted(
        [item for item in diff.route_deltas if _in_scope(item.file_path, scopes)],
        key=lambda item: (item.file_path, item.route_name, item.change_type),
    )
    schemas = sorted(
        [item for item in diff.schema_deltas if _in_scope(item.file_path, scopes)],
        key=lambda item: (item.file_path, item.model_name, item.field_name, item.change_type),
    )
    collections = [file_facts, symbol_facts, dependency, config, routes, schemas]
    total = sum(len(items) for items in collections)
    budget = limit
    bounded = []
    for items in collections:
        taken = items[:budget]
        bounded.append(taken)
        budget -= len(taken)
    files, symbols, dependency, config, routes, schemas = bounded
    added_files = sorted(item.file_path for item in files if item.change_type.value == "ADDED")
    deleted_files = sorted(item.file_path for item in files if item.change_type.value == "DELETED")
    renamed_files = sorted([[item.old_path, item.file_path] for item in files if item.change_type.value == "RENAMED" and item.old_path])
    modified_files = sorted(item.file_path for item in files if item.change_type.value == "MODIFIED")
    added_symbols = [item for item in symbols if item.change_type == SymbolChangeType.ADDED]
    deleted_symbols = [item for item in symbols if item.change_type == SymbolChangeType.DELETED]
    modified_symbols = [item for item in symbols if item.change_type not in {SymbolChangeType.ADDED, SymbolChangeType.DELETED}]
    returned = sum(len(items) for items in bounded)
    result = diff.model_copy(
        update={
            "changed_files": files,
            "added_files": added_files,
            "deleted_files": deleted_files,
            "renamed_files": renamed_files,
            "modified_files": modified_files,
            "changed_symbols": symbols,
            "added_symbols": added_symbols,
            "deleted_symbols": deleted_symbols,
            "modified_symbols": modified_symbols,
            "dependency_deltas": dependency,
            "config_deltas": config,
            "route_deltas": routes,
            "schema_deltas": schemas,
            "summary": {"total_facts": returned},
        },
        deep=True,
    )
    return result, total, returned


def _change_evidence(snapshot: RepositorySnapshot, category: str, item: Any) -> EvidenceRecord:
    data = _json(item)
    file_path = data.get("file_path") or data.get("manifest_file") or ""
    identity = repr(sorted(data.items()))
    evidence_id = f"change:{hashlib.sha256((snapshot.snapshot_id + category + identity).encode()).hexdigest()[:24]}"
    location = data.get("head_location") or data.get("base_location") or {}
    return EvidenceRecord(
        evidence_id=evidence_id,
        evidence_type=EvidenceType.CHANGE_FACT,
        source_component="change_diff_engine",
        file_path=file_path,
        symbol=data.get("symbol_name") or data.get("model_name") or data.get("route_name"),
        start_line=location.get("start_line"),
        end_line=location.get("end_line"),
        relationship=category,
        metadata={"change_type": data.get("change_type")},
    )


def _diff_evidence(snapshot: RepositorySnapshot, diff: StructuralDiffResult) -> tuple[EvidenceRecord, ...]:
    result = []
    for category, items in (
        ("FILE", diff.changed_files),
        ("SYMBOL", diff.changed_symbols),
        ("DEPENDENCY", diff.dependency_deltas),
        ("CONFIG", diff.config_deltas),
        ("ROUTE", diff.route_deltas),
        ("SCHEMA", diff.schema_deltas),
    ):
        result.extend(_change_evidence(snapshot, category, item) for item in items)
    return tuple(result)


def analyze_change(arguments: AnalyzeChangeInput, context: AgentToolContext) -> ToolExecution:
    base, head, diff = _obtain_diff(context, arguments.base_snapshot_id, arguments.head_snapshot_id)
    scopes = _authorize_change_scope(base, head, arguments.scope_paths)
    effective = min(arguments.max_results, context.limits.max_results)
    bounded, total, returned = _bounded_diff(diff, scopes, effective)
    truncated = total > returned or not bool(diff.discovery_coverage.get("complete", True))
    status = ToolResultStatus.RESOURCE_LIMIT if total > returned else (
        ToolResultStatus.INSUFFICIENT_EVIDENCE
        if diff.discovery_coverage and diff.discovery_coverage.get("complete") is False
        else ToolResultStatus.SUCCESS
    )
    warnings = ()
    if truncated:
        warnings = (_warning("CHANGE_COVERAGE_PARTIAL", "Change facts are bounded or discovery coverage is incomplete.", total=total, returned=returned),)
    return ToolExecution(
        status=status,
        output=AnalyzeChangeOutput(
            diff=bounded,
            total_facts=total,
            returned_facts=returned,
            truncated=truncated,
        ),
        snapshot=head,
        components=("change_diff_engine",),
        stage="structural_change_analysis",
        evidence=_diff_evidence(head, bounded),
        warnings=warnings,
    )


def _narrow_diff_to_symbol(diff: StructuralDiffResult, symbol: SymbolRecord) -> StructuralDiffResult:
    matches = [
        item for item in diff.changed_symbols
        if item.file_path.replace("\\", "/") == symbol.file_path and item.symbol_name == symbol.name
    ]
    if not matches:
        raise ToolFailure(ToolResultStatus.NOT_FOUND, "CHANGED_SYMBOL_NOT_FOUND", "The supplied symbol is not changed in this diff.")
    return diff.model_copy(
        update={
            "changed_symbols": matches,
            "added_symbols": [item for item in matches if item.change_type == SymbolChangeType.ADDED],
            "deleted_symbols": [item for item in matches if item.change_type == SymbolChangeType.DELETED],
            "modified_symbols": [item for item in matches if item.change_type not in {SymbolChangeType.ADDED, SymbolChangeType.DELETED}],
        },
        deep=True,
    )


def _impact_record(impact) -> ImpactRecord:
    payload = _json(impact.evidence_payload)
    impact_type = impact.impact_type.value
    direction = str(payload.get("direction") or ("UPSTREAM_CALLER" if impact_type == "CALLER_IMPACT" else "CROSS_LAYER" if "CONTRACT" in impact_type else "DIRECT"))
    return ImpactRecord(
        impact_type=impact_type,
        severity=impact.severity.value,
        title=impact.title,
        description=impact.description,
        source_file=impact.source_file,
        source_symbol=impact.source_symbol,
        affected_file=impact.affected_file,
        affected_symbol=impact.affected_symbol,
        direction=direction,
        depth=payload.get("depth"),
        confidence=impact.confidence,
        verification_status=impact.verification_status.value,
        evidence_payload=payload,
    )


def _impact_evidence(snapshot: RepositorySnapshot, record: ImpactRecord) -> EvidenceRecord:
    material = repr(record.model_dump(mode="json"))
    return EvidenceRecord(
        evidence_id=f"impact:{hashlib.sha256((snapshot.snapshot_id + material).encode()).hexdigest()[:24]}",
        evidence_type=EvidenceType.IMPACT_RELATIONSHIP,
        source_component="change_impact_engine",
        file_path=record.affected_file or record.source_file,
        symbol=record.affected_symbol or record.source_symbol,
        relationship=record.impact_type,
        metadata={"direction": record.direction, "depth": record.depth},
    )


def analyze_impact(arguments: AnalyzeImpactInput, context: AgentToolContext) -> ToolExecution:
    base, head, diff = _obtain_diff(context, arguments.base_snapshot_id, arguments.head_snapshot_id)
    scopes = _authorize_change_scope(base, head, arguments.scope_paths)
    if scopes:
        diff, _, _ = _bounded_diff(diff, scopes, 1_000_000_000)
    if base.graph is None:
        raise ToolFailure(ToolResultStatus.INSUFFICIENT_EVIDENCE, "GRAPH_UNAVAILABLE", "The base repository graph is unavailable.")
    if arguments.changed_symbol_id:
        try:
            symbol = _find_symbol(head, arguments.changed_symbol_id)
        except ToolFailure:
            symbol = _find_symbol(base, arguments.changed_symbol_id)
        diff = _narrow_diff_to_symbol(diff, symbol)
    effective_results = min(arguments.max_results, context.limits.max_results)
    effective_depth = min(arguments.max_depth, context.limits.max_graph_depth)
    report = get_impact_engine().compute_blast_radius(
        analysis_id=uuid5(NAMESPACE_URL, f"{base.snapshot_id}:{head.snapshot_id}"),
        diff_result=diff,
        base_graph=base.graph,
        head_graph=head.graph,
        max_depth=effective_depth,
        max_impacts=effective_results,
    )
    impacts = sorted(
        (_impact_record(item) for item in report.impacts),
        key=lambda item: (item.depth or 0, item.source_file or "", item.affected_file or "", item.impact_type, item.title),
    )
    truncated = report.is_truncated
    status = ToolResultStatus.RESOURCE_LIMIT if truncated else ToolResultStatus.SUCCESS
    return ToolExecution(
        status=status,
        output=AnalyzeImpactOutput(
            impacts=impacts,
            total_impacts=report.total_impacts,
            returned_impacts=len(impacts),
            direct_impacts=report.direct_impacts_count,
            transitive_impacts=report.transitive_impacts_count,
            max_depth_reached=report.max_depth_reached,
            overall_risk_level=report.overall_risk_level.value,
            truncated=truncated,
            truncation_reason=report.truncation_reason,
        ),
        snapshot=head,
        components=("change_diff_engine", "change_impact_engine", "repository_graph"),
        stage="impact_analysis",
        evidence=tuple(_impact_evidence(head, item) for item in impacts),
        warnings=(
            (_warning("IMPACT_TRAVERSAL_PARTIAL", "Impact traversal reached a configured resource boundary."),)
            if truncated else ()
        ),
    )


def _verification_result(claim: ProposedFinding, verdict: VerificationVerdict, reason: str, refs: Iterable[str] = ()) -> VerifyFindingOutput:
    return VerifyFindingOutput(
        verdict=verdict,
        claim_type=claim.claim_type,
        matched_evidence_refs=sorted(set(refs)),
        reason_code=reason,
    )


def _finish_verification(
    claim: ProposedFinding,
    snapshot: RepositorySnapshot,
    *,
    verdict: VerificationVerdict,
    reason: str,
    evidence: Iterable[EvidenceRecord] = (),
    components: tuple[str, ...],
) -> ToolExecution:
    available = tuple(evidence)
    available_ids = {item.evidence_id for item in available}
    matched = available_ids.intersection(claim.evidence_refs)
    if verdict == VerificationVerdict.SUPPORTED and not claim.evidence_refs:
        verdict, reason = VerificationVerdict.INVALID_CLAIM, "EVIDENCE_REFERENCES_REQUIRED"
    elif verdict == VerificationVerdict.SUPPORTED and not matched:
        verdict, reason = VerificationVerdict.INSUFFICIENT_EVIDENCE, "EVIDENCE_REFERENCE_UNRESOLVED"
    return ToolExecution(
        status=ToolResultStatus.SUCCESS,
        output=_verification_result(claim, verdict, reason, matched),
        snapshot=snapshot,
        components=components,
        stage="deterministic_claim_verification",
        evidence=tuple(item for item in available if item.evidence_id in matched),
    )


def verify_finding(arguments: VerifyFindingInput, context: AgentToolContext) -> ToolExecution:
    claim = arguments.claim
    if claim.claim_type == ClaimType.SECURITY_FINDING:
        if not claim.rule or not claim.file_path:
            snapshot = _snapshot(context, claim.snapshot_id)
            return _finish_verification(claim, snapshot, verdict=VerificationVerdict.INVALID_CLAIM, reason="RULE_AND_FILE_REQUIRED", components=("evidence_store",))
        execution = scan_security(
            ScanSecurityInput(snapshot_id=claim.snapshot_id, file_path=claim.file_path, rules=[claim.rule], max_results=context.limits.max_results),
            context,
        )
        assert isinstance(execution.output, SecurityScanOutput)
        matches = execution.output.findings
        if claim.symbol_id:
            symbol = _find_symbol(execution.snapshot, claim.symbol_id)  # type: ignore[arg-type]
            matches = [item for item in matches if item.file_path == symbol.file_path and item.start_line is not None and item.end_line is not None and item.start_line <= symbol.end_line and item.end_line >= symbol.start_line]
        if matches:
            evidence = [_finding_evidence(execution.snapshot, item) for item in matches]  # type: ignore[arg-type]
            return _finish_verification(claim, execution.snapshot, verdict=VerificationVerdict.SUPPORTED, reason="EXACT_SCANNER_FACT", evidence=evidence, components=execution.components)  # type: ignore[arg-type]
        verdict = VerificationVerdict.UNSUPPORTED if execution.output.coverage_complete else VerificationVerdict.INSUFFICIENT_EVIDENCE
        return _finish_verification(claim, execution.snapshot, verdict=verdict, reason="NO_MATCHING_SCANNER_FACT", components=execution.components)  # type: ignore[arg-type]

    if claim.claim_type == ClaimType.DATAFLOW:
        snapshot = _snapshot(context, claim.snapshot_id)
        if not claim.source_symbol_id or not claim.sink_category:
            return _finish_verification(claim, snapshot, verdict=VerificationVerdict.INVALID_CLAIM, reason="SOURCE_AND_SINK_REQUIRED", components=("semantic_flow_analysis",))
        execution = trace_dataflow(
            TraceDataflowInput(
                snapshot_id=snapshot.snapshot_id,
                source_symbol_id=claim.source_symbol_id,
                sink_category=claim.sink_category,
                max_depth=context.limits.max_graph_depth,
                max_paths=context.limits.max_dataflow_paths,
            ),
            context,
        )
        assert isinstance(execution.output, TraceDataflowOutput)
        if execution.output.paths:
            return _finish_verification(claim, snapshot, verdict=VerificationVerdict.SUPPORTED, reason="EXACT_PRODUCTION_FLOW", evidence=execution.evidence, components=execution.components)
        verdict = VerificationVerdict.UNSUPPORTED if execution.output.outcome == FlowOutcome.NOT_FOUND else VerificationVerdict.INSUFFICIENT_EVIDENCE
        return _finish_verification(claim, snapshot, verdict=verdict, reason="NO_MATCHING_PRODUCTION_FLOW", components=execution.components)

    if claim.claim_type == ClaimType.CALL_RELATIONSHIP:
        snapshot = _snapshot(context, claim.snapshot_id)
        if not claim.source_symbol_id or not claim.target_symbol_id:
            return _finish_verification(claim, snapshot, verdict=VerificationVerdict.INVALID_CLAIM, reason="SOURCE_AND_TARGET_REQUIRED", components=("repository_graph",))
        if snapshot.graph is None:
            return _finish_verification(claim, snapshot, verdict=VerificationVerdict.INSUFFICIENT_EVIDENCE, reason="GRAPH_UNAVAILABLE", components=("repository_graph",))
        edges = [
            edge for edge in snapshot.graph.get_outgoing_edges(claim.source_symbol_id)
            if edge.target == claim.target_symbol_id and edge.kind.value == (claim.relationship_type or EdgeKind.CALLS.value)
        ]
        relationships = [item for edge in edges if (item := _relationship(snapshot, edge))]
        evidence = [_edge_evidence(snapshot, item) for item in relationships]
        if relationships:
            return _finish_verification(claim, snapshot, verdict=VerificationVerdict.SUPPORTED, reason="EXACT_GRAPH_EDGE", evidence=evidence, components=("repository_graph",))
        verdict = VerificationVerdict.UNSUPPORTED if snapshot.graph_complete else VerificationVerdict.INSUFFICIENT_EVIDENCE
        return _finish_verification(claim, snapshot, verdict=verdict, reason="NO_MATCHING_GRAPH_EDGE", components=("repository_graph",))

    if claim.claim_type == ClaimType.STRUCTURAL_CHANGE:
        if not claim.base_snapshot_id or not claim.head_snapshot_id or not claim.file_path or not claim.change_type:
            snapshot = _snapshot(context, claim.head_snapshot_id or claim.snapshot_id)
            return _finish_verification(claim, snapshot, verdict=VerificationVerdict.INVALID_CLAIM, reason="CHANGE_COORDINATES_REQUIRED", components=("change_diff_engine",))
        base, head, diff = _obtain_diff(context, claim.base_snapshot_id, claim.head_snapshot_id)
        path = _authorize_change_scope(base, head, [claim.file_path])[0]
        facts: list[tuple[str, Any]] = []
        facts.extend(("FILE", item) for item in diff.changed_files if item.file_path == path and item.change_type.value == claim.change_type)
        facts.extend(("SYMBOL", item) for item in diff.changed_symbols if item.file_path == path and item.change_type.value == claim.change_type and (not claim.symbol_id or claim.symbol_id.endswith(f":{item.symbol_name}:{(item.head_location or item.base_location or {}).get('start_line', '')}")))
        evidence = [_change_evidence(head, category, item) for category, item in facts]
        if facts:
            return _finish_verification(claim, head, verdict=VerificationVerdict.SUPPORTED, reason="EXACT_STRUCTURAL_CHANGE_FACT", evidence=evidence, components=("change_diff_engine",))
        complete = not diff.discovery_coverage or diff.discovery_coverage.get("complete") is True
        verdict = VerificationVerdict.UNSUPPORTED if complete else VerificationVerdict.INSUFFICIENT_EVIDENCE
        return _finish_verification(claim, head, verdict=verdict, reason="NO_MATCHING_CHANGE_FACT", components=("change_diff_engine",))

    snapshot = _snapshot(context, claim.snapshot_id)
    return _finish_verification(claim, snapshot, verdict=VerificationVerdict.INVALID_CLAIM, reason="CLAIM_TYPE_UNSUPPORTED", components=("agent_tool_verifier",))


__all__ = [
    "ToolExecution",
    "ToolFailure",
    "analyze_change",
    "analyze_impact",
    "find_callees",
    "find_callers",
    "inspect_file",
    "inspect_symbol",
    "scan_security",
    "search_symbol",
    "trace_dataflow",
    "verify_finding",
]
