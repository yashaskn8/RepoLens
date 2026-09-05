"""Conservative deterministic hypotheses for candidate-first specialist reasoning."""

from __future__ import annotations

import ast
import hashlib
import textwrap
from enum import Enum
from typing import Any, Iterable

from pydantic import BaseModel, Field

from app.graph.repository_graph import RepositoryGraph
from app.graph.schemas import EdgeKind
from app.indexing.schemas import CodeChunk
from app.ingestion.schemas import RepositoryManifest, SymbolKind
from app.semantics import SemanticCertainty, analyze_security_flows, build_semantic_program


class CandidateStrength(str, Enum):
    """Rule confidence without pretending to provide statistical certainty."""

    STRONG = "STRONG"
    MODERATE = "MODERATE"


class FlowCertainty(str, Enum):
    """Whether a structural flow is proven or only a review hypothesis."""

    PROVEN_EDGE = "PROVEN_EDGE"
    POSSIBLE_EDGE = "POSSIBLE_EDGE"


class AnalysisCandidate(BaseModel):
    """Serializable deterministic hypothesis; never a confirmed Finding."""

    candidate_id: str
    candidate_kind: str
    deterministic_reason: str
    evidence_refs: list[str] = Field(default_factory=list, max_length=16)
    related_symbol: str | None = None
    strength: CandidateStrength = CandidateStrength.MODERATE
    counter_evidence: list[str] = Field(default_factory=list, max_length=8)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _candidate_id(kind: str, evidence_refs: Iterable[str], reason: str) -> str:
    material = "\0".join([kind, *sorted(evidence_refs), reason])
    return f"candidate:{hashlib.sha256(material.encode('utf-8')).hexdigest()[:24]}"


def _chunk_evidence_id(chunk: CodeChunk) -> str:
    """Match the canonical ID emitted by pack_repository_context."""
    return f"chunk:{chunk.chunk_id}"


def _call_name(node: ast.Call) -> str:
    parts: list[str] = []
    current: ast.AST = node.func
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def build_bug_candidates(
    chunks: Iterable[CodeChunk],
    *,
    manifest: RepositoryManifest | None = None,
    limit: int = 12,
    semantic_program=None,
) -> list[AnalysisCandidate]:
    """Find bounded cross-language correctness hypotheses from semantic facts."""
    chunk_list = list(chunks)
    candidates: list[AnalysisCandidate] = []
    blocking_calls = {
        "time.sleep",
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.popen",
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.delete",
        "urllib.request.urlopen",
        "fs.readfilesync",
        "fs.writefilesync",
        "child_process.execsync",
    }

    program = semantic_program if semantic_program is not None else build_semantic_program(manifest, chunk_list)
    functions_by_symbol = {function.symbol: function for function in program.functions}
    for guard in program.guards:
        if (
            guard.guard_kind == "EXCEPTION_HANDLER"
            and guard.metadata.get("broad") is True
            and guard.metadata.get("empty") is True
        ):
            reason = "A broad exception handler deterministically discards the exception without handling it."
            candidates.append(AnalysisCandidate(
                candidate_id=_candidate_id("BROAD_EXCEPTION_SWALLOW", [guard.evidence_id], reason),
                candidate_kind="BROAD_EXCEPTION_SWALLOW",
                deterministic_reason=reason,
                evidence_refs=[guard.evidence_id],
                related_symbol=guard.symbol,
                strength=CandidateStrength.STRONG,
                metadata={"source_line": guard.start_line, "semantic_fact_id": guard.fact_id},
            ))
    async_targets = {}
    for function in program.functions:
        if function.is_async:
            async_targets.setdefault((function.file_path, function.name), {})[function.symbol] = function
    for call in program.calls:
        enclosing = functions_by_symbol.get(call.symbol)
        callee = call.callee.lower()
        if enclosing and enclosing.is_async and callee in blocking_calls:
            reason = f"Async function {enclosing.name!r} structurally calls known blocking API {callee!r}."
            candidates.append(AnalysisCandidate(
                candidate_id=_candidate_id("ASYNC_BLOCKING_CALL", [call.evidence_id], reason),
                candidate_kind="ASYNC_BLOCKING_CALL",
                deterministic_reason=reason,
                evidence_refs=[call.evidence_id],
                related_symbol=enclosing.name,
                strength=CandidateStrength.STRONG,
                metadata={"callee": callee, "source_line": call.start_line, "semantic_fact_id": call.fact_id},
            ))
        short_callee = call.callee.rsplit(".", 1)[-1]
        targets = list(async_targets.get((call.file_path, short_callee), {}).values())
        if (len(targets) == 1 and "." not in call.callee and not call.awaited and call.result_discarded
                and any(chunk.file_path == call.file_path and chunk.language == "python" for chunk in chunk_list)):
            reason = f"The result of a call to same-file async function {short_callee!r} is discarded without awaiting."
            refs = list(dict.fromkeys([call.evidence_id, targets[0].evidence_id]))
            candidates.append(AnalysisCandidate(
                candidate_id=_candidate_id("UNAWAITED_ASYNC_CALL", refs, reason),
                candidate_kind="UNAWAITED_ASYNC_CALL",
                deterministic_reason=reason,
                evidence_refs=refs,
                related_symbol=call.symbol,
                strength=CandidateStrength.STRONG,
                metadata={"callee": call.callee, "source_line": call.start_line, "semantic_fact_id": call.fact_id},
            ))

    # Retain the AST path only as a parser-unavailable fallback for Python.
    if program.functions:
        deduplicated = {candidate.candidate_id: candidate for candidate in candidates}
        return [deduplicated[key] for key in sorted(deduplicated)][:limit]

    for chunk in sorted(chunk_list, key=lambda item: item.chunk_id):
        if str(chunk.language or "").lower() not in {"python", "py"}:
            continue
        try:
            tree = ast.parse(textwrap.dedent(chunk.content))
        except (SyntaxError, ValueError, TypeError):
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                broad = node.type is None or (
                    isinstance(node.type, ast.Name) and node.type.id in {"Exception", "BaseException"}
                )
                swallowed = bool(node.body) and all(isinstance(statement, ast.Pass) for statement in node.body)
                if broad and swallowed:
                    reason = "A broad exception handler deterministically discards the exception with only pass."
                    evidence_ref = _chunk_evidence_id(chunk)
                    candidates.append(
                        AnalysisCandidate(
                            candidate_id=_candidate_id("BROAD_EXCEPTION_SWALLOW", [evidence_ref], reason),
                            candidate_kind="BROAD_EXCEPTION_SWALLOW",
                            deterministic_reason=reason,
                            evidence_refs=[evidence_ref],
                            related_symbol=chunk.symbol,
                            strength=CandidateStrength.STRONG,
                            metadata={"source_line": chunk.start_line + node.lineno - 1},
                        )
                    )

            if isinstance(node, ast.AsyncFunctionDef):
                for descendant in ast.walk(node):
                    if not isinstance(descendant, ast.Call):
                        continue
                    callee = _call_name(descendant).lower()
                    if callee not in blocking_calls:
                        continue
                    reason = (
                        f"Async function {node.name!r} structurally calls known blocking API {callee!r}."
                    )
                    evidence_ref = _chunk_evidence_id(chunk)
                    candidates.append(
                        AnalysisCandidate(
                            candidate_id=_candidate_id("ASYNC_BLOCKING_CALL", [evidence_ref], reason),
                            candidate_kind="ASYNC_BLOCKING_CALL",
                            deterministic_reason=reason,
                            evidence_refs=[evidence_ref],
                            related_symbol=node.name,
                            strength=CandidateStrength.STRONG,
                            metadata={
                                "callee": callee,
                                "source_line": chunk.start_line + descendant.lineno - 1,
                            },
                        )
                    )

        if len(candidates) >= limit:
            break
    deduplicated = {candidate.candidate_id: candidate for candidate in candidates}
    return [deduplicated[key] for key in sorted(deduplicated)][:limit]


def _chunk_for_call(
    chunks: Iterable[CodeChunk],
    *,
    file_path: str,
    caller_name: str | None,
    line_number: int,
) -> CodeChunk | None:
    same_file = [chunk for chunk in chunks if chunk.file_path == file_path]
    exact = [chunk for chunk in same_file if caller_name and chunk.symbol == caller_name]
    containing = [chunk for chunk in same_file if chunk.start_line <= line_number <= chunk.end_line]
    pool = exact or containing
    return min(pool, key=lambda item: (item.end_line - item.start_line, item.chunk_id)) if pool else None


def _sink_kind(callee: str, callee_name: str) -> str | None:
    normalized = callee.lower()
    name = callee_name.lower()
    if normalized in {
        "open", "os.remove", "os.unlink", "shutil.rmtree", "path.open",
        "path.read_text", "path.write_text", "pathlib.path.open",
    }:
        return "INPUT_TO_FILESYSTEM"
    if normalized in {
        "os.system", "subprocess.run", "subprocess.call", "subprocess.popen",
        "subprocess.check_call", "subprocess.check_output",
    }:
        return "INPUT_TO_COMMAND"
    if name in {"execute", "executemany", "executescript"}:
        return "INPUT_TO_DATABASE"
    if name in {"render_template_string", "template"}:
        return "INPUT_TO_TEMPLATE"
    if normalized.startswith(("requests.", "urllib.request.", "httpx.")):
        return "INPUT_TO_NETWORK"
    return None


def build_security_flow_candidates(
    manifest: RepositoryManifest,
    chunks: Iterable[CodeChunk],
    *,
    limit: int = 12,
    semantic_program=None,
) -> list[AnalysisCandidate]:
    """Build possible route-input-to-sink flows from parsed call-site facts."""
    chunk_list = list(chunks)
    candidates: list[AnalysisCandidate] = []
    guard_markers = (
        "authoriz", "permission", "validate", "sanit", "escape", "allowlist",
        "normalize", "resolve_safe_path", "is_relative_to", "parameter",
    )

    program = semantic_program if semantic_program is not None else build_semantic_program(manifest, chunk_list)
    flows = analyze_security_flows(program)
    for flow in flows:
        # Only framework-derived route sources are sufficiently authoritative
        # to create a repository security hypothesis. Other parameters remain
        # available as POSSIBLE facts for contextual reasoning.
        if flow.source.certainty != SemanticCertainty.PROVEN:
            continue
        evidence_refs = list(dict.fromkeys(flow.evidence_refs))[:16]
        guard_refs = list(dict.fromkeys(guard.evidence_id for guard in flow.guards))[:8]
        sanitizer_refs = list(dict.fromkeys(item.evidence_id for item in flow.sanitizers))[:8]
        counter_evidence = list(dict.fromkeys(
            [item.name for item in flow.sanitizers] + [item.expression for item in flow.guards]
        ))[:8]
        certainty = (
            FlowCertainty.PROVEN_EDGE
            if flow.certainty == SemanticCertainty.PROVEN
            else FlowCertainty.POSSIBLE_EDGE
        )
        reason = (
            f"Route input {flow.source.name!r} has a bounded semantic flow to "
            f"{flow.sink.name!r} ({flow.sink.sink_kind})."
        )
        candidates.append(AnalysisCandidate(
            candidate_id=_candidate_id(flow.sink.sink_kind, evidence_refs, reason),
            candidate_kind=flow.sink.sink_kind,
            deterministic_reason=reason,
            evidence_refs=evidence_refs,
            related_symbol=flow.source.symbol,
            strength=(
                CandidateStrength.STRONG
                if certainty == FlowCertainty.PROVEN_EDGE
                else CandidateStrength.MODERATE
            ),
            counter_evidence=counter_evidence,
            metadata={
                "file_path": flow.source.file_path,
                "required_evidence_roles": ["primary", "flow", "guard"],
                "source": f"{flow.source.source_kind.lower()}:{flow.source.name}",
                "sink": flow.sink.name,
                "flow_certainty": certainty.value,
                "source_line": flow.sink.start_line,
                "flow_evidence_refs": evidence_refs,
                "caller_evidence_refs": evidence_refs[:1],
                "callee_evidence_refs": evidence_refs[1:],
                "guard_evidence_refs": guard_refs,
                "counter_evidence_refs": sanitizer_refs,
                "transformations": flow.transformations,
                "semantic_edges": [edge.model_dump(mode="json") for edge in flow.edges],
                "call_depth": flow.call_depth,
                "flow_coverage": flows.coverage,
            },
        ))

    # High-signal source patterns that do not require framework route metadata.
    for chunk in sorted(chunk_list, key=lambda item: item.chunk_id):
        if str(chunk.language or "").lower() not in {"python", "py"}:
            continue
        try:
            tree = ast.parse(textwrap.dedent(chunk.content))
        except (SyntaxError, ValueError, TypeError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            callee = _call_name(node).lower()
            evidence_ref = _chunk_evidence_id(chunk)
            source_line = chunk.start_line + node.lineno - 1

            if callee.endswith(".set_cookie") or callee == "set_cookie":
                keywords = {keyword.arg.lower(): keyword.value for keyword in node.keywords if keyword.arg}
                secure = isinstance(keywords.get("secure"), ast.Constant) and keywords["secure"].value is True
                httponly = (
                    isinstance(keywords.get("httponly"), ast.Constant)
                    and keywords["httponly"].value is True
                )
                samesite_node = keywords.get("samesite")
                samesite = (
                    str(samesite_node.value).lower()
                    if isinstance(samesite_node, ast.Constant) and isinstance(samesite_node.value, str)
                    else ""
                )
                missing = [
                    flag
                    for flag, present in (
                        ("secure=True", secure),
                        ("httponly=True", httponly),
                        ("samesite", samesite in {"lax", "strict"}),
                    )
                    if not present
                ]
                if missing:
                    reason = (
                        "Cookie creation structurally omits hardened attributes: "
                        + ", ".join(missing)
                        + "."
                    )
                    candidates.append(
                        AnalysisCandidate(
                            candidate_id=_candidate_id("INSECURE_COOKIE_ATTRIBUTES", [evidence_ref], reason),
                            candidate_kind="INSECURE_COOKIE_ATTRIBUTES",
                            deterministic_reason=reason,
                            evidence_refs=[evidence_ref],
                            related_symbol=chunk.symbol,
                            strength=CandidateStrength.STRONG,
                            metadata={"sink": callee, "source_line": source_line},
                        )
                    )

            if callee.endswith(".execute") or callee in {"execute", "executemany", "executescript"}:
                query = node.args[0] if node.args else None
                dynamic_query = isinstance(query, (ast.JoinedStr, ast.BinOp)) or (
                    isinstance(query, ast.Call)
                    and isinstance(query.func, ast.Attribute)
                    and query.func.attr == "format"
                )
                if dynamic_query:
                    reason = (
                        "Database execution structurally receives a dynamically constructed query; "
                        "input provenance and parameterization require verification."
                    )
                    candidates.append(
                        AnalysisCandidate(
                            candidate_id=_candidate_id("DYNAMIC_SQL_CONSTRUCTION", [evidence_ref], reason),
                            candidate_kind="DYNAMIC_SQL_CONSTRUCTION",
                            deterministic_reason=reason,
                            evidence_refs=[evidence_ref],
                            related_symbol=chunk.symbol,
                            strength=CandidateStrength.STRONG,
                            metadata={
                                "sink": callee,
                                "flow_certainty": FlowCertainty.POSSIBLE_EDGE.value,
                                "source_line": source_line,
                            },
                        )
                    )

        if len(candidates) >= limit:
            deduplicated = {candidate.candidate_id: candidate for candidate in candidates}
            return [deduplicated[key] for key in sorted(deduplicated)][:limit]

    # The semantic flow engine supersedes call-presence-only route hypotheses.
    # Preserve that legacy path only when Tree-sitter produced no flow facts.
    if program.functions:
        deduplicated = {candidate.candidate_id: candidate for candidate in candidates}
        return [deduplicated[key] for key in sorted(deduplicated)][:limit]

    for file_entry in sorted(manifest.files, key=lambda item: item.path):
        route_handlers = {
            str(symbol.details.get("handler") or symbol.name)
            for symbol in file_entry.symbols
            if symbol.kind in {SymbolKind.FASTAPI_ROUTE, SymbolKind.EXPRESS_ROUTE}
        }
        if not route_handlers:
            continue
        calls_by_caller: dict[str, list[Any]] = {}
        for call in file_entry.calls:
            if call.caller_name:
                calls_by_caller.setdefault(call.caller_name, []).append(call)

        for handler in sorted(route_handlers):
            handler_calls = calls_by_caller.get(handler, [])
            counter_evidence = sorted({
                call.callee
                for call in handler_calls
                if any(marker in call.callee.lower() for marker in guard_markers)
            })[:8]
            for call in sorted(handler_calls, key=lambda item: (item.line_number, item.callee)):
                kind = _sink_kind(call.callee, call.callee_name)
                if kind is None:
                    continue
                chunk = _chunk_for_call(
                    chunk_list,
                    file_path=file_entry.path,
                    caller_name=handler,
                    line_number=call.line_number,
                )
                if chunk is None:
                    continue
                reason = (
                    f"Route handler {handler!r} contains a structural call to {call.callee!r}; "
                    "argument-level taint is not proven."
                )
                evidence_ref = _chunk_evidence_id(chunk)
                candidates.append(
                    AnalysisCandidate(
                        candidate_id=_candidate_id(kind, [evidence_ref], reason),
                        candidate_kind=kind,
                        deterministic_reason=reason,
                        evidence_refs=[evidence_ref],
                        related_symbol=handler,
                        strength=CandidateStrength.MODERATE,
                        counter_evidence=counter_evidence,
                        metadata={
                            "source": f"route_handler:{handler}",
                            "sink": call.callee,
                            "flow_certainty": FlowCertainty.POSSIBLE_EDGE.value,
                            "source_line": call.line_number,
                        },
                    )
                )
                if len(candidates) >= limit:
                    deduplicated = {candidate.candidate_id: candidate for candidate in candidates}
                    return [deduplicated[key] for key in sorted(deduplicated)][:limit]
    deduplicated = {candidate.candidate_id: candidate for candidate in candidates}
    return [deduplicated[key] for key in sorted(deduplicated)][:limit]


def build_architecture_candidates(
    graph: RepositoryGraph,
    chunks: Iterable[CodeChunk],
    *,
    limit: int = 8,
) -> list[AnalysisCandidate]:
    """Create graph-supported review candidates for real dependency cycles."""
    relevant_kinds = {EdgeKind.IMPORTS, EdgeKind.DEPENDS_ON, EdgeKind.CALLS}
    adjacency: dict[str, set[str]] = {}
    edge_lookup: dict[tuple[str, str], EdgeKind] = {}
    for edge in graph.get_edges():
        if edge.kind not in relevant_kinds:
            continue
        adjacency.setdefault(edge.source, set()).add(edge.target)
        adjacency.setdefault(edge.target, set())
        edge_lookup[(edge.source, edge.target)] = edge.kind

    # Iterative Kosaraju traversal avoids recursion limits on large repositories.
    visited: set[str] = set()
    finish_order: list[str] = []
    for start in sorted(adjacency):
        if start in visited:
            continue
        stack: list[tuple[str, bool]] = [(start, False)]
        while stack:
            node_id, expanded = stack.pop()
            if expanded:
                finish_order.append(node_id)
                continue
            if node_id in visited:
                continue
            visited.add(node_id)
            stack.append((node_id, True))
            for target in sorted(adjacency.get(node_id, ()), reverse=True):
                if target not in visited:
                    stack.append((target, False))

    reverse_adjacency: dict[str, set[str]] = {node_id: set() for node_id in adjacency}
    for source, targets in adjacency.items():
        for target in targets:
            reverse_adjacency.setdefault(target, set()).add(source)

    components: list[list[str]] = []
    assigned: set[str] = set()
    for start in reversed(finish_order):
        if start in assigned:
            continue
        component: list[str] = []
        stack = [(start, False)]
        assigned.add(start)
        while stack:
            node_id, _ = stack.pop()
            component.append(node_id)
            for source in sorted(reverse_adjacency.get(node_id, ()), reverse=True):
                if source not in assigned:
                    assigned.add(source)
                    stack.append((source, False))
        if len(component) > 1:
            components.append(sorted(component))

    chunks_by_file: dict[str, list[CodeChunk]] = {}
    for chunk in sorted(chunks, key=lambda item: item.chunk_id):
        chunks_by_file.setdefault(chunk.file_path, []).append(chunk)

    candidates: list[AnalysisCandidate] = []
    for component in sorted(components, key=lambda item: (len(item), item)):
        component_set = set(component)
        cycle_edges = sorted(
            (source, target, kind.value)
            for (source, target), kind in edge_lookup.items()
            if source in component_set and target in component_set
        )
        evidence_refs: list[str] = []
        files: list[str] = []
        for node_id in component:
            node = graph.get_node(node_id)
            if not node or not node.file_path:
                continue
            files.append(node.file_path)
            file_chunks = chunks_by_file.get(node.file_path, [])
            if file_chunks:
                evidence_ref = _chunk_evidence_id(file_chunks[0])
                if evidence_ref not in evidence_refs:
                    evidence_refs.append(evidence_ref)
        if len(evidence_refs) < 2:
            continue
        reason = f"Deterministic dependency graph contains a strongly connected component across {len(set(files))} files."
        candidates.append(
            AnalysisCandidate(
                candidate_id=_candidate_id("DEPENDENCY_CYCLE", evidence_refs, reason),
                candidate_kind="DEPENDENCY_CYCLE",
                deterministic_reason=reason,
                evidence_refs=evidence_refs[:6],
                strength=CandidateStrength.STRONG,
                metadata={"nodes": component[:12], "edges": cycle_edges[:20], "files": sorted(set(files))[:12]},
            )
        )
        if len(candidates) >= limit:
            break
    return candidates


__all__ = [
    "AnalysisCandidate",
    "CandidateStrength",
    "FlowCertainty",
    "build_architecture_candidates",
    "build_bug_candidates",
    "build_security_flow_candidates",
]
