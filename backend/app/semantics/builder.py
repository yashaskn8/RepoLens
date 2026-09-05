"""Tree-sitter to normalized semantic IR projection."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from typing import Any

from tree_sitter import Node

from app.indexing.schemas import CodeChunk
from app.ingestion.parser import parse_syntax_tree
from app.ingestion.schemas import RepositoryManifest, SymbolKind
from app.semantics.schemas import (
    SemanticAssignment,
    SemanticCallSite,
    SemanticCertainty,
    SemanticFunction,
    SemanticGuard,
    SemanticParameter,
    SemanticProgram,
    SemanticResourceUse,
    SemanticReturn,
    SemanticSanitizer,
    SemanticSink,
    SemanticSource,
)

_CALL_NODES = {"call", "call_expression"}
_FUNCTION_NODES = {"function_definition", "function_declaration", "method_definition", "arrow_function"}
_ASSIGNMENT_NODES = {"assignment", "annotated_assignment", "assignment_expression", "variable_declarator"}
_RETURN_NODES = {"return_statement"}
_GUARD_NODES = {"if_statement", "while_statement", "conditional_expression"}
_SANITIZERS = {
    "resolve_safe_path": "PATH_CONFINEMENT",
    "realpath": "PATH_NORMALIZATION",
    "normalize": "NORMALIZATION",
    "escape": "ESCAPING",
    "html.escape": "HTML_ESCAPING",
    "parameterize": "PARAMETERIZATION",
    "validate": "VALIDATION",
}
_GUARD_CALLS = {"authorize", "is_authorized", "has_permission", "is_allowed", "validate"}
_SINKS = {
    "open": "INPUT_TO_FILESYSTEM",
    "path.open": "INPUT_TO_FILESYSTEM",
    "os.remove": "INPUT_TO_FILESYSTEM",
    "os.unlink": "INPUT_TO_FILESYSTEM",
    "fs.readfilesync": "INPUT_TO_FILESYSTEM",
    "fs.writefilesync": "INPUT_TO_FILESYSTEM",
    "os.system": "INPUT_TO_COMMAND",
    "subprocess.run": "INPUT_TO_COMMAND",
    "subprocess.call": "INPUT_TO_COMMAND",
    "child_process.exec": "INPUT_TO_COMMAND",
    "child_process.execsync": "INPUT_TO_COMMAND",
    "execute": "INPUT_TO_DATABASE",
    "executemany": "INPUT_TO_DATABASE",
    "executescript": "INPUT_TO_DATABASE",
    "render_template_string": "INPUT_TO_TEMPLATE",
    "eval": "INPUT_TO_TEMPLATE",
    "requests.get": "INPUT_TO_NETWORK",
    "requests.post": "INPUT_TO_NETWORK",
    "fetch": "INPUT_TO_NETWORK",
}


def _walk(node: Node) -> Iterable[Node]:
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def _text(node: Node | None, source: bytes) -> str:
    if node is None:
        return ""
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")


def _identifiers(node: Node | None, source: bytes) -> list[str]:
    if node is None:
        return []
    names = {
        _text(item, source)
        for item in _walk(node)
        if item.type in {"identifier", "shorthand_property_identifier"}
    }
    return sorted(name for name in names if name)


def _parameter_names(node: Node | None, source: bytes) -> list[str]:
    if node is None:
        return []
    names = []
    for parameter in node.named_children:
        target = _field(parameter, "name", "pattern")
        if target is None:
            target = parameter if parameter.type == "identifier" else next(
                (child for child in parameter.named_children if child.type == "identifier"), None)
        name = _text(target, source)
        if name and name not in {"self", "cls"}:
            names.append(name)
    return names[:64]


def _scope_walk(root: Node) -> Iterable[Node]:
    """Do not attribute a nested function's operations to its parent."""
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed([
            child for child in node.children if child.type not in _FUNCTION_NODES
        ]))


def _field(node: Node, *names: str) -> Node | None:
    for name in names:
        value = node.child_by_field_name(name)
        if value is not None:
            return value
    return None


def _fact_base(chunk: CodeChunk, node: Node, kind: str, discriminator: str) -> dict[str, Any]:
    start_line = chunk.start_line + node.start_point[0]
    end_line = chunk.start_line + node.end_point[0]
    material = "\0".join([kind, chunk.commit_sha, chunk.content_hash, chunk.file_path, str(start_line),
                            str(node.start_point[1]), discriminator])
    return {
        "fact_id": f"semantic:{hashlib.sha256(material.encode('utf-8')).hexdigest()[:24]}",
        "language": str(chunk.language or "unknown").lower(),
        "file_path": chunk.file_path,
        "symbol": chunk.symbol,
        "start_line": start_line,
        "end_line": max(start_line, end_line),
        "commit_sha": chunk.commit_sha,
        "content_hash": chunk.content_hash,
        "evidence_id": f"chunk:{chunk.chunk_id}",
        "certainty": SemanticCertainty.PROVEN,
    }


def _callee_name(call: Node, source: bytes) -> str:
    return _text(_field(call, "function"), source).strip()


def _result_target(call: Node, source: bytes) -> str | None:
    parent = call.parent
    if parent is None or parent.type not in _ASSIGNMENT_NODES:
        return None
    target = _field(parent, "left", "name")
    value = _field(parent, "right", "value")
    if value is not None and not (value.start_byte <= call.start_byte <= value.end_byte):
        return None
    names = _identifiers(target, source)
    return names[0] if names else None


def _is_awaited(call: Node) -> bool:
    parent = call.parent
    return bool(parent and parent.type in {"await", "await_expression"})


def _function_node(root: Node) -> Node | None:
    return next((node for node in _walk(root) if node.type in _FUNCTION_NODES), None)


def build_semantic_program(
    manifest: RepositoryManifest | None,
    chunks: Iterable[CodeChunk],
) -> SemanticProgram:
    """Normalize supported Python/JavaScript/TypeScript/TSX syntax into facts."""
    program = SemanticProgram()
    route_handlers = {
        (file_entry.path, str(symbol.details.get("handler") or symbol.name))
        for file_entry in (manifest.files if manifest is not None else [])
        for symbol in file_entry.symbols
        if symbol.kind in {SymbolKind.FASTAPI_ROUTE, SymbolKind.EXPRESS_ROUTE}
    }
    seen: set[tuple[str, str]] = set()

    def append(collection: list, fact: Any) -> None:
        if len(seen) >= 4096:
            program.coverage = {"complete": False, "reason": "semantic_fact_limit", "max_facts": 4096}
            return
        key = (type(fact).__name__, fact.fact_id)
        if key not in seen:
            seen.add(key)
            collection.append(fact)

    for chunk in sorted(chunks, key=lambda item: (item.end_line - item.start_line, item.chunk_id)):
        language = str(chunk.language or "").lower()
        if language not in {"python", "javascript", "typescript", "tsx"}:
            continue
        source = chunk.content.encode("utf-8")
        root = parse_syntax_tree(language, source)
        if root is None:
            continue
        function_node = _function_node(root)
        function_name_node = _field(function_node, "name") if function_node else None
        function_name = _text(function_name_node, source).strip() or chunk.symbol
        def fact_base(node: Node, kind: str, discriminator: str) -> dict[str, Any]:
            base = _fact_base(chunk, node, kind, discriminator)
            base["symbol"] = f"{chunk.file_path}:{function_name}:{function_base_line}"
            return base

        function_base_line = chunk.start_line + (function_node.start_point[0] if function_node else 0)
        is_route = (chunk.file_path, function_name) in route_handlers
        parameters_node = _field(function_node, "parameters") if function_node else None
        parameter_names = _parameter_names(parameters_node, source)
        function_base = fact_base(function_node or root, "function", function_name)
        is_async = bool(
            function_node
            and (
                any(child.type == "async" for child in function_node.children)
                or _text(function_node, source).lstrip().startswith("async ")
            )
        )
        append(program.functions, SemanticFunction(
            **function_base,
            name=function_name,
            parameter_names=parameter_names,
            is_async=is_async,
            is_route_handler=is_route,
        ))
        for position, name in enumerate(parameter_names):
            base = fact_base(parameters_node or function_node or root, "parameter", f"{position}:{name}")
            parameter = SemanticParameter(**base, name=name, position=position)
            append(program.parameters, parameter)
            append(program.sources, SemanticSource(
                **{
                    **base,
                    "certainty": (
                        SemanticCertainty.PROVEN
                        if is_route
                        else SemanticCertainty.POSSIBLE
                    ),
                },
                source_kind="ROUTE_PARAMETER" if is_route else "PARAMETER",
                name=name,
            ))

        for node in _scope_walk(function_node or root):
            if node.type in _CALL_NODES:
                callee = _callee_name(node, source)
                if not callee:
                    continue
                arguments_node = _field(node, "arguments")
                named_arguments = list(arguments_node.named_children) if arguments_node else []
                argument_expressions = [_text(arg, source)[:1_000] for arg in named_arguments][:32]
                argument_names = [_identifiers(arg, source)[:32] for arg in named_arguments][:32]
                base = fact_base(node, "call", callee)
                call = SemanticCallSite(
                    **base,
                    callee=callee,
                    argument_expressions=argument_expressions,
                    argument_names=argument_names,
                    result_target=_result_target(node, source),
                    awaited=_is_awaited(node),
                    result_discarded=bool(node.parent and node.parent.type == "expression_statement"),
                )
                append(program.calls, call)
                normalized = callee.lower()
                short_name = normalized.rsplit(".", 1)[-1]
                sanitizer_kind = _SANITIZERS.get(normalized) or _SANITIZERS.get(short_name)
                flat_names = sorted({name for group in argument_names for name in group})
                if sanitizer_kind:
                    append(program.sanitizers, SemanticSanitizer(
                        **base,
                        sanitizer_kind=sanitizer_kind,
                        name=callee,
                        argument_names=flat_names,
                    ))
                if normalized in _GUARD_CALLS or short_name in _GUARD_CALLS:
                    append(program.guards, SemanticGuard(
                        **base,
                        guard_kind="CALL_GUARD",
                        expression=callee,
                        referenced_names=flat_names,
                    ))
                sink_kind = _SINKS.get(normalized) or _SINKS.get(short_name)
                if sink_kind:
                    append(program.sinks, SemanticSink(**base, sink_kind=sink_kind, name=callee))
                    append(program.resources, SemanticResourceUse(
                        **base,
                        resource_kind=sink_kind,
                        operation=callee,
                        argument_names=flat_names,
                    ))

            elif node.type in _ASSIGNMENT_NODES:
                target = _field(node, "left", "name")
                value = _field(node, "right", "value")
                targets = _identifiers(target, source)
                if targets and value is not None:
                    base = fact_base(node, "assignment", targets[0])
                    append(program.assignments, SemanticAssignment(
                        **base,
                        target=targets[0],
                        source_names=_identifiers(value, source)[:32],
                    ))

            elif node.type in _RETURN_NODES:
                base = fact_base(node, "return", function_name)
                append(program.returns, SemanticReturn(
                    **base,
                    source_names=_identifiers(node, source)[:32],
                ))

            elif node.type in _GUARD_NODES:
                condition = _field(node, "condition")
                base = fact_base(node, "guard", node.type)
                append(program.guards, SemanticGuard(
                    **base,
                    guard_kind="CONTROL_GUARD",
                    expression=_text(condition, source)[:1_000],
                    referenced_names=_identifiers(condition, source)[:32],
                ))

            elif node.type in {"except_clause", "catch_clause"}:
                body = _field(node, "body") or next(
                    (child for child in node.named_children if child.type in {"block", "statement_block"}),
                    None,
                )
                named = list(body.named_children) if body else []
                meaningful = [child for child in named if child.type not in {"pass_statement", "comment"}]
                base = fact_base(node, "guard", "exception_handler")
                append(program.guards, SemanticGuard(
                    **base,
                    guard_kind="EXCEPTION_HANDLER",
                    expression=_text(node, source)[:1_000],
                    referenced_names=_identifiers(node, source)[:32],
                    metadata={
                        "empty": not meaningful,
                        "broad": language != "python" or any(
                            _text(child, source) in {"Exception", "BaseException"}
                            for child in node.named_children if child.type != "block"
                        ) or _text(node, source).lstrip().startswith("except:"),
                    },
                ))

    for field_name in SemanticProgram.model_fields:
        values = getattr(program, field_name)
        if isinstance(values, list):
            values.sort(key=lambda item: (item.file_path, item.start_line, item.fact_id))
    return program


__all__ = ["build_semantic_program"]
