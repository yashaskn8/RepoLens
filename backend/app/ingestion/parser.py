"""Tree-sitter structural parser for Python, JavaScript, TypeScript, and TSX with deterministic call extraction."""

import hashlib
import re
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple
from tree_sitter import Language, Node, Parser
import tree_sitter_javascript as ts_js
import tree_sitter_python as ts_py
import tree_sitter_typescript as ts_ts

from app.ingestion.schemas import ParsedCall, ParsedSymbol, SymbolKind


def compute_symbol_body_fingerprint(node: Optional[Node], source_bytes: bytes) -> str:
    """Compute deterministic, line-shift-independent structural body fingerprint using AST tokens."""
    if node is None:
        return ""
    body_node = node.child_by_field_name("body")
    target_node = body_node if body_node is not None else node

    tokens: List[str] = []

    def collect_tokens(curr: Node):
        # Skip AST comment nodes structurally
        if curr.type in ("comment", "line_comment", "block_comment"):
            return

        # If leaf node (no children), extract token text
        if curr.child_count == 0:
            text = _node_text(curr, source_bytes).strip()
            if text:
                tokens.append(text)
            return

        for child in curr.children:
            collect_tokens(child)

    collect_tokens(target_node)

    if not tokens:
        normalized = _node_text(target_node, source_bytes).strip()
    else:
        normalized = " ".join(tokens)

    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


@lru_cache
def _get_language(lang_name: str) -> Optional[Language]:
    """Retrieve cached tree-sitter Language instance."""
    try:
        if lang_name == "python":
            return Language(ts_py.language())
        elif lang_name == "javascript":
            return Language(ts_js.language())
        elif lang_name == "typescript":
            return Language(ts_ts.language_typescript())
        elif lang_name == "tsx":
            return Language(ts_ts.language_tsx())
    except Exception:
        pass
    return None


def _node_text(node: Optional[Node], source_bytes: bytes) -> str:
    """Extract utf-8 decoded text corresponding to AST node."""
    if node is None:
        return ""
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")


def _parse_python_import_details(node: Node, source_bytes: bytes) -> Dict[str, Any]:
    """Parse structured import details from a Python import node."""
    raw_text = _node_text(node, source_bytes).strip()
    details: Dict[str, Any] = {"raw": raw_text}

    if node.type == "import_from_statement":
        details["is_from"] = True
        module_parts = []
        imported_names: Dict[str, str] = {}  # local_alias -> source_symbol_name

        for child in node.children:
            if child.type == "dotted_name" and "from" in details and "module" not in details:
                details["module"] = _node_text(child, source_bytes)
            elif child.type == "relative_import":
                details["module"] = _node_text(child, source_bytes)
            elif child.type == "dotted_name" and "import" in _node_text(node, source_bytes):
                # Target imported symbol
                name = _node_text(child, source_bytes)
                if "module" in details:
                    imported_names[name] = name
                else:
                    details["module"] = name
            elif child.type == "aliased_import":
                orig_node = child.child_by_field_name("name")
                alias_node = child.child_by_field_name("alias")
                orig_name = _node_text(orig_node, source_bytes)
                alias_name = _node_text(alias_node, source_bytes) if alias_node else orig_name
                imported_names[alias_name] = orig_name
            elif child.type == "wildcard_import":
                details["wildcard"] = True

        # Fallback text parsing if AST children were unassigned
        if "module" not in details and "from " in raw_text:
            try:
                after_from = raw_text.split("from ", 1)[1].split(" import ", 1)[0].strip()
                details["module"] = after_from
            except Exception:
                pass

        if not imported_names and " import " in raw_text:
            try:
                after_import = raw_text.split(" import ", 1)[1].strip()
                for item in after_import.split(","):
                    parts = item.strip().split(" as ")
                    if len(parts) == 2:
                        imported_names[parts[1].strip()] = parts[0].strip()
                    elif parts and parts[0]:
                        imported_names[parts[0].strip()] = parts[0].strip()
            except Exception:
                pass

        details["imported_names"] = imported_names

    elif node.type == "import_statement":
        details["is_from"] = False
        modules: Dict[str, str] = {}  # local_alias -> module_name
        for child in node.children:
            if child.type == "dotted_name":
                m_name = _node_text(child, source_bytes)
                modules[m_name] = m_name
            elif child.type == "aliased_import":
                orig_node = child.child_by_field_name("name")
                alias_node = child.child_by_field_name("alias")
                orig_name = _node_text(orig_node, source_bytes)
                alias_name = _node_text(alias_node, source_bytes) if alias_node else orig_name
                modules[alias_name] = orig_name

        if not modules and "import " in raw_text:
            try:
                after_import = raw_text.split("import ", 1)[1].strip()
                for item in after_import.split(","):
                    parts = item.strip().split(" as ")
                    if len(parts) == 2:
                        modules[parts[1].strip()] = parts[0].strip()
                    elif parts and parts[0]:
                        modules[parts[0].strip()] = parts[0].strip()
            except Exception:
                pass

        details["modules"] = modules

    return details


def _parse_js_ts_import_details(node: Node, source_bytes: bytes) -> Dict[str, Any]:
    """Parse structured import details from a JS/TS import node."""
    raw_text = _node_text(node, source_bytes).strip()
    details: Dict[str, Any] = {"raw": raw_text, "imported_names": {}}

    # Extract source string (e.g. from './auth')
    for child in node.children:
        if child.type == "string":
            details["source"] = _node_text(child, source_bytes).strip("\"'`")

    # Fallback source extraction
    if "source" not in details and " from " in raw_text:
        try:
            details["source"] = raw_text.split(" from ", 1)[1].strip().strip(";\"'`")
        except Exception:
            pass

    # Extract named, namespace, and default imports
    imported_names: Dict[str, str] = {}
    for child in node.children:
        if child.type == "import_clause":
            for sub in child.children:
                if sub.type == "named_imports":
                    for spec in sub.children:
                        if spec.type == "import_specifier":
                            name_node = spec.child_by_field_name("name")
                            alias_node = spec.child_by_field_name("alias")
                            orig = _node_text(name_node, source_bytes)
                            alias = _node_text(alias_node, source_bytes) if alias_node else orig
                            if orig:
                                imported_names[alias] = orig
                elif sub.type == "namespace_import":
                    for ns_child in sub.children:
                        if ns_child.type == "identifier":
                            details["namespace_import"] = _node_text(ns_child, source_bytes)
                elif sub.type == "identifier":
                    details["default_import"] = _node_text(sub, source_bytes)

    # Fallback text extraction for named imports: import { a, b as c } from '...'
    if not imported_names and "{" in raw_text and "}" in raw_text:
        try:
            inside = raw_text.split("{", 1)[1].split("}", 1)[0]
            for item in inside.split(","):
                parts = item.strip().split(" as ")
                if len(parts) == 2:
                    imported_names[parts[1].strip()] = parts[0].strip()
                elif parts and parts[0]:
                    imported_names[parts[0].strip()] = parts[0].strip()
        except Exception:
            pass

    details["imported_names"] = imported_names
    return details


def _extract_python_symbols_and_calls(
    root_node: Node,
    source_bytes: bytes,
) -> Tuple[List[ParsedSymbol], List[ParsedCall]]:
    """Extract functions, classes, imports, FastAPI routes, and resolvable call sites from Python AST."""
    symbols: List[ParsedSymbol] = []
    calls: List[ParsedCall] = []

    def visit(node: Node, caller_ctx: Optional[Dict[str, Any]] = None):
        # 1. Decorated definitions (FastAPI / Flask routes)
        if node.type == "decorated_definition":
            decorators = []
            func_def_node = None
            for child in node.children:
                if child.type == "decorator":
                    decorators.append(_node_text(child, source_bytes))
                elif child.type in ("function_definition", "async_function_definition"):
                    func_def_node = child

            if func_def_node:
                name_node = func_def_node.child_by_field_name("name")
                func_name = _node_text(name_node, source_bytes) if name_node else "unknown"
                start_l = func_def_node.start_point[0] + 1
                end_l = func_def_node.end_point[0] + 1

                for dec in decorators:
                    for method in ("get", "post", "put", "delete", "patch", "options", "head", "api_route"):
                        if f".{method}(" in dec or f".{method} " in dec:
                            path = "unknown"
                            if "(" in dec:
                                inside = dec[dec.index("(") + 1:].split(")")[0]
                                parts = inside.split(",")
                                if parts and parts[0]:
                                    path = parts[0].strip().strip("\"'")
                            symbols.append(
                                ParsedSymbol(
                                    name=f"{method.upper()} {path}",
                                    kind=SymbolKind.FASTAPI_ROUTE,
                                    start_line=node.start_point[0] + 1,
                                    end_line=node.end_point[0] + 1,
                                    start_column=node.start_point[1],
                                    end_column=node.end_point[1],
                                    details={
                                        "http_method": method.upper(),
                                        "path": path,
                                        "handler": func_name,
                                        "decorator": dec,
                                    },
                                )
                            )

                params_node = func_def_node.child_by_field_name("parameters")
                return_type_node = func_def_node.child_by_field_name("return_type")
                params_text = _node_text(params_node, source_bytes).strip() if params_node else ""
                return_type_text = _node_text(return_type_node, source_bytes).strip() if return_type_node else ""
                fp = compute_symbol_body_fingerprint(func_def_node, source_bytes)

                symbols.append(
                    ParsedSymbol(
                        name=func_name,
                        kind=SymbolKind.FUNCTION,
                        start_line=start_l,
                        end_line=end_l,
                        start_column=func_def_node.start_point[1],
                        end_column=func_def_node.end_point[1],
                        details={
                            "async": func_def_node.type == "async_function_definition",
                            "parameters": params_text,
                            "return_type": return_type_text,
                            "body_fingerprint": fp,
                        },
                    )
                )

                new_ctx = {"name": func_name, "kind": "FUNCTION", "start_line": start_l}
                for child in func_def_node.children:
                    visit(child, new_ctx)
                return

        # 2. Function definition
        elif node.type in ("function_definition", "async_function_definition"):
            name_node = node.child_by_field_name("name")
            name = _node_text(name_node, source_bytes) if name_node else "anonymous"
            start_l = node.start_point[0] + 1
            end_l = node.end_point[0] + 1
            kind = SymbolKind.METHOD if (caller_ctx and caller_ctx.get("kind") == "CLASS") else SymbolKind.FUNCTION

            params_node = node.child_by_field_name("parameters")
            return_type_node = node.child_by_field_name("return_type")
            params_text = _node_text(params_node, source_bytes).strip() if params_node else ""
            return_type_text = _node_text(return_type_node, source_bytes).strip() if return_type_node else ""
            fp = compute_symbol_body_fingerprint(node, source_bytes)

            symbols.append(
                ParsedSymbol(
                    name=name,
                    kind=kind,
                    start_line=start_l,
                    end_line=end_l,
                    start_column=node.start_point[1],
                    end_column=node.end_point[1],
                    details={
                        "async": node.type == "async_function_definition",
                        "parameters": params_text,
                        "return_type": return_type_text,
                        "body_fingerprint": fp,
                    },
                )
            )

            new_ctx = {"name": name, "kind": kind.value, "start_line": start_l}
            for child in node.children:
                visit(child, new_ctx)
            return

        # 3. Class definition
        elif node.type == "class_definition":
            name_node = node.child_by_field_name("name")
            name = _node_text(name_node, source_bytes) if name_node else "anonymous"
            start_l = node.start_point[0] + 1
            end_l = node.end_point[0] + 1
            fp = compute_symbol_body_fingerprint(node, source_bytes)

            # Extract superclasses
            superclasses_node = node.child_by_field_name("superclasses")
            superclasses = []
            if superclasses_node:
                for arg in superclasses_node.children:
                    if arg.type in ("identifier", "attribute"):
                        superclasses.append(_node_text(arg, source_bytes))

            # Extract class body fields / attributes
            body_node = node.child_by_field_name("body")
            fields: Dict[str, str] = {}
            if body_node:
                for child in body_node.children:
                    if child.type == "expression_statement":
                        for sub in child.children:
                            if sub.type in ("assignment", "annotated_assignment"):
                                left_node = sub.child_by_field_name("left")
                                type_node = sub.child_by_field_name("type")
                                val_node = sub.child_by_field_name("value") or sub.child_by_field_name("right")
                                if left_node:
                                    f_name = _node_text(left_node, source_bytes).strip()
                                    f_type = _node_text(type_node, source_bytes).strip() if type_node else (_node_text(val_node, source_bytes).strip() if val_node else "Any")
                                    fields[f_name] = f_type

            symbols.append(
                ParsedSymbol(
                    name=name,
                    kind=SymbolKind.CLASS,
                    start_line=start_l,
                    end_line=end_l,
                    start_column=node.start_point[1],
                    end_column=node.end_point[1],
                    details={"superclasses": superclasses, "fields": fields, "body_fingerprint": fp},
                )
            )

            new_ctx = {"name": name, "kind": "CLASS", "start_line": start_l}
            for child in node.children:
                visit(child, new_ctx)
            return

        # 4. Imports
        elif node.type in ("import_statement", "import_from_statement"):
            import_text = _node_text(node, source_bytes).strip()
            import_details = _parse_python_import_details(node, source_bytes)

            symbols.append(
                ParsedSymbol(
                    name=import_text,
                    kind=SymbolKind.IMPORT,
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                    start_column=node.start_point[1],
                    end_column=node.end_point[1],
                    details=import_details,
                )
            )

        # 5. Call expressions
        elif node.type == "call":
            fn_node = node.child_by_field_name("function")
            call_text = _node_text(node, source_bytes)

            # Special case for fetch/requests HTTP client symbols
            if any(call_text.startswith(pkg) for pkg in ("requests.", "httpx.", "client.get", "client.post")):
                fn_name = _node_text(fn_node, source_bytes) if fn_node else "http_call"
                symbols.append(
                    ParsedSymbol(
                        name=fn_name,
                        kind=SymbolKind.FETCH_CALL,
                        start_line=node.start_point[0] + 1,
                        end_line=node.end_point[0] + 1,
                        details={"snippet": call_text.splitlines()[0] if call_text else ""},
                    )
                )

            # Extract general function/method call
            if fn_node:
                if fn_node.type == "identifier":
                    fn_name = _node_text(fn_node, source_bytes)
                    calls.append(
                        ParsedCall(
                            callee=fn_name,
                            callee_name=fn_name,
                            callee_base=None,
                            line_number=node.start_point[0] + 1,
                            column_number=node.start_point[1],
                            caller_name=caller_ctx["name"] if caller_ctx else None,
                            caller_kind=caller_ctx["kind"] if caller_ctx else None,
                            caller_start_line=caller_ctx["start_line"] if caller_ctx else None,
                        )
                    )
                elif fn_node.type == "attribute":
                    obj_node = fn_node.child_by_field_name("object")
                    attr_node = fn_node.child_by_field_name("attribute")
                    obj_text = _node_text(obj_node, source_bytes)
                    attr_text = _node_text(attr_node, source_bytes)
                    calls.append(
                        ParsedCall(
                            callee=f"{obj_text}.{attr_text}" if obj_text and attr_text else attr_text,
                            callee_name=attr_text,
                            callee_base=obj_text or None,
                            line_number=node.start_point[0] + 1,
                            column_number=node.start_point[1],
                            caller_name=caller_ctx["name"] if caller_ctx else None,
                            caller_kind=caller_ctx["kind"] if caller_ctx else None,
                            caller_start_line=caller_ctx["start_line"] if caller_ctx else None,
                        )
                    )

        for child in node.children:
            visit(child, caller_ctx)

    visit(root_node)
    return symbols, calls


def _extract_js_ts_symbols_and_calls(
    root_node: Node,
    source_bytes: bytes,
) -> Tuple[List[ParsedSymbol], List[ParsedCall]]:
    """Extract functions, classes, imports, express routes, and resolvable call sites from JS/TS AST."""
    symbols: List[ParsedSymbol] = []
    calls: List[ParsedCall] = []

    def visit(node: Node, caller_ctx: Optional[Dict[str, Any]] = None):
        # 1. Function Declarations
        if node.type in ("function_declaration", "generator_function_declaration"):
            name_node = node.child_by_field_name("name")
            name = _node_text(name_node, source_bytes) if name_node else "anonymous"
            start_l = node.start_point[0] + 1
            end_l = node.end_point[0] + 1

            params_node = node.child_by_field_name("parameters")
            return_type_node = node.child_by_field_name("return_type")
            params_text = _node_text(params_node, source_bytes).strip() if params_node else ""
            return_type_text = _node_text(return_type_node, source_bytes).strip() if return_type_node else ""
            fp = compute_symbol_body_fingerprint(node, source_bytes)

            symbols.append(
                ParsedSymbol(
                    name=name,
                    kind=SymbolKind.FUNCTION,
                    start_line=start_l,
                    end_line=end_l,
                    start_column=node.start_point[1],
                    end_column=node.end_point[1],
                    details={
                        "parameters": params_text,
                        "return_type": return_type_text,
                        "body_fingerprint": fp,
                    },
                )
            )

            new_ctx = {"name": name, "kind": "FUNCTION", "start_line": start_l}
            for child in node.children:
                visit(child, new_ctx)
            return

        # 2. Class Declarations
        elif node.type in ("class_declaration", "class"):
            name_node = node.child_by_field_name("name")
            name = _node_text(name_node, source_bytes) if name_node else "anonymous"
            start_l = node.start_point[0] + 1
            end_l = node.end_point[0] + 1
            fp = compute_symbol_body_fingerprint(node, source_bytes)

            heritage_node = None
            for ch in node.children:
                if ch.type in ("class_heritage", "heritage"):
                    heritage_node = ch
                    break
            heritage_text = _node_text(heritage_node, source_bytes).strip() if heritage_node else ""

            body_node = node.child_by_field_name("body")
            fields: Dict[str, str] = {}
            if body_node:
                for child in body_node.children:
                    if child.type in ("field_definition", "public_field_definition", "property_definition"):
                        prop_name_node = child.child_by_field_name("name") or child.child_by_field_name("property")
                        type_node = child.child_by_field_name("type")
                        if prop_name_node:
                            p_name = _node_text(prop_name_node, source_bytes).strip()
                            p_type = _node_text(type_node, source_bytes).strip() if type_node else "any"
                            fields[p_name] = p_type

            symbols.append(
                ParsedSymbol(
                    name=name,
                    kind=SymbolKind.CLASS,
                    start_line=start_l,
                    end_line=end_l,
                    start_column=node.start_point[1],
                    end_column=node.end_point[1],
                    details={"heritage": heritage_text, "fields": fields, "body_fingerprint": fp},
                )
            )

            new_ctx = {"name": name, "kind": "CLASS", "start_line": start_l}
            for child in node.children:
                visit(child, new_ctx)
            return

        # 3. Method Definitions
        elif node.type == "method_definition":
            name_node = node.child_by_field_name("name")
            name = _node_text(name_node, source_bytes) if name_node else "anonymous_method"
            start_l = node.start_point[0] + 1
            end_l = node.end_point[0] + 1
            fp = compute_symbol_body_fingerprint(node, source_bytes)

            params_node = node.child_by_field_name("parameters")
            return_type_node = node.child_by_field_name("return_type")
            params_text = _node_text(params_node, source_bytes).strip() if params_node else ""
            return_type_text = _node_text(return_type_node, source_bytes).strip() if return_type_node else ""

            symbols.append(
                ParsedSymbol(
                    name=name,
                    kind=SymbolKind.METHOD,
                    start_line=start_l,
                    end_line=end_l,
                    start_column=node.start_point[1],
                    end_column=node.end_point[1],
                    details={
                        "parameters": params_text,
                        "return_type": return_type_text,
                        "body_fingerprint": fp,
                    },
                )
            )

            new_ctx = {"name": name, "kind": "METHOD", "start_line": start_l}
            for child in node.children:
                visit(child, new_ctx)
            return

        # 4. Variable declarations with arrow functions / function expressions
        elif node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            val_node = node.child_by_field_name("value")
            if val_node and val_node.type in ("arrow_function", "function_expression"):
                name = _node_text(name_node, source_bytes) if name_node else "anonymous"
                start_l = node.start_point[0] + 1
                end_l = node.end_point[0] + 1
                fp = compute_symbol_body_fingerprint(val_node, source_bytes)

                symbols.append(
                    ParsedSymbol(
                        name=name,
                        kind=SymbolKind.FUNCTION,
                        start_line=start_l,
                        end_line=end_l,
                        start_column=node.start_point[1],
                        end_column=node.end_point[1],
                        details={"arrow_function": val_node.type == "arrow_function", "body_fingerprint": fp},
                    )
                )

                new_ctx = {"name": name, "kind": "FUNCTION", "start_line": start_l}
                for child in node.children:
                    visit(child, new_ctx)
                return

        # 5. Imports
        elif node.type in ("import_statement", "import_declaration", "export_statement"):
            import_text = _node_text(node, source_bytes).strip()
            import_details = _parse_js_ts_import_details(node, source_bytes)

            # Re-exports with an explicit source are module dependencies;
            # local/default export declarations are not imports.
            if node.type != "export_statement" or import_details.get("source"):
                symbols.append(
                ParsedSymbol(
                    name=import_text,
                    kind=SymbolKind.IMPORT,
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                    start_column=node.start_point[1],
                    end_column=node.end_point[1],
                    details=import_details,
                ))

        # 6. Call Expressions
        elif node.type == "call_expression":
            fn_node = node.child_by_field_name("function")
            args_node = node.child_by_field_name("arguments")

            if fn_node:
                # Direct calls: fetch(...), axios(...), or regular identifier calls
                if fn_node.type == "identifier":
                    fn_name = _node_text(fn_node, source_bytes)
                    if fn_name == "fetch":
                        url_arg = "unknown"
                        http_method = "GET"  # fetch() defaults to GET
                        if args_node and args_node.children:
                            for arg in args_node.children:
                                if arg.type in ("string", "template_string", "string_fragment", "identifier"):
                                    url_arg = _node_text(arg, source_bytes).strip("\"'`")
                                    break
                            # Extract HTTP method from options object: fetch(url, { method: 'POST' })
                            for arg in args_node.children:
                                if arg.type == "object":
                                    for prop in arg.children:
                                        if prop.type in ("pair", "property"):
                                            key_node = prop.child_by_field_name("key")
                                            val_node = prop.child_by_field_name("value")
                                            if key_node and val_node:
                                                key_text = _node_text(key_node, source_bytes).strip("\"'")
                                                if key_text == "method":
                                                    val_text = _node_text(val_node, source_bytes).strip("\"'`")
                                                    if val_text.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                                                        http_method = val_text.upper()
                                    break  # Only inspect first object argument
                        symbols.append(
                            ParsedSymbol(
                                name=f"fetch({url_arg})",
                                kind=SymbolKind.FETCH_CALL,
                                start_line=node.start_point[0] + 1,
                                end_line=node.end_point[0] + 1,
                                start_column=node.start_point[1],
                                end_column=node.end_point[1],
                                details={"target": url_arg, "url": url_arg, "http_method": http_method},
                            )
                        )
                    elif fn_name == "axios":
                        target_url = "unknown"
                        if args_node and args_node.children:
                            for arg in args_node.children:
                                if arg.type in ("string", "template_string", "string_fragment", "identifier"):
                                    target_url = _node_text(arg, source_bytes).strip("\"'`")
                                    break
                        symbols.append(
                            ParsedSymbol(
                                name=f"axios({target_url})",
                                kind=SymbolKind.AXIOS_CALL,
                                start_line=node.start_point[0] + 1,
                                end_line=node.end_point[0] + 1,
                                start_column=node.start_point[1],
                                end_column=node.end_point[1],
                                details={"callee": "axios", "target": target_url, "url": target_url},
                            )
                        )
                    else:
                        # Regular function call
                        calls.append(
                            ParsedCall(
                                callee=fn_name,
                                callee_name=fn_name,
                                callee_base=None,
                                line_number=node.start_point[0] + 1,
                                column_number=node.start_point[1],
                                caller_name=caller_ctx["name"] if caller_ctx else None,
                                caller_kind=caller_ctx["kind"] if caller_ctx else None,
                                caller_start_line=caller_ctx["start_line"] if caller_ctx else None,
                            )
                        )

                # Member calls: obj.method(...)
                elif fn_node.type == "member_expression":
                    obj_node = fn_node.child_by_field_name("object")
                    prop_node = fn_node.child_by_field_name("property")
                    obj_text = _node_text(obj_node, source_bytes) if obj_node else ""
                    prop_text = _node_text(prop_node, source_bytes) if prop_node else ""

                    # Axios methods
                    if obj_text == "axios" and prop_text in ("get", "post", "put", "delete", "patch", "request"):
                        target_url = "unknown"
                        if args_node and args_node.children:
                            for arg in args_node.children:
                                if arg.type in ("string", "template_string", "string_fragment", "identifier"):
                                    target_url = _node_text(arg, source_bytes).strip("\"'`")
                                    break
                        symbols.append(
                            ParsedSymbol(
                                name=f"axios.{prop_text}({target_url})",
                                kind=SymbolKind.AXIOS_CALL,
                                start_line=node.start_point[0] + 1,
                                end_line=node.end_point[0] + 1,
                                start_column=node.start_point[1],
                                end_column=node.end_point[1],
                                details={"callee": f"axios.{prop_text}", "target": target_url, "url": target_url},
                            )
                        )
                    # Express routes
                    elif prop_text.lower() in ("get", "post", "put", "delete", "patch", "use", "all") and (
                        obj_text in ("app", "router", "apiRouter", "server", "routes") or obj_text.endswith("Router")
                    ):
                        path = "unknown"
                        if args_node and args_node.children:
                            for arg in args_node.children:
                                if arg.type in ("string", "template_string", "string_fragment"):
                                    path = _node_text(arg, source_bytes).strip("\"'`")
                                    break
                        symbols.append(
                            ParsedSymbol(
                                name=f"{prop_text.upper()} {path}",
                                kind=SymbolKind.EXPRESS_ROUTE,
                                start_line=node.start_point[0] + 1,
                                end_line=node.end_point[0] + 1,
                                start_column=node.start_point[1],
                                end_column=node.end_point[1],
                                details={"http_method": prop_text.upper(), "path": path, "callee": f"{obj_text}.{prop_text}"},
                            )
                        )
                    else:
                        # General member call
                        calls.append(
                            ParsedCall(
                                callee=f"{obj_text}.{prop_text}" if obj_text and prop_text else prop_text,
                                callee_name=prop_text,
                                callee_base=obj_text or None,
                                line_number=node.start_point[0] + 1,
                                column_number=node.start_point[1],
                                caller_name=caller_ctx["name"] if caller_ctx else None,
                                caller_kind=caller_ctx["kind"] if caller_ctx else None,
                                caller_start_line=caller_ctx["start_line"] if caller_ctx else None,
                            )
                        )

        for child in node.children:
            visit(child, caller_ctx)

    visit(root_node)
    return symbols, calls


def parse_file_with_calls(
    file_path: str,
    language: str,
    source_bytes: bytes,
) -> Tuple[List[ParsedSymbol], List[ParsedCall]]:
    """Parse source file using Tree-sitter, returning both extracted symbols and function call sites."""
    lang_obj = _get_language(language)
    if not lang_obj:
        return [], []

    try:
        parser = Parser(lang_obj)
        tree = parser.parse(source_bytes)
        root = tree.root_node

        if language == "python":
            return _extract_python_symbols_and_calls(root, source_bytes)
        elif language in ("javascript", "typescript", "tsx"):
            return _extract_js_ts_symbols_and_calls(root, source_bytes)
    except Exception:
        pass

    return [], []


def parse_syntax_tree(language: str, source_bytes: bytes) -> Optional[Node]:
    """Return a Tree-sitter root for supported source without executing repository code."""
    lang_obj = _get_language(language)
    if not lang_obj:
        return None
    try:
        return Parser(lang_obj).parse(source_bytes).root_node
    except Exception:
        return None


def parse_file(file_path: str, language: str, source_bytes: bytes) -> List[ParsedSymbol]:
    """Parse source file using Tree-sitter and return list of extracted symbols (backward-compatible)."""
    symbols, _ = parse_file_with_calls(file_path, language, source_bytes)
    return symbols
