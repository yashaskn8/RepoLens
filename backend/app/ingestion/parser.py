"""Tree-sitter structural parser for Python, JavaScript, TypeScript, and TSX."""

from functools import lru_cache
from typing import List, Optional
from tree_sitter import Language, Node, Parser
import tree_sitter_javascript as ts_js
import tree_sitter_python as ts_py
import tree_sitter_typescript as ts_ts

from app.ingestion.schemas import ParsedSymbol, SymbolKind


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


def _node_text(node: Node, source_bytes: bytes) -> str:
    """Extract utf-8 decoded text corresponding to AST node."""
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")


def _extract_python_symbols(root_node: Node, source_bytes: bytes) -> List[ParsedSymbol]:
    """Extract functions, classes, imports, and FastAPI routes from Python AST."""
    symbols: List[ParsedSymbol] = []

    def visit(node: Node):
        # 1. Decorated definitions (often FastAPI / Flask routes)
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

                # Check if any decorator represents a route (e.g. @app.get("/items"), @router.post("/items"))
                for dec in decorators:
                    # Match pattern like @(app|router|api_router).(get|post|put|delete|patch|options|head|api_route)("...")
                    for method in ("get", "post", "put", "delete", "patch", "options", "head", "api_route"):
                        if f".{method}(" in dec or f".{method} " in dec:
                            # Extract path string
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

                # Also record the function itself
                symbols.append(
                    ParsedSymbol(
                        name=func_name,
                        kind=SymbolKind.FUNCTION,
                        start_line=func_def_node.start_point[0] + 1,
                        end_line=func_def_node.end_point[0] + 1,
                        start_column=func_def_node.start_point[1],
                        end_column=func_def_node.end_point[1],
                        details={"async": func_def_node.type == "async_function_definition"},
                    )
                )

                # Visit inner children of function (e.g. nested calls)
                for child in func_def_node.children:
                    visit(child)
                return

        # 2. Regular function definition (not under decorated_definition)
        elif node.type in ("function_definition", "async_function_definition"):
            name_node = node.child_by_field_name("name")
            name = _node_text(name_node, source_bytes) if name_node else "anonymous"
            symbols.append(
                ParsedSymbol(
                    name=name,
                    kind=SymbolKind.FUNCTION,
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                    start_column=node.start_point[1],
                    end_column=node.end_point[1],
                    details={"async": node.type == "async_function_definition"},
                )
            )

        # 3. Class definition
        elif node.type == "class_definition":
            name_node = node.child_by_field_name("name")
            name = _node_text(name_node, source_bytes) if name_node else "anonymous"
            symbols.append(
                ParsedSymbol(
                    name=name,
                    kind=SymbolKind.CLASS,
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                    start_column=node.start_point[1],
                    end_column=node.end_point[1],
                )
            )

        # 4. Imports
        elif node.type in ("import_statement", "import_from_statement"):
            import_text = _node_text(node, source_bytes).strip()
            symbols.append(
                ParsedSymbol(
                    name=import_text,
                    kind=SymbolKind.IMPORT,
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                    start_column=node.start_point[1],
                    end_column=node.end_point[1],
                )
            )

        # 5. Call expressions (e.g. requests.get, httpx.post)
        elif node.type == "call":
            call_text = _node_text(node, source_bytes)
            if any(call_text.startswith(pkg) for pkg in ("requests.", "httpx.", "client.get", "client.post")):
                fn_node = node.child_by_field_name("function")
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

        for child in node.children:
            visit(child)

    visit(root_node)
    return symbols


def _extract_js_ts_symbols(root_node: Node, source_bytes: bytes) -> List[ParsedSymbol]:
    """Extract functions, classes, imports, express routes, and fetch/axios calls from JS/TS/TSX AST."""
    symbols: List[ParsedSymbol] = []

    def visit(node: Node):
        # 1. Function Declarations
        if node.type in ("function_declaration", "generator_function_declaration"):
            name_node = node.child_by_field_name("name")
            name = _node_text(name_node, source_bytes) if name_node else "anonymous"
            symbols.append(
                ParsedSymbol(
                    name=name,
                    kind=SymbolKind.FUNCTION,
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                    start_column=node.start_point[1],
                    end_column=node.end_point[1],
                )
            )

        # 2. Class Declarations
        elif node.type in ("class_declaration", "class"):
            name_node = node.child_by_field_name("name")
            name = _node_text(name_node, source_bytes) if name_node else "anonymous"
            symbols.append(
                ParsedSymbol(
                    name=name,
                    kind=SymbolKind.CLASS,
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                    start_column=node.start_point[1],
                    end_column=node.end_point[1],
                )
            )

        # 3. Method Definitions inside classes / objects
        elif node.type == "method_definition":
            name_node = node.child_by_field_name("name")
            name = _node_text(name_node, source_bytes) if name_node else "anonymous_method"
            symbols.append(
                ParsedSymbol(
                    name=name,
                    kind=SymbolKind.METHOD,
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                    start_column=node.start_point[1],
                    end_column=node.end_point[1],
                )
            )

        # 4. Imports (import ... from '...', require(...))
        elif node.type in ("import_statement", "import_declaration"):
            import_text = _node_text(node, source_bytes).strip()
            symbols.append(
                ParsedSymbol(
                    name=import_text,
                    kind=SymbolKind.IMPORT,
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                    start_column=node.start_point[1],
                    end_column=node.end_point[1],
                )
            )

        # 5. Call Expressions (Express routes, fetch, axios)
        elif node.type == "call_expression":
            fn_node = node.child_by_field_name("function")
            args_node = node.child_by_field_name("arguments")

            if fn_node:
                # Handle direct calls: fetch(...), axios(...)
                if fn_node.type == "identifier":
                    fn_name = _node_text(fn_node, source_bytes)
                    if fn_name == "fetch":
                        url_arg = "unknown"
                        if args_node and args_node.children:
                            for arg in args_node.children:
                                if arg.type in ("string", "template_string", "string_fragment", "identifier"):
                                    url_arg = _node_text(arg, source_bytes).strip("\"'`")
                                    break
                        symbols.append(
                            ParsedSymbol(
                                name=f"fetch({url_arg})",
                                kind=SymbolKind.FETCH_CALL,
                                start_line=node.start_point[0] + 1,
                                end_line=node.end_point[0] + 1,
                                start_column=node.start_point[1],
                                end_column=node.end_point[1],
                                details={"target": url_arg},
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
                                details={"callee": "axios", "target": target_url},
                            )
                        )

                # Handle member calls: app.get(...), router.post(...), axios.get(...)
                elif fn_node.type == "member_expression":
                    obj_node = fn_node.child_by_field_name("object")
                    prop_node = fn_node.child_by_field_name("property")
                    obj_text = _node_text(obj_node, source_bytes) if obj_node else ""
                    prop_text = _node_text(prop_node, source_bytes) if prop_node else ""

                    # Axios methods: axios.get, axios.post, etc.
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
                                details={"callee": f"axios.{prop_text}", "target": target_url},
                            )
                        )

                    # Express routes: (app|router|apiRouter|server).(get|post|put|delete|patch|use|all)
                    express_methods = ("get", "post", "put", "delete", "patch", "use", "all")
                    if prop_text.lower() in express_methods and (
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

        # 6. Variable declarations with arrow functions (e.g. const handleSubmit = async () => {})
        elif node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            val_node = node.child_by_field_name("value")
            if val_node and val_node.type in ("arrow_function", "function_expression"):
                name = _node_text(name_node, source_bytes) if name_node else "anonymous"
                symbols.append(
                    ParsedSymbol(
                        name=name,
                        kind=SymbolKind.FUNCTION,
                        start_line=node.start_point[0] + 1,
                        end_line=node.end_point[0] + 1,
                        start_column=node.start_point[1],
                        end_column=node.end_point[1],
                        details={"arrow_function": val_node.type == "arrow_function"},
                    )
                )

        for child in node.children:
            visit(child)

    visit(root_node)
    return symbols


def parse_file(file_path: str, language: str, source_bytes: bytes) -> List[ParsedSymbol]:
    """Parse source file using Tree-sitter and return list of extracted symbols."""
    lang_obj = _get_language(language)
    if not lang_obj:
        return []

    try:
        parser = Parser(lang_obj)
        tree = parser.parse(source_bytes)
        root = tree.root_node

        if language == "python":
            return _extract_python_symbols(root, source_bytes)
        elif language in ("javascript", "typescript", "tsx"):
            return _extract_js_ts_symbols(root, source_bytes)
    except Exception:
        pass

    return []
