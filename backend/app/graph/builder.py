"""Deterministic graph builder constructing RepositoryGraph from structural AST manifest evidence."""

import os
from typing import Any, Dict, List, Optional, Set, Tuple

from app.analysis.store import EvidenceStore
from app.graph.repository_graph import RepositoryGraph
from app.graph.schemas import EdgeKind, NodeKind
from app.ingestion.schemas import RepositoryManifest, SymbolKind


def _is_test_file(path: str) -> bool:
    """Determine if a file path is a test file by standard conventions."""
    normalized = path.replace("\\", "/").lower()
    base = os.path.basename(normalized)

    if (
        normalized.startswith(("tests/", "test/", "__tests__/"))
        or "/tests/" in normalized
        or "/test/" in normalized
        or "/__tests__/" in normalized
    ):
        return True

    return bool(
        base.startswith("test_")
        or base.endswith(("_test.py", ".test.js", ".test.ts", ".test.tsx", ".spec.js", ".spec.ts", ".spec.tsx"))
    )


def _infer_tested_file_path(test_path: str) -> Optional[str]:
    """Infer the production file path targeted by a test file."""
    normalized = test_path.replace("\\", "/")
    base = os.path.basename(normalized)

    if base.startswith("test_"):
        target_base = base[5:]
    elif base.endswith("_test.py"):
        target_base = base[:-8] + ".py"
    elif ".test." in base:
        target_base = base.replace(".test.", ".")
    elif ".spec." in base:
        target_base = base.replace(".spec.", ".")
    else:
        return None

    return target_base


def _resolve_python_module_to_file(
    module_str: str,
    source_file: str,
    all_file_paths: Set[str],
) -> Optional[str]:
    """Deterministically resolve a Python module string to a concrete file path in repository."""
    if not module_str:
        return None

    # 1. Handle relative imports (e.g. .utils, ..services.auth)
    if module_str.startswith("."):
        leading_dots = len(module_str) - len(module_str.lstrip("."))
        remainder = module_str[leading_dots:].replace(".", "/")

        source_dir = os.path.dirname(source_file)
        curr_dir = source_dir
        for _ in range(leading_dots - 1):
            curr_dir = os.path.dirname(curr_dir)

        candidate_rel = os.path.normpath(os.path.join(curr_dir, remainder)).replace("\\", "/")
        candidates = [
            f"{candidate_rel}.py",
            f"{candidate_rel}/__init__.py",
        ]
        for cand in candidates:
            if cand in all_file_paths:
                return cand
        return None

    # 2. Handle absolute module strings (e.g. app.services.auth)
    module_path = module_str.replace(".", "/")
    candidates = [
        f"{module_path}.py",
        f"{module_path}/__init__.py",
    ]
    for cand in candidates:
        if cand in all_file_paths:
            return cand

    # 3. Check suffix match (e.g. backend/app/services/auth.py)
    matching = [
        f for f in all_file_paths
        if f.endswith(f"/{module_path}.py") or f.endswith(f"/{module_path}/__init__.py") or f == f"{module_path}.py"
    ]
    if len(matching) == 1:
        return matching[0]

    return None


def _resolve_js_ts_module_to_file(
    source_str: str,
    source_file: str,
    all_file_paths: Set[str],
) -> Optional[str]:
    """Deterministically resolve a JS/TS relative or alias import string to a concrete file path."""
    if not source_str:
        return None

    source_dir = os.path.dirname(source_file)

    # Relative imports starting with ./ or ../ or .
    if source_str.startswith(("./", "../", ".")):
        norm_path = os.path.normpath(os.path.join(source_dir, source_str)).replace("\\", "/")
        extensions = [".ts", ".tsx", ".js", ".jsx", ".d.ts", "/index.ts", "/index.tsx", "/index.js", "/index.jsx"]
        for ext in extensions:
            cand = f"{norm_path}{ext}"
            if cand in all_file_paths:
                return cand
        if norm_path in all_file_paths:
            return norm_path
        return None

    # Suffix match for non-relative aliases
    matching = [
        f for f in all_file_paths
        if f.endswith(f"/{source_str}.ts")
        or f.endswith(f"/{source_str}.tsx")
        or f.endswith(f"/{source_str}.js")
        or f.endswith(f"/{source_str}/index.ts")
        or f.endswith(f"/{source_str}/index.js")
    ]
    if len(matching) == 1:
        return matching[0]

    return None


def build_repository_graph(
    manifest: RepositoryManifest,
    evidence_store: Optional[EvidenceStore] = None,
) -> RepositoryGraph:
    """Deterministically build canonical RepositoryGraph using three-pass node & edge wiring."""
    graph = RepositoryGraph()
    all_file_paths = {f.path.replace("\\", "/") for f in manifest.files}

    # Index functions, methods, and imports for fast deterministic resolution
    functions_by_file: Dict[str, Dict[str, List[Tuple[int, str]]]] = {}
    imports_by_file: Dict[str, List[Dict[str, Any]]] = {}

    # =========================================================================
    # PASS 1: Register ALL Nodes First
    # =========================================================================
    for file_entry in manifest.files:
        clean_path = file_entry.path.replace("\\", "/")
        file_node_id = f"file:{clean_path}"
        is_test = _is_test_file(clean_path)

        functions_by_file[clean_path] = {}
        imports_by_file[clean_path] = []

        if is_test:
            test_node_id = f"test:{clean_path}"
            graph.add_node(
                node_id=test_node_id,
                kind=NodeKind.TEST,
                label=os.path.basename(clean_path),
                file_path=clean_path,
                start_line=1,
                end_line=file_entry.lines_count,
                metadata={"lines_count": file_entry.lines_count, "language": file_entry.language},
            )

        graph.add_node(
            node_id=file_node_id,
            kind=NodeKind.FILE,
            label=clean_path,
            file_path=clean_path,
            start_line=1,
            end_line=file_entry.lines_count,
            metadata={
                "language": file_entry.language,
                "size_bytes": file_entry.size_bytes,
                "lines_count": file_entry.lines_count,
                "is_binary": file_entry.is_binary,
                "is_test": is_test,
            },
        )

        for sym in file_entry.symbols:
            if sym.kind in (SymbolKind.FASTAPI_ROUTE, SymbolKind.EXPRESS_ROUTE):
                http_method = str(sym.details.get("http_method", "GET")).upper()
                route_path = str(sym.details.get("path", "/"))
                route_node_id = f"route:{http_method}:{route_path}"

                graph.add_node(
                    node_id=route_node_id,
                    kind=NodeKind.ROUTE,
                    label=f"{http_method} {route_path}",
                    file_path=clean_path,
                    start_line=sym.start_line,
                    end_line=sym.end_line,
                    metadata={
                        "http_method": http_method,
                        "path": route_path,
                        "framework": "fastapi" if sym.kind == SymbolKind.FASTAPI_ROUTE else "express",
                        "handler_name": sym.name,
                    },
                )

                handler_sym_id = f"symbol:{clean_path}:FUNCTION:{sym.name}:{sym.start_line}"
                graph.add_node(
                    node_id=handler_sym_id,
                    kind=NodeKind.SYMBOL,
                    label=sym.name,
                    file_path=clean_path,
                    start_line=sym.start_line,
                    end_line=sym.end_line,
                    metadata={"kind": "FUNCTION", "route_handler": True},
                )
                handler_name = sym.details.get("handler") or sym.name
                functions_by_file[clean_path].setdefault(handler_name, []).append((sym.start_line, handler_sym_id))

            elif sym.kind in (SymbolKind.FETCH_CALL, SymbolKind.AXIOS_CALL):
                target_url = str(sym.details.get("url", "/"))
                http_method = str(sym.details.get("http_method", "GET")).upper()
                client_type = "axios" if sym.kind == SymbolKind.AXIOS_CALL else "fetch"
                req_node_id = f"req:{clean_path}:{sym.start_line}:{http_method}:{target_url}"

                graph.add_node(
                    node_id=req_node_id,
                    kind=NodeKind.FRONTEND_REQUEST,
                    label=f"{http_method} {target_url}",
                    file_path=clean_path,
                    start_line=sym.start_line,
                    end_line=sym.end_line,
                    metadata={
                        "http_method": http_method,
                        "url": target_url,
                        "client": client_type,
                    },
                )

            else:
                sym_node_id = f"symbol:{clean_path}:{sym.kind.value}:{sym.name}:{sym.start_line}"
                graph.add_node(
                    node_id=sym_node_id,
                    kind=NodeKind.SYMBOL,
                    label=sym.name,
                    file_path=clean_path,
                    start_line=sym.start_line,
                    end_line=sym.end_line,
                    metadata={"kind": sym.kind.value, "details": sym.details},
                )

                if sym.kind in (SymbolKind.FUNCTION, SymbolKind.METHOD):
                    functions_by_file[clean_path].setdefault(sym.name, []).append((sym.start_line, sym_node_id))
                elif sym.kind == SymbolKind.IMPORT:
                    imports_by_file[clean_path].append(sym.details or {})

    for fw in manifest.frameworks:
        dep_node_id = f"dep:{fw.name.lower()}"
        graph.add_node(
            node_id=dep_node_id,
            kind=NodeKind.DEPENDENCY,
            label=fw.name,
            metadata={"version": fw.version, "evidence": fw.evidence},
        )

    # =========================================================================
    # PASS 2: Wire Structural, Containment, and Import Edges
    # =========================================================================
    for file_entry in manifest.files:
        clean_path = file_entry.path.replace("\\", "/")
        file_node_id = f"file:{clean_path}"
        is_test = _is_test_file(clean_path)

        if is_test:
            graph.add_edge(file_node_id, f"test:{clean_path}", EdgeKind.CONTAINS)

            # Test -> Tested File Edge
            inferred_target_base = _infer_tested_file_path(clean_path)
            if inferred_target_base:
                for cand_f in all_file_paths:
                    if not _is_test_file(cand_f) and (cand_f.endswith(inferred_target_base) or os.path.basename(cand_f) == inferred_target_base):
                        graph.add_edge(
                            source_id=f"test:{clean_path}",
                            target_id=f"file:{cand_f}",
                            kind=EdgeKind.TESTS,
                            metadata={"inferred": True},
                        )

        # File -> Dependency Edges
        if clean_path.endswith(("package.json", "requirements.txt", "pyproject.toml", "Pipfile", "go.mod")):
            for fw in manifest.frameworks:
                graph.add_edge(
                    source_id=file_node_id,
                    target_id=f"dep:{fw.name.lower()}",
                    kind=EdgeKind.DEPENDS_ON,
                    metadata={"framework": True},
                )

        # Symbol & Route Edges
        for sym in file_entry.symbols:
            if sym.kind in (SymbolKind.FASTAPI_ROUTE, SymbolKind.EXPRESS_ROUTE):
                http_method = str(sym.details.get("http_method", "GET")).upper()
                route_path = str(sym.details.get("path", "/"))
                route_node_id = f"route:{http_method}:{route_path}"
                handler_sym_id = f"symbol:{clean_path}:FUNCTION:{sym.name}:{sym.start_line}"

                graph.add_edge(file_node_id, route_node_id, EdgeKind.CONTAINS)
                graph.add_edge(file_node_id, handler_sym_id, EdgeKind.CONTAINS)
                graph.add_edge(handler_sym_id, route_node_id, EdgeKind.EXPOSES_ROUTE)

            elif sym.kind in (SymbolKind.FETCH_CALL, SymbolKind.AXIOS_CALL):
                target_url = str(sym.details.get("url", "/"))
                http_method = str(sym.details.get("http_method", "GET")).upper()
                req_node_id = f"req:{clean_path}:{sym.start_line}:{http_method}:{target_url}"
                graph.add_edge(file_node_id, req_node_id, EdgeKind.CONTAINS)

            else:
                sym_node_id = f"symbol:{clean_path}:{sym.kind.value}:{sym.name}:{sym.start_line}"
                graph.add_edge(file_node_id, sym_node_id, EdgeKind.CONTAINS)

                if sym.kind == SymbolKind.IMPORT:
                    imported_module = sym.name.replace(".", "/")
                    for target_f in all_file_paths:
                        if (
                            target_f != clean_path
                            and (target_f.startswith(imported_module) or target_f.endswith(imported_module + ".py") or target_f.endswith(imported_module + ".ts") or target_f.endswith(imported_module + ".js"))
                        ):
                            graph.add_edge(
                                source_id=file_node_id,
                                target_id=f"file:{target_f}",
                                kind=EdgeKind.IMPORTS,
                                metadata={"imported_symbol": sym.name},
                            )

    # =========================================================================
    # PASS 3: Deterministic Function / Method CALLS Edges (Phase 3.5O)
    # =========================================================================
    for file_entry in manifest.files:
        clean_path = file_entry.path.replace("\\", "/")
        file_node_id = f"file:{clean_path}"
        file_imports = imports_by_file.get(clean_path, [])
        unresolved_calls: List[Dict[str, Any]] = []

        for call in file_entry.calls:
            # 1. Identify caller node ID
            caller_id = file_node_id
            if call.caller_name and call.caller_start_line:
                caller_kind = call.caller_kind or "FUNCTION"
                cand_caller_id = f"symbol:{clean_path}:{caller_kind}:{call.caller_name}:{call.caller_start_line}"
                if graph.get_node(cand_caller_id):
                    caller_id = cand_caller_id
                else:
                    # Fallback to function kind if method not found
                    fallback_id = f"symbol:{clean_path}:FUNCTION:{call.caller_name}:{call.caller_start_line}"
                    if graph.get_node(fallback_id):
                        caller_id = fallback_id

            resolved_target_id: Optional[str] = None
            resolution_type: Optional[str] = None
            imported_from_file: Optional[str] = None
            unresolved_reason: Optional[str] = None

            # 2. Case A: Simple identifier call (e.g. helper(), verify_token())
            if call.callee_base is None:
                # Check imports in current file first
                for imp_info in file_imports:
                    imported_names = imp_info.get("imported_names", {})
                    if call.callee_name in imported_names:
                        orig_sym_name = imported_names[call.callee_name]
                        target_file: Optional[str] = None

                        if imp_info.get("is_from"):
                            # Python from import
                            mod_str = imp_info.get("module", "")
                            target_file = _resolve_python_module_to_file(mod_str, clean_path, all_file_paths)
                        elif "source" in imp_info:
                            # JS/TS import from source
                            src_str = imp_info.get("source", "")
                            target_file = _resolve_js_ts_module_to_file(src_str, clean_path, all_file_paths)

                        if target_file and target_file in functions_by_file:
                            candidates = functions_by_file[target_file].get(orig_sym_name, [])
                            if len(candidates) == 1:
                                resolved_target_id = candidates[0][1]
                                resolution_type = "imported"
                                imported_from_file = target_file
                                break
                            elif len(candidates) > 1:
                                unresolved_reason = "ambiguous_imported_target_functions"
                                break

                # If not resolved via import, check same-file definition
                if not resolved_target_id and not unresolved_reason:
                    local_candidates = functions_by_file.get(clean_path, {}).get(call.callee_name, [])
                    if len(local_candidates) == 1:
                        resolved_target_id = local_candidates[0][1]
                        resolution_type = "same_file"
                    elif len(local_candidates) > 1:
                        unresolved_reason = "ambiguous_local_functions"

            # 3. Case B: Member expression call (e.g. utils.formatText(), auth.verify_token())
            elif call.callee_base is not None:
                for imp_info in file_imports:
                    target_file = None
                    # Python aliased module import: import app.utils as utils
                    modules = imp_info.get("modules", {})
                    if call.callee_base in modules:
                        mod_str = modules[call.callee_base]
                        target_file = _resolve_python_module_to_file(mod_str, clean_path, all_file_paths)

                    # JS/TS namespace import: import * as utils from './utils'
                    elif imp_info.get("namespace_import") == call.callee_base:
                        src_str = imp_info.get("source", "")
                        target_file = _resolve_js_ts_module_to_file(src_str, clean_path, all_file_paths)

                    if target_file and target_file in functions_by_file:
                        candidates = functions_by_file[target_file].get(call.callee_name, [])
                        if len(candidates) == 1:
                            resolved_target_id = candidates[0][1]
                            resolution_type = "imported_member"
                            imported_from_file = target_file
                            break
                        elif len(candidates) > 1:
                            unresolved_reason = "ambiguous_imported_member_functions"
                            break

                if not resolved_target_id and not unresolved_reason:
                    # Dynamic receiver / unknown class instance method call (e.g. user.save(), res.json())
                    unresolved_reason = "unresolved_receiver_method"

            # 4. Create CALLS edge or record unresolved metadata
            if resolved_target_id and graph.get_node(resolved_target_id):
                graph.add_edge(
                    source_id=caller_id,
                    target_id=resolved_target_id,
                    kind=EdgeKind.CALLS,
                    metadata={
                        "call_site_file": clean_path,
                        "call_site_line": call.line_number,
                        "callee_name": call.callee_name,
                        "callee_expression": call.callee,
                        "resolution": resolution_type,
                        "imported_from": imported_from_file,
                        "deterministic": True,
                    },
                )
            else:
                unresolved_calls.append({
                    "caller_id": caller_id,
                    "call_site_file": clean_path,
                    "call_site_line": call.line_number,
                    "callee": call.callee,
                    "callee_name": call.callee_name,
                    "callee_base": call.callee_base,
                    "reason": unresolved_reason or "unresolved_or_external",
                })

        # Save unresolved calls on file node metadata
        if unresolved_calls:
            graph.update_node_metadata(file_node_id, {"unresolved_calls": unresolved_calls})

    # =========================================================================
    # PASS 4: Evaluate Cross-Layer Route Contracts (MATCHES_ROUTE)
    # =========================================================================
    graph.evaluate_route_contracts()

    return graph
