"""Deterministic graph builder constructing RepositoryGraph from structural AST manifest evidence."""

import os
from typing import Optional

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


def build_repository_graph(
    manifest: RepositoryManifest,
    evidence_store: Optional[EvidenceStore] = None,
) -> RepositoryGraph:
    """Deterministically build canonical RepositoryGraph using two-pass node & edge wiring."""
    graph = RepositoryGraph()
    all_file_paths = {f.path.replace("\\", "/") for f in manifest.files}

    # =========================================================================
    # PASS 1: Register ALL Nodes First
    # =========================================================================
    for file_entry in manifest.files:
        clean_path = file_entry.path.replace("\\", "/")
        file_node_id = f"file:{clean_path}"
        is_test = _is_test_file(clean_path)

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

    for fw in manifest.frameworks:
        dep_node_id = f"dep:{fw.name.lower()}"
        graph.add_node(
            node_id=dep_node_id,
            kind=NodeKind.DEPENDENCY,
            label=fw.name,
            metadata={"version": fw.version, "evidence": fw.evidence},
        )

    # =========================================================================
    # PASS 2: Wire ALL Edges (All Nodes Guaranteed to Exist)
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
    # PASS 3: Evaluate Cross-Layer Route Contracts (MATCHES_ROUTE)
    # =========================================================================
    graph.evaluate_route_contracts()

    return graph
