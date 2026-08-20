"""Unit and fixture tests for Phase 2A deterministic repository relationship graph and contract matcher."""

import pytest

from app.graph.builder import build_repository_graph
from app.graph.matcher import match_route_contract, normalize_route_path
from app.graph.repository_graph import RepositoryGraph
from app.graph.schemas import (
    ContractMatchStatus,
    EdgeKind,
    GraphNode,
    NodeKind,
)
from app.ingestion.schemas import (
    FileEntry,
    FrameworkDetected,
    ParsedSymbol,
    RepositoryManifest,
    SymbolKind,
)


def test_route_parameter_normalization():
    """Verify route path normalization across Express, FastAPI, Next.js, and template literals."""
    # Express style (:param)
    assert normalize_route_path("/api/v1/users/:userId/posts/:postId") == "/api/v1/users/{param}/posts/{param}"
    assert normalize_route_path("/items/:id") == "/items/{param}"

    # FastAPI / OpenAPI style ({param})
    assert normalize_route_path("/api/v1/users/{user_id}/posts/{post_id}") == "/api/v1/users/{param}/posts/{param}"
    assert normalize_route_path("/items/{item_id}") == "/items/{param}"

    # Next.js dynamic brackets ([id], [...slug])
    assert normalize_route_path("/users/[id]") == "/users/{param}"
    assert normalize_route_path("/blog/[...slug]") == "/blog/{param}"

    # Query strings and fragments
    assert normalize_route_path("/api/search?q=test&page=1#results") == "/api/search"

    # Template literal interpolation
    assert normalize_route_path("http://localhost:8000/api/items/${itemId}") == "/api/items/{param}"
    assert normalize_route_path("/api/orders/${orderId}/status") == "/api/orders/{param}/status"

    # Redundant and trailing slashes
    assert normalize_route_path("///api//v1///items/") == "/api/v1/items"
    assert normalize_route_path("/") == "/"


def test_cross_layer_contract_matcher_scenarios():
    """Verify deterministic detection of MATCHED, METHOD_MISMATCH, UNMATCHED, and AMBIGUOUS."""
    backend_routes = [
        GraphNode(
            id="route:GET:/api/users/{id}",
            kind=NodeKind.ROUTE,
            label="GET /api/users/{id}",
            metadata={"http_method": "GET", "path": "/api/users/{id}"},
        ),
        GraphNode(
            id="route:POST:/api/users",
            kind=NodeKind.ROUTE,
            label="POST /api/users",
            metadata={"http_method": "POST", "path": "/api/users"},
        ),
        GraphNode(
            id="route:GET:/api/duplicate",
            kind=NodeKind.ROUTE,
            label="GET /api/duplicate",
            metadata={"http_method": "GET", "path": "/api/duplicate"},
        ),
        GraphNode(
            id="route:GET:/api/duplicate/v2",
            kind=NodeKind.ROUTE,
            label="GET /api/duplicate/v2",
            metadata={"http_method": "GET", "path": "/api/duplicate"},
        ),
    ]

    frontend_requests = [
        # 1. Matched with parameter normalization (Express :userId vs FastAPI {id})
        GraphNode(
            id="req:1",
            kind=NodeKind.FRONTEND_REQUEST,
            label="GET /api/users/:userId",
            file_path="src/api.ts",
            start_line=10,
            metadata={"http_method": "GET", "url": "/api/users/:userId"},
        ),
        # 2. Method Mismatch (Frontend sends PUT to POST route)
        GraphNode(
            id="req:2",
            kind=NodeKind.FRONTEND_REQUEST,
            label="PUT /api/users",
            file_path="src/api.ts",
            start_line=20,
            metadata={"http_method": "PUT", "url": "/api/users"},
        ),
        # 3. Unmatched Frontend Request (Missing backend endpoint)
        GraphNode(
            id="req:3",
            kind=NodeKind.FRONTEND_REQUEST,
            label="DELETE /api/nonexistent",
            file_path="src/api.ts",
            start_line=30,
            metadata={"http_method": "DELETE", "url": "/api/nonexistent"},
        ),
    ]

    report = match_route_contract(frontend_requests, backend_routes)

    assert report.total_frontend_requests == 3
    assert report.total_backend_routes == 4
    assert report.matched_count == 1
    assert report.method_mismatch_count == 1
    assert report.unmatched_count == 1

    matches_by_id = {m.frontend_request_id: m for m in report.matches}

    # Verify req:1 is MATCHED
    assert matches_by_id["req:1"].status == ContractMatchStatus.MATCHED
    assert "route:GET:/api/users/{id}" in matches_by_id["req:1"].matched_route_ids

    # Verify req:2 is METHOD_MISMATCH
    assert matches_by_id["req:2"].status == ContractMatchStatus.METHOD_MISMATCH
    assert "['POST']" in matches_by_id["req:2"].details

    # Verify req:3 is UNMATCHED
    assert matches_by_id["req:3"].status == ContractMatchStatus.UNMATCHED_FRONTEND_REQUEST


def test_repository_graph_typed_nodes_and_edges():
    """Verify typed node and edge manipulation in RepositoryGraph."""
    graph = RepositoryGraph()

    # Add all 6 typed node kinds
    f_node = graph.add_node("file:app/main.py", NodeKind.FILE, "app/main.py", "app/main.py", 1, 100)
    s_node = graph.add_node("symbol:get_user", NodeKind.SYMBOL, "get_user", "app/main.py", 10, 20)
    r_node = graph.add_node("route:GET:/users", NodeKind.ROUTE, "GET /users", "app/main.py", 10, 20)
    req_node = graph.add_node("req:fetch_user", NodeKind.FRONTEND_REQUEST, "GET /users", "src/api.ts", 5, 6)
    dep_node = graph.add_node("dep:fastapi", NodeKind.DEPENDENCY, "fastapi")
    test_node = graph.add_node("test:tests/test_main.py", NodeKind.TEST, "test_main.py", "tests/test_main.py", 1, 50)

    assert f_node.kind == NodeKind.FILE
    assert s_node.kind == NodeKind.SYMBOL
    assert r_node.kind == NodeKind.ROUTE
    assert req_node.kind == NodeKind.FRONTEND_REQUEST
    assert dep_node.kind == NodeKind.DEPENDENCY
    assert test_node.kind == NodeKind.TEST

    # Add all 8 typed edge kinds
    e1 = graph.add_edge("file:app/main.py", "symbol:get_user", EdgeKind.CONTAINS)
    e2 = graph.add_edge("symbol:get_user", "route:GET:/users", EdgeKind.EXPOSES_ROUTE)
    e3 = graph.add_edge("file:app/main.py", "file:app/main.py", EdgeKind.IMPORTS)
    e4 = graph.add_edge("symbol:get_user", "symbol:get_user", EdgeKind.CALLS)
    e5 = graph.add_edge("symbol:get_user", "req:fetch_user", EdgeKind.REQUESTS_ROUTE)
    e6 = graph.add_edge("req:fetch_user", "route:GET:/users", EdgeKind.MATCHES_ROUTE)
    e7 = graph.add_edge("file:app/main.py", "dep:fastapi", EdgeKind.DEPENDS_ON)
    e8 = graph.add_edge("test:tests/test_main.py", "file:app/main.py", EdgeKind.TESTS)

    assert e1 is not None and e1.kind == EdgeKind.CONTAINS
    assert e2 is not None and e2.kind == EdgeKind.EXPOSES_ROUTE
    assert e3 is not None and e3.kind == EdgeKind.IMPORTS
    assert e4 is not None and e4.kind == EdgeKind.CALLS
    assert e5 is not None and e5.kind == EdgeKind.REQUESTS_ROUTE
    assert e6 is not None and e6.kind == EdgeKind.MATCHES_ROUTE
    assert e7 is not None and e7.kind == EdgeKind.DEPENDS_ON
    assert e8 is not None and e8.kind == EdgeKind.TESTS

    data = graph.to_domain_data()
    assert data.total_nodes == 6
    assert data.total_edges == 8


def test_build_repository_graph_from_manifest_fixture():
    """Verify deterministic build_repository_graph() with multi-tier manifest."""
    manifest = RepositoryManifest(
        repository_url="https://github.com/org/repo.git",
        commit_hash="abcdef1234567890",
        total_files=4,
        total_size_bytes=2000,
        languages={"python": 2, "typescript": 2},
        frameworks=[
            FrameworkDetected(name="FastAPI", version="0.115.0", evidence="from fastapi import FastAPI"),
            FrameworkDetected(name="React", version="19.0.0", evidence="import React from 'react'"),
        ],
        files=[
            # Backend server file
            FileEntry(
                path="app/server.py",
                language="python",
                size_bytes=500,
                lines_count=30,
                symbols=[
                    ParsedSymbol(
                        name="get_items",
                        kind=SymbolKind.FASTAPI_ROUTE,
                        start_line=10,
                        end_line=15,
                        details={"http_method": "GET", "path": "/api/v1/items/{item_id}"},
                    ),
                    ParsedSymbol(
                        name="app.models",
                        kind=SymbolKind.IMPORT,
                        start_line=1,
                        end_line=1,
                    ),
                ],
            ),
            # Backend models file
            FileEntry(
                path="app/models.py",
                language="python",
                size_bytes=300,
                lines_count=20,
                symbols=[
                    ParsedSymbol(
                        name="Item",
                        kind=SymbolKind.CLASS,
                        start_line=5,
                        end_line=15,
                    ),
                ],
            ),
            # Frontend client file
            FileEntry(
                path="frontend/src/api.ts",
                language="typescript",
                size_bytes=400,
                lines_count=25,
                symbols=[
                    ParsedSymbol(
                        name="fetchItem",
                        kind=SymbolKind.FETCH_CALL,
                        start_line=8,
                        end_line=12,
                        details={"http_method": "GET", "url": "/api/v1/items/:id"},
                    ),
                    ParsedSymbol(
                        name="deleteItem",
                        kind=SymbolKind.FETCH_CALL,
                        start_line=16,
                        end_line=20,
                        details={"http_method": "DELETE", "url": "/api/v1/items/:id"},
                    ),
                ],
            ),
            # Test file
            FileEntry(
                path="tests/test_server.py",
                language="python",
                size_bytes=600,
                lines_count=35,
                symbols=[
                    ParsedSymbol(
                        name="test_get_items",
                        kind=SymbolKind.FUNCTION,
                        start_line=5,
                        end_line=10,
                    ),
                ],
            ),
        ],
    )

    graph = build_repository_graph(manifest)
    data = graph.to_domain_data()

    # 1. Node assertions
    assert data.node_counts_by_kind["FILE"] == 4
    assert data.node_counts_by_kind["TEST"] == 1
    assert data.node_counts_by_kind["ROUTE"] == 1
    assert data.node_counts_by_kind["FRONTEND_REQUEST"] == 2
    assert data.node_counts_by_kind["DEPENDENCY"] == 2

    # 2. Edge assertions
    # File containment edges
    assert data.edge_counts_by_kind["CONTAINS"] >= 4
    # Route exposition
    assert data.edge_counts_by_kind["EXPOSES_ROUTE"] >= 1
    # Inter-file import (app/server.py -> app/models.py)
    assert data.edge_counts_by_kind["IMPORTS"] >= 1
    # Test linkage (tests/test_server.py -> app/server.py)
    assert data.edge_counts_by_kind["TESTS"] >= 1

    # 3. Cross-layer contract report
    report = data.contract_report
    assert report is not None
    assert report.total_frontend_requests == 2
    assert report.total_backend_routes == 1
    assert report.matched_count == 1          # GET /api/v1/items/:id matches GET /api/v1/items/{item_id}
    assert report.method_mismatch_count == 1  # DELETE /api/v1/items/:id has method mismatch on backend
