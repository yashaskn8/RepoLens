"""Synthetic repository fixtures with explicit ground-truth issue labels."""

from dataclasses import dataclass
from typing import Dict, List

from app.analysis.schemas import ScannerResult, StaticFinding, ToolStatus
from app.analysis.store import EvidenceStore
from app.evaluation.schemas import GroundTruthIssue, IssueCategory
from app.graph.builder import build_repository_graph
from app.graph.repository_graph import RepositoryGraph
from app.indexing.chunker import chunk_manifest
from app.indexing.schemas import CodeChunk
from app.ingestion.schemas import (
    FileEntry,
    FrameworkDetected,
    ParsedSymbol,
    RepositoryManifest,
    SymbolKind,
)
from app.schemas.enums import Severity
from app.schemas.finding import Evidence


@dataclass
class SyntheticRepoFixture:
    """A self-contained synthetic repository fixture with manifest, graph, and ground truth."""

    name: str
    description: str
    manifest: RepositoryManifest
    files_content: Dict[str, str]
    evidence_store: EvidenceStore
    repository_graph: RepositoryGraph
    chunks: List[CodeChunk]
    ground_truth_issues: List[GroundTruthIssue]


def build_synthetic_ecommerce_fixture() -> SyntheticRepoFixture:
    """Construct standard synthetic multi-tier repository fixture with 4 documented ground-truth issues."""
    commit_sha = "e1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0"

    files_content = {
        "app/routes/orders.py": (
            "# Order processing endpoints\n"
            "@app.post('/api/v1/orders/checkout')\n"
            "def checkout_order(order_data: dict):\n"
            "    # Process checkout\n"
            "    return {'order_id': '123', 'status': 'confirmed'}\n"
        ),
        "frontend/src/api/orders.ts": (
            "// Frontend orders API client\n"
            "export async function submitOrder(data: any) {\n"
            "  // Route mismatch: targets /submit instead of /checkout\n"
            "  return await fetch('/api/v1/orders/submit', {\n"
            "    method: 'POST',\n"
            "    body: JSON.stringify(data),\n"
            "  });\n"
            "}\n"
        ),
        "app/routes/users.py": (
            "# User management endpoints\n"
            "@app.get('/api/v1/users/{id}')\n"
            "def get_user_profile(id: str):\n"
            "    # Only GET is implemented\n"
            "    return {'id': id, 'name': 'Alice'}\n"
        ),
        "frontend/src/api/users.ts": (
            "// Frontend users API client\n"
            "export async function deleteUser(id: string) {\n"
            "  // Method mismatch: sends DELETE to GET-only endpoint\n"
            "  return await fetch(`/api/v1/users/${id}`, {\n"
            "    method: 'DELETE',\n"
            "  });\n"
            "}\n"
        ),
        "app/db/query.py": (
            "# Database query utility\n"
            "import sqlite3\n\n"
            "def execute_user_query(user_id: str):\n"
            "    # SQL Injection vulnerability: formatted string in SQL query\n"
            "    conn = sqlite3.connect('app.db')\n"
            "    cursor = conn.cursor()\n"
            "    query = f\"SELECT * FROM accounts WHERE user_id = '{user_id}'\"\n"
            "    cursor.execute(query)\n"
            "    return cursor.fetchall()\n"
        ),
        "app/core/calculator.py": (
            "# Financial calculation utilities\n"
            "def calculate_discount_ratio(total_amount: float, discount: float) -> float:\n"
            "    # Logic bug: Unhandled division by zero when total_amount is 0\n"
            "    return discount / total_amount\n"
        ),
        "tests/test_calculator.py": (
            "# Calculator unit tests\n"
            "from app.core.calculator import calculate_discount_ratio\n\n"
            "def test_calculate_discount_ratio():\n"
            "    assert calculate_discount_ratio(100.0, 10.0) == 0.1\n"
        ),
    }

    manifest = RepositoryManifest(
        repository_url="https://github.com/repolens-eval/synth-ecommerce.git",
        commit_hash=commit_sha,
        total_files=len(files_content),
        total_size_bytes=sum(len(c) for c in files_content.values()),
        languages={"python": 5, "typescript": 2},
        frameworks=[
            FrameworkDetected(name="FastAPI", version="0.115.0", evidence="from fastapi import FastAPI"),
            FrameworkDetected(name="React", version="19.0.0", evidence="import React from 'react'"),
        ],
        files=[
            FileEntry(
                path="app/routes/orders.py",
                language="python",
                size_bytes=len(files_content["app/routes/orders.py"]),
                lines_count=6,
                symbols=[
                    ParsedSymbol(
                        name="checkout_order",
                        kind=SymbolKind.FASTAPI_ROUTE,
                        start_line=2,
                        end_line=5,
                        details={"http_method": "POST", "path": "/api/v1/orders/checkout"},
                    ),
                ],
            ),
            FileEntry(
                path="frontend/src/api/orders.ts",
                language="typescript",
                size_bytes=len(files_content["frontend/src/api/orders.ts"]),
                lines_count=9,
                symbols=[
                    ParsedSymbol(
                        name="submitOrder",
                        kind=SymbolKind.FETCH_CALL,
                        start_line=4,
                        end_line=7,
                        details={"http_method": "POST", "url": "/api/v1/orders/submit"},
                    ),
                ],
            ),
            FileEntry(
                path="app/routes/users.py",
                language="python",
                size_bytes=len(files_content["app/routes/users.py"]),
                lines_count=6,
                symbols=[
                    ParsedSymbol(
                        name="get_user_profile",
                        kind=SymbolKind.FASTAPI_ROUTE,
                        start_line=2,
                        end_line=5,
                        details={"http_method": "GET", "path": "/api/v1/users/{id}"},
                    ),
                ],
            ),
            FileEntry(
                path="frontend/src/api/users.ts",
                language="typescript",
                size_bytes=len(files_content["frontend/src/api/users.ts"]),
                lines_count=8,
                symbols=[
                    ParsedSymbol(
                        name="deleteUser",
                        kind=SymbolKind.FETCH_CALL,
                        start_line=4,
                        end_line=6,
                        details={"http_method": "DELETE", "url": "/api/v1/users/${id}"},
                    ),
                ],
            ),
            FileEntry(
                path="app/db/query.py",
                language="python",
                size_bytes=len(files_content["app/db/query.py"]),
                lines_count=10,
                symbols=[
                    ParsedSymbol(
                        name="execute_user_query",
                        kind=SymbolKind.FUNCTION,
                        start_line=4,
                        end_line=10,
                    ),
                ],
            ),
            FileEntry(
                path="app/core/calculator.py",
                language="python",
                size_bytes=len(files_content["app/core/calculator.py"]),
                lines_count=5,
                symbols=[
                    ParsedSymbol(
                        name="calculate_discount_ratio",
                        kind=SymbolKind.FUNCTION,
                        start_line=2,
                        end_line=4,
                    ),
                ],
            ),
            FileEntry(
                path="tests/test_calculator.py",
                language="python",
                size_bytes=len(files_content["tests/test_calculator.py"]),
                lines_count=6,
                symbols=[
                    ParsedSymbol(
                        name="test_calculate_discount_ratio",
                        kind=SymbolKind.FUNCTION,
                        start_line=4,
                        end_line=5,
                    ),
                ],
            ),
        ],
    )

    # Setup EvidenceStore with deterministic static findings
    evidence_store = EvidenceStore(manifest=manifest)
    sql_injection_finding = StaticFinding(
        tool="semgrep",
        rule_id="python.lang.security.audit.sqli.format-string-sqli",
        title="Unsanitized SQL Query with Formatted String",
        description="Formatted string in SQL execution allows direct SQL injection.",
        severity=Severity.HIGH,
        category="security",
        evidence=Evidence(
            file_path="app/db/query.py",
            start_line=8,
            end_line=9,
            code_snippet="query = f\"SELECT * FROM accounts WHERE user_id = '{user_id}'\"",
        ),
        mitigation="Use parameterized queries cursor.execute('SELECT * FROM accounts WHERE user_id = ?', (user_id,))",
    )
    evidence_store.add_scanner_result(
        ScannerResult(
            tool="semgrep",
            status=ToolStatus.COMPLETED,
            findings=[sql_injection_finding],
            execution_time_ms=25.0,
        )
    )

    # Build relationship graph and code chunks
    repository_graph = build_repository_graph(manifest, evidence_store)
    chunks = chunk_manifest(manifest, files_content)

    # Map chunk IDs by file path and symbol
    chunks_by_file_sym = {(c.file_path, c.symbol): c.chunk_id for c in chunks}

    # Ground-truth documented issues
    ground_truth_issues = [
        GroundTruthIssue(
            issue_id="GT-001",
            category=IssueCategory.ROUTE_MISMATCH,
            title="Unmatched Route: Frontend calls /submit instead of /checkout",
            description="Client invokes POST /api/v1/orders/submit which does not exist on backend.",
            expected_file="frontend/src/api/orders.ts",
            expected_start_line=2,
            expected_end_line=8,
            query="order checkout submit endpoint route mismatch",
            expected_chunk_ids=[
                chunks_by_file_sym.get(("frontend/src/api/orders.ts", "orders.ts"), ""),
                chunks_by_file_sym.get(("app/routes/orders.py", "checkout_order"), ""),
            ],
        ),
        GroundTruthIssue(
            issue_id="GT-002",
            category=IssueCategory.METHOD_MISMATCH,
            title="HTTP Method Mismatch on Users Endpoint",
            description="Client sends DELETE to /api/v1/users/{id} which only implements GET.",
            expected_file="frontend/src/api/users.ts",
            expected_start_line=2,
            expected_end_line=7,
            query="delete user endpoint HTTP method mismatch DELETE GET",
            expected_chunk_ids=[
                chunks_by_file_sym.get(("frontend/src/api/users.ts", "users.ts"), ""),
                chunks_by_file_sym.get(("app/routes/users.py", "get_user_profile"), ""),
            ],
        ),
        GroundTruthIssue(
            issue_id="GT-003",
            category=IssueCategory.SECURITY,
            title="SQL Injection in Database Query Utility",
            description="Unsanitized string interpolation in SQL query permits arbitrary SQL injection.",
            expected_file="app/db/query.py",
            expected_start_line=4,
            expected_end_line=10,
            query="execute_user_query SQL injection formatted string",
            expected_chunk_ids=[
                chunks_by_file_sym.get(("app/db/query.py", "execute_user_query"), ""),
            ],
        ),
        GroundTruthIssue(
            issue_id="GT-004",
            category=IssueCategory.CORRECTNESS,
            title="Unhandled ZeroDivisionError in Discount Calculation",
            description="Division by total_amount without checking for 0.0 causes unhandled crash.",
            expected_file="app/core/calculator.py",
            expected_start_line=2,
            expected_end_line=4,
            query="calculate_discount_ratio zero division error exception",
            expected_chunk_ids=[
                chunks_by_file_sym.get(("app/core/calculator.py", "calculate_discount_ratio"), ""),
            ],
        ),
    ]

    return SyntheticRepoFixture(
        name="synth-ecommerce",
        description="Multi-tier synthetic repo with 4 known cross-layer, security, and logic defects.",
        manifest=manifest,
        files_content=files_content,
        evidence_store=evidence_store,
        repository_graph=repository_graph,
        chunks=chunks,
        ground_truth_issues=ground_truth_issues,
    )
