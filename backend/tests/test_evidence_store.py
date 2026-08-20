"""Unit tests for EvidenceStore querying, filtering, and contextual retrieval."""

import pytest
from app.analysis.schemas import ScannerResult, StaticFinding, ToolStatus
from app.analysis.store import EvidenceStore
from app.ingestion.schemas import FileEntry, ParsedSymbol, RepositoryManifest, SymbolKind
from app.schemas.enums import Severity
from app.schemas.evidence import Evidence


@pytest.fixture
def sample_evidence_store():
    """Create an EvidenceStore pre-populated with manifest and static findings."""
    manifest = RepositoryManifest(
        repository_url="https://github.com/org/repo.git",
        commit_hash="c0ffee123456",
        total_files=2,
        total_size_bytes=1024,
        languages={"python": 1, "typescript": 1},
        files=[
            FileEntry(
                path="backend/main.py",
                language="python",
                size_bytes=500,
                lines_count=30,
                symbols=[
                    ParsedSymbol(
                        name="GET /health",
                        kind=SymbolKind.FASTAPI_ROUTE,
                        start_line=10,
                        end_line=15,
                        details={"http_method": "GET", "path": "/health"},
                    ),
                    ParsedSymbol(
                        name="UserProfile",
                        kind=SymbolKind.CLASS,
                        start_line=20,
                        end_line=28,
                    ),
                ],
            ),
            FileEntry(
                path="frontend/api.ts",
                language="typescript",
                size_bytes=524,
                lines_count=20,
                symbols=[
                    ParsedSymbol(
                        name="fetch(/health)",
                        kind=SymbolKind.FETCH_CALL,
                        start_line=5,
                        end_line=8,
                        details={"target": "/health"},
                    ),
                ],
            ),
        ],
    )

    finding1 = StaticFinding(
        tool="semgrep",
        rule_id="python.security.sql-injection",
        title="SQL Injection",
        description="Unsanitized query formatting",
        severity=Severity.HIGH,
        category="security",
        evidence=Evidence(
            file_path="backend/main.py",
            start_line=12,
            end_line=14,
            code_snippet="db.execute(f'SELECT * FROM {user}')",
        ),
    )

    finding2 = StaticFinding(
        tool="trivy",
        rule_id="CVE-2024-9999",
        title="Critical Vulnerability",
        description="Buffer overflow vulnerability",
        severity=Severity.CRITICAL,
        category="vulnerability",
        evidence=Evidence(
            file_path="package-lock.json",
        ),
    )

    scanner_results = {
        "semgrep": ScannerResult(tool="semgrep", status=ToolStatus.COMPLETED, findings=[finding1]),
        "trivy": ScannerResult(tool="trivy", status=ToolStatus.COMPLETED, findings=[finding2]),
    }

    return EvidenceStore(manifest=manifest, scanner_results=scanner_results)


def test_evidence_store_get_findings_filtering(sample_evidence_store):
    """Verify filtering static findings by file path, severity, category, and tool."""
    # Filter by file path
    backend_findings = sample_evidence_store.get_findings(file_path="backend/main.py")
    assert len(backend_findings) == 1
    assert backend_findings[0].rule_id == "python.security.sql-injection"

    # Filter by severity
    critical_findings = sample_evidence_store.get_findings(severity=Severity.CRITICAL)
    assert len(critical_findings) == 1
    assert critical_findings[0].tool == "trivy"

    # Filter by category
    security_findings = sample_evidence_store.get_findings(category="security")
    assert len(security_findings) == 1


def test_evidence_store_routes_and_http_calls(sample_evidence_store):
    """Verify helper queries for AST routes and HTTP calls."""
    routes = sample_evidence_store.get_routes()
    assert len(routes) == 1
    assert routes[0].name == "GET /health"

    http_calls = sample_evidence_store.get_http_calls()
    assert len(http_calls) == 1
    assert http_calls[0].name == "fetch(/health)"


def test_evidence_store_context_retrieval(sample_evidence_store):
    """Verify localized evidence context retrieval for specific line spans."""
    context = sample_evidence_store.get_evidence_context(
        file_path="backend/main.py",
        start_line=10,
        end_line=16,
    )
    assert context["file_path"] == "backend/main.py"
    assert context["language"] == "python"
    assert len(context["symbols"]) == 1
    assert context["symbols"][0].name == "GET /health"
    assert len(context["findings"]) == 1
    assert context["findings"][0].rule_id == "python.security.sql-injection"


def test_evidence_store_summary_aggregation(sample_evidence_store):
    """Verify summary metrics calculation."""
    summary = sample_evidence_store.get_summary()
    assert summary["total_files"] == 2
    assert summary["routes_count"] == 1
    assert summary["total_findings"] == 2
    assert summary["findings_by_severity"][Severity.CRITICAL.value] == 1
    assert summary["findings_by_severity"][Severity.HIGH.value] == 1
    assert summary["scanners_executed"]["semgrep"] == ToolStatus.COMPLETED.value
