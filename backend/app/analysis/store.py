"""EvidenceStore combining repository AST structural manifest and deterministic scanner evidence."""

from typing import Any, Dict, List, Optional
from app.analysis.schemas import ScannerResult, StaticFinding, ToolStatus
from app.ingestion.schemas import FileEntry, ParsedSymbol, RepositoryManifest, SymbolKind
from app.schemas.enums import Severity


class EvidenceStore:
    """Central repository intelligence knowledge store.
    
    Unifies AST structural parsing (symbols, routes, imports) with deterministic
    static findings from Semgrep, Trivy, and OSV-Scanner.
    """

    def __init__(
        self,
        manifest: RepositoryManifest,
        scanner_results: Optional[Dict[str, ScannerResult]] = None,
    ):
        self.manifest = manifest
        self.persistent_index = None
        self.scanner_results: Dict[str, ScannerResult] = scanner_results or {}
        self._findings: List[StaticFinding] = []

        # Flatten and index all static findings
        for result in self.scanner_results.values():
            if result.status == ToolStatus.COMPLETED:
                self._findings.extend(result.findings)

        # Index files by normalized path
        self._files_by_path: Dict[str, FileEntry] = {
            f.path: f for f in self.manifest.files
        }

    @property
    def all_findings(self) -> List[StaticFinding]:
        """All normalized static findings collected across all scanners."""
        return self._findings

    def add_scanner_result(self, result: ScannerResult) -> None:
        """Add or update a scanner result in the evidence store."""
        self.scanner_results[result.tool] = result
        if result.status == ToolStatus.COMPLETED:
            self._findings.extend(result.findings)

    def get_findings(
        self,
        file_path: Optional[str] = None,
        severity: Optional[Severity] = None,
        category: Optional[str] = None,
        tool: Optional[str] = None,
    ) -> List[StaticFinding]:
        """Filter static findings matching the specified criteria."""
        results = self._findings
        if file_path:
            norm_path = file_path.replace("\\", "/")
            results = [f for f in results if f.evidence.file_path == norm_path]
        if severity:
            results = [f for f in results if f.severity == severity]
        if category:
            results = [f for f in results if f.category.lower() == category.lower()]
        if tool:
            results = [f for f in results if f.tool.lower() == tool.lower()]
        return results

    def get_symbols(
        self,
        file_path: Optional[str] = None,
        kind: Optional[SymbolKind] = None,
    ) -> List[ParsedSymbol]:
        """Retrieve AST symbols, optionally filtered by file and symbol kind."""
        symbols: List[ParsedSymbol] = []
        if file_path:
            norm_path = file_path.replace("\\", "/")
            file_entry = self._files_by_path.get(norm_path)
            if file_entry:
                symbols = file_entry.symbols
        else:
            for f in self.manifest.files:
                symbols.extend(f.symbols)

        if kind:
            symbols = [s for s in symbols if s.kind == kind]

        return symbols

    def get_routes(self) -> List[ParsedSymbol]:
        """Retrieve all detected backend routes (FastAPI and Express)."""
        return [
            s for s in self.get_symbols()
            if s.kind in (SymbolKind.FASTAPI_ROUTE, SymbolKind.EXPRESS_ROUTE)
        ]

    def get_http_calls(self) -> List[ParsedSymbol]:
        """Retrieve all detected client HTTP calls (fetch and axios)."""
        return [
            s for s in self.get_symbols()
            if s.kind in (SymbolKind.FETCH_CALL, SymbolKind.AXIOS_CALL)
        ]

    def get_file_entry(self, file_path: str) -> Optional[FileEntry]:
        """Retrieve the FileEntry corresponding to a relative file path."""
        norm_path = file_path.replace("\\", "/")
        return self._files_by_path.get(norm_path)

    def get_evidence_context(
        self,
        file_path: str,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Gather contextual AST symbols and static findings for a specific file region."""
        norm_path = file_path.replace("\\", "/")
        file_entry = self.get_file_entry(norm_path)
        findings = self.get_findings(file_path=norm_path)
        symbols = self.get_symbols(file_path=norm_path)

        # Filter overlapping symbols if line range is provided
        if start_line is not None and end_line is not None:
            symbols = [
                s for s in symbols
                if not (s.end_line < start_line or s.start_line > end_line)
            ]
            findings = [
                f for f in findings
                if f.evidence.start_line is not None and f.evidence.end_line is not None
                and not (f.evidence.end_line < start_line or f.evidence.start_line > end_line)
            ]

        return {
            "file_path": norm_path,
            "language": file_entry.language if file_entry else None,
            "lines_count": file_entry.lines_count if file_entry else 0,
            "symbols": symbols,
            "findings": findings,
        }

    def get_summary(self) -> Dict[str, Any]:
        """Aggregate high-level intelligence summary of the repository."""
        severity_counts: Dict[str, int] = {s.value: 0 for s in Severity}
        category_counts: Dict[str, int] = {}
        tool_counts: Dict[str, int] = {}

        for f in self._findings:
            severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1
            category_counts[f.category] = category_counts.get(f.category, 0) + 1
            tool_counts[f.tool] = tool_counts.get(f.tool, 0) + 1

        return {
            "repository_url": self.manifest.repository_url,
            "commit_hash": self.manifest.commit_hash,
            "total_files": self.manifest.total_files,
            "total_size_bytes": self.manifest.total_size_bytes,
            "languages": self.manifest.languages,
            "frameworks": [fw.name for fw in self.manifest.frameworks],
            "routes_count": len(self.get_routes()),
            "total_findings": len(self._findings),
            "findings_by_severity": severity_counts,
            "findings_by_category": category_counts,
            "findings_by_tool": tool_counts,
            "scanners_executed": {
                tool: res.status.value for tool, res in self.scanner_results.items()
            },
        }
