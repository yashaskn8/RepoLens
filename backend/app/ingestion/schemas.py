"""Schemas for repository ingestion, file manifest, and parsed AST symbols."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SymbolKind(str, Enum):
    """Categorization of symbols extracted via AST parsing."""

    FUNCTION = "FUNCTION"
    CLASS = "CLASS"
    METHOD = "METHOD"
    IMPORT = "IMPORT"
    FASTAPI_ROUTE = "FASTAPI_ROUTE"
    EXPRESS_ROUTE = "EXPRESS_ROUTE"
    FETCH_CALL = "FETCH_CALL"
    AXIOS_CALL = "AXIOS_CALL"


class ParsedSymbol(BaseModel):
    """A localized structural symbol extracted from source code."""

    name: str = Field(..., description="Symbol name, route path, or imported entity")
    kind: SymbolKind = Field(..., description="Type of symbol")
    start_line: int = Field(..., ge=1, description="Starting line (1-indexed)")
    end_line: int = Field(..., ge=1, description="Ending line (1-indexed)")
    start_column: Optional[int] = Field(default=None, ge=0, description="Starting column")
    end_column: Optional[int] = Field(default=None, ge=0, description="Ending column")
    details: Dict[str, Any] = Field(default_factory=dict, description="Metadata such as HTTP methods, signatures, or parent class")


class ParsedCall(BaseModel):
    """A detected call expression with call-site location and callee identifier."""

    callee: str = Field(..., description="Raw callee expression string (e.g. 'helper', 'auth.login')")
    callee_name: str = Field(..., description="Base function or method name (e.g. 'helper', 'login')")
    callee_base: Optional[str] = Field(default=None, description="Module or receiver base if member access (e.g. 'auth', 'self', 'utils')")
    line_number: int = Field(..., ge=1, description="Call-site line number (1-indexed)")
    column_number: Optional[int] = Field(default=None, ge=0, description="Call-site column number")
    caller_name: Optional[str] = Field(default=None, description="Enclosing function or method name")
    caller_kind: Optional[str] = Field(default=None, description="Enclosing symbol kind (FUNCTION, METHOD, CLASS)")
    caller_start_line: Optional[int] = Field(default=None, description="Enclosing function or method start line")


class FileEntry(BaseModel):
    """Metadata and extracted symbols for an individual file in a repository."""

    path: str = Field(..., description="Normalized relative file path from repository root")
    language: Optional[str] = Field(default=None, description="Identified language (e.g. python, typescript, javascript, json)")
    size_bytes: int = Field(default=0, ge=0, description="File size in bytes")
    lines_count: int = Field(default=0, ge=0, description="Total line count")
    symbols: List[ParsedSymbol] = Field(default_factory=list, description="Extracted functions, classes, imports, and routes")
    calls: List[ParsedCall] = Field(default_factory=list, description="Extracted function and method call sites")
    is_binary: bool = Field(default=False, description="Flag indicating if file is binary")
    skipped_reason: Optional[str] = Field(default=None, description="Reason file was not parsed (e.g. exceeds_max_size, binary)")


class FrameworkDetected(BaseModel):
    """A detected software framework or library with deterministic evidence."""

    name: str = Field(..., description="Framework name (e.g. FastAPI, Next.js, Express, React)")
    version: Optional[str] = Field(default=None, description="Detected version string if specified in manifest")
    evidence: str = Field(..., description="Deterministic file and dependency evidence")


class AnalysisScope(BaseModel):
    """Resource boundary and truncation scope metadata."""

    truncated: bool = Field(default=False, description="True if processing stopped due to file count or byte limits")
    reason: Optional[str] = Field(default=None, description="Reason for truncation if applicable")
    files_processed: int = Field(default=0, ge=0, description="Total files actually parsed and indexed")
    source_bytes_processed: int = Field(default=0, ge=0, description="Total source bytes actually parsed and indexed")
    total_observed_files: int = Field(default=0, ge=0, description="Total files discovered in repository")
    total_observed_bytes: int = Field(default=0, ge=0, description="Total raw size in bytes across repository")

    @property
    def is_truncated(self) -> bool:
        """Alias for truncated."""
        return self.truncated

    @property
    def truncated_file_count(self) -> int:
        """Count of unparsed files due to resource limit truncation."""
        return max(0, self.total_observed_files - self.files_processed)

    @property
    def total_source_bytes(self) -> int:
        """Total source bytes processed."""
        return self.source_bytes_processed


class RepositoryManifest(BaseModel):
    """Complete structural manifest of an ingested repository."""

    repository_url: str = Field(..., description="Source public GitHub repository URL")
    commit_hash: str = Field(..., description="Exact 40-character commit SHA ingested")
    commit_sha: Optional[str] = Field(default=None, description="Authoritative 40-character commit SHA alias")
    branch: Optional[str] = Field(default=None, description="Resolved branch or ref analyzed")
    requested_branch: Optional[str] = Field(default=None, description="Branch originally requested if supplied")
    resolved_branch_or_ref: Optional[str] = Field(default=None, description="Actual resolved branch or ref from Git")
    total_files: int = Field(default=0, ge=0, description="Total files discovered")
    total_size_bytes: int = Field(default=0, ge=0, description="Total size in bytes")
    languages: Dict[str, int] = Field(default_factory=dict, description="File counts mapped by programming language")
    frameworks: List[FrameworkDetected] = Field(default_factory=list, description="Detected frameworks and libraries")
    files: List[FileEntry] = Field(default_factory=list, description="List of processed files")
    cloned_at: datetime = Field(default_factory=_utc_now, description="Timestamp when ingestion started")
    scan_duration_ms: Optional[float] = Field(default=None, ge=0.0, description="Ingestion and parsing wall time in milliseconds")
    analysis_scope: Optional[AnalysisScope] = Field(default=None, description="Observed vs processed scope and truncation state")
