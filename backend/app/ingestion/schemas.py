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


class FileEntry(BaseModel):
    """Metadata and extracted symbols for an individual file in a repository."""

    path: str = Field(..., description="Normalized relative file path from repository root")
    language: Optional[str] = Field(default=None, description="Identified language (e.g. python, typescript, javascript, json)")
    size_bytes: int = Field(default=0, ge=0, description="File size in bytes")
    lines_count: int = Field(default=0, ge=0, description="Total line count")
    symbols: List[ParsedSymbol] = Field(default_factory=list, description="Extracted functions, classes, imports, and routes")
    is_binary: bool = Field(default=False, description="Flag indicating if file is binary")
    skipped_reason: Optional[str] = Field(default=None, description="Reason file was not parsed (e.g. exceeds_max_size, binary)")


class FrameworkDetected(BaseModel):
    """A detected software framework or library with deterministic evidence."""

    name: str = Field(..., description="Framework name (e.g. FastAPI, Next.js, Express, React)")
    version: Optional[str] = Field(default=None, description="Detected version string if specified in manifest")
    evidence: str = Field(..., description="Deterministic file and dependency evidence")


class RepositoryManifest(BaseModel):
    """Complete structural manifest of an ingested repository."""

    repository_url: str = Field(..., description="Source public GitHub repository URL")
    commit_hash: str = Field(..., description="Exact 40-character commit SHA ingested")
    branch: Optional[str] = Field(default=None, description="Branch analyzed")
    total_files: int = Field(default=0, ge=0, description="Total files discovered")
    total_size_bytes: int = Field(default=0, ge=0, description="Total size in bytes")
    languages: Dict[str, int] = Field(default_factory=dict, description="File counts mapped by programming language")
    frameworks: List[FrameworkDetected] = Field(default_factory=list, description="Detected frameworks and libraries")
    files: List[FileEntry] = Field(default_factory=list, description="List of processed files")
    cloned_at: datetime = Field(default_factory=_utc_now, description="Timestamp when ingestion started")
    scan_duration_ms: Optional[float] = Field(default=None, ge=0.0, description="Ingestion and parsing wall time in milliseconds")
