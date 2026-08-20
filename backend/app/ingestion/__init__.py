"""Repository ingestion: safe cloning, manifest generation, and structural parsing."""

from app.ingestion.schemas import (
    FileEntry,
    ParsedSymbol,
    RepositoryManifest,
    SymbolKind,
)
from app.ingestion.clone import clone_repository, validate_github_url
from app.ingestion.manifest import build_manifest
from app.ingestion.parser import parse_file

__all__ = [
    "FileEntry",
    "ParsedSymbol",
    "RepositoryManifest",
    "SymbolKind",
    "clone_repository",
    "validate_github_url",
    "build_manifest",
    "parse_file",
]
