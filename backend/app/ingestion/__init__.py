"""Repository ingestion: safe cloning, manifest generation, structural parsing, and exact-commit snapshot rehydration."""

from app.ingestion.schemas import (
    FileEntry,
    ParsedSymbol,
    RepositoryManifest,
    SymbolKind,
)
from app.ingestion.clone import (
    CloneFailedError,
    CloneTimeoutError,
    IngestionError,
    InvalidRepositoryURLError,
    clone_repository,
    validate_github_url,
)
from app.ingestion.manifest import build_manifest
from app.ingestion.parser import parse_file
from app.ingestion.snapshot import (
    RepositorySnapshotService,
    ScanNotFoundError,
    SnapshotError,
    SnapshotMetadataError,
    SnapshotRehydrationError,
    SnapshotVerificationError,
    get_snapshot_service,
)

__all__ = [
    "CloneFailedError",
    "CloneTimeoutError",
    "FileEntry",
    "IngestionError",
    "InvalidRepositoryURLError",
    "ParsedSymbol",
    "RepositoryManifest",
    "RepositorySnapshotService",
    "ScanNotFoundError",
    "SnapshotError",
    "SnapshotMetadataError",
    "SnapshotRehydrationError",
    "SnapshotVerificationError",
    "SymbolKind",
    "build_manifest",
    "clone_repository",
    "get_snapshot_service",
    "parse_file",
    "validate_github_url",
]

