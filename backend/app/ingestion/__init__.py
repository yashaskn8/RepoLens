"""Repository ingestion: safe cloning, manifest generation, structural parsing, and exact-commit snapshot rehydration."""

from app.ingestion.schemas import (
    FileEntry,
    ParsedCall,
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
    get_git_resolved_branch_or_ref,
    validate_github_url,
)
from app.ingestion.manifest import build_manifest
from app.ingestion.parser import parse_file, parse_file_with_calls
from app.ingestion.snapshot import (
    RepositorySnapshotService,
    ScanNotFoundError,
    SnapshotError,
    SnapshotMetadataError,
    SnapshotRehydrationError,
    SnapshotVerificationError,
    get_snapshot_service,
)
from app.ingestion.comparison_snapshot import (
    ChangeAnalysisNotFoundError,
    ComparisonSnapshotError,
    ComparisonSnapshotService,
    ComparisonWorkspacePair,
    InvalidRevisionError,
    ResourceLimitExceededError,
    SubmoduleExecutionError,
    SymlinkEscapeError,
    get_comparison_snapshot_service,
    validate_workspace_safety,
)

__all__ = [
    "CloneFailedError",
    "CloneTimeoutError",
    "FileEntry",
    "IngestionError",
    "InvalidRepositoryURLError",
    "ParsedCall",
    "ParsedSymbol",
    "RepositoryManifest",
    "RepositorySnapshotService",
    "ScanNotFoundError",
    "SnapshotError",
    "SnapshotMetadataError",
    "SnapshotRehydrationError",
    "SnapshotVerificationError",
    "ComparisonSnapshotError",
    "ChangeAnalysisNotFoundError",
    "InvalidRevisionError",
    "ResourceLimitExceededError",
    "SymlinkEscapeError",
    "SubmoduleExecutionError",
    "ComparisonSnapshotService",
    "ComparisonWorkspacePair",
    "get_comparison_snapshot_service",
    "validate_workspace_safety",
    "SymbolKind",
    "build_manifest",
    "clone_repository",
    "get_git_resolved_branch_or_ref",
    "get_snapshot_service",
    "parse_file",
    "parse_file_with_calls",
    "validate_github_url",
]


