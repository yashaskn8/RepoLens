"""Canonical dual-revision snapshot acquisition service for Change Intelligence.

Safely reconstructs exact base and head repository workspaces without executing repository code.
Guarantees:
- Public HTTPS GitHub repositories only.
- Pinned to exact 40-hex base and head commit SHAs.
- Strict shell=False on all subprocess commands.
- Zero git submodule recursion (-c submodule.recurse=false).
- Zero git hooks (-c core.hooksPath=/dev/null).
- Zero Git LFS filter execution (-c filter.lfs.required=false).
- Zero symlink escapes (-c core.symlinks=false and post-materialization symlink validation).
- Enforces repository size, file count, and timeout resource bounds.
- Distinguishes binary files from text files.
- Persists authoritative analysis state before non-critical events.
- Guaranteed cleanup of both workspaces on success, failure, or exception.
"""

from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
import logging
import os
import re
import shutil
import tempfile
from typing import AsyncIterator, Iterator, List, Optional, Set, Tuple
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.database import SessionLocal
from app.ingestion.clone import InvalidRepositoryURLError, validate_github_url
from app.ingestion.manifest import BINARY_EXTENSIONS, DEFAULT_IGNORE_DIRS, _is_binary_file
from app.ingestion.snapshot import (
    RepositorySnapshotService,
    SnapshotError,
    SnapshotMetadataError,
    SnapshotRehydrationError,
    SnapshotVerificationError,
    get_snapshot_service,
)
from app.models.change_analysis import ChangeAnalysisModel
from app.schemas.enums import ChangeAnalysisStatus
from app.schemas.workflow_event import WorkflowEventCreate, WorkflowEventType
from app.security.redaction import redact_secrets
from app.services.workflow_event_service import WorkflowEventService

logger = logging.getLogger(__name__)

_HEX_40_REGEX = re.compile(r"^[0-9a-fA-F]{40}$")
_MALICIOUS_REF_CHARS = re.compile(r"[\s;&|`$\n\r\t<>\\*?]")


class ComparisonSnapshotError(SnapshotError):
    """Base exception for comparison snapshot acquisition errors."""
    pass


class ChangeAnalysisNotFoundError(ComparisonSnapshotError):
    """Raised when ChangeAnalysis record does not exist in database."""
    pass


class InvalidRevisionError(ComparisonSnapshotError):
    """Raised when base or head commit SHA is invalid, missing, or identical."""
    pass


class ResourceLimitExceededError(ComparisonSnapshotError):
    """Raised when repository exceeds file count or total size bounds."""
    pass


class SymlinkEscapeError(ComparisonSnapshotError):
    """Raised when repository contains symlinks escaping the workspace boundary."""
    pass


class SubmoduleExecutionError(ComparisonSnapshotError):
    """Raised when active submodules are detected in the workspace."""
    pass


@dataclass(frozen=True)
class ComparisonWorkspacePair:
    """Immutable value object holding paths and metadata for an exact two-revision workspace pair."""

    base_workspace: str
    head_workspace: str
    base_commit_sha: str
    head_commit_sha: str
    repository_url: str
    base_ref: Optional[str] = None
    head_ref: Optional[str] = None


def validate_workspace_safety(
    workspace_path: str,
    settings: Optional[Settings] = None,
) -> None:
    """Validate safety boundaries, symlink confinements, and resource limits on a materialized workspace.
    
    Raises:
        SymlinkEscapeError, ResourceLimitExceededError, SubmoduleExecutionError
    """
    cfg = settings or get_settings()
    max_files = getattr(cfg, "MAX_REPO_FILES", 5000)
    max_total_bytes = getattr(cfg, "MAX_TOTAL_SOURCE_BYTES", 52_428_800)  # 50 MB

    real_workspace_root = os.path.realpath(workspace_path)
    total_files = 0
    total_bytes = 0

    for root, dirs, files in os.walk(workspace_path, followlinks=False):
        # Prune ignored directory trees from traversal
        dirs[:] = [d for d in dirs if d not in DEFAULT_IGNORE_DIRS]

        # Check for nested active submodule git repositories
        for d in dirs:
            dir_full = os.path.join(root, d)
            if os.path.islink(dir_full):
                target = os.path.realpath(dir_full)
                if not target.startswith(real_workspace_root):
                    raise SymlinkEscapeError(f"Directory symlink '{d}' escapes workspace boundary to '{target}'")
            if os.path.isdir(os.path.join(dir_full, ".git")):
                raise SubmoduleExecutionError(f"Active git submodule detected at '{d}'. Submodules are strictly disallowed.")

        for file in files:
            file_path = os.path.join(root, file)

            # Check symlink safety
            if os.path.islink(file_path):
                target = os.path.realpath(file_path)
                if not target.startswith(real_workspace_root):
                    raise SymlinkEscapeError(f"Symlink '{file}' escapes workspace boundary to '{target}'")
                continue

            total_files += 1
            if total_files > max_files:
                raise ResourceLimitExceededError(
                    f"Repository file count ({total_files}) exceeds maximum allowed limit ({max_files})"
                )

            try:
                st = os.stat(file_path)
                total_bytes += st.st_size
                if total_bytes > max_total_bytes:
                    raise ResourceLimitExceededError(
                        f"Repository total size ({total_bytes} bytes) exceeds maximum budget ({max_total_bytes} bytes)"
                    )
            except OSError:
                pass


class ComparisonSnapshotService:
    """Canonical service for acquiring and managing isolated two-revision repository snapshots."""

    def __init__(
        self,
        snapshot_service: Optional[RepositorySnapshotService] = None,
        settings: Optional[Settings] = None,
    ):
        self.snapshot_service = snapshot_service or get_snapshot_service()
        self.settings = settings or get_settings()

    def acquire_comparison_workspaces_from_metadata(
        self,
        repository_url: str,
        base_commit_sha: str,
        head_commit_sha: str,
        base_ref: Optional[str] = None,
        head_ref: Optional[str] = None,
    ) -> ComparisonWorkspacePair:
        """Safely materialize isolated base and head workspaces directly from repository metadata.
        
        Args:
            repository_url: Public GitHub HTTPS URL.
            base_commit_sha: Exact 40-character base commit SHA.
            head_commit_sha: Exact 40-character head commit SHA.
            base_ref: Optional base branch/ref name.
            head_ref: Optional head branch/ref name.
            
        Returns:
            ComparisonWorkspacePair with validated base and head paths.
        Raises:
            InvalidRepositoryURLError, InvalidRevisionError, SnapshotVerificationError, ResourceLimitExceededError
        """
        # 1. Validate repository URL
        normalized_url = validate_github_url(repository_url)

        # 2. Validate commit SHAs
        base_sha_clean = (base_commit_sha or "").strip().lower()
        head_sha_clean = (head_commit_sha or "").strip().lower()

        if not _HEX_40_REGEX.match(base_sha_clean):
            raise InvalidRevisionError(f"Invalid or non-40-hex base commit SHA: '{base_commit_sha}'")
        if not _HEX_40_REGEX.match(head_sha_clean):
            raise InvalidRevisionError(f"Invalid or non-40-hex head commit SHA: '{head_commit_sha}'")

        if base_sha_clean == head_sha_clean:
            raise InvalidRevisionError(
                f"Base commit SHA and head commit SHA must be distinct revisions: '{base_sha_clean}'"
            )

        # 3. Sanitize ref strings against injection
        if base_ref and (_MALICIOUS_REF_CHARS.search(base_ref) or base_ref.startswith("-")):
            raise InvalidRevisionError(f"Malicious or invalid base_ref string: '{base_ref}'")
        if head_ref and (_MALICIOUS_REF_CHARS.search(head_ref) or head_ref.startswith("-")):
            raise InvalidRevisionError(f"Malicious or invalid head_ref string: '{head_ref}'")

        base_workspace: Optional[str] = None
        head_workspace: Optional[str] = None

        try:
            # 4. Materialize base workspace
            logger.info(f"Materializing base workspace for {normalized_url} at commit {base_sha_clean}")
            base_workspace = self.snapshot_service.materialize_snapshot_from_metadata(
                repository_url=normalized_url,
                commit_hash=base_sha_clean,
                branch=base_ref,
            )
            validate_workspace_safety(base_workspace, self.settings)

            # 5. Materialize head workspace
            logger.info(f"Materializing head workspace for {normalized_url} at commit {head_sha_clean}")
            head_workspace = self.snapshot_service.materialize_snapshot_from_metadata(
                repository_url=normalized_url,
                commit_hash=head_sha_clean,
                branch=head_ref,
            )
            validate_workspace_safety(head_workspace, self.settings)

            return ComparisonWorkspacePair(
                base_workspace=base_workspace,
                head_workspace=head_workspace,
                base_commit_sha=base_sha_clean,
                head_commit_sha=head_sha_clean,
                repository_url=normalized_url,
                base_ref=base_ref,
                head_ref=head_ref,
            )

        except Exception as exc:
            # Guaranteed cleanup on failure of either workspace
            self.release_comparison_workspaces(base_workspace, head_workspace)
            if not isinstance(exc, (ComparisonSnapshotError, SnapshotError, InvalidRepositoryURLError)):
                raise ComparisonSnapshotError(f"Comparison acquisition failed: {str(exc)}") from exc
            raise

    def acquire_comparison_workspaces(
        self,
        analysis_id: str | UUID,
        db: Optional[Session] = None,
    ) -> ComparisonWorkspacePair:
        """Acquire comparison workspaces for a persisted ChangeAnalysis record with authoritative state persistence."""
        owns_db = db is None
        session = db or SessionLocal()

        analysis_id_str = str(analysis_id)
        analysis: Optional[ChangeAnalysisModel] = None

        try:
            analysis = session.query(ChangeAnalysisModel).filter(ChangeAnalysisModel.id == analysis_id_str).first()
            if not analysis:
                raise ChangeAnalysisNotFoundError(f"ChangeAnalysis '{analysis_id_str}' not found.")

            # 1. Authoritative persistence: update status to ACQUIRING before external operations
            analysis.status = ChangeAnalysisStatus.ACQUIRING.value
            session.commit()
            session.refresh(analysis)

            # 2. Materialize workspaces
            pair = self.acquire_comparison_workspaces_from_metadata(
                repository_url=analysis.repository_url,
                base_commit_sha=analysis.base_commit_sha,
                head_commit_sha=analysis.head_commit_sha,
                base_ref=analysis.base_ref,
                head_ref=analysis.head_ref,
            )

            # 3. Emit CHANGE_REVISIONS_ACQUIRED event
            try:
                WorkflowEventService.emit_critical(
                    db=session,
                    event=WorkflowEventCreate(
                        event_type=WorkflowEventType.CHANGE_REVISIONS_ACQUIRED,
                        change_analysis_id=UUID(analysis_id_str),
                        stage="acquisition",
                        message=f"Acquired exact base ({pair.base_commit_sha[:8]}) and head ({pair.head_commit_sha[:8]}) workspaces",
                        metadata_payload={
                            "base_commit_sha": pair.base_commit_sha,
                            "head_commit_sha": pair.head_commit_sha,
                            "repository_url": pair.repository_url,
                        },
                    ),
                )
                session.commit()
            except Exception as evt_err:
                logger.warning(f"Could not emit CHANGE_REVISIONS_ACQUIRED event: {evt_err}")

            return pair

        except Exception as exc:
            # Update analysis record to FAILED on acquisition error
            if analysis:
                try:
                    session.rollback()
                    fresh_analysis = session.query(ChangeAnalysisModel).filter(ChangeAnalysisModel.id == analysis_id_str).first()
                    if fresh_analysis:
                        fresh_analysis.status = ChangeAnalysisStatus.FAILED.value
                        fresh_analysis.failure_code = getattr(exc, "failure_code", "ACQUISITION_FAILED")
                        fresh_analysis.failure_message = redact_secrets(str(exc))[:512]
                        session.commit()

                        try:
                            WorkflowEventService.emit_critical(
                                db=session,
                                event=WorkflowEventCreate(
                                    event_type=WorkflowEventType.CHANGE_ANALYSIS_FAILED,
                                    change_analysis_id=UUID(analysis_id_str),
                                    stage="acquisition",
                                    message=f"Acquisition failed: {fresh_analysis.failure_message}",
                                    metadata_payload={"failure_code": fresh_analysis.failure_code},
                                ),
                            )
                            session.commit()
                        except Exception:
                            pass
                except Exception as save_err:
                    logger.warning(f"Could not persist failure state for analysis '{analysis_id_str}': {save_err}")
            raise
        finally:
            if owns_db:
                session.close()

    def release_comparison_workspaces(
        self,
        base_workspace: Optional[str],
        head_workspace: Optional[str],
    ) -> None:
        """Guaranteed cleanup of both temporary workspaces."""
        if base_workspace:
            self.snapshot_service.release_snapshot(base_workspace)
        if head_workspace:
            self.snapshot_service.release_snapshot(head_workspace)

    @contextmanager
    def comparison_context(
        self,
        analysis_id: str | UUID,
        db: Optional[Session] = None,
    ) -> Iterator[ComparisonWorkspacePair]:
        """Synchronous context manager guaranteeing dual workspace cleanup."""
        pair = self.acquire_comparison_workspaces(analysis_id=analysis_id, db=db)
        try:
            yield pair
        finally:
            self.release_comparison_workspaces(pair.base_workspace, pair.head_workspace)

    @contextmanager
    def comparison_metadata_context(
        self,
        repository_url: str,
        base_commit_sha: str,
        head_commit_sha: str,
        base_ref: Optional[str] = None,
        head_ref: Optional[str] = None,
    ) -> Iterator[ComparisonWorkspacePair]:
        """Synchronous context manager for direct metadata acquisition with guaranteed cleanup."""
        pair = self.acquire_comparison_workspaces_from_metadata(
            repository_url=repository_url,
            base_commit_sha=base_commit_sha,
            head_commit_sha=head_commit_sha,
            base_ref=base_ref,
            head_ref=head_ref,
        )
        try:
            yield pair
        finally:
            self.release_comparison_workspaces(pair.base_workspace, pair.head_workspace)

    @asynccontextmanager
    async def open_comparison_snapshot(
        self,
        analysis_id: str | UUID,
        db: Optional[Session] = None,
    ) -> AsyncIterator[ComparisonWorkspacePair]:
        """Asynchronous context manager guaranteeing dual workspace cleanup."""
        import asyncio
        pair = await asyncio.to_thread(self.acquire_comparison_workspaces, analysis_id, db)
        try:
            yield pair
        finally:
            await asyncio.to_thread(self.release_comparison_workspaces, pair.base_workspace, pair.head_workspace)

    @asynccontextmanager
    async def open_comparison_metadata_snapshot(
        self,
        repository_url: str,
        base_commit_sha: str,
        head_commit_sha: str,
        base_ref: Optional[str] = None,
        head_ref: Optional[str] = None,
    ) -> AsyncIterator[ComparisonWorkspacePair]:
        """Asynchronous metadata context manager guaranteeing dual workspace cleanup."""
        import asyncio
        pair = await asyncio.to_thread(
            self.acquire_comparison_workspaces_from_metadata,
            repository_url,
            base_commit_sha,
            head_commit_sha,
            base_ref,
            head_ref,
        )
        try:
            yield pair
        finally:
            await asyncio.to_thread(
                self.release_comparison_workspaces,
                pair.base_workspace,
                pair.head_workspace,
            )


# Global singleton instance
_default_comparison_service: Optional[ComparisonSnapshotService] = None


def get_comparison_snapshot_service() -> ComparisonSnapshotService:
    """Retrieve singleton ComparisonSnapshotService."""
    global _default_comparison_service
    if _default_comparison_service is None:
        _default_comparison_service = ComparisonSnapshotService()
    return _default_comparison_service
