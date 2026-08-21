"""Canonical repository snapshot rehydration service for exact-commit workspace reproduction.

Guarantees:
- HTTPS GitHub repositories only.
- Shallow and fetch-efficient checkout pinned to the exact persisted commit SHA.
- Verification that HEAD == persisted commit SHA before returning workspace.
- shell=False for all git subprocess operations.
- Zero submodules recursion (-c submodule.recurse=false).
- Zero untrusted repository code execution.
- Caller owns workspace strictly through context manager / service lifecycle.
- Guaranteed cleanup on success, cancellation, or failure.
- Zero permanent retention of cloned repositories on disk.
"""

from contextlib import asynccontextmanager, contextmanager
import logging
import os
import re
import shutil
import subprocess
import tempfile
from typing import AsyncIterator, Iterator, Optional, Tuple
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import SessionLocal
from app.ingestion.clone import InvalidRepositoryURLError, validate_github_url
from app.models.scan import ScanModel

logger = logging.getLogger(__name__)


class SnapshotError(Exception):
    """Base exception for snapshot service errors."""
    pass


class ScanNotFoundError(SnapshotError):
    """Raised when the specified scan_id does not exist in the database."""
    pass


class SnapshotMetadataError(SnapshotError):
    """Raised when scan metadata is missing or insufficient to rehydrate (e.g. missing commit SHA)."""
    pass


class SnapshotRehydrationError(SnapshotError):
    """Raised when git operations fail during snapshot materialization."""
    pass


class SnapshotVerificationError(SnapshotError):
    """Raised when rehydrated workspace HEAD does not match the persisted commit SHA."""
    pass


class RepositorySnapshotService:
    """Canonical service for materializing exact-commit repository snapshots."""

    def __init__(self, settings=None):
        self.settings = settings or get_settings()

    def _run_git_cmd(
        self,
        args: list[str],
        cwd: Optional[str] = None,
        timeout: int = 60,
    ) -> Tuple[int, str, str]:
        """Execute a git command with shell=False and strict security flags."""
        base_cmd = [
            "git",
            "-c", "core.symlinks=false",
            "-c", "submodule.recurse=false",
        ]
        full_cmd = base_cmd + args

        res = subprocess.run(
            full_cmd,
            cwd=cwd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return res.returncode, res.stdout.strip(), res.stderr.strip()

    def materialize_snapshot_from_metadata(
        self,
        repository_url: str,
        commit_hash: str,
        branch: Optional[str] = None,
    ) -> str:
        """Materialize an isolated temporary workspace containing EXACTLY the specified commit SHA.
        
        Args:
            repository_url: Public GitHub HTTPS URL.
            commit_hash: 40-character hex commit SHA.
            branch: Optional branch name originally requested.
            
        Returns:
            Absolute path to temporary workspace directory.
        Raises:
            InvalidRepositoryURLError, SnapshotMetadataError, SnapshotRehydrationError, SnapshotVerificationError
        """
        # 1. Validate inputs
        normalized_url = validate_github_url(repository_url)

        cleaned_sha = (commit_hash or "").strip()
        if not cleaned_sha or len(cleaned_sha) < 7 or not re.match(r"^[0-9a-fA-F]+$", cleaned_sha):
            raise SnapshotMetadataError(f"Invalid or missing commit SHA for snapshot: '{commit_hash}'")

        # 2. Create isolated temporary workspace directory
        workspace_path = tempfile.mkdtemp(prefix="repolens_snapshot_")

        try:
            timeout = getattr(self.settings, "CLONE_TIMEOUT_SECONDS", 120)

            # 3. Initialize empty git repository with security options
            code, out, err = self._run_git_cmd(["init"], cwd=workspace_path, timeout=15)
            if code != 0:
                raise SnapshotRehydrationError(f"git init failed in workspace: {err}")

            # 4. Add remote origin
            code, out, err = self._run_git_cmd(["remote", "add", "origin", normalized_url], cwd=workspace_path, timeout=15)
            if code != 0:
                raise SnapshotRehydrationError(f"git remote add failed: {err}")

            # 5. Fetch specific commit SHA (shallow depth=1)
            fetch_code, fetch_out, fetch_err = self._run_git_cmd(
                ["fetch", "--depth=1", "--no-recurse-submodules", "--tags", "origin", cleaned_sha],
                cwd=workspace_path,
                timeout=timeout,
            )

            # If direct commit fetch failed (e.g. server restrictions), try fetching branch or full fetch
            if fetch_code != 0:
                logger.warning(
                    f"Direct fetch of SHA {cleaned_sha} failed ({fetch_err}). Attempting fallback fetch..."
                )
                if branch:
                    cleaned_branch = branch.strip()
                    if not re.search(r"[\s;&|`$\n\r\t<>\\*?]", cleaned_branch) and not cleaned_branch.startswith("-"):
                        self._run_git_cmd(
                            ["fetch", "--depth=50", "--no-recurse-submodules", "origin", cleaned_branch],
                            cwd=workspace_path,
                            timeout=timeout,
                        )
                # If still not present, fallback to general fetch
                self._run_git_cmd(
                    ["fetch", "--depth=100", "--no-recurse-submodules", "origin"],
                    cwd=workspace_path,
                    timeout=timeout,
                )

            # 6. Checkout exact commit SHA (detached HEAD)
            co_code, co_out, co_err = self._run_git_cmd(
                ["checkout", "--detach", cleaned_sha],
                cwd=workspace_path,
                timeout=30,
            )
            if co_code != 0:
                raise SnapshotRehydrationError(
                    f"Failed to checkout exact commit {cleaned_sha} for {normalized_url}: {co_err}"
                )

            # 7. Verify HEAD == persisted commit SHA
            rev_code, current_head, rev_err = self._run_git_cmd(["rev-parse", "HEAD"], cwd=workspace_path, timeout=10)
            if rev_code != 0:
                raise SnapshotVerificationError(f"Could not verify repository HEAD SHA: {rev_err}")

            # Compare full or prefix match
            if not (current_head.lower().startswith(cleaned_sha.lower()) or cleaned_sha.lower().startswith(current_head.lower())):
                raise SnapshotVerificationError(
                    f"Snapshot HEAD verification mismatch: expected {cleaned_sha}, got {current_head}"
                )

            logger.info(
                f"Successfully materialized exact snapshot for {normalized_url} at commit {current_head} in {workspace_path}"
            )
            return workspace_path

        except Exception:
            # Guaranteed cleanup on failure
            self.release_snapshot(workspace_path)
            raise

    def materialize_snapshot(self, scan_id: str | UUID, db: Optional[Session] = None) -> str:
        """Materialize snapshot by looking up the scan record in database."""
        owns_db = db is None
        session = db or SessionLocal()

        try:
            scan_id_str = str(scan_id)
            scan = session.query(ScanModel).filter(ScanModel.id == scan_id_str).first()
            if not scan:
                raise ScanNotFoundError(f"Scan with ID '{scan_id_str}' not found.")

            if not scan.repository_url:
                raise SnapshotMetadataError(f"Scan '{scan_id_str}' has no repository URL.")

            if not scan.commit_hash or scan.commit_hash == "unknown":
                raise SnapshotMetadataError(
                    f"Scan '{scan_id_str}' has no recorded commit SHA (value: '{scan.commit_hash}')."
                )

            return self.materialize_snapshot_from_metadata(
                repository_url=scan.repository_url,
                commit_hash=scan.commit_hash,
                branch=scan.branch,
            )
        finally:
            if owns_db:
                session.close()

    def release_snapshot(self, workspace_path: Optional[str]) -> None:
        """Guaranteed cleanup of temporary workspace."""
        if workspace_path and os.path.exists(workspace_path):
            try:
                shutil.rmtree(workspace_path, ignore_errors=True)
                logger.debug(f"Released snapshot workspace: {workspace_path}")
            except Exception as exc:
                logger.warning(f"Error during workspace cleanup for '{workspace_path}': {exc}")

    @contextmanager
    def snapshot_context(
        self,
        scan_id: str | UUID,
        db: Optional[Session] = None,
    ) -> Iterator[str]:
        """Synchronous context manager guaranteeing workspace cleanup."""
        workspace = self.materialize_snapshot(scan_id, db=db)
        try:
            yield workspace
        finally:
            self.release_snapshot(workspace)

    @asynccontextmanager
    async def open_snapshot(
        self,
        scan_id: str | UUID,
        db: Optional[Session] = None,
    ) -> AsyncIterator[str]:
        """Asynchronous context manager guaranteeing workspace cleanup."""
        import asyncio
        workspace = await asyncio.to_thread(self.materialize_snapshot, scan_id, db)
        try:
            yield workspace
        finally:
            await asyncio.to_thread(self.release_snapshot, workspace)


# Global singleton instance
_default_snapshot_service: Optional[RepositorySnapshotService] = None


def get_snapshot_service() -> RepositorySnapshotService:
    """Retrieve singleton RepositorySnapshotService."""
    global _default_snapshot_service
    if _default_snapshot_service is None:
        _default_snapshot_service = RepositorySnapshotService()
    return _default_snapshot_service
