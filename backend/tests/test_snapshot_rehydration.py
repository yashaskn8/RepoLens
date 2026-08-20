"""Tests for Phase 3.5A: Durable exact-commit repository snapshot rehydration service."""

import os
from unittest.mock import MagicMock, patch
from uuid import uuid4
import pytest

from app.ingestion.clone import InvalidRepositoryURLError
from app.ingestion.snapshot import (
    RepositorySnapshotService,
    ScanNotFoundError,
    SnapshotMetadataError,
    SnapshotRehydrationError,
    SnapshotVerificationError,
    get_snapshot_service,
)
from app.models.scan import ScanModel
from app.schemas.enums import ScanStatus


# =========================================================================
# 1. URL & Metadata Validation Tests
# =========================================================================


def test_materialize_snapshot_rejects_invalid_url():
    """Verify snapshot materialization rejects non-HTTPS or malformed GitHub URLs."""
    service = RepositorySnapshotService()

    with pytest.raises(InvalidRepositoryURLError):
        service.materialize_snapshot_from_metadata(
            repository_url="http://github.com/insecure/repo",
            commit_hash="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        )

    with pytest.raises(InvalidRepositoryURLError):
        service.materialize_snapshot_from_metadata(
            repository_url="https://gitlab.com/other/repo",
            commit_hash="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        )


def test_materialize_snapshot_rejects_missing_or_malformed_sha():
    """Verify snapshot materialization rejects missing, empty, or non-hex commit SHAs."""
    service = RepositorySnapshotService()

    with pytest.raises(SnapshotMetadataError):
        service.materialize_snapshot_from_metadata(
            repository_url="https://github.com/owner/repo",
            commit_hash="",
        )

    with pytest.raises(SnapshotMetadataError):
        service.materialize_snapshot_from_metadata(
            repository_url="https://github.com/owner/repo",
            commit_hash="not-a-valid-sha-xyz",
        )


def test_materialize_snapshot_nonexistent_scan_id(db_session):
    """Verify ScanNotFoundError is raised when scan_id does not exist."""
    service = RepositorySnapshotService()
    non_existent = uuid4()

    with pytest.raises(ScanNotFoundError):
        service.materialize_snapshot(scan_id=non_existent, db=db_session)


def test_materialize_snapshot_scan_missing_commit_sha(db_session):
    """Verify SnapshotMetadataError is raised when scan record has no commit hash."""
    service = RepositorySnapshotService()
    scan_id = str(uuid4())

    scan_model = ScanModel(
        id=scan_id,
        repository_url="https://github.com/owner/repo.git",
        commit_hash=None,
        status=ScanStatus.PENDING.value,
    )
    db_session.add(scan_model)
    db_session.commit()

    with pytest.raises(SnapshotMetadataError):
        service.materialize_snapshot(scan_id=scan_id, db=db_session)


# =========================================================================
# 2. Exact Commit SHA Rehydration & Verification Tests
# =========================================================================


def test_exact_sha_rehydration_success():
    """Verify exact SHA rehydration executes safe git commands and verifies HEAD SHA."""
    service = RepositorySnapshotService()
    target_sha = "e1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0"
    created_paths = []

    def mock_subprocess_run(cmd, *args, **kwargs):
        # Verify shell=False on all calls
        assert kwargs.get("shell") is False
        cmd_str = " ".join(cmd)
        # Verify security flags
        assert "core.symlinks=false" in cmd_str
        assert "submodule.recurse=false" in cmd_str

        # Mock git commands
        if "rev-parse HEAD" in cmd_str:
            return MagicMock(returncode=0, stdout=target_sha, stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=mock_subprocess_run):
        workspace = service.materialize_snapshot_from_metadata(
            repository_url="https://github.com/fastapi/fastapi",
            commit_hash=target_sha,
            branch="main",
        )
        created_paths.append(workspace)

        assert os.path.exists(workspace)
        assert "repolens_snapshot_" in workspace

        # Cleanup
        service.release_snapshot(workspace)
        assert not os.path.exists(workspace)


def test_mismatched_sha_rejection_and_cleanup():
    """Verify SnapshotVerificationError is raised and directory cleaned up if HEAD != commit SHA."""
    service = RepositorySnapshotService()
    target_sha = "e1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0"
    different_sha = "9999999999999999999999999999999999999999"
    created_workspaces = []

    def mock_subprocess_run(cmd, *args, **kwargs):
        cmd_str = " ".join(cmd)
        if "rev-parse HEAD" in cmd_str:
            # Return unexpected SHA
            return MagicMock(returncode=0, stdout=different_sha, stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=mock_subprocess_run):
        with pytest.raises(SnapshotVerificationError) as exc_info:
            workspace = service.materialize_snapshot_from_metadata(
                repository_url="https://github.com/fastapi/fastapi",
                commit_hash=target_sha,
            )
            created_workspaces.append(workspace)

        assert "mismatch" in str(exc_info.value).lower()
        # Verify no directory leaked
        for w in created_workspaces:
            assert not os.path.exists(w)


def test_checkout_failure_raises_and_cleans_up():
    """Verify SnapshotRehydrationError is raised and workspace cleaned up when git checkout fails."""
    service = RepositorySnapshotService()
    target_sha = "e1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0"

    def mock_subprocess_run(cmd, *args, **kwargs):
        cmd_str = " ".join(cmd)
        if "checkout --detach" in cmd_str:
            return MagicMock(returncode=128, stdout="", stderr="fatal: reference is not a tree")
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=mock_subprocess_run):
        with pytest.raises(SnapshotRehydrationError) as exc_info:
            service.materialize_snapshot_from_metadata(
                repository_url="https://github.com/fastapi/fastapi",
                commit_hash=target_sha,
            )

        assert "Failed to checkout exact commit" in str(exc_info.value)


# =========================================================================
# 3. Context Manager Lifecycle & Guaranteed Cleanup Tests
# =========================================================================


def test_sync_snapshot_context_manager_lifecycle(db_session):
    """Verify synchronous context manager provides workspace and guarantees cleanup."""
    service = RepositorySnapshotService()
    target_sha = "e1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0"
    scan_id = str(uuid4())

    scan_model = ScanModel(
        id=scan_id,
        repository_url="https://github.com/fastapi/fastapi.git",
        commit_hash=target_sha,
        status=ScanStatus.COMPLETED.value,
    )
    db_session.add(scan_model)
    db_session.commit()

    captured_workspace = None

    def mock_subprocess_run(cmd, *args, **kwargs):
        cmd_str = " ".join(cmd)
        if "rev-parse HEAD" in cmd_str:
            return MagicMock(returncode=0, stdout=target_sha, stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=mock_subprocess_run):
        with service.snapshot_context(scan_id=scan_id, db=db_session) as ws:
            captured_workspace = ws
            assert os.path.exists(ws)

        # After exiting context manager, workspace should be deleted
        assert not os.path.exists(captured_workspace)


@pytest.mark.asyncio
async def test_async_snapshot_context_manager_lifecycle(db_session):
    """Verify asynchronous context manager provides workspace and guarantees cleanup."""
    service = RepositorySnapshotService()
    target_sha = "e1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0"
    scan_id = str(uuid4())

    scan_model = ScanModel(
        id=scan_id,
        repository_url="https://github.com/fastapi/fastapi.git",
        commit_hash=target_sha,
        status=ScanStatus.COMPLETED.value,
    )
    db_session.add(scan_model)
    db_session.commit()

    captured_workspace = None

    def mock_subprocess_run(cmd, *args, **kwargs):
        cmd_str = " ".join(cmd)
        if "rev-parse HEAD" in cmd_str:
            return MagicMock(returncode=0, stdout=target_sha, stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=mock_subprocess_run):
        async with service.open_snapshot(scan_id=scan_id, db=db_session) as ws:
            captured_workspace = ws
            assert os.path.exists(ws)

        # After exiting async context manager, workspace should be deleted
        assert not os.path.exists(captured_workspace)


def test_singleton_accessor():
    """Verify get_snapshot_service returns singleton instance."""
    s1 = get_snapshot_service()
    s2 = get_snapshot_service()
    assert s1 is s2
    assert isinstance(s1, RepositorySnapshotService)
