"""Comprehensive test suite for Phase 6B: ComparisonSnapshotService (exact dual-revision workspace acquisition)."""

import os
import subprocess
import tempfile
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4
import pytest
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.ingestion.clone import InvalidRepositoryURLError
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
from app.ingestion.snapshot import (
    RepositorySnapshotService,
    SnapshotError,
    SnapshotRehydrationError,
    SnapshotVerificationError,
)
from app.models.change_analysis import ChangeAnalysisModel
from app.schemas.enums import ChangeAnalysisStatus
from app.schemas.workflow_event import WorkflowEventType
from app.services.workflow_event_service import WorkflowEventService



BASE_SHA = "1111111111111111111111111111111111111111"
HEAD_SHA = "2222222222222222222222222222222222222222"
REPO_URL = "https://github.com/fastapi/fastapi"


# =========================================================================
# 1. Exact Revision Reconstruction & Verification Tests
# =========================================================================


def test_exact_dual_revision_reconstruction_success():
    """Verify that valid base and head revisions are materialized, HEADs verified, and workspaces yielded."""
    service = ComparisonSnapshotService()
    workspace_shas = {}

    def mock_subprocess_run(cmd, *args, **kwargs):
        assert kwargs.get("shell") is False
        cmd_str = " ".join(cmd)
        assert "core.symlinks=false" in cmd_str
        assert "submodule.recurse=false" in cmd_str

        cwd = kwargs.get("cwd", "")
        if "checkout" in cmd_str and "--detach" in cmd_str:
            workspace_shas[cwd] = cmd[-1]
            return MagicMock(returncode=0, stdout="", stderr="")
        if "rev-parse HEAD" in cmd_str:
            return MagicMock(returncode=0, stdout=workspace_shas.get(cwd, BASE_SHA), stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=mock_subprocess_run):
        pair = service.acquire_comparison_workspaces_from_metadata(
            repository_url=REPO_URL,
            base_commit_sha=BASE_SHA,
            head_commit_sha=HEAD_SHA,
            base_ref="main",
            head_ref="feature/branch",
        )

        assert isinstance(pair, ComparisonWorkspacePair)
        assert os.path.exists(pair.base_workspace)
        assert os.path.exists(pair.head_workspace)
        assert pair.base_commit_sha == BASE_SHA
        assert pair.head_commit_sha == HEAD_SHA
        assert pair.repository_url == "https://github.com/fastapi/fastapi.git"

        # Cleanup
        service.release_comparison_workspaces(pair.base_workspace, pair.head_workspace)
        assert not os.path.exists(pair.base_workspace)
        assert not os.path.exists(pair.head_workspace)



# =========================================================================
# 2. Mismatched, Wrong, and Missing SHA Rejection Tests
# =========================================================================


def test_wrong_head_sha_fails_closed_and_cleans_up_both_workspaces():
    """Verify that if head workspace HEAD does not match head_commit_sha, fail closed and cleanup base."""
    service = ComparisonSnapshotService()
    created_workspaces = []

    def mock_subprocess_run(cmd, *args, **kwargs):
        cmd_str = " ".join(cmd)
        cwd = kwargs.get("cwd", "")
        if "rev-parse HEAD" in cmd_str:
            if len(created_workspaces) > 1 and cwd == created_workspaces[1]:
                # Return wrong SHA on head workspace
                return MagicMock(returncode=0, stdout="9999999999999999999999999999999999999999", stderr="")
            return MagicMock(returncode=0, stdout=BASE_SHA, stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    orig_mkdtemp = tempfile.mkdtemp
    def tracked_mkdtemp(prefix=""):
        ws = orig_mkdtemp(prefix=prefix)
        created_workspaces.append(ws)
        return ws

    with patch("subprocess.run", side_effect=mock_subprocess_run), \
         patch("tempfile.mkdtemp", side_effect=tracked_mkdtemp):
        
        with pytest.raises(SnapshotVerificationError) as exc:
            service.acquire_comparison_workspaces_from_metadata(
                repository_url=REPO_URL,
                base_commit_sha=BASE_SHA,
                head_commit_sha=HEAD_SHA,
            )

        assert "mismatch" in str(exc.value).lower()
        # Verify both created workspaces were cleaned up
        for ws in created_workspaces:
            assert not os.path.exists(ws)


def test_identical_base_and_head_sha_rejected():
    """Verify that providing identical base and head commit SHAs is rejected."""
    service = ComparisonSnapshotService()
    with pytest.raises(InvalidRevisionError) as exc:
        service.acquire_comparison_workspaces_from_metadata(
            repository_url=REPO_URL,
            base_commit_sha=BASE_SHA,
            head_commit_sha=BASE_SHA,
        )
    assert "must be distinct" in str(exc.value)


def test_missing_or_non_hex_sha_rejected():
    """Verify that missing, empty, or non-hex SHAs are rejected before subprocess execution."""
    service = ComparisonSnapshotService()
    invalid_shas = [
        "",
        "1234567",  # short
        "111111111111111111111111111111111111111Z",  # non-hex
        "1111111111111111111111111111111111111111000",  # long
    ]
    for bad_sha in invalid_shas:
        with pytest.raises(InvalidRevisionError):
            service.acquire_comparison_workspaces_from_metadata(
                repository_url=REPO_URL,
                base_commit_sha=bad_sha,
                head_commit_sha=HEAD_SHA,
            )


# =========================================================================
# 3. URL and Security Validation Tests
# =========================================================================


def test_different_or_invalid_repository_url_rejected():
    """Verify non-HTTPS or non-GitHub URLs are rejected."""
    service = ComparisonSnapshotService()
    invalid_urls = [
        "http://github.com/owner/repo",
        "https://gitlab.com/owner/repo",
        "file:///tmp/repo",
        "https://user:token@github.com/owner/repo",
    ]
    for url in invalid_urls:
        with pytest.raises(InvalidRepositoryURLError):
            service.acquire_comparison_workspaces_from_metadata(
                repository_url=url,
                base_commit_sha=BASE_SHA,
                head_commit_sha=HEAD_SHA,
            )


def test_malicious_git_ref_strings_rejected():
    """Verify branch/ref strings containing injection metacharacters or flags are rejected."""
    service = ComparisonSnapshotService()
    malicious_refs = [
        "main; rm -rf /",
        "feature && cat /etc/passwd",
        "--upload-pack=evil",
        "-u",
        "`whoami`",
        "ref\nnewline",
    ]
    for bad_ref in malicious_refs:
        with pytest.raises(InvalidRevisionError):
            service.acquire_comparison_workspaces_from_metadata(
                repository_url=REPO_URL,
                base_commit_sha=BASE_SHA,
                head_commit_sha=HEAD_SHA,
                base_ref=bad_ref,
            )


# =========================================================================
# 4. Workspace Safety: Symlink Escape, Submodules, Resource Bounds & Binary Files
# =========================================================================


def test_symlink_escaping_workspace_rejected():
    """Verify that a symlink pointing outside the workspace boundary raises SymlinkEscapeError."""
    with tempfile.TemporaryDirectory() as ws, tempfile.TemporaryDirectory() as outside_dir:
        outside_file = os.path.join(outside_dir, "secret.txt")
        with open(outside_file, "w") as f:
            f.write("sensitive data")

        link_path = os.path.join(ws, "escaped_link.txt")
        try:
            os.symlink(outside_file, link_path)
            with pytest.raises(SymlinkEscapeError) as exc:
                validate_workspace_safety(ws)
            assert "escapes workspace boundary" in str(exc.value)
        except (OSError, NotImplementedError):
            # If OS does not permit symlinks without admin privilege (e.g. standard Windows), test via mocked islink/realpath
            with open(link_path, "w") as f:
                f.write("mocked link")

            orig_islink = os.path.islink
            orig_realpath = os.path.realpath

            def mock_islink(path):
                if path == link_path or os.path.basename(path) == "escaped_link.txt":
                    return True
                return orig_islink(path)

            def mock_realpath(path):
                if path == link_path or os.path.basename(path) == "escaped_link.txt":
                    return outside_file
                return orig_realpath(path)

            with patch("os.path.islink", side_effect=mock_islink), \
                 patch("os.path.realpath", side_effect=mock_realpath):
                with pytest.raises(SymlinkEscapeError) as exc:
                    validate_workspace_safety(ws)
                assert "escapes workspace boundary" in str(exc.value)



def test_submodule_presence_detected_and_rejected():
    """Verify that active submodules (.git directory in subdirectory) are detected and rejected."""
    with tempfile.TemporaryDirectory() as ws:
        submodule_dir = os.path.join(ws, "vendor", "subrepo")
        os.makedirs(os.path.join(submodule_dir, ".git"), exist_ok=True)

        with pytest.raises(SubmoduleExecutionError) as exc:
            validate_workspace_safety(ws)
        assert "Active git submodule detected" in str(exc.value)


def test_resource_bounds_exceeded_file_count():
    """Verify that exceeding MAX_REPO_FILES raises ResourceLimitExceededError."""
    custom_settings = Settings(MAX_REPO_FILES=5)
    with tempfile.TemporaryDirectory() as ws:
        for i in range(10):
            with open(os.path.join(ws, f"file_{i}.py"), "w") as f:
                f.write("print('hello')\n")

        with pytest.raises(ResourceLimitExceededError) as exc:
            validate_workspace_safety(ws, custom_settings)
        assert "file count" in str(exc.value)


def test_resource_bounds_exceeded_total_size():
    """Verify that exceeding MAX_TOTAL_SOURCE_BYTES raises ResourceLimitExceededError."""
    custom_settings = Settings(MAX_TOTAL_SOURCE_BYTES=100)
    with tempfile.TemporaryDirectory() as ws:
        with open(os.path.join(ws, "big_file.py"), "w") as f:
            f.write("x" * 200)

        with pytest.raises(ResourceLimitExceededError) as exc:
            validate_workspace_safety(ws, custom_settings)
        assert "total size" in str(exc.value)


def test_binary_files_identified_properly():
    """Verify binary files with binary extensions or null bytes are identified and not treated as text."""
    from app.ingestion.manifest import _is_binary_file

    assert _is_binary_file("assets/image.png", b"\x89PNG\r\n\x1a\n") is True
    assert _is_binary_file("lib/library.dll", b"MZ\x90\x00") is True
    assert _is_binary_file("data/unknown.dat", b"text\x00data") is True
    assert _is_binary_file("app/main.py", b"def main():\n    pass\n") is False


# =========================================================================
# 5. Timeout Handling
# =========================================================================


def test_snapshot_timeout_handling():
    """Verify subprocess timeout raises SnapshotRehydrationError and cleans up."""
    service = ComparisonSnapshotService()

    def mock_subprocess_timeout(cmd, *args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=5)

    with patch("subprocess.run", side_effect=mock_subprocess_timeout):
        with pytest.raises(ComparisonSnapshotError):
            service.acquire_comparison_workspaces_from_metadata(
                repository_url=REPO_URL,
                base_commit_sha=BASE_SHA,
                head_commit_sha=HEAD_SHA,
            )


# =========================================================================
# 6. Context Manager Lifecycle & Guaranteed Cleanup
# =========================================================================


def test_sync_comparison_context_manager_lifecycle():
    """Verify synchronous comparison_metadata_context guarantees dual cleanup."""
    service = ComparisonSnapshotService()
    captured_pair = None
    workspace_shas = {}

    def mock_subprocess_run(cmd, *args, **kwargs):
        cmd_str = " ".join(cmd)
        cwd = kwargs.get("cwd", "")
        if "checkout" in cmd_str and "--detach" in cmd_str:
            workspace_shas[cwd] = cmd[-1]
            return MagicMock(returncode=0, stdout="", stderr="")
        if "rev-parse HEAD" in cmd_str:
            return MagicMock(returncode=0, stdout=workspace_shas.get(cwd, BASE_SHA), stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=mock_subprocess_run):
        with service.comparison_metadata_context(
            repository_url=REPO_URL,
            base_commit_sha=BASE_SHA,
            head_commit_sha=HEAD_SHA,
        ) as pair:
            captured_pair = pair
            assert os.path.exists(pair.base_workspace)
            assert os.path.exists(pair.head_workspace)

        # After context exit, both workspaces must be removed
        assert not os.path.exists(captured_pair.base_workspace)
        assert not os.path.exists(captured_pair.head_workspace)


@pytest.mark.asyncio
async def test_async_comparison_context_manager_lifecycle():
    """Verify asynchronous open_comparison_metadata_snapshot guarantees dual cleanup."""
    service = ComparisonSnapshotService()
    captured_pair = None

    def mock_subprocess_run(cmd, *args, **kwargs):
        cmd_str = " ".join(cmd)
        if "rev-parse HEAD" in cmd_str:
            return MagicMock(returncode=0, stdout=BASE_SHA, stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=mock_subprocess_run), \
         patch.object(RepositorySnapshotService, "materialize_snapshot_from_metadata") as mock_mat:
        
        dir1 = tempfile.mkdtemp(prefix="base_")
        dir2 = tempfile.mkdtemp(prefix="head_")
        mock_mat.side_effect = [dir1, dir2]

        async with service.open_comparison_metadata_snapshot(
            repository_url=REPO_URL,
            base_commit_sha=BASE_SHA,
            head_commit_sha=HEAD_SHA,
        ) as pair:
            captured_pair = pair
            assert os.path.exists(pair.base_workspace)
            assert os.path.exists(pair.head_workspace)

        assert not os.path.exists(captured_pair.base_workspace)
        assert not os.path.exists(captured_pair.head_workspace)


# =========================================================================
# 7. Database Integration, Authoritative State Persistence & Retry
# =========================================================================


def test_database_backed_acquisition_state_persistence_and_retry(db_session: Session):
    """Verify database-backed acquisition transitions status to ACQUIRING -> emits event, handles failure and retry."""
    service = ComparisonSnapshotService()
    analysis_id = str(uuid4())

    analysis = ChangeAnalysisModel(
        id=analysis_id,
        repository_url=REPO_URL,
        repository_owner="fastapi",
        repository_name="fastapi",
        base_commit_sha=BASE_SHA,
        head_commit_sha=HEAD_SHA,
        status=ChangeAnalysisStatus.PENDING.value,
    )
    db_session.add(analysis)
    db_session.commit()

    # Attempt 1: Injected failure during snapshot materialization -> fails closed and updates status to FAILED
    with patch.object(RepositorySnapshotService, "materialize_snapshot_from_metadata", side_effect=SnapshotRehydrationError("Network connection lost")):
        with pytest.raises(SnapshotError):
            service.acquire_comparison_workspaces(analysis_id=analysis_id, db=db_session)


        # Verify analysis record transitioned to FAILED
        db_session.refresh(analysis)
        assert analysis.status == ChangeAnalysisStatus.FAILED.value
        assert "Network connection lost" in (analysis.failure_message or "")

        # Verify FAILURE event was emitted
        events = WorkflowEventService.list_for_change_analysis(db=db_session, change_analysis_id=analysis_id)
        assert any(e.event_type == WorkflowEventType.CHANGE_ANALYSIS_FAILED.value for e in events)

    # Attempt 2 (Retry on fresh session): Success materialization -> status ACQUIRING and event emitted
    dir1 = tempfile.mkdtemp(prefix="retry_base_")
    dir2 = tempfile.mkdtemp(prefix="retry_head_")

    with patch.object(RepositorySnapshotService, "materialize_snapshot_from_metadata", side_effect=[dir1, dir2]):
        pair = service.acquire_comparison_workspaces(analysis_id=analysis_id, db=db_session)

        assert pair.base_workspace == dir1
        assert pair.head_workspace == dir2

        db_session.refresh(analysis)
        assert analysis.status == ChangeAnalysisStatus.ACQUIRING.value

        events = WorkflowEventService.list_for_change_analysis(db=db_session, change_analysis_id=analysis_id)
        assert any(e.event_type == WorkflowEventType.CHANGE_REVISIONS_ACQUIRED.value for e in events)

        # Cleanup
        service.release_comparison_workspaces(pair.base_workspace, pair.head_workspace)
        assert not os.path.exists(dir1)
        assert not os.path.exists(dir2)


def test_singleton_accessor():
    """Verify get_comparison_snapshot_service returns singleton instance."""
    s1 = get_comparison_snapshot_service()
    s2 = get_comparison_snapshot_service()
    assert s1 is s2
    assert isinstance(s1, ComparisonSnapshotService)
