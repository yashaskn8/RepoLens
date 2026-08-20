"""Unit tests for safe shallow cloning mechanics and error handling."""

import subprocess
from unittest.mock import MagicMock, patch
import pytest

from app.ingestion.clone import (
    CloneFailedError,
    CloneTimeoutError,
    IngestionError,
    clone_repository,
)


def test_clone_repository_invokes_git_safely():
    """Verify that clone_repository passes safe flags and shell=False to subprocess."""
    mock_clone_res = MagicMock(return_code=0, stdout="", stderr="", returncode=0)
    mock_rev_res = MagicMock(return_code=0, stdout="c0ffee1234567890\n", stderr="", returncode=0)

    def mock_subprocess_run(cmd, *args, **kwargs):
        assert kwargs.get("shell") is False
        if "clone" in cmd:
            assert "--depth" in cmd
            assert "1" in cmd
            assert "--no-recurse-submodules" in cmd
            assert "core.symlinks=false" in cmd
            return mock_clone_res
        elif "rev-parse" in cmd:
            return mock_rev_res
        return MagicMock(returncode=0)

    with patch("subprocess.run", side_effect=mock_subprocess_run):
        workspace, commit_sha = clone_repository(
            repo_url="https://github.com/fastapi/fastapi",
            branch="main",
            target_dir="/tmp/test_dir",
        )

    assert workspace == "/tmp/test_dir"
    assert commit_sha == "c0ffee1234567890"


def test_clone_repository_rejects_malicious_branch():
    """Verify that malicious branch names with shell metacharacters are rejected."""
    with pytest.raises(IngestionError):
        clone_repository(
            repo_url="https://github.com/fastapi/fastapi",
            branch="main; rm -rf /",
        )


def test_clone_repository_timeout_handling():
    """Verify that subprocess timeout raises CloneTimeoutError."""
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="git clone", timeout=10)):
        with pytest.raises(CloneTimeoutError):
            clone_repository(
                repo_url="https://github.com/fastapi/fastapi",
                timeout_seconds=10,
                target_dir="/tmp/timeout_test",
            )


def test_clone_repository_non_zero_exit_handling():
    """Verify that non-zero git exit raises CloneFailedError."""
    mock_failed_res = MagicMock(returncode=128, stderr="fatal: repository not found")
    with patch("subprocess.run", return_value=mock_failed_res):
        with pytest.raises(CloneFailedError) as exc_info:
            clone_repository(
                repo_url="https://github.com/nonexistent/repo",
                target_dir="/tmp/fail_test",
            )
        assert "git clone failed with exit code 128" in str(exc_info.value)
