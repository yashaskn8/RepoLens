"""Unit tests for safe shallow cloning mechanics and error handling."""

import subprocess
import os
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
    mock_rev_res = MagicMock(return_code=0, stdout="c0ffee1234567890abcdef1234567890abcdef12\n", stderr="", returncode=0)
    monkeypatch_env = {
        "GITHUB_TOKEN": "red-team-ambient-secret",
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "filter.poison.smudge",
        "GIT_CONFIG_VALUE_0": "poison-command",
        "GIT_DIR": "C:/foreign/.git",
    }

    def mock_subprocess_run(cmd, *args, **kwargs):
        assert kwargs.get("shell") is False
        env = kwargs["env"]
        assert env["GIT_CONFIG_NOSYSTEM"] == "1"
        assert env["GIT_CONFIG_GLOBAL"] == os.devnull
        assert env["GIT_LFS_SKIP_SMUDGE"] == "1"
        assert not set(monkeypatch_env).intersection(env)
        if "clone" in cmd:
            assert "--depth" in cmd
            assert "1" in cmd
            assert "--no-recurse-submodules" in cmd
            assert "core.symlinks=false" in cmd
            assert "core.autocrlf=false" in cmd
            return mock_clone_res
        elif "rev-parse" in cmd:
            return mock_rev_res
        return MagicMock(returncode=0)

    with patch.dict(os.environ, monkeypatch_env), patch("subprocess.run", side_effect=mock_subprocess_run):
        workspace, commit_sha = clone_repository(
            repo_url="https://github.com/fastapi/fastapi",
            branch="main",
            target_dir="/tmp/test_dir",
        )

    assert workspace == "/tmp/test_dir"
    assert commit_sha == "c0ffee1234567890abcdef1234567890abcdef12"


def test_resolved_git_metadata_uses_sanitized_environment(tmp_path, monkeypatch):
    from app.ingestion.clone import get_git_resolved_branch_or_ref

    repo_dir = tmp_path / "repo"
    (repo_dir / ".git").mkdir(parents=True)
    monkeypatch.setenv("GIT_DIR", "C:/foreign/.git")
    monkeypatch.setenv("GITHUB_TOKEN", "ambient-secret")
    captured = []

    def mock_subprocess_run(cmd, *args, **kwargs):
        captured.append(kwargs["env"])
        return MagicMock(returncode=1, stdout="", stderr="not a repository")

    with patch("subprocess.run", side_effect=mock_subprocess_run):
        assert get_git_resolved_branch_or_ref(str(repo_dir)) is None

    assert len(captured) == 3
    for env in captured:
        assert env["GIT_CONFIG_NOSYSTEM"] == "1"
        assert "GIT_DIR" not in env
        assert "GITHUB_TOKEN" not in env


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
