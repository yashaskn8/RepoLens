"""Unit tests for safe shallow cloning mechanics and error handling."""

import subprocess
import os
import io
import sys
import time
from unittest.mock import MagicMock, patch
import pytest

from app.ingestion.clone import (
    CloneFailedError,
    CloneTimeoutError,
    IngestionError,
    RepositoryResourceLimitError,
    clone_repository,
    validate_repository_tree_budget,
)


def test_clone_repository_invokes_git_safely():
    """Verify that clone_repository passes safe flags and shell=False to subprocess."""
    mock_rev_res = MagicMock(return_code=0, stdout="c0ffee1234567890abcdef1234567890abcdef12\n", stderr="", returncode=0)
    monkeypatch_env = {
        "GITHUB_TOKEN": "red-team-ambient-secret",
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "filter.poison.smudge",
        "GIT_CONFIG_VALUE_0": "poison-command",
        "GIT_DIR": "C:/foreign/.git",
    }

    command_order = []

    class CompletedGitProcess:
        pid = 2**31 - 1

        def __init__(self):
            self.returncode = 0
            self.stderr = io.BytesIO()

        def poll(self):
            return self.returncode

        def wait(self):
            return self.returncode

        def kill(self):
            self.returncode = -9

    def mock_popen(cmd, *args, **kwargs):
        assert kwargs.get("shell") is False
        env = kwargs["env"]
        assert env["GIT_CONFIG_NOSYSTEM"] == "1"
        assert env["GIT_CONFIG_GLOBAL"] == os.devnull
        assert env["GIT_LFS_SKIP_SMUDGE"] == "1"
        assert not set(monkeypatch_env).intersection(env)
        if "clone" in cmd:
            command_order.append("clone")
            assert "--depth" in cmd
            assert "1" in cmd
            assert "--filter=blob:none" in cmd
            assert "--no-tags" in cmd
            assert "--no-checkout" in cmd
            assert "--no-recurse-submodules" in cmd
            assert "core.symlinks=false" in cmd
            assert "core.autocrlf=false" in cmd
        else:
            assert "checkout" in cmd
            assert kwargs["cwd"] == "/tmp/test_dir"
            command_order.append("checkout")
        return CompletedGitProcess()

    def mock_subprocess_run(cmd, *args, **kwargs):
        assert kwargs.get("shell") is False
        if "rev-parse" in cmd:
            command_order.append("rev-parse")
            return mock_rev_res
        return MagicMock(returncode=0)

    def start_guarded_process(tree, cmd, **kwargs):
        tree.process = mock_popen(cmd, **kwargs)
        return tree.process

    with patch.dict(os.environ, monkeypatch_env), patch(
        "app.ingestion.clone._GitProcessTreeGuard.start", autospec=True, side_effect=start_guarded_process
    ), patch(
        "subprocess.run", side_effect=mock_subprocess_run
    ), patch(
        "app.ingestion.clone.validate_repository_tree_budget",
        side_effect=lambda *_args, **_kwargs: command_order.append("preflight"),
    ):
        workspace, commit_sha = clone_repository(
            repo_url="https://github.com/fastapi/fastapi",
            branch="main",
            target_dir="/tmp/test_dir",
        )

    assert workspace == "/tmp/test_dir"
    assert commit_sha == "c0ffee1234567890abcdef1234567890abcdef12"
    assert command_order == ["clone", "preflight", "checkout", "rev-parse"]


def test_production_clone_fails_closed_before_workspace_or_git(monkeypatch):
    from types import SimpleNamespace

    from app.ingestion.acquisition_boundary import AcquisitionEnforcementUnavailable

    monkeypatch.setattr(
        "app.ingestion.clone.get_settings",
        lambda: SimpleNamespace(is_production=True, CLONE_TIMEOUT_SECONDS=120),
    )
    monkeypatch.setattr(
        "app.ingestion.clone.tempfile.mkdtemp",
        lambda **_kwargs: pytest.fail("production must fail before allocating a workspace"),
    )
    monkeypatch.setattr(
        "app.ingestion.clone._run_clone_with_object_budget",
        lambda *_args, **_kwargs: pytest.fail("production must fail before Git starts"),
    )

    with pytest.raises(AcquisitionEnforcementUnavailable) as exc_info:
        clone_repository("https://github.com/owner/repo")
    assert exc_info.value.failure_code == "ACQUISITION_ENFORCEMENT_UNAVAILABLE"


@pytest.mark.parametrize(
    ("max_files", "max_file_bytes", "max_total_bytes", "expected"),
    [
        (0, 4096, 4096, "file-count"),
        (10, 4, 4096, "per-file"),
        (10, 4096, 4, "aggregate"),
    ],
)
def test_git_tree_budget_rejects_over_limit_before_checkout(
    tmp_path, max_files, max_file_bytes, max_total_bytes, expected
):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@invalid"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "RepoLens test"], check=True)
    (repo / "a.py").write_bytes(b"12345")
    (repo / "b.py").write_bytes(b"12345")
    subprocess.run(["git", "-C", str(repo), "add", "a.py", "b.py"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "fixture"], check=True)

    with pytest.raises(IngestionError, match=expected):
        validate_repository_tree_budget(
            str(repo),
            "HEAD",
            max_files=max_files,
            max_file_bytes=max_file_bytes,
            max_total_bytes=max_total_bytes,
        )


def test_git_tree_budget_rejects_object_store_over_limit_before_listing(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@invalid"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "RepoLens test"], check=True)
    (repo / "a.py").write_text("pass\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "a.py"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "fixture"], check=True)

    with pytest.raises(RepositoryResourceLimitError, match="object-store"):
        validate_repository_tree_budget(
            str(repo),
            "HEAD",
            max_files=10,
            max_file_bytes=4096,
            max_total_bytes=4096,
            max_git_object_bytes=1,
        )


def test_clone_process_is_killed_when_object_store_budget_is_exceeded(tmp_path):
    class RunningProcess:
        pid = 2**31 - 1
        returncode = None
        stderr = io.BytesIO()
        killed = False

        def poll(self):
            return self.returncode

        def kill(self):
            self.killed = True
            self.returncode = -9

        def wait(self):
            return self.returncode

    process = RunningProcess()
    def start_fake_process(tree, *_args, **_kwargs):
        tree.process = process
        return process

    with patch("app.ingestion.clone._git_object_store_bytes", side_effect=[0, 5]), patch(
        "app.ingestion.clone._GitProcessTreeGuard.start", autospec=True, side_effect=start_fake_process
    ), patch(
        "app.ingestion.clone._GitProcessTreeGuard.terminate", autospec=True, side_effect=lambda tree: tree.process.kill()
    ):
        with pytest.raises(RepositoryResourceLimitError, match="object-store byte limit"):
            from app.ingestion.clone import _run_clone_with_object_budget

            _run_clone_with_object_budget(
                ["git", "clone"],
                environment={},
                repository_dir=str(tmp_path),
                timeout_seconds=10,
                max_git_object_bytes=4,
            )
    assert process.killed is True


def test_completed_clone_is_checked_against_object_budget():
    from app.ingestion.clone import _run_clone_with_object_budget

    class CompletedGitProcess:
        pid = 2**31 - 1
        returncode = 0
        stderr = io.BytesIO()

        def poll(self):
            return self.returncode

        def wait(self):
            return self.returncode

        def kill(self):
            self.returncode = -9

    def start_completed_process(tree, *_args, **_kwargs):
        process = CompletedGitProcess()
        tree.process = process
        return process

    with patch("app.ingestion.clone._GitProcessTreeGuard.start", autospec=True, side_effect=start_completed_process), patch(
        "app.ingestion.clone._git_object_store_bytes", return_value=5
    ):
        with pytest.raises(RepositoryResourceLimitError, match="object-store byte limit"):
            _run_clone_with_object_budget(
                ["git", "clone"],
                environment={},
                repository_dir="unused",
                timeout_seconds=10,
                max_git_object_bytes=4,
            )


def test_checkout_uses_object_budget_runner_and_cleans_rejected_clone(tmp_path):
    from types import SimpleNamespace

    from app.ingestion.clone import RepositoryResourceLimitError

    clone_dir = tmp_path / "temporary-clone"
    calls = []

    def create_clone_dir(*_args, **_kwargs):
        clone_dir.mkdir()
        return str(clone_dir)

    def run_git(command, **_kwargs):
        calls.append(command)
        if "clone" in command:
            return subprocess.CompletedProcess(command, 0, "", "")
        assert "checkout" in command
        raise RepositoryResourceLimitError("object budget exceeded during checkout")

    settings = SimpleNamespace(
        CLONE_TIMEOUT_SECONDS=10,
        MAX_GIT_OBJECT_BYTES=4,
        MAX_REPO_FILES=10,
        MAX_FILE_SIZE_BYTES=4096,
        MAX_TOTAL_SOURCE_BYTES=4096,
    )
    with patch("app.ingestion.clone.get_settings", return_value=settings), patch(
        "app.ingestion.clone.tempfile.mkdtemp", side_effect=create_clone_dir
    ), patch("app.ingestion.clone._run_clone_with_object_budget", side_effect=run_git), patch(
        "app.ingestion.clone.validate_repository_tree_budget"
    ):
        with pytest.raises(RepositoryResourceLimitError, match="during checkout"):
            clone_repository("https://github.com/org/repo")

    assert ["clone" in call for call in calls] == [True, False]
    assert not clone_dir.exists()


@pytest.mark.parametrize("parent_exit_before_cleanup", [False, True])
def test_git_process_tree_guard_stops_descendants(tmp_path, parent_exit_before_cleanup):
    from app.ingestion.clone import _GitProcessTreeGuard

    marker = tmp_path / "child-writes.bin"
    child_script = tmp_path / "bounded_child.py"
    child_script.write_text(
        "import pathlib,sys,time\n"
        "p=pathlib.Path(sys.argv[1])\n"
        "f=p.open('ab', buffering=0)\n"
        "for _ in range(150):\n"
        "    f.write(b'x' * 1024)\n"
        "    time.sleep(0.01)\n",
        encoding="utf-8",
    )
    parent_script = tmp_path / "bounded_parent.py"
    parent_script.write_text(
        "import subprocess,sys,time\n"
        "child=subprocess.Popen([sys.executable,sys.argv[1],sys.argv[2]])\n"
        "print(child.pid, flush=True)\n"
        "time.sleep(float(sys.argv[3]))\n",
        encoding="utf-8",
    )
    parent_duration = "0.15" if parent_exit_before_cleanup else "60"
    process_tree = _GitProcessTreeGuard()
    process = process_tree.start(
        [sys.executable, str(parent_script), str(child_script), str(marker), parent_duration],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout is not None
        child_pid = process.stdout.readline().strip()
        assert child_pid.isdigit(), process.stderr.read() if process.stderr is not None else ""
        assert process.poll() is None
        deadline = time.monotonic() + 5
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert marker.exists()

        if parent_exit_before_cleanup:
            process.wait(timeout=5)
            assert process.poll() is not None
        else:
            process_tree.terminate()
            process.wait(timeout=5)
        stopped_size = marker.stat().st_size
        process_tree.close()
        time.sleep(0.1)
        assert marker.stat().st_size == stopped_size
    finally:
        process_tree.close()


def test_rejected_temporary_clone_is_removed(tmp_path):
    from types import SimpleNamespace

    from app.ingestion.clone import RepositoryResourceLimitError

    clone_dir = tmp_path / "temporary-clone"

    def create_clone_dir(*_args, **_kwargs):
        clone_dir.mkdir()
        return str(clone_dir)

    settings = SimpleNamespace(
        CLONE_TIMEOUT_SECONDS=10,
        MAX_GIT_OBJECT_BYTES=4,
    )
    with patch("app.ingestion.clone.get_settings", return_value=settings), patch(
        "app.ingestion.clone.tempfile.mkdtemp", side_effect=create_clone_dir
    ), patch(
        "app.ingestion.clone._run_clone_with_object_budget",
        side_effect=RepositoryResourceLimitError("object budget exceeded"),
    ):
        with pytest.raises(RepositoryResourceLimitError, match="object budget exceeded"):
            clone_repository("https://github.com/org/repo")

    assert not clone_dir.exists()


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
    class RunningProcess:
        pid = 2**31 - 1
        returncode = None
        stderr = io.BytesIO()

        def poll(self):
            return self.returncode

        def kill(self):
            self.returncode = -9

        def wait(self):
            return self.returncode

    def start_running_process(tree, *_args, **_kwargs):
        process = RunningProcess()
        tree.process = process
        return process

    with patch("app.ingestion.clone._GitProcessTreeGuard.start", autospec=True, side_effect=start_running_process), patch(
        "app.ingestion.clone._GitProcessTreeGuard.terminate", autospec=True, side_effect=lambda tree: tree.process.kill()
    ), patch(
        "app.ingestion.clone._git_object_store_bytes", return_value=0
    ), patch("app.ingestion.clone.time.monotonic", side_effect=[0.0, 11.0]):
        with pytest.raises(CloneTimeoutError):
            clone_repository(
                repo_url="https://github.com/fastapi/fastapi",
                timeout_seconds=10,
                target_dir="/tmp/timeout_test",
            )


def test_clone_repository_non_zero_exit_handling():
    """Verify that non-zero git exit raises CloneFailedError."""
    class FailedGitProcess:
        pid = 2**31 - 1
        returncode = 128
        stderr = io.BytesIO(b"fatal: repository not found")

        def poll(self):
            return self.returncode

        def wait(self):
            return self.returncode

        def kill(self):
            self.returncode = -9

    def start_failed_process(tree, *_args, **_kwargs):
        tree.process = FailedGitProcess()
        return tree.process

    with patch(
        "app.ingestion.clone._GitProcessTreeGuard.start",
        autospec=True,
        side_effect=start_failed_process,
    ):
        with pytest.raises(CloneFailedError) as exc_info:
            clone_repository(
                repo_url="https://github.com/nonexistent/repo",
                target_dir="/tmp/fail_test",
            )
        assert "git clone failed with exit code 128" in str(exc_info.value)
