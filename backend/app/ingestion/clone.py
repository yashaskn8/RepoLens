"""Safe GitHub repository cloning and URL validation."""

import os
import re
import shutil
import subprocess
import tempfile
import threading
from typing import Optional, Tuple
from urllib.parse import urlparse
from app.core.config import get_settings


class IngestionError(Exception):
    """Base exception for ingestion failures."""
    pass


class InvalidRepositoryURLError(IngestionError):
    """Raised when repository URL does not match strict GitHub HTTPS format."""
    pass


class CloneTimeoutError(IngestionError):
    """Raised when git clone exceeds configured time limit."""
    pass


class CloneFailedError(IngestionError):
    """Raised when git clone terminates with a non-zero exit code."""
    pass


class RepositoryResourceLimitError(IngestionError):
    """Raised when Git tree metadata or source blob sizes exceed admission limits."""
    pass


# Strict regex for public GitHub repository: https://github.com/owner/repo(.git)?
GITHUB_URL_PATTERN = re.compile(
    r"^https://github\.com/([a-zA-Z0-9_.-]+)/([a-zA-Z0-9_.-]+?)(?:\.git)?/?$"
)

_GIT_TRANSPORT_ENV = frozenset({
    "PATH", "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "SYSTEMROOT", "WINDIR",
    "COMSPEC", "PATHEXT", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE",
})


def safe_git_environment() -> dict[str, str]:
    """Build a minimal Git transport environment without ambient Git config/secrets.

    System/global Git configuration can register arbitrary clean/smudge filters;
    repository-controlled ``.gitattributes`` can name those filters during
    checkout. Disable that configuration and Git LFS smudging, while preserving
    only platform, proxy, and CA settings needed for HTTPS transport.
    """
    env = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in _GIT_TRANSPORT_ENV
    }
    env.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "",
        "GIT_LFS_SKIP_SMUDGE": "1",
    })
    return env


_MAX_GIT_PATH_BYTES = 4096
_GIT_PIPE_READ_BYTES = 64 * 1024


def validate_repository_tree_budget(
    repository_dir: str,
    commit_ref: str,
    *,
    max_files: int,
    max_file_bytes: int,
    max_total_bytes: int,
    timeout_seconds: int = 30,
) -> tuple[int, int]:
    """Inspect a commit tree before checkout and reject over-budget blob sets.

    Partial clone leaves source blobs unmaterialized until checkout. This
    bounded `ls-tree` pass admits the exact tree only when file-count, per-blob,
    aggregate bytes, and metadata output fit ingestion policy.
    """
    metadata_limit = max(64 * 1024, max_files * (_MAX_GIT_PATH_BYTES + 128))
    command = ["git", "-c", "core.symlinks=false", "-c", "core.autocrlf=false", "ls-tree", "-r", "-l", "-z", commit_ref]
    process = subprocess.Popen(
        command,
        cwd=repository_dir,
        env=safe_git_environment(),
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    overflow = threading.Event()
    captured = {"stdout": bytearray(), "stderr": bytearray()}

    def drain(name: str, stream, limit: int) -> None:
        try:
            while True:
                chunk = stream.read(_GIT_PIPE_READ_BYTES)
                if not chunk:
                    return
                remaining = limit - len(captured[name])
                captured[name].extend(chunk[:max(remaining, 0)])
                if len(chunk) > remaining:
                    overflow.set()
                    try:
                        process.kill()
                    except OSError:
                        pass
                    return
        finally:
            stream.close()

    assert process.stdout is not None and process.stderr is not None
    readers = (
        threading.Thread(target=drain, args=("stdout", process.stdout, metadata_limit), daemon=True),
        threading.Thread(target=drain, args=("stderr", process.stderr, 64 * 1024), daemon=True),
    )
    for reader in readers:
        reader.start()
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.wait()
        raise RepositoryResourceLimitError("Git tree inspection exceeded its time limit") from exc
    finally:
        for reader in readers:
            reader.join(timeout=2)
        if process.poll() is None:
            process.kill()
            process.wait()

    if overflow.is_set():
        raise RepositoryResourceLimitError("Git tree metadata exceeded its configured byte limit")
    if process.returncode != 0:
        raise CloneFailedError("Git tree inspection failed for the requested commit")

    output = bytes(captured["stdout"])
    if output and not output.endswith(b"\0"):
        raise CloneFailedError("Git tree inspection returned malformed output")
    file_count = 0
    total_bytes = 0
    for record in output.split(b"\0"):
        if not record:
            continue
        try:
            metadata, path = record.split(b"\t", 1)
            mode, object_type, _object_id, size_raw = metadata.split(b" ", 3)
        except ValueError as exc:
            raise CloneFailedError("Git tree inspection returned malformed output") from exc
        if len(path) > _MAX_GIT_PATH_BYTES:
            raise RepositoryResourceLimitError("Repository path exceeds the acquisition path limit")
        if object_type == b"commit":
            continue  # submodule gitlinks are not recursively materialized
        if object_type != b"blob":
            raise CloneFailedError("Git tree inspection returned an unexpected object type")
        try:
            blob_size = int(size_raw)
        except ValueError as exc:
            raise CloneFailedError("Git tree inspection omitted a blob size") from exc
        file_count += 1
        total_bytes += blob_size
        if file_count > max_files:
            raise RepositoryResourceLimitError("Repository exceeds the configured file-count limit")
        if blob_size > max_file_bytes:
            raise RepositoryResourceLimitError("Repository contains a blob exceeding the configured per-file limit")
        if total_bytes > max_total_bytes:
            raise RepositoryResourceLimitError("Repository exceeds the configured aggregate source-byte limit")
    return file_count, total_bytes


def validate_github_url(url: str) -> str:
    """Validate that URL is strictly a public HTTPS github.com repository URL.
    
    Rejects non-HTTPS schemes, other hosts, embedded credentials, shell characters, and invalid paths.
    Returns normalized URL format: https://github.com/{owner}/{repo}.git
    """
    if not url or not isinstance(url, str):
        raise InvalidRepositoryURLError("Repository URL must be a non-empty string.")

    cleaned_url = url.strip()

    # Disallow shell metacharacters, control chars, whitespace, or flags
    if re.search(r"[\s;&|`$\n\r\t<>\\*?]", cleaned_url):
        raise InvalidRepositoryURLError("Repository URL contains forbidden characters.")

    # Disallow flags attempting to inject git options
    if cleaned_url.startswith("-"):
        raise InvalidRepositoryURLError("Repository URL cannot start with a dash.")

    parsed = urlparse(cleaned_url)

    # Must be HTTPS
    if parsed.scheme.lower() != "https":
        raise InvalidRepositoryURLError(f"Only HTTPS protocol is permitted; got '{parsed.scheme}'.")

    # Disallow embedded credentials (e.g. https://user:pass@github.com)
    if parsed.username or parsed.password:
        raise InvalidRepositoryURLError("Credentials in repository URLs are strictly prohibited.")

    # Must be github.com
    if parsed.netloc.lower() not in ("github.com", "www.github.com"):
        raise InvalidRepositoryURLError(f"Only github.com repositories are supported; got '{parsed.netloc}'.")

    match = GITHUB_URL_PATTERN.match(cleaned_url)
    if not match:
        raise InvalidRepositoryURLError(
            "Invalid GitHub repository URL format. Expected 'https://github.com/owner/repo'."
        )

    owner, repo = match.groups()
    if owner in (".", "..") or repo in (".", ".."):
        raise InvalidRepositoryURLError("Invalid owner or repository name.")

    # Remove trailing .git if present in repo group
    if repo.endswith(".git"):
        repo = repo[:-4]

    return f"https://github.com/{owner}/{repo}.git"


def clone_repository(
    repo_url: str,
    branch: Optional[str] = None,
    target_dir: Optional[str] = None,
    timeout_seconds: Optional[int] = None,
) -> Tuple[str, str]:
    """Safely perform a shallow clone of a public GitHub repository without executing code.
    
    Returns:
        Tuple of (workspace_path, commit_sha)
    """
    settings = get_settings()
    timeout = timeout_seconds or settings.CLONE_TIMEOUT_SECONDS
    normalized_url = validate_github_url(repo_url)

    dest_dir = target_dir or tempfile.mkdtemp(prefix="repolens_repo_")

    cmd = [
        "git",
        "clone",
        "--quiet",
        "--depth",
        "1",
        "--filter=blob:none",
        "--no-checkout",
        "--no-recurse-submodules",
        "--config",
        "core.symlinks=false",
        # Evidence manifests are bound to Git blob bytes. Prevent checkout-time
        # newline conversion from making the worktree differ from that source.
        "--config",
        "core.autocrlf=false",
        "--config",
        "credential.helper=",
    ]

    if branch:
        # Validate branch name doesn't start with dash or contain shell characters
        cleaned_branch = branch.strip()
        if re.search(r"[\s;&|`$\n\r\t<>\\*?]", cleaned_branch) or cleaned_branch.startswith("-"):
            raise IngestionError(f"Invalid branch name: '{branch}'")
        cmd.extend(["--branch", cleaned_branch, "--single-branch"])

    cmd.extend(["--", normalized_url, dest_dir])

    env = safe_git_environment()

    try:
        result = subprocess.run(
            cmd,
            env=env,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

        if result.returncode != 0:
            # Clean up directory on failure if created by us
            if target_dir is None and os.path.exists(dest_dir):
                shutil.rmtree(dest_dir, ignore_errors=True)
            raise CloneFailedError(f"git clone failed with exit code {result.returncode}: {result.stderr.strip()}")

        validate_repository_tree_budget(
            dest_dir,
            "HEAD",
            max_files=int(settings.MAX_REPO_FILES),
            max_file_bytes=int(settings.MAX_FILE_SIZE_BYTES),
            max_total_bytes=int(settings.MAX_TOTAL_SOURCE_BYTES),
            timeout_seconds=min(timeout, 60),
        )

        checkout_result = subprocess.run(
            ["git", "checkout", "--detach", "HEAD"],
            cwd=dest_dir,
            env=safe_git_environment(),
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if checkout_result.returncode != 0:
            if target_dir is None and os.path.exists(dest_dir):
                shutil.rmtree(dest_dir, ignore_errors=True)
            raise CloneFailedError("git checkout failed after repository admission.")

        # Record exact commit SHA
        rev_cmd = ["git", "rev-parse", "HEAD"]
        rev_result = subprocess.run(
            rev_cmd,
            cwd=dest_dir,
            env=safe_git_environment(),
            shell=False,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

        if rev_result.returncode != 0:
            if target_dir is None and os.path.exists(dest_dir):
                shutil.rmtree(dest_dir, ignore_errors=True)
            raise CloneFailedError(f"git rev-parse HEAD failed with exit code {rev_result.returncode}: {rev_result.stderr.strip()}")

        commit_sha = rev_result.stdout.strip()
        if not re.match(r"^[0-9a-fA-F]{40}$", commit_sha):
            if target_dir is None and os.path.exists(dest_dir):
                shutil.rmtree(dest_dir, ignore_errors=True)
            raise CloneFailedError(f"git rev-parse HEAD returned invalid non-40-character commit SHA: '{commit_sha}'")

        return dest_dir, commit_sha

    except subprocess.TimeoutExpired:
        if target_dir is None and os.path.exists(dest_dir):
            shutil.rmtree(dest_dir, ignore_errors=True)
        raise CloneTimeoutError(f"git clone timed out after {timeout} seconds.")
    except Exception as exc:
        if not isinstance(exc, IngestionError):
            if target_dir is None and os.path.exists(dest_dir):
                shutil.rmtree(dest_dir, ignore_errors=True)
            raise CloneFailedError(f"Unexpected clone error: {str(exc)}")
        raise


def get_git_resolved_branch_or_ref(repo_dir: str) -> Optional[str]:
    """Deterministically inspect a local git repository to discover its current resolved branch or ref.

    Returns:
        The branch name (e.g. 'main', 'master', 'feature/x'), or ref string if detached HEAD, or None.
    """
    if not os.path.exists(repo_dir) or not os.path.exists(os.path.join(repo_dir, ".git")):
        return None

    # 1. Try symbolic-ref for active branch
    try:
        res = subprocess.run(
            ["git", "symbolic-ref", "--short", "HEAD"],
            cwd=repo_dir,
            env=safe_git_environment(),
            shell=False,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except Exception:
        pass

    # 2. Fallback to rev-parse --abbrev-ref HEAD
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=repo_dir,
            env=safe_git_environment(),
            shell=False,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if res.returncode == 0:
            out = res.stdout.strip()
            if out and out != "HEAD":
                return out
    except Exception:
        pass

    # 3. If in detached HEAD state, return ref with commit SHA prefix
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_dir,
            env=safe_git_environment(),
            shell=False,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if res.returncode == 0 and res.stdout.strip():
            full_sha = res.stdout.strip()
            return f"HEAD@{full_sha[:8]}"
    except Exception:
        pass

    return None
