"""Safe GitHub repository cloning and URL validation."""

import os
import re
import shutil
import subprocess
import tempfile
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


# Strict regex for public GitHub repository: https://github.com/owner/repo(.git)?
GITHUB_URL_PATTERN = re.compile(
    r"^https://github\.com/([a-zA-Z0-9_.-]+)/([a-zA-Z0-9_.-]+?)(?:\.git)?/?$"
)


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
        "--depth",
        "1",
        "--no-recurse-submodules",
        "--config",
        "core.symlinks=false",
    ]

    if branch:
        # Validate branch name doesn't start with dash or contain shell characters
        cleaned_branch = branch.strip()
        if re.search(r"[\s;&|`$\n\r\t<>\\*?]", cleaned_branch) or cleaned_branch.startswith("-"):
            raise IngestionError(f"Invalid branch name: '{branch}'")
        cmd.extend(["--branch", cleaned_branch, "--single-branch"])

    cmd.extend(["--", normalized_url, dest_dir])

    try:
        result = subprocess.run(
            cmd,
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

        # Record exact commit SHA
        rev_cmd = ["git", "rev-parse", "HEAD"]
        rev_result = subprocess.run(
            rev_cmd,
            cwd=dest_dir,
            shell=False,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

        if rev_result.returncode != 0:
            commit_sha = "unknown"
        else:
            commit_sha = rev_result.stdout.strip()

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
