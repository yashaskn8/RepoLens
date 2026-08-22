"""Provider-level data structures and exceptions for repository delivery providers."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class DeliveryProviderError(Exception):
    """Base exception for delivery provider operations."""

    def __init__(self, message: str, status_code: Optional[int] = None, safe_code: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.safe_code = safe_code or "PROVIDER_ERROR"


class GitHubAPIError(DeliveryProviderError):
    """Exception raised when GitHub API returns an error response."""

    def __init__(
        self,
        message: str,
        status_code: int,
        safe_code: Optional[str] = None,
        response_data: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, status_code=status_code, safe_code=safe_code or f"GITHUB_{status_code}")
        self.response_data = response_data or {}


@dataclass
class GitCommitInfo:
    """Commit SHA and tree SHA resolution from a repository provider."""

    sha: str
    tree_sha: str
    message: Optional[str] = None
    parents: List[str] = field(default_factory=list)


@dataclass
class GitTreeEntry:
    """Entry within a Git tree object for Git Data API tree construction."""

    path: str
    mode: str = "100644"  # 100644 for file (blob), 100755 for executable, 040000 for tree
    type: str = "blob"    # blob or tree
    sha: Optional[str] = None  # None indicates deletion in GitHub tree API if omitted or sha is null
    content: Optional[str] = None


@dataclass
class GitPullRequestInfo:
    """Pull request metadata returned by a repository provider."""

    number: int
    html_url: str
    head_branch: str
    base_branch: str
    title: str
    state: str = "open"
