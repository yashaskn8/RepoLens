"""Canonical GitHubDeliveryProvider communicating with GitHub REST and Git Data APIs."""

import asyncio
import logging
from typing import Any, Dict, List, Optional
import httpx

from app.core.config import Settings, get_settings
from app.delivery.github_client import GITHUB_API_BASE_URL, GitHubHttpTransport
from app.ingestion.clone import IngestionError, validate_git_branch_name
from app.delivery.provider import RepositoryDeliveryProvider
from app.delivery.schemas import (
    GitCommitInfo,
    GitPullRequestInfo,
    GitTreeEntry,
    GitHubAPIError,
)
from app.security.redaction import redact_secrets

logger = logging.getLogger(__name__)


class GitHubDeliveryProvider(RepositoryDeliveryProvider):
    """Concrete implementation of RepositoryDeliveryProvider for GitHub."""

    def __init__(
        self,
        token: Optional[str] = None,
        delivery_enabled: Optional[bool] = None,
        base_url: str = GITHUB_API_BASE_URL,
        settings: Optional[Settings] = None,
        client: Optional[httpx.AsyncClient] = None,
    ):
        app_settings = settings or get_settings()
        self._token = token if token is not None else app_settings.GITHUB_TOKEN
        self._delivery_enabled = (
            delivery_enabled
            if delivery_enabled is not None
            else getattr(app_settings, "GITHUB_DELIVERY_ENABLED", False)
        )
        self.transport = GitHubHttpTransport(
            token=self._token,
            base_url=base_url,
            user_agent="RepoLens-Delivery-Engine/1.0",
            settings=app_settings,
            client=client,
        )
        self.base_url = self.transport.base_url
        self._client = client
        self._timeout = self.transport._timeout

    @property
    def credentials_configured(self) -> bool:
        """Return True if GitHub credentials are non-empty."""
        return self.transport.has_credentials

    @property
    def delivery_enabled(self) -> bool:
        """Return True if GitHub delivery is administratively enabled."""
        return bool(self._delivery_enabled)

    @property
    def is_configured(self) -> bool:
        """Return True only if delivery is enabled AND credentials are present."""
        return self.credentials_configured and self.delivery_enabled

    def _get_headers(self) -> Dict[str, str]:
        """Build safe HTTP headers for GitHub API requests without exposing tokens in logs."""
        return self.transport.get_headers()

    async def _request(
        self,
        method: str,
        path: str,
        json_data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        is_write: bool = False,
    ) -> Dict[str, Any]:
        """Execute an HTTP request to the GitHub API with bounded retries on reads and no blind retries on writes."""
        return await self.transport.request(
            method=method,
            path=path,
            json_data=json_data,
            params=params,
            is_write=is_write,
        )

    @staticmethod
    def _checked_branch_ref(branch: str) -> str:
        """Validate refs before creating an outbound credentialed GitHub request."""
        try:
            if not isinstance(branch, str) or any(char in branch for char in ("#", "%")):
                # Git permits fragments/percent signs in refs, but these can
                # be reinterpreted as URL syntax or encoded path components.
                raise IngestionError("Invalid Git branch name.")
            # Remove only one conventional prefix, never every occurrence
            # within a legitimate nested branch name.
            return validate_git_branch_name(branch.removeprefix("refs/heads/"))
        except IngestionError:
            raise GitHubAPIError("Invalid GitHub branch ref.", status_code=400) from None

    async def get_branch_head(self, owner: str, repo: str, branch: str) -> str:
        """Resolve current commit SHA at the head of a remote branch."""
        clean_branch = self._checked_branch_ref(branch)
        try:
            data = await self._request("GET", f"/repos/{owner}/{repo}/git/ref/heads/{clean_branch}")
            obj = data.get("object", {})
            sha = obj.get("sha")
            if sha:
                return str(sha)
        except GitHubAPIError as err:
            if err.status_code != 404:
                raise

        # Fallback to branches API
        data = await self._request("GET", f"/repos/{owner}/{repo}/branches/{clean_branch}")
        commit = data.get("commit", {})
        sha = commit.get("sha")
        if not sha:
            raise GitHubAPIError(f"Could not resolve head commit for branch '{clean_branch}'", status_code=404)
        return str(sha)

    async def get_commit(self, owner: str, repo: str, sha: str) -> GitCommitInfo:
        """Retrieve commit details including its root tree SHA."""
        data = await self._request("GET", f"/repos/{owner}/{repo}/git/commits/{sha}")
        tree_sha = data.get("tree", {}).get("sha")
        if not tree_sha:
            raise GitHubAPIError(f"Commit '{sha}' response did not contain a tree SHA", status_code=500)
        parents = [p.get("sha") for p in data.get("parents", []) if p.get("sha")]
        return GitCommitInfo(
            sha=data.get("sha", sha),
            tree_sha=str(tree_sha),
            message=data.get("message"),
            parents=parents,
        )

    async def create_blob(self, owner: str, repo: str, content: str, encoding: str = "utf-8") -> str:
        """Create a Git blob object and return its SHA."""
        payload = {"content": content, "encoding": encoding}
        data = await self._request("POST", f"/repos/{owner}/{repo}/git/blobs", json_data=payload, is_write=True)
        blob_sha = data.get("sha")
        if not blob_sha:
            raise GitHubAPIError("Failed to create blob: no SHA returned", status_code=500)
        return str(blob_sha)

    async def create_tree(
        self,
        owner: str,
        repo: str,
        base_tree_sha: str,
        tree_entries: List[GitTreeEntry],
    ) -> str:
        """Create a new Git tree object based on base_tree_sha and return its SHA."""
        tree_list = []
        for entry in tree_entries:
            entry_dict: Dict[str, Any] = {
                "path": entry.path,
                "mode": entry.mode,
                "type": entry.type,
            }
            if entry.sha is not None:
                entry_dict["sha"] = entry.sha
            elif entry.content is not None:
                entry_dict["content"] = entry.content
            else:
                # Deletion entry in GitHub Git Data API
                entry_dict["sha"] = None
            tree_list.append(entry_dict)

        payload = {
            "base_tree": base_tree_sha,
            "tree": tree_list,
        }
        data = await self._request("POST", f"/repos/{owner}/{repo}/git/trees", json_data=payload, is_write=True)
        tree_sha = data.get("sha")
        if not tree_sha:
            raise GitHubAPIError("Failed to create tree: no SHA returned", status_code=500)
        return str(tree_sha)

    async def create_commit(
        self,
        owner: str,
        repo: str,
        message: str,
        tree_sha: str,
        parent_shas: List[str],
    ) -> str:
        """Create a Git commit object and return its SHA."""
        clean_msg = redact_secrets(message)
        payload = {
            "message": clean_msg,
            "tree": tree_sha,
            "parents": parent_shas,
        }
        data = await self._request("POST", f"/repos/{owner}/{repo}/git/commits", json_data=payload, is_write=True)
        commit_sha = data.get("sha")
        if not commit_sha:
            raise GitHubAPIError("Failed to create commit: no SHA returned", status_code=500)
        return str(commit_sha)

    async def create_branch(self, owner: str, repo: str, branch_name: str, sha: str) -> str:
        """Create a new reference refs/heads/{branch_name} pointing to sha and return the ref name."""
        clean_branch = self._checked_branch_ref(branch_name)
        payload = {
            "ref": f"refs/heads/{clean_branch}",
            "sha": sha,
        }
        data = await self._request("POST", f"/repos/{owner}/{repo}/git/refs", json_data=payload, is_write=True)
        ref = data.get("ref")
        if not ref:
            raise GitHubAPIError(f"Failed to create branch '{clean_branch}': no ref returned", status_code=500)
        return str(ref)


    @staticmethod
    def _verified_pull_request(
        payload: Dict[str, Any],
        *,
        owner: str,
        repo: str,
        head: str,
        base: str,
    ) -> GitPullRequestInfo:
        """Verify remote PR identity before it can satisfy delivery reconciliation.

        GitHub's search filters are advisory to the client: never treat the first
        returned row as proof that our intended repository/branch was used.
        Do not reflect untrusted response fields into diagnostic messages.
        """
        if not isinstance(payload, dict):
            raise GitHubAPIError("Invalid GitHub pull request response", status_code=502)
        number = payload.get("number")
        remote_head = payload.get("head")
        remote_base = payload.get("base")
        if (
            isinstance(number, bool)
            or not isinstance(number, int)
            or number < 1
            or not isinstance(remote_head, dict)
            or not isinstance(remote_base, dict)
        ):
            raise GitHubAPIError("Invalid GitHub pull request identity", status_code=502)
        # An absent or unexpected state cannot be silently treated as an
        # open PR and later persisted as a successful delivery.
        remote_state = payload.get("state")
        if remote_state not in ("open", "closed") or not isinstance(remote_state, str):
            raise GitHubAPIError("Invalid GitHub pull request state", status_code=502)
        expected_repo = f"{owner}/{repo}".casefold()
        for section, expected_ref in ((remote_head, head), (remote_base, base)):
            repo_info = section.get("repo")
            if (
                section.get("ref") != expected_ref
                or not isinstance(repo_info, dict)
                or not isinstance(repo_info.get("full_name"), str)
                or repo_info["full_name"].casefold() != expected_repo
            ):
                raise GitHubAPIError(
                    "GitHub pull request identity does not match intended delivery",
                    status_code=409,
                )
        return GitPullRequestInfo(
            number=number,
            html_url=f"https://github.com/{owner}/{repo}/pull/{number}",
            head_branch=head,
            base_branch=base,
            title=payload.get("title") if isinstance(payload.get("title"), str) else "",
            state=remote_state,
        )

    async def find_existing_pull_request(
        self,
        owner: str,
        repo: str,
        head: str,
        base: str,
    ) -> Optional[GitPullRequestInfo]:
        """Search for an existing open pull request matching the head and base branches."""
        clean_head = self._checked_branch_ref(head)
        clean_base = self._checked_branch_ref(base)
        # GitHub search parameter for head is owner:branch or just branch
        params = {
            "head": f"{owner}:{clean_head}",
            "base": clean_base,
            "state": "all",
        }
        data = await self._request("GET", f"/repos/{owner}/{repo}/pulls", params=params)
        if not isinstance(data, list):
            raise GitHubAPIError("Invalid GitHub pull request search response", status_code=502)
        if not data:
            return None
        return self._verified_pull_request(
            data[0], owner=owner, repo=repo, head=clean_head, base=clean_base,
        )

    async def create_pull_request(
        self,
        owner: str,
        repo: str,
        title: str,
        body: str,
        head: str,
        base: str,
    ) -> GitPullRequestInfo:
        """Create a new pull request and return canonical pull request info."""
        clean_head = self._checked_branch_ref(head)
        clean_base = self._checked_branch_ref(base)
        payload = {
            "title": redact_secrets(title)[:256],
            "body": redact_secrets(body),
            "head": clean_head,
            "base": clean_base,
        }
        data = await self._request("POST", f"/repos/{owner}/{repo}/pulls", json_data=payload, is_write=True)
        verified = self._verified_pull_request(
            data, owner=owner, repo=repo, head=clean_head, base=clean_base,
        )
        if verified.state != "open":
            raise GitHubAPIError("New GitHub pull request did not return an open state", status_code=502)
        return verified
