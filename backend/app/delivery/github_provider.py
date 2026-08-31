"""Canonical GitHubDeliveryProvider communicating with GitHub REST and Git Data APIs."""

import asyncio
import logging
from typing import Any, Dict, List, Optional
import httpx

from app.core.config import Settings, get_settings
from app.delivery.github_client import GITHUB_API_BASE_URL, GitHubHttpTransport
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

    async def get_branch_head(self, owner: str, repo: str, branch: str) -> str:
        """Resolve current commit SHA at the head of a remote branch."""
        clean_branch = branch.replace("refs/heads/", "")
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
        clean_branch = branch_name.replace("refs/heads/", "")
        payload = {
            "ref": f"refs/heads/{clean_branch}",
            "sha": sha,
        }
        data = await self._request("POST", f"/repos/{owner}/{repo}/git/refs", json_data=payload, is_write=True)
        ref = data.get("ref")
        if not ref:
            raise GitHubAPIError(f"Failed to create branch '{clean_branch}': no ref returned", status_code=500)
        return str(ref)

    async def find_existing_pull_request(
        self,
        owner: str,
        repo: str,
        head: str,
        base: str,
    ) -> Optional[GitPullRequestInfo]:
        """Search for an existing open pull request matching the head and base branches."""
        clean_head = head.replace("refs/heads/", "")
        clean_base = base.replace("refs/heads/", "")
        # GitHub search parameter for head is owner:branch or just branch
        params = {
            "head": f"{owner}:{clean_head}",
            "base": clean_base,
            "state": "all",
        }
        data = await self._request("GET", f"/repos/{owner}/{repo}/pulls", params=params)
        if isinstance(data, list) and len(data) > 0:
            pr = data[0]
            pr_num = pr.get("number")
            if pr_num is not None:
                canonical_url = f"https://github.com/{owner}/{repo}/pull/{pr_num}"
                return GitPullRequestInfo(
                    number=int(pr_num),
                    html_url=canonical_url,
                    head_branch=clean_head,
                    base_branch=clean_base,
                    title=pr.get("title", ""),
                    state=pr.get("state", "open"),
                )
        return None

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
        clean_head = head.replace("refs/heads/", "")
        clean_base = base.replace("refs/heads/", "")
        payload = {
            "title": redact_secrets(title)[:256],
            "body": redact_secrets(body),
            "head": clean_head,
            "base": clean_base,
        }
        data = await self._request("POST", f"/repos/{owner}/{repo}/pulls", json_data=payload, is_write=True)
        pr_number = data.get("number")
        if pr_number is None:
            raise GitHubAPIError("Pull request creation response did not contain a PR number", status_code=500)

        canonical_url = f"https://github.com/{owner}/{repo}/pull/{pr_number}"
        return GitPullRequestInfo(
            number=int(pr_number),
            html_url=canonical_url,
            head_branch=clean_head,
            base_branch=clean_base,
            title=str(data.get("title", title)),
            state=str(data.get("state", "open")),
        )
