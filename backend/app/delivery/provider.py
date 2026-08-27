"""Abstract interface for repository write and pull request delivery providers."""

from abc import ABC, abstractmethod
from typing import List, Optional
from app.delivery.schemas import (
    DeliveryProviderError,
    GitCommitInfo,
    GitPullRequestInfo,
    GitTreeEntry,
)


class RepositoryDeliveryProvider(ABC):
    """Abstract interface defining required provider capabilities for safe delivery."""

    @property
    def is_configured(self) -> bool:
        """Indicates if provider is configured and available for delivery operations."""
        return True

    async def try_get_branch_head(self, owner: str, repo: str, branch: str) -> Optional[str]:
        """Resolve current commit SHA at the head of a remote branch, returning None ONLY on confirmed 404."""
        try:
            return await self.get_branch_head(owner=owner, repo=repo, branch=branch)
        except DeliveryProviderError as err:
            if getattr(err, "status_code", None) == 404:
                return None
            raise

    @abstractmethod
    async def get_branch_head(self, owner: str, repo: str, branch: str) -> str:
        """Resolve current commit SHA at the head of a remote branch."""
        pass

    @abstractmethod
    async def get_commit(self, owner: str, repo: str, sha: str) -> GitCommitInfo:
        """Retrieve commit details including its root tree SHA."""
        pass

    @abstractmethod
    async def create_blob(self, owner: str, repo: str, content: str, encoding: str = "utf-8") -> str:
        """Create a Git blob object and return its SHA."""
        pass

    @abstractmethod
    async def create_tree(
        self,
        owner: str,
        repo: str,
        base_tree_sha: str,
        tree_entries: List[GitTreeEntry],
    ) -> str:
        """Create a new Git tree object based on base_tree_sha and return its SHA."""
        pass

    @abstractmethod
    async def create_commit(
        self,
        owner: str,
        repo: str,
        message: str,
        tree_sha: str,
        parent_shas: List[str],
    ) -> str:
        """Create a Git commit object and return its SHA."""
        pass

    @abstractmethod
    async def create_branch(self, owner: str, repo: str, branch_name: str, sha: str) -> str:
        """Create a new reference refs/heads/{branch_name} pointing to sha and return the ref name."""
        pass

    @abstractmethod
    async def find_existing_pull_request(
        self,
        owner: str,
        repo: str,
        head: str,
        base: str,
    ) -> Optional[GitPullRequestInfo]:
        """Search for an existing open pull request for the given head and base branches."""
        pass

    @abstractmethod
    async def create_pull_request(
        self,
        owner: str,
        repo: str,
        title: str,
        body: str,
        head: str,
        base: str,
    ) -> GitPullRequestInfo:
        """Create a new pull request and return its metadata."""
        pass
