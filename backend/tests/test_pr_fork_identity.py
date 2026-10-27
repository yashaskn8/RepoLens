"""Regression coverage for PR source repository identity.

GitHub's repo.fork flag describes whether the *repository* was forked from
another project; it does not describe whether this PR crosses repositories.
"""
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.ingestion.github_pr import GitHubPRResolver


def _pr_payload(base_name: str, head_name: str, *, head_repo_is_fork: bool) -> dict:
    return {
        "title": "Change in a forked project",
        "state": "open",
        "base": {
            "ref": "main",
            "sha": "1" * 40,
            "repo": {
                "full_name": base_name,
                "html_url": f"https://github.com/{base_name}",
            },
        },
        "head": {
            "ref": "feature",
            "sha": "2" * 40,
            "repo": {
                "full_name": head_name,
                "html_url": f"https://github.com/{head_name}",
                "fork": head_repo_is_fork,
            },
        },
    }


@pytest.mark.asyncio
async def test_same_repository_pr_in_forked_project_is_not_cross_repo():
    """A repository may be a fork while its PR is entirely within that repo."""
    transport = MagicMock()
    transport.request = AsyncMock(
        return_value=_pr_payload(
            "contributor/forked-project",
            "contributor/forked-project",
            head_repo_is_fork=True,
        )
    )

    resolved = await GitHubPRResolver(transport=transport).resolve_pr(
        "https://github.com/contributor/forked-project/pull/17"
    )

    assert resolved.is_fork is False
    assert resolved.repository_url == "https://github.com/contributor/forked-project"
    assert resolved.head_repo_url == resolved.repository_url
    transport.request.assert_awaited_once_with(
        method="GET",
        path="repos/contributor/forked-project/pulls/17",
        is_write=False,
    )


@pytest.mark.asyncio
async def test_cross_repository_pr_detected_even_without_fork_metadata():
    """Different head/base identities are a cross-repository PR regardless of flags."""
    transport = MagicMock()
    transport.request = AsyncMock(
        return_value=_pr_payload(
            "upstream/project",
            "contributor/project",
            head_repo_is_fork=False,
        )
    )

    resolved = await GitHubPRResolver(transport=transport).resolve_pr(
        "https://github.com/upstream/project/pull/19"
    )

    assert resolved.is_fork is True
    assert resolved.head_repo_url == "https://github.com/contributor/project"


@pytest.mark.asyncio
async def test_same_repository_pr_in_original_project_stays_supported():
    transport = MagicMock()
    transport.request = AsyncMock(
        return_value=_pr_payload(
            "upstream/project",
            "upstream/project",
            head_repo_is_fork=False,
        )
    )

    resolved = await GitHubPRResolver(transport=transport).resolve_pr(
        "https://github.com/upstream/project/pull/21"
    )

    assert resolved.is_fork is False
