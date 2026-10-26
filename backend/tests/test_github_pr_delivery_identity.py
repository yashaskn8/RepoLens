"""GitHub delivery must not reconcile a PR for any other branch or repository."""
from copy import deepcopy
from unittest.mock import AsyncMock

import pytest

from app.delivery.github_provider import GitHubDeliveryProvider
from app.delivery.schemas import GitHubAPIError


def _pr():
    return {
        "number": 42,
        "title": "Remediation",
        "state": "open",
        "head": {"ref": "repolens/fix-1", "repo": {"full_name": "org/repo"}},
        "base": {"ref": "main", "repo": {"full_name": "org/repo"}},
    }


@pytest.mark.asyncio
async def test_existing_pr_reconciles_only_with_exact_target_identity():
    provider = GitHubDeliveryProvider(token="test-token", delivery_enabled=True)
    provider._request = AsyncMock(return_value=[_pr()])
    result = await provider.find_existing_pull_request(
        "org", "repo", "repolens/fix-1", "main",
    )
    assert result.number == 42
    assert result.html_url == "https://github.com/org/repo/pull/42"
    assert result.head_branch == "repolens/fix-1"
    assert result.base_branch == "main"


@pytest.mark.asyncio
@pytest.mark.parametrize("alteration", [
    ("head", "ref", "other-branch"),
    ("base", "ref", "different-base"),
    ("head", "repo", {"full_name": "attacker/repo"}),
    ("base", "repo", {"full_name": "other/repo"}),
    ("head", "repo", None),
])
async def test_mismatched_remote_pr_never_satisfies_reconciliation(alteration):
    provider = GitHubDeliveryProvider(token="test-token", delivery_enabled=True)
    pr = deepcopy(_pr())
    group, field, value = alteration
    pr[group][field] = value
    provider._request = AsyncMock(return_value=[pr])
    with pytest.raises(GitHubAPIError, match="identity does not match"):
        await provider.find_existing_pull_request(
            "org", "repo", "repolens/fix-1", "main",
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid_number", [0, -1, True, "42", None])
async def test_remote_pr_number_must_be_a_positive_integer(invalid_number):
    provider = GitHubDeliveryProvider(token="test-token", delivery_enabled=True)
    pr = _pr()
    pr["number"] = invalid_number
    provider._request = AsyncMock(return_value=[pr])
    with pytest.raises(GitHubAPIError, match="Invalid GitHub pull request identity"):
        await provider.find_existing_pull_request(
            "org", "repo", "repolens/fix-1", "main",
        )


@pytest.mark.asyncio
async def test_bad_search_response_never_causes_duplicate_pr_creation():
    provider = GitHubDeliveryProvider(token="test-token", delivery_enabled=True)
    provider._request = AsyncMock(return_value={"number": 42})
    with pytest.raises(GitHubAPIError, match="search response"):
        await provider.find_existing_pull_request(
            "org", "repo", "repolens/fix-1", "main",
        )


@pytest.mark.asyncio
async def test_pr_creation_rejects_remote_identity_mismatch_without_claiming_success():
    provider = GitHubDeliveryProvider(token="test-token", delivery_enabled=True)
    pr = _pr()
    pr["base"]["ref"] = "wrong"
    provider._request = AsyncMock(return_value=pr)
    with pytest.raises(GitHubAPIError, match="identity does not match"):
        await provider.create_pull_request(
            "org", "repo", "Fix", "Details", "repolens/fix-1", "main",
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("remote_state", [None, "", "draft", "merged", 200, True])
async def test_invalid_pr_state_never_satisfies_delivery_reconciliation(remote_state):
    provider = GitHubDeliveryProvider(token="test-token", delivery_enabled=True)
    pr = _pr()
    if remote_state is None:
        pr.pop("state")
    else:
        pr["state"] = remote_state
    provider._request = AsyncMock(return_value=[pr])
    with pytest.raises(GitHubAPIError, match="Invalid GitHub pull request state"):
        await provider.find_existing_pull_request(
            "org", "repo", "repolens/fix-1", "main",
        )


@pytest.mark.asyncio
async def test_new_pr_must_be_open_before_delivery_claims_success():
    provider = GitHubDeliveryProvider(token="test-token", delivery_enabled=True)
    pr = _pr()
    pr["state"] = "closed"
    provider._request = AsyncMock(return_value=pr)
    with pytest.raises(GitHubAPIError, match="did not return an open state"):
        await provider.create_pull_request(
            "org", "repo", "Fix", "Details", "repolens/fix-1", "main",
        )
