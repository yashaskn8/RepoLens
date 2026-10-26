"""GitHub branch refs are validated at the credentialed provider boundary."""
from unittest.mock import AsyncMock
import pytest

from app.delivery.github_provider import GitHubDeliveryProvider
from app.delivery.schemas import GitHubAPIError


@pytest.mark.parametrize("invalid", [
    "../other",
    "feature..other",
    "team//branch",
    "feature@{old}",
    "main?access_token=secret",
    "main#fragment",
    "-option",
    "bad\\backslash",
    "bad\nref",
    "",
    None,
])
@pytest.mark.asyncio
async def test_branch_head_lookup_rejects_invalid_ref_before_request(invalid):
    provider = GitHubDeliveryProvider(token="test-token", delivery_enabled=True)
    provider._request = AsyncMock()
    with pytest.raises(GitHubAPIError, match="Invalid GitHub branch ref"):
        await provider.get_branch_head("org", "repo", invalid)
    provider._request.assert_not_awaited()


@pytest.mark.asyncio
async def test_github_write_endpoints_reject_untrusted_branch_refs():
    provider = GitHubDeliveryProvider(token="test-token", delivery_enabled=True)
    provider._request = AsyncMock()
    with pytest.raises(GitHubAPIError):
        await provider.create_branch("org", "repo", "feature..unsafe", "a" * 40)
    with pytest.raises(GitHubAPIError):
        await provider.create_pull_request("org", "repo", "Title", "Body", "main", "invalid?base")
    with pytest.raises(GitHubAPIError):
        await provider.find_existing_pull_request("org", "repo", "invalid#head", "main")
    provider._request.assert_not_awaited()


@pytest.mark.asyncio
async def test_github_provider_normalizes_only_one_branch_prefix():
    provider = GitHubDeliveryProvider(token="test-token", delivery_enabled=True)
    provider._request = AsyncMock(return_value={
        "object": {"sha": "a" * 40},
    })
    result = await provider.get_branch_head(
        "org", "repo", "refs/heads/refs/heads/release",
    )
    assert result == "a" * 40
    provider._request.assert_awaited_once()
    assert provider._request.await_args.args[1].endswith(
        "/git/ref/heads/refs/heads/release"
    )
