"""Unit tests for GitHubReviewPublicationProvider."""

from unittest.mock import AsyncMock, MagicMock
import httpx
import pytest

from app.delivery.publication_provider import GITHUB_API_BASE_URL, GitHubReviewPublicationProvider
from app.schemas.review_publication import (
    GitHubAuthFailedError,
    GitHubRateLimitedError,
    GitHubReviewStateUncertainError,
    GitHubReviewWriteDisabledError,
    InlineReviewComment,
    PRNotFoundError,
)


@pytest.mark.asyncio
async def test_provider_write_disabled_by_default():
    """Verify provider rejects writes when write_enabled is False."""
    provider = GitHubReviewPublicationProvider(token="mock_token", write_enabled=False)
    assert provider.write_enabled is False

    with pytest.raises(GitHubReviewWriteDisabledError):
        await provider.create_comment_review(
            owner="octocat",
            repo="Hello-World",
            pr_number=1,
            commit_sha="a" * 40,
            body="Review body",
        )


@pytest.mark.asyncio
async def test_provider_rejects_untrusted_origin():
    """Verify provider strictly enforces https://api.github.com and rejects arbitrary origins (SSRF prevention)."""
    with pytest.raises(ValueError, match="Untrusted API origin"):
        GitHubReviewPublicationProvider(token="mock", base_url="https://attacker.com/api")


@pytest.mark.asyncio
async def test_provider_payload_enforces_comment_event():
    """Verify POST review payload strictly contains event='COMMENT' and commit_id."""
    mock_client = MagicMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "id": 12345,
        "html_url": "https://github.com/octocat/Hello-World/pull/1#pullrequestreview-12345",
        "state": "COMMENTED",
    }
    mock_client.request = AsyncMock(return_value=mock_resp)

    provider = GitHubReviewPublicationProvider(
        token="valid_token",
        write_enabled=True,
        client=mock_client,
    )

    comments = [
        InlineReviewComment(path="app.py", line=10, side="RIGHT", body="Fix this")
    ]
    res = await provider.create_comment_review(
        owner="octocat",
        repo="Hello-World",
        pr_number=1,
        commit_sha="b" * 40,
        body="## RepoLens Review",
        comments=comments,
    )

    assert res["id"] == 12345

    # Inspect call args
    mock_client.request.assert_called_once()
    kwargs = mock_client.request.call_args.kwargs
    assert kwargs["method"] == "POST"
    assert kwargs["url"] == f"{GITHUB_API_BASE_URL}/repos/octocat/Hello-World/pulls/1/reviews"

    payload = kwargs["json"]
    assert payload["event"] == "COMMENT"
    assert payload["commit_id"] == "b" * 40
    assert payload["body"] == "## RepoLens Review"
    assert len(payload["comments"]) == 1
    assert payload["comments"][0]["path"] == "app.py"
    assert payload["comments"][0]["side"] == "RIGHT"


@pytest.mark.asyncio
async def test_provider_write_timeout_causes_uncertain_state_without_retry():
    """Verify network timeout on write raises GitHubReviewStateUncertainError without blind retry."""
    mock_client = MagicMock(spec=httpx.AsyncClient)
    mock_client.request = AsyncMock(side_effect=httpx.TimeoutException("Write timed out"))

    provider = GitHubReviewPublicationProvider(
        token="valid_token",
        write_enabled=True,
        client=mock_client,
    )

    with pytest.raises(GitHubReviewStateUncertainError):
        await provider.create_comment_review(
            owner="octocat",
            repo="Hello-World",
            pr_number=1,
            commit_sha="b" * 40,
            body="## Review",
        )

    # Exactly 1 attempt on write (no retry)
    assert mock_client.request.call_count == 1


@pytest.mark.asyncio
async def test_provider_status_code_mappings():
    """Verify HTTP status codes map to typed exceptions."""
    mock_client = MagicMock(spec=httpx.AsyncClient)

    # 404 Not Found
    resp_404 = MagicMock()
    resp_404.status_code = 404
    mock_client.request = AsyncMock(return_value=resp_404)
    provider = GitHubReviewPublicationProvider(token="tok", write_enabled=True, client=mock_client)
    with pytest.raises(PRNotFoundError):
        await provider.get_current_pull_request("owner", "repo", 999)

    # 401 Auth Failed
    resp_401 = MagicMock()
    resp_401.status_code = 401
    resp_401.text = "Bad credentials"
    mock_client.request = AsyncMock(return_value=resp_401)
    with pytest.raises(GitHubAuthFailedError):
        await provider.get_current_pull_request("owner", "repo", 1)

    # 429 Rate Limited
    resp_429 = MagicMock()
    resp_429.status_code = 429
    resp_429.text = "API rate limit exceeded"
    mock_client.request = AsyncMock(return_value=resp_429)
    with pytest.raises(GitHubRateLimitedError):
        await provider.get_current_pull_request("owner", "repo", 1)


@pytest.mark.asyncio
async def test_provider_bounded_list_reviews_pagination():
    """Verify list_pull_request_reviews is bounded to max_pages."""
    mock_client = MagicMock(spec=httpx.AsyncClient)
    # Return 100 items per page for 5 pages, but max_pages is 3
    page_items = [{"id": i, "body": f"Review {i}"} for i in range(100)]
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = page_items
    mock_client.request = AsyncMock(return_value=resp)

    provider = GitHubReviewPublicationProvider(token="tok", client=mock_client)
    reviews = await provider.list_pull_request_reviews("owner", "repo", 1, max_pages=3, per_page=100)

    assert len(reviews) == 300
    assert mock_client.request.call_count == 3
