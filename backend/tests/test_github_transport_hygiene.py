"""No-network GitHub transport failure and credential hygiene regressions."""
import httpx
import pytest

from app.delivery.github_client import GitHubHttpTransport
from app.delivery.schemas import GitHubAPIError


@pytest.mark.asyncio
async def test_github_protocol_failures_become_sanitized_errors_without_write_retries():
    calls = 0
    marker = "private-github-credential-canary"

    async def handler(request):
        nonlocal calls
        calls += 1
        raise httpx.RemoteProtocolError(marker)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        transport = GitHubHttpTransport(token="test-token", client=client)
        with pytest.raises(GitHubAPIError) as failure:
            await transport.request("POST", "/repos/org/repo/git/blobs", json_data={"content": "hello"}, is_write=True)
    assert calls == 1
    assert failure.value.status_code == 502
    assert marker not in str(failure.value)


@pytest.mark.asyncio
async def test_github_protocol_failures_use_bounded_read_retries(monkeypatch):
    calls = 0

    async def handler(request):
        nonlocal calls
        calls += 1
        raise httpx.RemoteProtocolError("private-github-token-canary")

    async def skip_sleep(_delay):
        pass

    monkeypatch.setattr("app.delivery.github_client.asyncio.sleep", skip_sleep)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        transport = GitHubHttpTransport(token="test-token", client=client)
        with pytest.raises(GitHubAPIError) as failure:
            await transport.request("GET", "/repos/org/repo")
    assert calls == 3
    assert failure.value.status_code == 502
    assert "private-github-token-canary" not in str(failure.value)


@pytest.mark.asyncio
async def test_github_error_payload_is_not_retained_or_exposed():
    marker = "secret-github-error-payload-canary"

    async def handler(request):
        return httpx.Response(422, json={
            "message": marker,
            "errors": [{"provider_data": marker, "metadata": {"token": marker}}],
        })

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        transport = GitHubHttpTransport(token="test-token", client=client)
        with pytest.raises(GitHubAPIError) as failure:
            await transport.request("POST", "/repos/org/repo/git/refs", json_data={}, is_write=True)
    assert failure.value.status_code == 422
    assert failure.value.response_data == {}
    assert marker not in str(failure.value)


@pytest.mark.asyncio
async def test_github_success_status_with_malformed_json_fails_closed():
    marker = "private-provider-invalid-json-canary"

    async def handler(request):
        return httpx.Response(200, text=marker)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        transport = GitHubHttpTransport(token="test-token", client=client)
        with pytest.raises(GitHubAPIError) as failure:
            await transport.request("GET", "/repos/org/repo")
    assert failure.value.status_code == 502
    assert marker not in str(failure.value)
