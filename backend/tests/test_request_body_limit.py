"""Streaming request-body boundary tests, including requests without Content-Length."""

import asyncio
import json

import pytest

from app.core.config import get_settings

from app.security.request_body import RequestBodyLimitMiddleware


def _scope(headers: list[tuple[bytes, bytes]], path: str = "/api/v1/auth/login") -> dict:
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "headers": headers,
        "server": ("testserver", 80),
        "client": ("127.0.0.1", 1234),
    }


async def _run_middleware(
    payloads: list[bytes],
    *,
    content_length: int | str | None = None,
    path: str = "/api/v1/auth/login",
    api_prefix: str = "/api/v1",
    webhook_path: str = "/api/v1/github-app/webhook",
    extra_headers: list[tuple[bytes, bytes]] | None = None,
):
    delivered = False
    next_payload = 0
    inner_called = False
    response: list[dict] = []
    body_seen = bytearray()

    async def receive():
        nonlocal next_payload
        if next_payload < len(payloads):
            body = payloads[next_payload]
            next_payload += 1
            return {"type": "http.request", "body": body, "more_body": next_payload < len(payloads)}
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        response.append(message)

    async def inner(_scope_value, receive_value, send_value):
        nonlocal inner_called
        inner_called = True
        while True:
            message = await receive_value()
            if message["type"] == "http.disconnect":
                break
            body_seen.extend(message.get("body", b""))
            if not message.get("more_body", False):
                break
        await send_value({"type": "http.response.start", "status": 200, "headers": []})
        await send_value({"type": "http.response.body", "body": b"ok"})

    headers = [(b"content-type", b"application/json")]
    if content_length is not None:
        headers.append((b"content-length", str(content_length).encode("ascii")))
    headers.extend(extra_headers or [])
    middleware = RequestBodyLimitMiddleware(
        inner,
        api_prefix=api_prefix,
        max_json_bytes=8,
        webhook_path=webhook_path,
        webhook_max_bytes=32,
    )
    await middleware(_scope(headers, path), receive, send)
    return inner_called, bytes(body_seen), response


def test_json_body_limit_rejects_declared_oversize_before_route():
    inner_called, _body, response = asyncio.run(_run_middleware([b"123456789"], content_length=9))
    assert not inner_called
    assert response[0]["status"] == 413
    assert json.loads(response[1]["body"]) == {"detail": "Request body exceeds the configured limit."}


def test_json_body_limit_rejects_chunked_oversize_without_content_length():
    inner_called, _body, response = asyncio.run(_run_middleware([b"1234", b"56789"]))
    assert not inner_called
    assert response[0]["status"] == 413


def test_json_body_limit_allows_body_without_content_length_within_stream_limit():
    payload = b"12345678"
    inner_called, body, response = asyncio.run(_run_middleware([payload]))
    assert inner_called
    assert body == payload
    assert response[0]["status"] == 200


def test_json_body_limit_allows_zero_content_length_for_empty_body():
    inner_called, body, response = asyncio.run(_run_middleware([], content_length=0))
    assert inner_called
    assert body == b""
    assert response[0]["status"] == 200


def test_json_body_limit_allows_declared_length_within_limit_when_stream_matches():
    payload = b"12345678"
    inner_called, body, response = asyncio.run(
        _run_middleware([payload], content_length=len(payload))
    )
    assert inner_called
    assert body == payload
    assert response[0]["status"] == 200


def test_json_body_limit_allows_bounded_decimal_with_leading_zeroes():
    inner_called, body, response = asyncio.run(
        _run_middleware([b"ok"], content_length="00000000000000000002")
    )
    assert inner_called
    assert body == b"ok"
    assert response[0]["status"] == 200


@pytest.mark.parametrize("content_length", ["-1", "-999", "abc", "1x", "+10", "1.5", " ", "0x8"])
def test_json_body_limit_rejects_malformed_content_length_without_echoing_value(content_length):
    inner_called, _body, response = asyncio.run(
        _run_middleware([b"ok"], content_length=content_length)
    )
    assert not inner_called
    assert response[0]["status"] == 400
    assert json.loads(response[1]["body"]) == {"detail": "Content-Length header is invalid."}
    if content_length.strip():
        assert content_length.encode("ascii") not in response[1]["body"]


def test_json_body_limit_rejects_extremely_long_numeric_content_length_without_parsing_it():
    content_length = "9" * 10_000
    inner_called, _body, response = asyncio.run(
        _run_middleware([b"ok"], content_length=content_length)
    )
    assert not inner_called
    assert response[0]["status"] == 400
    assert len(response[1]["body"]) < 128


@pytest.mark.parametrize("duplicate_length", [b"2", b"3"])
def test_json_body_limit_rejects_duplicate_content_length_headers(duplicate_length):
    inner_called, _body, response = asyncio.run(
        _run_middleware(
            [b"ok"],
            content_length=2,
            extra_headers=[(b"content-length", duplicate_length)],
        )
    )
    assert not inner_called
    assert response[0]["status"] == 400


def test_json_body_limit_rejects_lies_about_small_content_length():
    inner_called, _body, response = asyncio.run(
        _run_middleware([b"123456789"], content_length=1)
    )
    assert not inner_called
    assert response[0]["status"] == 413


def test_json_body_limit_passes_exact_boundary_and_replays_body():
    payload = b"12345678"
    inner_called, body, response = asyncio.run(_run_middleware([payload]))
    assert inner_called
    assert body == payload
    assert response[0]["status"] == 200


def test_webhook_body_replay_preserves_exact_raw_bytes():
    payload = b'{ "action" : "opened" }\n'
    webhook_path = "/api/v1/github-app/webhook"
    inner_called, body, response = asyncio.run(
        _run_middleware(
            [payload],
            content_length=len(payload),
            path=webhook_path,
            webhook_path=webhook_path,
        )
    )
    assert inner_called
    assert body == payload
    assert response[0]["status"] == 200


def test_json_body_limit_uses_configured_api_prefix():
    inner_called, _body, response = asyncio.run(
        _run_middleware(
            [b"123456789"],
            content_length=9,
            path="/internal/v2/auth/login",
            api_prefix="/internal/v2",
        )
    )
    assert not inner_called
    assert response[0]["status"] == 413


def test_fastapi_auth_route_rejects_oversized_body_before_validation(client):
    limit = get_settings().MAX_JSON_REQUEST_BYTES
    body = b'{"email":"unknown@example.com","password":"' + b"x" * limit + b'"}'
    response = client.post(
        "/api/v1/auth/login",
        content=body,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413
