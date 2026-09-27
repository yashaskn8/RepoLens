"""Bound API request-body buffering before FastAPI/Pydantic materializes it."""

from __future__ import annotations

import json
from typing import Any, Awaitable, Callable


_MAX_CONTENT_LENGTH_DIGITS = 20


class RequestBodyLimitMiddleware:
    """Buffer only bounded API mutation bodies, including chunked requests.

    Existing API mutations accept structured request bodies, not file uploads.
    The GitHub App webhook retains its separately configured (and rechecked)
    streaming limit. Read-only responses and SSE/PDF streams are untouched.
    """

    _BODY_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

    def __init__(
        self,
        app: Callable[..., Awaitable[None]],
        *,
        api_prefix: str,
        max_json_bytes: int,
        webhook_path: str,
        webhook_max_bytes: int,
    ) -> None:
        self.app = app
        self.api_prefix = "/" + api_prefix.strip("/")
        self.max_json_bytes = max_json_bytes
        self.webhook_path = webhook_path
        self.webhook_max_bytes = webhook_max_bytes

    async def __call__(self, scope: dict[str, Any], receive: Callable, send: Callable) -> None:
        if (
            scope.get("type") != "http"
            or scope.get("method", "").upper() not in self._BODY_METHODS
            or not (
                str(scope.get("path", "")) == self.api_prefix
                or str(scope.get("path", "")).startswith(f"{self.api_prefix}/")
            )
        ):
            await self.app(scope, receive, send)
            return

        limit = (
            self.webhook_max_bytes
            if scope.get("path") == self.webhook_path
            else self.max_json_bytes
        )
        headers = scope.get("headers", [])
        content_lengths = [
            value for name, value in headers if name.lower() == b"content-length"
        ]
        if len(content_lengths) > 1:
            await self._invalid_content_length(send)
            return
        if content_lengths:
            content_length = content_lengths[0]
            max_digits = max(_MAX_CONTENT_LENGTH_DIGITS, len(str(limit)))
            if (
                not isinstance(content_length, bytes)
                or not content_length
                or len(content_length) > max_digits
                or any(byte < ord("0") or byte > ord("9") for byte in content_length)
            ):
                await self._invalid_content_length(send)
                return
            # The representation is now a short, ASCII-only decimal string, so
            # integer conversion is bounded by the configured limit's digit count.
            declared = int(content_length)
            if declared > limit:
                await self._too_large(send)
                return

        chunks: list[bytes] = []
        size = 0
        while True:
            message = await receive()
            if message.get("type") == "http.disconnect":
                return
            if message.get("type") != "http.request":
                # Preserve non-body ASGI messages rather than treating them as
                # request data. HTTP servers normally send only http.request here.
                await self.app(scope, receive, send)
                return
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > limit:
                await self._too_large(send)
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break

        body = b"".join(chunks)
        replayed = False

        async def replay_receive():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay_receive, send)

    @staticmethod
    async def _invalid_content_length(send: Callable) -> None:
        payload = json.dumps({"detail": "Content-Length header is invalid."}).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": 400,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode("ascii")),
            ],
        })
        await send({"type": "http.response.body", "body": payload, "more_body": False})

    @staticmethod
    async def _too_large(send: Callable) -> None:
        payload = json.dumps({"detail": "Request body exceeds the configured limit."}).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode("ascii")),
            ],
        })
        await send({"type": "http.response.body", "body": payload, "more_body": False})
