"""Backward-compatible API error envelopes with stable machine codes."""

import re
from typing import Any

from fastapi import HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


_CODE_PREFIX = re.compile(r"^([A-Z][A-Z0-9_]{2,63}):\s*(.*)$", re.DOTALL)


def _request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


def _normalized(detail: Any, default_code: str) -> tuple[str, str]:
    if isinstance(detail, dict):
        return str(detail.get("error_code") or default_code), str(detail.get("message") or detail)
    if isinstance(detail, str):
        match = _CODE_PREFIX.match(detail)
        if match:
            return match.group(1), match.group(2)
        return default_code, detail
    return default_code, "The request could not be completed."


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    code, message = _normalized(exc.detail, f"HTTP_{exc.status_code}")
    return JSONResponse(
        status_code=exc.status_code,
        headers=exc.headers,
        content=jsonable_encoder({
            "detail": exc.detail,
            "error": {
                "code": code,
                "message": message,
                "request_id": _request_id(request),
            },
        }),
    )


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    detail = exc.errors()
    return JSONResponse(
        status_code=422,
        content=jsonable_encoder({
            "detail": detail,
            "error": {
                "code": "USER_INPUT_ERROR",
                "message": "Request validation failed.",
                "request_id": _request_id(request),
            },
        }),
    )
