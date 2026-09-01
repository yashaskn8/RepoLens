"""Consistent API idempotency identities without persisting caller keys."""

import hashlib
import json
import re
from typing import Any

from fastapi import HTTPException, status


_VALID_KEY = re.compile(r"^[A-Za-z0-9._:-]+$")


def request_digest(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def idempotency_identity(scope: str, raw_key: str | None, *, maximum: int = 128) -> str | None:
    # FastAPI's Header default is only resolved by dependency injection. Direct
    # service-level callers see the FieldInfo object and therefore mean "absent".
    if not isinstance(raw_key, str):
        return None
    value = raw_key.strip()
    if len(value) < 8 or len(value) > maximum or not _VALID_KEY.fullmatch(value):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error_code": "INVALID_IDEMPOTENCY_KEY",
                "message": "Idempotency-Key must contain 8-128 URL-safe identifier characters.",
            },
        )
    return hashlib.sha256(f"{scope}:{value}".encode("utf-8")).hexdigest()
