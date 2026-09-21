"""Stable semantic names and bounded attribute handling for RepoLens traces."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from app.security.redaction import redact_secrets

CONTENT_KEYS = frozenset({
    "prompt", "messages", "message", "response", "completion", "source", "content",
    "raw_args", "raw_arguments", "raw_result", "result", "query", "chunks", "vector",
    "authorization", "cookie", "headers", "api_key", "secret", "token", "password",
    "exception", "stacktrace", "path", "file_path", "absolute_path",
})

_SAFE_ATTRIBUTE_SUFFIXES = frozenset({
    "id", "name", "type", "version", "status", "state", "count", "number",
    "duration_ms", "bytes", "tokens", "token_count", "temperature", "ratio",
    "step", "limit", "attempt", "resume", "truncated", "operation", "capability",
    "policy", "provider", "model", "error_type", "digest", "method", "node",
    "intent", "max_tokens", "kind", "keys", "hit", "avoided", "requested", "complete",
})

_ALLOWED_ATTRIBUTE_NAMESPACES = ("gen_ai.", "http.", "error.", "repolens.")


def digest(value: Any) -> str:
    """Return a stable digest without retaining the value."""
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    except Exception:
        encoded = repr(value).encode("utf-8", "replace")
    return hashlib.sha256(encoded).hexdigest()


def safe_attributes(attributes: Mapping[str, Any] | None) -> dict[str, Any]:
    """Allow only bounded scalar metadata; never attach repository/model content."""
    safe: dict[str, Any] = {}
    for key, value in (attributes or {}).items():
        normalized = str(key).strip().lower().replace("-", "_")
        # OTel semantic attributes use their registered namespaces.  RepoLens
        # metadata is deliberately namespaced so application-specific keys can
        # never masquerade as vendor/GenAI attributes.
        if not normalized.startswith(_ALLOWED_ATTRIBUTE_NAMESPACES):
            continue
        token_count = normalized.endswith("_tokens") or normalized.endswith(".tokens") or normalized.endswith("_token_count")
        prompt_version = (
            normalized.endswith("_prompt_version")
            or normalized.endswith(".prompt_version")
            or normalized == "gen_ai.prompt.version"
            or normalized.endswith(".prompt.version")
        )
        leaf = normalized.rsplit(".", 1)[-1].rsplit("_", 1)[-1]
        allowed_key = normalized.endswith("_prompt_version") or normalized.endswith(".prompt_version") or leaf in _SAFE_ATTRIBUTE_SUFFIXES
        if not normalized or not allowed_key or normalized in CONTENT_KEYS or ("prompt" in normalized and not prompt_version) or any(part in normalized for part in ("secret", "password", "auth", "cookie")) or ("token" in normalized and not token_count):
            continue
        if isinstance(value, bool):
            safe[normalized] = value
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            safe[normalized] = value
        elif isinstance(value, str):
            # Redaction is defense-in-depth for identifiers and error messages.
            safe[normalized] = redact_secrets(value)[:256]
    return safe


__all__ = ["CONTENT_KEYS", "digest", "safe_attributes"]
