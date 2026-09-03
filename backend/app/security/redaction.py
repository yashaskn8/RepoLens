"""Canonical security and secret redaction utilities for RepoLens."""

import json
import logging
import re
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)

# Bounding limits for telemetry and workflow event metadata
MAX_METADATA_DEPTH = 6
MAX_METADATA_DICT_ENTRIES = 50
MAX_METADATA_LIST_ITEMS = 50
MAX_METADATA_STRING_LENGTH = 2048
MAX_METADATA_SERIALIZED_BYTES = 65536

# Keys that should never be persisted in event metadata
_SENSITIVE_KEY_SUBSTRINGS = ("key", "token", "secret", "auth", "password", "credential", "prompt")

# Canonical Secret and Host-Path Redaction Patterns
_SECRET_PATTERNS = [
    (re.compile(r"(?i)\b(bearer\s+)[a-zA-Z0-9_\-\.]{10,}\b"), r"\1[REDACTED]"),
    (re.compile(r"\b(sk-or-v1-[a-zA-Z0-9_\-]{16,})\b"), r"sk-or-[REDACTED]"),
    (re.compile(r"\b(sk-[a-zA-Z0-9_\-]{16,})\b"), r"sk-[REDACTED]"),
    (re.compile(r"\b(gsk_[a-zA-Z0-9_\-]{16,})\b"), r"gsk_[REDACTED]"),
    (re.compile(r"\b(hf_[a-zA-Z0-9_\-]{16,})\b"), r"hf_[REDACTED]"),
    (re.compile(r"\b(nvapi-[a-zA-Z0-9_\-]{16,})\b"), r"nvapi-[REDACTED]"),
    (re.compile(r"\b(AIza[0-9A-Za-z\-_]{20,})\b"), r"AIza[REDACTED]"),
    (re.compile(r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,})\b"), r"[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\b(eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,})\b"), r"[REDACTED_JWT]"),
    (re.compile(r"\b(cfut_[a-zA-Z0-9_\-]{16,})\b"), r"cfut_[REDACTED]"),
    (re.compile(r"\b(cohere_[a-zA-Z0-9_\-]{16,})\b"), r"cohere_[REDACTED]"),
    (re.compile(r"(?i)\b(api[_-]?key|secret|password|auth[_-]?token)\s*[:=]\s*['\"][^\s'\"]{6,}['\"]"), r"\1='[REDACTED]'"),
]

_HOST_PATH_PATTERNS = [
    (re.compile(r"[a-zA-Z]:\\[Uu]sers\\[^\s\\/:]+"), r"[HOST_USER_DIR]"),
    (re.compile(r"/home/[^\s/:]+"), r"/home/[HOST_USER]"),
]


def redact_secrets(text: Optional[str]) -> str:
    """Mask raw API credentials, JWTs, secret keys, and private host paths from text."""
    if not text:
        return ""
    result = str(text)
    for pattern, replacement in _SECRET_PATTERNS:
        result = pattern.sub(replacement, result)
    for pattern, replacement in _HOST_PATH_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def contains_secrets(text: Optional[str]) -> bool:
    """Check if text matches any canonical secret pattern (API keys, JWTs, tokens)."""
    if not text:
        return False
    text_str = str(text)
    for pattern, _ in _SECRET_PATTERNS:
        if pattern.search(text_str):
            return True
    return False


# Keys and identifiers representing credentials, auth tokens, or secrets
_CREDENTIAL_KEY_IDENTIFIERS = (
    "api_key",
    "apikey",
    "token",
    "secret",
    "password",
    "credential",
    "authorization",
    "auth",
)


def contains_sensitive_material(val: Any, depth: int = 0) -> bool:
    """Recursively inspect whether a value, dictionary key, or nested data structure
    contains sensitive credentials, tokens, or known secret patterns.

    Detects:
    1. Known token/credential patterns in strings (via contains_secrets).
    2. Structural credential field names in dict keys (e.g. api_key, apikey, token,
       secret, password, credential, authorization, auth).
    3. Nested dicts, lists, tuples, sets, and Pydantic models containing credentials.
    """
    if depth > MAX_METADATA_DEPTH:
        return False

    if val is None or isinstance(val, (int, float, bool)):
        return False

    if isinstance(val, str):
        return contains_secrets(val)

    if hasattr(val, "model_dump") and callable(val.model_dump):
        try:
            val = val.model_dump()
        except Exception:
            pass
    elif hasattr(val, "dict") and callable(val.dict):
        try:
            val = val.dict()
        except Exception:
            pass

    if isinstance(val, dict):
        for k, v in val.items():
            k_str = str(k).lower()
            if any(ident in k_str for ident in _CREDENTIAL_KEY_IDENTIFIERS):
                return True
            if contains_secrets(str(k)):
                return True
            if contains_sensitive_material(v, depth + 1):
                return True
        return False

    if isinstance(val, (list, tuple, set)):
        for item in val:
            if contains_sensitive_material(item, depth + 1):
                return True
        return False

    try:
        return contains_secrets(str(val))
    except Exception:
        return False


def _sanitize_value(val: Any, depth: int = 0) -> Any:
    """Recursively sanitize, redact, and bound a JSON-like value."""
    if depth > MAX_METADATA_DEPTH:
        return "[truncated: max depth exceeded]"

    if val is None:
        return None

    if isinstance(val, (int, float, bool)):
        return val

    if isinstance(val, str):
        redacted = redact_secrets(val)
        if len(redacted) > MAX_METADATA_STRING_LENGTH:
            return redacted[:MAX_METADATA_STRING_LENGTH] + "... [truncated]"
        return redacted

    if isinstance(val, dict):
        sanitized_dict: Dict[str, Any] = {}
        entries_count = 0
        truncated_entries = False

        for k, v in val.items():
            k_str = str(k)
            k_lower = k_str.lower()

            # Skip sensitive keys entirely
            if any(substr in k_lower for substr in _SENSITIVE_KEY_SUBSTRINGS):
                continue

            if entries_count >= MAX_METADATA_DICT_ENTRIES:
                truncated_entries = True
                break

            sanitized_dict[k_str] = _sanitize_value(v, depth + 1)
            entries_count += 1

        if truncated_entries:
            sanitized_dict["_truncated"] = True
        return sanitized_dict

    if isinstance(val, (list, tuple)):
        items_to_process = list(val)[:MAX_METADATA_LIST_ITEMS]
        sanitized_list = [_sanitize_value(item, depth + 1) for item in items_to_process]
        if len(val) > MAX_METADATA_LIST_ITEMS:
            sanitized_list.append("[truncated: max items exceeded]")
        return sanitized_list

    # Unknown or non-JSON object — safely stringify, redact, and bound
    safe_repr = redact_secrets(str(val))
    if len(safe_repr) > MAX_METADATA_STRING_LENGTH:
        return safe_repr[:MAX_METADATA_STRING_LENGTH] + "... [truncated]"
    return safe_repr


def sanitize_metadata(metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Sanitize metadata dictionary to ensure no sensitive credentials, raw prompts,
    deep nestings, or unbounded memory payloads are persisted or broadcasted."""
    if not metadata or not isinstance(metadata, dict):
        return {}

    sanitized = _sanitize_value(metadata, depth=0)
    if not isinstance(sanitized, dict):
        return {}

    # Check total serialized payload size
    try:
        serialized = json.dumps(sanitized, default=str)
        if len(serialized.encode("utf-8")) > MAX_METADATA_SERIALIZED_BYTES:
            return {
                "_truncated": True,
                "reason": f"Total metadata serialized bytes exceeded limit ({MAX_METADATA_SERIALIZED_BYTES} bytes)",
            }
    except Exception as exc:
        logger.warning(f"Failed to serialize sanitized metadata: {exc}")
        return {"_truncated": True, "reason": "Failed to serialize metadata"}

    return sanitized
