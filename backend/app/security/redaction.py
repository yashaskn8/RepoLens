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
