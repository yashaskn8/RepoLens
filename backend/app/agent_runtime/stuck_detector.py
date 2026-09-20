"""Stable duplicate/cycle protection for one investigation target."""

from __future__ import annotations

import hashlib
import json


def tool_call_fingerprint(target_id: str, tool_name: str, arguments: dict) -> str:
    payload = json.dumps(
        {"target_id": target_id, "tool_name": tool_name, "arguments": arguments},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def is_stuck(fingerprints: list[str], next_fingerprint: str) -> bool:
    """Reject exact repeats and A/B cycles that produced no intervening evidence."""

    if next_fingerprint in fingerprints:
        return True
    if len(fingerprints) >= 3:
        projected = [*fingerprints, next_fingerprint]
        if projected[-4:-2] == projected[-2:]:
            return True
    return False


__all__ = ["is_stuck", "tool_call_fingerprint"]
