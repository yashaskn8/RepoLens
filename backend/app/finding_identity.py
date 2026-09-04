"""Deterministic finding identity independent of model-authored prose."""

from __future__ import annotations

import hashlib


def canonical_issue_fingerprint(
    *,
    category: str,
    detector_identity: str,
    file_path: str,
    start_line: int | None,
    end_line: int | None,
) -> str:
    """Hash canonical detector and source coordinates, never generated wording."""
    material = "\0".join(
        [
            category.strip().lower(),
            detector_identity.strip(),
            file_path.replace("\\", "/").lstrip("/"),
            str(start_line or 0),
            str(end_line or start_line or 0),
        ]
    )
    return f"issue:{hashlib.sha256(material.encode('utf-8')).hexdigest()[:32]}"


__all__ = ["canonical_issue_fingerprint"]
