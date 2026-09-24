"""Fixed-root, digest-verified loader for public DEV agent-security cases."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any

from app.evaluation.security.contracts import (
    AgentSecurityCase,
    AgentSecurityCorpus,
    AgentSecurityCorpusManifest,
    canonical_digest,
)


_CORPUS_ROOT = Path(__file__).resolve().parents[3] / "evaluation_data" / "agent_security" / "v1"
_EXPECTED_FILES = ("cases/attacks.json", "controls/benign.json")


class SecurityCorpusError(ValueError):
    """Public security corpus is missing, unsafe, or not digest-consistent."""


def _reject_linked_path(root: Path, relative: str) -> Path:
    """Resolve one manifest-owned relative path and reject symlink/junction hops."""
    posix = PurePosixPath(relative)
    windows = PureWindowsPath(relative)
    if (
        not relative or "\\" in relative or posix.is_absolute() or windows.is_absolute()
        or windows.drive or ".." in posix.parts
    ):
        raise SecurityCorpusError("security corpus path must be a normalized relative path")
    root = Path(root)
    if root.is_symlink() or getattr(os.path, "isjunction", lambda _path: False)(str(root)):
        raise SecurityCorpusError("security corpus root cannot be linked")
    for parent in root.parents:
        if parent.is_symlink() or getattr(os.path, "isjunction", lambda _path: False)(str(parent)):
            raise SecurityCorpusError("security corpus ancestor cannot be linked")
    root = root.resolve(strict=True)
    candidate = root / relative
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise SecurityCorpusError("security corpus path escapes or is unavailable") from exc
    current = root
    for part in Path(relative).parts:
        current = current / part
        if current.is_symlink() or getattr(os.path, "isjunction", lambda _path: False)(str(current)):
            raise SecurityCorpusError("security corpus contains a linked or junctioned path")
    return resolved


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_agent_security_corpus() -> AgentSecurityCorpus:
    """Load only the bundled PUBLIC_DEV corpus; callers cannot supply a root."""
    try:
        root = _CORPUS_ROOT
        manifest_path = _reject_linked_path(root, "manifest.json")
        raw_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest = AgentSecurityCorpusManifest.model_validate(raw_manifest)
        manifest_payload = manifest.model_dump(mode="json", exclude={"corpus_digest"})
        if canonical_digest(manifest_payload) != manifest.corpus_digest:
            raise SecurityCorpusError("security corpus manifest digest mismatch")
        bindings = {item.path: item.sha256 for item in manifest.files}
        if set(bindings) != set(_EXPECTED_FILES):
            raise SecurityCorpusError("security corpus manifest inventory is not canonical")
        raw_cases: list[dict[str, Any]] = []
        for relative in _EXPECTED_FILES:
            path = _reject_linked_path(root, relative)
            if _file_sha256(path) != bindings[relative]:
                raise SecurityCorpusError("security corpus case-file digest mismatch")
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, list):
                raise SecurityCorpusError("security corpus file must contain a case list")
            raw_cases.extend(payload)
        cases = tuple(AgentSecurityCase.model_validate(item) for item in raw_cases)
        if len(cases) != manifest.case_count:
            raise SecurityCorpusError("security corpus case inventory count mismatch")
        case_digests = {
            case.case_id: canonical_digest(raw)
            for case, raw in zip(cases, raw_cases, strict=True)
        }
        return AgentSecurityCorpus(
            version=manifest.corpus_version,
            digest=manifest.corpus_digest,
            mutation_policy_version=manifest.mutation_policy_version,
            cases=cases,
            case_digests=case_digests,
        )
    except SecurityCorpusError:
        raise
    except Exception as exc:
        raise SecurityCorpusError(f"invalid bundled security corpus ({type(exc).__name__})") from exc


__all__ = ["SecurityCorpusError", "load_agent_security_corpus"]
