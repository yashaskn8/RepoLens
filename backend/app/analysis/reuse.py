"""Deterministic exact and cross-commit finding reuse.

The helpers in this module never use semantic similarity and never promote a
model-only statement.  Reuse is an optimization for already verified evidence,
not a second finding authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable, Mapping

from app.schemas.evidence import Evidence
from app.services.finding_grounding import (
    GROUNDING_SCHEMA_VERSION,
    build_grounding_context_notes,
    is_canonical_confirmed_finding,
)


@dataclass(frozen=True, slots=True)
class ReuseDecision:
    reusable: bool
    reason: str
    evidence: tuple[Evidence, ...] = ()
    provenance: Mapping[str, Any] = None  # type: ignore[assignment]

    def as_dict(self) -> dict[str, Any]:
        return {
            "reusable": self.reusable,
            "reason": self.reason,
            "evidence": [item.model_dump(mode="json") for item in self.evidence],
            "provenance": dict(self.provenance or {}),
        }


def exact_reuse_key(
    *,
    tenant_id: str | None,
    repository_id: str | None,
    commit_sha: str | None,
    authorities: Mapping[str, Any],
) -> str | None:
    """Build an exact immutable analysis key, or ``None`` for a safe miss."""
    if not tenant_id or not repository_id or not commit_sha:
        return None
    required = dict(authorities)
    required.update({"tenant": tenant_id, "repository": repository_id, "commit": commit_sha})
    # The key must contain the authority values themselves, not only a caller
    # supplied digest, so an omitted component cannot collide accidentally.
    missing = [k for k in ("ingestion", "parser", "scanner", "analysis_policy", "graph", "verifier", "detectors", "prompt_schema", "runtime_policy") if required.get(k) in (None, "", "unknown", "UNVERIFIED")]
    if missing:
        return None
    encoded = json.dumps(required, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _attestation(notes: Any) -> dict[str, Any] | None:
    if not isinstance(notes, str):
        return None
    try:
        value = json.loads(notes)
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _value(value: Any, name: str, default: Any = None) -> Any:
    """Read a field from either a Pydantic/ORM object or a mapping.

    Reuse is also exercised against serialized artifact projections, so the
    safety checks must not silently fail just because a caller supplied a
    dictionary instead of a domain object.
    """
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _relocate_evidence(repo_dir: str, evidence: Any, commit_sha: str) -> Evidence | None:
    """Re-read exact source bytes and relocate a unique unchanged snippet."""
    raw_path = str(_value(evidence, "file_path", "") or "").replace("\\", "/")
    snippet = str(_value(evidence, "code_snippet", "") or "")
    notes = _attestation(_value(evidence, "context_notes"))
    if not raw_path or not snippet or not notes:
        return None
    if notes.get("schema_version") != GROUNDING_SCHEMA_VERSION:
        return None
    old_file_sha = str(notes.get("file_sha256") or "")
    old_snippet_sha = str(notes.get("snippet_sha256") or "")
    if hashlib.sha256(snippet.encode("utf-8")).hexdigest() != old_snippet_sha:
        return None
    root = Path(repo_dir).resolve()
    try:
        candidate = Path(raw_path)
        path = (candidate if candidate.is_absolute() else root / candidate).resolve(strict=True)
        path.relative_to(root)
        payload = path.read_bytes()
    except (OSError, ValueError, RuntimeError):
        return None
    if b"\x00" in payload:
        return None
    lines = payload.decode("utf-8", errors="replace").splitlines()
    target = snippet.splitlines()
    if not target:
        return None
    matches: list[tuple[int, int]] = []
    width = len(target)
    for index in range(0, max(0, len(lines) - width + 1)):
        if lines[index : index + width] == target:
            matches.append((index + 1, index + width))
    if len(matches) != 1:
        # An unchanged file can retain its original range; a changed file with
        # ambiguous relocation is deliberately invalidated.
        if hashlib.sha256(payload).hexdigest() != old_file_sha:
            return None
        start = int(notes.get("start_line", _value(evidence, "start_line", 0)) or 0)
        end = int(notes.get("end_line", _value(evidence, "end_line", 0)) or 0)
        if start < 1 or end < start or end > len(lines):
            return None
        matches = [(start, end)]
    start, end = matches[0]
    canonical_snippet = "\n".join(lines[start - 1 : end])
    file_sha = hashlib.sha256(payload).hexdigest()
    snippet_sha = hashlib.sha256(canonical_snippet.encode("utf-8")).hexdigest()
    payload_value = {
        "id": _value(evidence, "id"),
        "file_path": path.relative_to(root).as_posix(),
        "start_line": start,
        "end_line": end,
        "code_snippet": canonical_snippet,
        "context_notes": build_grounding_context_notes(
            commit_sha=commit_sha,
            file_path=path.relative_to(root).as_posix(),
            start_line=start,
            end_line=end,
            file_sha256=file_sha,
            snippet_sha256=snippet_sha,
        ),
    }
    if payload_value["id"] is None:
        payload_value.pop("id")
    try:
        return Evidence.model_validate(payload_value)
    except (TypeError, ValueError):
        return None


def changed_files_by_hash(
    previous_repo_dir: str,
    current_repo_dir: str,
    *,
    max_files: int = 100_000,
) -> set[str]:
    """Return normalized paths whose exact bytes differ between snapshots.

    This is a deterministic, read-only fallback for incremental callers that
    do not have a precomputed Git diff.  It skips ``.git`` metadata and
    symlinks, bounds traversal, and hashes in chunks so repository contents
    are never executed or loaded wholesale into memory.
    """
    def _index(root_value: str) -> dict[str, str]:
        root = Path(root_value).resolve(strict=True)
        result: dict[str, str] = {}
        for directory, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [item for item in dirs if item != ".git"]
            for name in files:
                if len(result) >= max_files:
                    return result
                path = Path(directory) / name
                if path.is_symlink() or not path.is_file():
                    continue
                try:
                    relative = path.relative_to(root).as_posix()
                    digest = hashlib.sha256()
                    with path.open("rb") as stream:
                        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                            digest.update(chunk)
                    result[relative] = digest.hexdigest()
                except (OSError, ValueError):
                    # An unreadable file is changed/unsafe for reuse.
                    result[relative] = "UNREADABLE"
        return result

    previous = _index(previous_repo_dir)
    current = _index(current_repo_dir)
    return {
        path for path in (set(previous) | set(current))
        if previous.get(path) != current.get(path)
    }


def revalidate_finding(
    finding: Any,
    *,
    repo_dir: str,
    commit_sha: str,
    previous_commit_sha: str,
    changed_files: Iterable[str] = (),
    changed_symbols: Iterable[str] = (),
    changed_dependencies: Iterable[str] = (),
    previous_authority_fingerprint: str | None,
    current_authority_fingerprint: str | None,
    tenant_matches: bool = True,
) -> ReuseDecision:
    """Revalidate one confirmed finding for a new immutable repository commit."""
    if not tenant_matches:
        return ReuseDecision(False, "tenant/reuse authority differs")
    if not previous_authority_fingerprint or previous_authority_fingerprint != current_authority_fingerprint:
        return ReuseDecision(False, "analysis authority/version changed")
    if not is_canonical_confirmed_finding(finding, expected_commit_sha=previous_commit_sha):
        return ReuseDecision(False, "finding is not a previously verified attested finding")
    changed_file_set = {str(path).replace("\\", "/") for path in changed_files}
    evidence_values = tuple(_value(finding, "evidences", ()) or ())
    evidence_paths = {str(_value(item, "file_path", "")).replace("\\", "/") for item in evidence_values}
    if changed_file_set & evidence_paths:
        # A changed evidence file may still be safely reused only when the
        # exact snippet can be uniquely relocated and remains byte-identical.
        pass
    metadata = _value(finding, "model_metadata") or {}
    if hasattr(metadata, "model_dump"):
        metadata = metadata.model_dump(mode="json")
    provenance = metadata.get("provenance", {}) if isinstance(metadata, Mapping) else {}
    if not provenance and isinstance(metadata, Mapping):
        extra = metadata.get("extra_metadata")
        if isinstance(extra, Mapping):
            provenance = extra.get("provenance", {})
    if not isinstance(provenance, Mapping):
        provenance = {}
    # A changed dependency/symbol scope is unsafe to ignore when the prior
    # finding did not persist the corresponding identity set.  Missing
    # provenance is therefore a conservative cache miss, never a broad reuse.
    known_dependency_ids = {str(item) for item in (provenance.get("dependency_ids", []) or [])}
    known_dependency_paths = {str(item).replace("\\", "/") for item in (provenance.get("dependency_paths", []) or [])}
    known_symbol_ids = {str(item) for item in (provenance.get("symbol_ids", []) or [])}
    if changed_dependencies and not (known_dependency_ids or known_dependency_paths):
        return ReuseDecision(False, "dependency neighborhood identity unavailable")
    if changed_symbols and not known_symbol_ids:
        return ReuseDecision(False, "referenced symbol identity unavailable")
    relevant_paths = set(provenance.get("dependency_paths", []) or []) if isinstance(provenance, Mapping) else set()
    relevant_paths |= set(provenance.get("contract_paths", []) or []) if isinstance(provenance, Mapping) else set()
    if changed_file_set & {str(path).replace("\\", "/") for path in relevant_paths}:
        return ReuseDecision(False, "relevant dependency or contract neighborhood changed")
    if set(str(item) for item in changed_symbols) & known_symbol_ids:
        return ReuseDecision(False, "referenced symbol changed")
    if set(str(item) for item in changed_dependencies) & known_dependency_ids:
        return ReuseDecision(False, "relevant dependency changed")
    relocated = tuple(
        value for item in evidence_values
        if (value := _relocate_evidence(repo_dir, item, commit_sha)) is not None
    )
    if len(relocated) != len(evidence_values):
        return ReuseDecision(False, "source evidence could not be uniquely re-attested")
    return ReuseDecision(
        True,
        "unchanged authoritative evidence re-attested on new commit",
        evidence=relocated,
        provenance={
            "reuse_type": "incremental",
            "origin_finding_id": str(_value(finding, "id", "")),
            "previous_commit_sha": previous_commit_sha,
            "new_commit_sha": commit_sha,
            "reuse_reason": "unchanged evidence and dependency neighborhood",
            "authority_fingerprint": current_authority_fingerprint,
        },
    )


__all__ = ["ReuseDecision", "changed_files_by_hash", "exact_reuse_key", "revalidate_finding"]
