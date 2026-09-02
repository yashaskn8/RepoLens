"""Canonical evidence grounding invariants for persisted and reported findings.

LLM output is never authoritative for source locations or snippets.  Before a
finding can enter the canonical database, its proposed location is resolved
inside the immutable repository snapshot and the evidence is rebuilt from the
bytes at that commit.  Reports can then validate the persisted attestation
without trusting the model-authored payload.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable

from app.schemas.evidence import Evidence


GROUNDING_SCHEMA_VERSION = "repository-evidence/1.0"
MAX_CANONICAL_SNIPPET_CHARS = 65_536
_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _field(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, dict):
        return value.get(name, default)
    return getattr(value, name, default)


def build_grounding_context_notes(
    *,
    commit_sha: str,
    file_path: str,
    start_line: int,
    end_line: int,
    file_sha256: str,
    snippet_sha256: str,
) -> str:
    """Return a machine-verifiable, deterministic evidence attestation."""
    return json.dumps(
        {
            "schema_version": GROUNDING_SCHEMA_VERSION,
            "commit_sha": commit_sha,
            "file_path": file_path,
            "start_line": start_line,
            "end_line": end_line,
            "file_sha256": file_sha256,
            "snippet_sha256": snippet_sha256,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def canonicalize_repository_evidences(
    *,
    repo_dir: str,
    commit_sha: str,
    evidences: Iterable[Any],
) -> list[Evidence]:
    """Rebuild proposed evidences from an exact repository snapshot.

    Invalid, out-of-repository, binary, empty, or out-of-range references are
    discarded.  Returned snippets and locators are authoritative repository
    data; none of the model-authored snippet or explanatory text survives.
    """
    root = Path(repo_dir).resolve(strict=True)
    canonical: list[Evidence] = []
    seen: set[tuple[str, int, int, str]] = set()

    for proposed in evidences:
        raw_path = str(_field(proposed, "file_path", "") or "").strip()
        start_line = _field(proposed, "start_line")
        end_line = _field(proposed, "end_line")
        if not raw_path or not isinstance(start_line, int) or isinstance(start_line, bool):
            continue
        if start_line < 1:
            continue
        if end_line is None:
            end_line = start_line
        if not isinstance(end_line, int) or isinstance(end_line, bool) or end_line < start_line:
            continue

        try:
            candidate = Path(raw_path)
            resolved = (candidate if candidate.is_absolute() else root / candidate).resolve(strict=True)
            relative_path = resolved.relative_to(root).as_posix()
        except (OSError, RuntimeError, ValueError):
            # Includes missing files, malformed paths, and symlinks/path
            # traversal escaping the repository snapshot.
            continue

        if not resolved.is_file():
            continue

        try:
            file_bytes = resolved.read_bytes()
        except OSError:
            continue
        if b"\x00" in file_bytes:
            continue

        source_lines = file_bytes.decode("utf-8", errors="replace").splitlines()
        if end_line > len(source_lines):
            continue
        snippet = "\n".join(source_lines[start_line - 1 : end_line])
        if not snippet.strip() or len(snippet) > MAX_CANONICAL_SNIPPET_CHARS:
            continue

        snippet_sha256 = hashlib.sha256(snippet.encode("utf-8")).hexdigest()
        dedupe_key = (relative_path, start_line, end_line, snippet_sha256)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        file_sha256 = hashlib.sha256(file_bytes).hexdigest()
        evidence_id = _field(proposed, "id")
        evidence_payload = {
            "file_path": relative_path,
            "start_line": start_line,
            "end_line": end_line,
            "code_snippet": snippet,
            "context_notes": build_grounding_context_notes(
                commit_sha=str(commit_sha),
                file_path=relative_path,
                start_line=start_line,
                end_line=end_line,
                file_sha256=file_sha256,
                snippet_sha256=snippet_sha256,
            ),
        }
        if evidence_id is not None:
            evidence_payload["id"] = evidence_id
        try:
            canonical.append(Evidence.model_validate(evidence_payload))
        except (TypeError, ValueError):
            continue

    return canonical


def is_deterministically_grounded_evidence(
    evidence: Any,
    *,
    expected_commit_sha: str | None = None,
) -> bool:
    """Validate a persisted evidence record against its canonical attestation."""
    file_path = str(_field(evidence, "file_path", "") or "").strip()
    snippet = str(_field(evidence, "code_snippet", "") or "")
    start_line = _field(evidence, "start_line")
    end_line = _field(evidence, "end_line")
    notes = _field(evidence, "context_notes")
    if (
        not file_path
        or not snippet.strip()
        or len(snippet) > MAX_CANONICAL_SNIPPET_CHARS
        or not isinstance(start_line, int)
        or isinstance(start_line, bool)
        or start_line < 1
        or not isinstance(end_line, int)
        or isinstance(end_line, bool)
        or end_line < start_line
        or not isinstance(notes, str)
    ):
        return False

    try:
        attestation = json.loads(notes)
    except (TypeError, ValueError):
        return False
    if not isinstance(attestation, dict):
        return False
    if attestation.get("schema_version") != GROUNDING_SCHEMA_VERSION:
        return False
    if expected_commit_sha and attestation.get("commit_sha") != expected_commit_sha:
        return False
    if (
        attestation.get("file_path") != file_path
        or attestation.get("start_line") != start_line
        or attestation.get("end_line") != end_line
    ):
        return False

    file_sha256 = str(attestation.get("file_sha256") or "")
    snippet_sha256 = str(attestation.get("snippet_sha256") or "")
    if not _HEX_SHA256.fullmatch(file_sha256) or not _HEX_SHA256.fullmatch(snippet_sha256):
        return False
    return hashlib.sha256(snippet.encode("utf-8")).hexdigest() == snippet_sha256


def is_canonical_confirmed_finding(
    finding: Any,
    *,
    expected_commit_sha: str | None = None,
) -> bool:
    """Return whether a finding is safe to expose as verified canonical truth."""
    verdict = _field(finding, "verification_verdict")
    verdict_value = getattr(verdict, "value", verdict)
    if str(verdict_value or "").upper() != "CONFIRMED":
        return False
    evidences = list(_field(finding, "evidences", []) or [])
    return bool(evidences) and all(
        is_deterministically_grounded_evidence(
            evidence,
            expected_commit_sha=expected_commit_sha,
        )
        for evidence in evidences
    )
