"""Deterministic SARIF 2.1.0 projection of canonically verified RepoLens findings.

This is a read-only interchange format, not a new source of security truth.
Never emit unverified candidates, repository snippets, or unchecked paths.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterable

from app.security.redaction import redact_secrets
from app.services.finding_grounding import is_canonical_confirmed_finding

MAX_SARIF_RESULTS = 5_000
MAX_RELATED_LOCATIONS = 100
_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
_SAFE_PATH = re.compile(r"^[^\\x00-\\x1f\\x7f]+$")
_RULE_CHARS = re.compile(r"[^a-zA-Z0-9._/-]")


class SarifTooLarge(ValueError):
    """The export cannot be represented within the bounded SARIF contract."""


def _safe_path(value: Any) -> str | None:
    path = str(value or "")
    if (
        not path
        or len(path) > 512
        or not _SAFE_PATH.fullmatch(path)
        or "\\" in path
        or path.startswith("/")
        or path.startswith("./")
        or ":" in path
        or any(part in ("", ".", "..") for part in path.split("/"))
    ):
        return None
    return path


def _rule_id(finding: Any) -> str:
    source = str(getattr(finding, "source_tool", "") or "repolens")
    detector = str(
        getattr(finding, "detector_id", None)
        or getattr(finding, "rule_id", None)
        or getattr(finding, "title", "finding")
    )
    name = _RULE_CHARS.sub("_", f"{source}/{detector}").strip("._/")
    # Keep the collision-resistant identity even when the display name is truncated.
    digest = hashlib.sha256(f"{source}\\0{detector}".encode("utf-8")).hexdigest()[:12]
    return f"RL-{name[:85]}-{digest}"


def _level(severity: Any) -> str:
    normalized = str(getattr(severity, "value", severity) or "").upper()
    return {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }.get(normalized, "none")


def _location(evidence: Any) -> dict[str, Any] | None:
    path = _safe_path(getattr(evidence, "file_path", ""))
    start = getattr(evidence, "start_line", None)
    end = getattr(evidence, "end_line", None)
    if (
        path is None
        or type(start) is not int
        or type(end) is not int
        or start < 1
        or end < start
    ):
        return None
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": path, "uriBaseId": "%SRCROOT%"},
            "region": {"startLine": start, "endLine": end},
        }
    }


def build_sarif_document(findings: Iterable[Any], *, commit_sha: str) -> dict[str, Any]:
    """Build an ordered, portable report; invalid/unverified rows fail closed.

    Caller MUST already enforce scan ownership and completed state.
    The expected commit must be a full SHA so stale/unknown evidence cannot pass.
    """
    if not _SHA.fullmatch(commit_sha):
        raise ValueError("SARIF requires an exact 40-character scan commit SHA")

    rows: list[tuple[str, str, int, str, dict[str, Any]]] = []
    rules: dict[str, dict[str, Any]] = {}

    for finding in findings:
        if str(getattr(finding, "status", "")).upper() != "OPEN":
            continue
        if not is_canonical_confirmed_finding(
            finding, expected_commit_sha=commit_sha
        ):
            continue

        evidences = list(getattr(finding, "evidences", ()) or ())
        locations = [_location(evidence) for evidence in evidences]
        # Refuse an ambiguous partial finding rather than emit a misleading alert.
        if not locations or any(location is None for location in locations):
            continue
        if len(locations) > MAX_RELATED_LOCATIONS + 1:
            raise SarifTooLarge("One finding exceeds the SARIF evidence location limit")

        rule_id = _rule_id(finding)
        title = redact_secrets(str(getattr(finding, "title", "") or "Finding"))[:256]
        description = redact_secrets(str(getattr(finding, "description", "") or ""))[:1800]
        safe_message = f"{title}. {description}".strip()[:2000]
        if not safe_message.strip(". "):
            safe_message = "Verified RepoLens finding"

        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": title or "RepoLens finding"},
            "properties": {"tags": ["repolens", "verified"]},
        })
        primary = locations[0]
        path = primary["physicalLocation"]["artifactLocation"]["uri"]
        line = primary["physicalLocation"]["region"]["startLine"]
        snippet = str(getattr(evidences[0], "code_snippet", "") or "")
        snippet_hash = hashlib.sha256(snippet.encode("utf-8")).hexdigest()
        fingerprint = hashlib.sha256(
            f"{rule_id}\\0{path}\\0{snippet_hash}".encode("utf-8")
        ).hexdigest()

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _level(getattr(finding, "severity", "")),
            "message": {"text": safe_message},
            "locations": [primary],
            "partialFingerprints": {"primaryLocationLineHash": fingerprint},
        }
        if len(locations) > 1:
            result["relatedLocations"] = [
                {"id": index, **location}
                for index, location in enumerate(locations[1:], start=1)
            ]
        rows.append((rule_id, path, line, fingerprint, result))
        if len(rows) > MAX_SARIF_RESULTS:
            raise SarifTooLarge("SARIF result limit exceeded; export was not truncated")

    rows.sort(key=lambda item: item[:4])
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "RepoLens",
                "informationUri": "https://github.com/yashaskn8/RepoLens",
                "rules": [rules[key] for key in sorted(rules)],
            }},
            "originalUriBaseIds": {"%SRCROOT%": {"uri": "file:///"}},
            "results": [row[-1] for row in rows],
            "properties": {
                "commitSha": commit_sha.lower(),
                "exportScope": "OPEN canonical CONFIRMED findings with grounded evidence only",
                "coverageWarning": (
                    "This file is not evidence of a complete repository security assessment."
                ),
            },
        }],
    }


def encode_sarif(document: dict[str, Any]) -> str:
    """Canonical output: stable ordering and no raw repository source snippets."""
    return json.dumps(document, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
