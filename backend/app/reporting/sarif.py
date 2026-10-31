"""Deterministic, read-only SARIF 2.1.0 export of verified RepoLens findings.

Only caller-authorized, canonically confirmed, OPEN findings belong here.
Never include raw source snippets, model metadata, credentials, or host paths.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Iterable
from urllib.parse import quote

from app.security.redaction import redact_secrets

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _field(obj: Any, name: str, default: Any = None) -> Any:
    return obj.get(name, default) if isinstance(obj, dict) else getattr(obj, name, default)


def _token(value: Any, fallback: str) -> str:
    raw = str(value or "").strip()
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", raw).strip("-._")
    if not safe:
        return fallback
    if len(safe) > 100:
        return safe[:80] + "-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    return safe


def _safe_path(path: Any) -> str | None:
    """Reject ambiguous or absolute repository locations rather than correcting them."""
    if not isinstance(path, str) or not path or path.startswith("/") or "\\" in path or ":" in path:
        return None
    if any(part in ("", ".", "..") for part in path.split("/")):
        return None
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in path):
        return None
    return path


def _safe_message(value: Any, *, fallback: str, limit: int) -> str:
    text = redact_secrets(str(value or "")).strip()
    return (text or fallback)[:limit]


def _level(severity: Any) -> str:
    value = str(getattr(severity, "value", severity) or "").upper()
    if value in {"CRITICAL", "HIGH"}:
        return "error"
    if value == "MEDIUM":
        return "warning"
    return "note"


def build_sarif(findings: Iterable[Any], *, commit_sha: str) -> dict[str, Any]:
    """Build a stable SARIF document from already canonically verified findings.

    The route must enforce scan ownership, terminal scan state, evidence grounding,
    and export size limits before calling this pure projection.
    """
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in findings:
        if str(getattr(_field(finding, "status"), "value", _field(finding, "status"))).upper() != "OPEN":
            continue
        evidences = list(_field(finding, "evidences") or [])
        if not evidences:
            continue
        # GitHub code scanning uses the first location as the alert's primary location.
        evidence = sorted(evidences, key=lambda e: (
            str(_field(e, "file_path") or ""), int(_field(e, "start_line") or 0)
        ))[0]
        path = _safe_path(_field(evidence, "file_path"))
        start = _field(evidence, "start_line")
        end = _field(evidence, "end_line")
        if not path or type(start) is not int or type(end) is not int or start < 1 or end < start:
            continue

        rule = "repolens/{}/{}".format(
            _token(_field(finding, "source_tool"), "internal"),
            _token(_field(finding, "detector_id") or _field(finding, "rule_id"), "unclassified"),
        )
        title = _safe_message(_field(finding, "title"), fallback="Verified finding", limit=256)
        description = _safe_message(_field(finding, "description"), fallback=title, limit=1024)
        rules.setdefault(rule, {"id": rule, "shortDescription": {"text": title}})

        # Stable across finding/scan UUID changes and source line shifts.
        snippet_hash = hashlib.sha256(
            str(_field(evidence, "code_snippet") or "").encode("utf-8")
        ).hexdigest()
        fingerprint = hashlib.sha256(
            (rule + "\0" + path + "\0" + snippet_hash).encode("utf-8")
        ).hexdigest()
        results.append({
            "ruleId": rule,
            "level": _level(_field(finding, "severity")),
            "message": {"text": (title + ": " + description)[:1280]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": quote(path, safe="/-._~")},
                    "region": {"startLine": start, "endLine": end},
                }
            }],
            "partialFingerprints": {"primaryLocationLineHash": fingerprint},
        })

    results.sort(key=lambda x: (
        x["ruleId"],
        x["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        x["locations"][0]["physicalLocation"]["region"]["startLine"],
        x["partialFingerprints"]["primaryLocationLineHash"],
    ))
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "RepoLens",
                "informationUri": "https://github.com/yashaskn8/RepoLens",
                "rules": [rules[key] for key in sorted(rules)],
            }},
            "results": results,
            "properties": {
                "scanCommit": commit_sha,
                "resultScope": "OPEN, CONFIRMED, canonically grounded findings only",
            },
        }],
    }
