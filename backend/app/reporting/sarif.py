"""Deterministic read-only SARIF 2.1.0 export of attested findings.

No source snippets, model metadata, or unverified findings are exported.
Caller enforces tenant ownership and completed scan status.
"""
from __future__ import annotations

import hashlib
import re
from typing import Iterable
from urllib.parse import quote

from app.security.redaction import contains_secrets, redact_secrets
from app.services.finding_grounding import is_canonical_confirmed_finding

MAX_SARIF_FINDINGS = 2_000
MAX_SARIF_EVIDENCES = 10_000
_SHA = re.compile(r"^[a-fA-F0-9]{40}(?:[a-fA-F0-9]{24})?$")
_RULE_CHARS = re.compile(r"[^A-Za-z0-9_.:-]")
# Reserve the digest suffix so a legitimate ID cannot impersonate a sanitized ID.
_HASH_SUFFIX = re.compile(r"-[0-9a-f]{12}$")
# Canonical redaction uses word boundaries; underscores can hide embedded GitHub tokens,
# including GitHub App and OAuth tokens.
_EMBEDDED_GITHUB_TOKEN = re.compile(r"(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|(?:ghs_|ghu_|ghr_)[A-Za-z0-9_.-]{10,})")
# Canonical \b boundaries miss other secret formats when preceded by an underscore.
# Match the same known credential families at underscore/non-alphanumeric boundaries.
_EMBEDDED_NON_GITHUB_SECRET = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"(?:sk-or-v1-|sk-|gsk_|hf_|nvapi-|cfut_|cohere_)[A-Za-z0-9_-]{16,}"
    r"|AIza[A-Za-z0-9_-]{20,}"
    r"|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    r"|(?i:bearer\s+)[A-Za-z0-9_.-]{10,}"
    r"|(?i:api[_-]?key|secret|password|auth[_-]?token)\s*[:=]\s*['\"][^\s'\"]{6,}['\"]"
    r")"
)
_LEVELS = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}


class SarifExportLimitExceeded(ValueError):
    """Fail closed rather than return silently truncated findings."""


def _redact_export_text(value: str) -> str:
    """Cover GitHub tokens embedded in identifiers and prose after underscores."""
    redacted = _EMBEDDED_GITHUB_TOKEN.sub("[REDACTED_GITHUB_TOKEN]", redact_secrets(value))
    return _EMBEDDED_NON_GITHUB_SECRET.sub("[REDACTED_API_TOKEN]", redacted)


def _safe_path(raw: str) -> str | None:
    """Require exact repository-relative POSIX paths, then percent-encode for URI."""
    if not raw or len(raw) > 512 or raw.startswith("/") or "\\" in raw or ":" in raw:
        return None
    if any(part in ("", ".", "..") for part in raw.split("/")):
        return None
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        return None
    # A credential in a path would otherwise survive URI encoding and leak in SARIF.
    # Do not redact paths in place: that would point consumers at a fictitious file.
    if (
        contains_secrets(raw)
        or _EMBEDDED_GITHUB_TOKEN.search(raw)
        or _EMBEDDED_NON_GITHUB_SECRET.search(raw)
    ):
        return None
    return quote(raw, safe="/-._~")


def _rule_component(value: str, limit: int) -> str:
    """Preserve ordinary IDs; disambiguate lossy sanitization or truncation."""
    # Rule identifiers can originate in scanner metadata; never export raw credentials.
    sanitized = _RULE_CHARS.sub("_", _redact_export_text(value))
    if sanitized == value and len(value) <= limit and not _HASH_SUFFIX.search(value):
        return value
    suffix = "-" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return sanitized[:limit - len(suffix)] + suffix


def _rule_id(finding: object) -> str:
    tool = _rule_component(str(getattr(finding, "source_tool", None) or "repolens"), 64)
    detector = getattr(finding, "detector_id", None) or getattr(finding, "rule_id", None) or "verified-finding"
    key = _rule_component(str(detector), 160)
    return f"{tool}/{key}"


def build_verified_sarif(*, scan: object, findings: Iterable[object]) -> dict:
    """Project only open, canonical CONFIRMED findings at an immutable Git commit."""
    commit_sha = str(getattr(scan, "commit_hash", "") or "")
    if not _SHA.fullmatch(commit_sha):
        raise ValueError("A recorded immutable Git commit hash is required for SARIF export.")

    rules: dict[str, dict] = {}
    results: list[dict] = []
    total_evidences = 0
    for finding in findings:
        if str(getattr(finding, "status", "")).upper() != "OPEN":
            continue
        if not is_canonical_confirmed_finding(finding, expected_commit_sha=commit_sha):
            continue

        locations = []
        for evidence in sorted(
            finding.evidences,
            key=lambda e: (str(e.file_path), int(e.start_line or 0), int(e.end_line or 0)),
        ):
            uri = _safe_path(str(evidence.file_path))
            if uri is None:
                locations = []
                break
            total_evidences += 1
            if total_evidences > MAX_SARIF_EVIDENCES:
                raise SarifExportLimitExceeded("SARIF evidence limit exceeded; export was not truncated.")
            locations.append({
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": evidence.start_line, "endLine": evidence.end_line},
                }
            })
        if not locations:
            continue
        if len(results) >= MAX_SARIF_FINDINGS:
            raise SarifExportLimitExceeded("SARIF finding limit exceeded; export was not truncated.")

        rule_id = _rule_id(finding)
        title = _redact_export_text(str(finding.title or ""))[:256] or "Verified finding"
        message = _redact_export_text(str(finding.description or ""))[:1024] or title
        level = _LEVELS.get(str(finding.severity).upper(), "warning")
        rules.setdefault(rule_id, {
            "id": rule_id,
            "shortDescription": {"text": title},
            "defaultConfiguration": {"level": level},
        })
        first = locations[0]["physicalLocation"]
        fingerprint = hashlib.sha256(
            f"{rule_id}\0{first['artifactLocation']['uri']}\0{first['region']['startLine']}".encode("utf-8")
        ).hexdigest()
        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message},
            "locations": locations,
            # GitHub primaryLocationLineHash requires source-line content, not a location digest.
            # Leave it unset so a later upload-sarif action can derive it from a checkout.
            "partialFingerprints": {"repolens/v1": fingerprint},
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "RepoLens",
                "informationUri": "https://github.com/yashaskn8/RepoLens",
                "rules": [rules[key] for key in sorted(rules)],
            }},
            "results": results,
        }],
    }
