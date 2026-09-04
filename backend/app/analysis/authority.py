"""Central version identity for reusable analysis artifacts.

Reuse is deliberately conservative: callers must provide every authority that
can change an analysis result.  Missing identities produce a cache miss rather
than guessing a compatibility version.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any
from pathlib import Path


REQUIRED_ANALYSIS_AUTHORITIES = (
    "repository",
    "commit",
    "tenant",
    "ingestion",
    "parser",
    "scanner",
    "analysis_policy",
    "graph",
    "verifier",
    "detectors",
    "prompt_schema",
    "runtime_policy",
)


def authority_digest(authorities: Mapping[str, Any]) -> str | None:
    """Return a stable digest only when all required authorities are known."""
    normalized = {str(key): value for key, value in authorities.items()}
    missing = [
        key for key in REQUIRED_ANALYSIS_AUTHORITIES
        if normalized.get(key) in (None, "", "unknown", "UNVERIFIED")
    ]
    if missing:
        return None
    encoded = json.dumps(normalized, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def analysis_fingerprint(authorities: Mapping[str, Any]) -> str | None:
    """Alias used by scan/reuse services."""
    return authority_digest(authorities)


def compatibility_digest(authorities: Mapping[str, Any]) -> str | None:
    """Digest authorities that must remain stable across commits.

    Exact reuse includes repository/tenant/commit identity.  Incremental reuse
    intentionally removes only the immutable commit component; every analyzer,
    verifier, prompt, and runtime-policy authority remains mandatory.
    """
    normalized = {str(key): value for key, value in authorities.items() if str(key) != "commit"}
    required = tuple(key for key in REQUIRED_ANALYSIS_AUTHORITIES if key != "commit")
    if any(normalized.get(key) in (None, "", "unknown", "UNVERIFIED") for key in required):
        return None
    encoded = json.dumps(normalized, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def source_fingerprint(*paths: str) -> str | None:
    """Hash authority source files when they are available on this runtime."""
    import pathlib

    digest = hashlib.sha256()
    for raw_path in sorted(paths):
        path = pathlib.Path(raw_path)
        try:
            payload = path.read_bytes()
        except OSError:
            return None
        digest.update(path.as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(payload)
    return digest.hexdigest() if paths else None


def runtime_authorities(
    *,
    repository_url: str,
    commit_sha: str,
    tenant_id: str,
    policy_snapshot_id: str | None,
    scanner_summary: Any,
) -> dict[str, Any]:
    """Build authority inputs from the installed RepoLens implementation.

    Source digests change automatically when an analyzer/verifier/parser is
    changed.  If a source authority cannot be read, callers receive a cache
    miss rather than a guessed compatibility value.
    """
    root = Path(__file__).resolve().parents[1]
    authority_files = {
        "ingestion": root / "ingestion" / "manifest.py",
        "parser": root / "ingestion" / "parser.py",
        "scanner": root / "analysis" / "service.py",
        "graph": root / "graph" / "repository_graph.py",
        "verifier": root / "agents" / "verifier.py",
        "detectors": root / "agents" / "deterministic.py",
        "prompt_schema": root / "llm" / "workflow_contracts.py",
    }
    scanner_sources = [
        root / "analysis" / "service.py",
        root / "analysis" / "base.py",
        root / "analysis" / "adapters" / "semgrep.py",
        root / "analysis" / "adapters" / "trivy.py",
        root / "analysis" / "adapters" / "osv.py",
    ]
    scanner_config_fingerprint = source_fingerprint(*(str(path) for path in scanner_sources))
    values: dict[str, Any] = {
        "repository": hashlib.sha256(repository_url.encode("utf-8")).hexdigest(),
        "commit": commit_sha,
        "tenant": tenant_id,
        "analysis_policy": source_fingerprint(str(root / "llm" / "admission.py")),
        "runtime_policy": policy_snapshot_id,
        # Scanner results are runtime observations and must not become an
        # authority version: findings naturally differ between commits.  The
        # scanner implementation/configuration identity is stable instead.
        "scanner_config": scanner_config_fingerprint,
    }
    for key, path in authority_files.items():
        values[key] = source_fingerprint(str(path))
    values["scanner"] = values.get("scanner") or scanner_config_fingerprint
    return values


__all__ = [
    "REQUIRED_ANALYSIS_AUTHORITIES",
    "analysis_fingerprint",
    "authority_digest",
    "compatibility_digest",
    "source_fingerprint",
    "runtime_authorities",
]
