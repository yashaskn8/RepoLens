"""Regression coverage for the tenant-isolated evidence-only SARIF export."""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.models.finding import EvidenceModel, FindingModel
from app.models.scan import ScanModel
from app.models.user import UserModel
from app.reporting.sarif import SarifTooLarge, build_sarif_document
from app.services.finding_grounding import build_grounding_context_notes


COMMIT = "a" * 40
SNIPPET = "return safe_value"
HASH = hashlib.sha256(SNIPPET.encode()).hexdigest()


def _evidence(path="src/example.py", *, commit=COMMIT, line=7, notes=None):
    return SimpleNamespace(
        file_path=path,
        start_line=line,
        end_line=line,
        code_snippet=SNIPPET,
        context_notes=notes if notes is not None else build_grounding_context_notes(
            commit_sha=commit,
            file_path=path,
            start_line=line,
            end_line=line,
            file_sha256="b" * 64,
            snippet_sha256=HASH,
        ),
    )


def _finding(*, verdict="CONFIRMED", status="OPEN", evidence=None):
    return SimpleNamespace(
        id=str(uuid4()),
        title="Safe title",
        description="Deterministically verified evidence",
        severity="HIGH",
        status=status,
        verification_verdict=verdict,
        source_tool="semgrep",
        detector_id="PY-EXAMPLE",
        rule_id="PY-EXAMPLE",
        evidences=[evidence if evidence is not None else _evidence()],
    )


def test_sarif_exports_portable_version_and_stable_fingerprint():
    one = build_sarif_document([_finding()], commit_sha=COMMIT)
    two = build_sarif_document([_finding()], commit_sha=COMMIT)
    result = one["runs"][0]["results"][0]
    assert one["version"] == "2.1.0"
    assert len(one["runs"][0]["tool"]["driver"]["rules"]) == 1
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/example.py"
    assert result["partialFingerprints"] == two["runs"][0]["results"][0]["partialFingerprints"]
    assert "code_snippet" not in json.dumps(one)
    assert SNIPPET not in json.dumps(one)


def test_sarif_never_exports_unverified_suppressed_or_stale_evidence():
    bad_path = _evidence("../escape.py")
    results = build_sarif_document([
        _finding(verdict="POSSIBLE"),
        _finding(status="SUPPRESSED"),
        _finding(evidence=_evidence(commit="c" * 40)),
        _finding(evidence=bad_path),
        _finding(),
    ], commit_sha=COMMIT)["runs"][0]["results"]
    assert len(results) == 1


def test_sarif_rejects_unknown_commit():
    with pytest.raises(ValueError):
        build_sarif_document([_finding()], commit_sha="unknown")


def test_sarif_fails_closed_before_silent_truncation(monkeypatch):
    from app.reporting import sarif

    monkeypatch.setattr(sarif, "MAX_SARIF_RESULTS", 1)
    with pytest.raises(SarifTooLarge):
        build_sarif_document([_finding(), _finding()], commit_sha=COMMIT)


def test_sarif_api_requires_completed_owned_scan_and_exact_attestation(client, db_session):
    owner = db_session.query(UserModel).filter_by(email="default_test_user@example.com").one()
    scan_id = str(uuid4())
    scan = ScanModel(
        id=scan_id, owner_user_id=owner.id, repository_url="https://github.com/example/public",
        commit_hash=COMMIT, status="COMPLETED",
    )
    db_session.add(scan)
    db_session.flush()
    finding = FindingModel(
        id=str(uuid4()), scan_id=scan_id, title="Safe title", description="Evidence",
        severity="HIGH", status="OPEN", rule_id="PY-EXAMPLE",
        verification_verdict="CONFIRMED", source_tool="semgrep",
    )
    db_session.add(finding)
    db_session.flush()
    db_session.add(EvidenceModel(
        id=str(uuid4()), finding_id=finding.id, file_path="src/example.py",
        start_line=7, end_line=7, code_snippet=SNIPPET,
        context_notes=_evidence().context_notes,
    ))
    db_session.flush()

    response = client.get(f"/api/v1/scans/{scan_id}/sarif")
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/sarif+json")
    assert response.headers["cache-control"] == "private, no-store"
    assert response.headers["content-disposition"].endswith('.sarif"')
    assert len(response.json()["runs"][0]["results"]) == 1

    scan.status = "RUNNING"
    db_session.flush()
    assert client.get(f"/api/v1/scans/{scan_id}/sarif").status_code == 409

    scan.status = "COMPLETED"
    scan.commit_hash = "unknown"
    db_session.flush()
    assert client.get(f"/api/v1/scans/{scan_id}/sarif").status_code == 409

    scan.commit_hash = COMMIT
    scan.owner_user_id = str(uuid4())  # Simulates a scan owned by another identity.
    db_session.flush()
    assert client.get(f"/api/v1/scans/{scan_id}/sarif").status_code == 404


def test_sarif_api_requires_login(client):
    client.cookies.clear()
    response = client.get(f"/api/v1/scans/{uuid4()}/sarif")
    assert response.status_code == 401
