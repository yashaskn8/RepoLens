"""SARIF regression tests for validated evidence, ownership and export limits."""

import hashlib
import json
from types import SimpleNamespace
from uuid import uuid4

from app.models.finding import EvidenceModel, FindingModel
from app.models.scan import ScanModel
from app.reporting.sarif import build_sarif
from app.schemas.enums import ScanStatus
from app.services.finding_grounding import build_grounding_context_notes


COMMIT = "a" * 40
REDACTABLE = "password='examplevalue'"


def _evidence(*, text="safe = True", path="src/lib#1.py", grounded=True):
    notes = build_grounding_context_notes(
        commit_sha=COMMIT,
        file_path=path,
        start_line=3,
        end_line=3,
        file_sha256=hashlib.sha256(b"known file").hexdigest(),
        snippet_sha256=hashlib.sha256(text.encode()).hexdigest(),
    ) if grounded else "untrusted location"
    return EvidenceModel(
        file_path=path,
        start_line=3,
        end_line=3,
        code_snippet=text,
        context_notes=notes,
    )


def _scan(db, *, status=ScanStatus.COMPLETED.value, owner=None):
    scan = ScanModel(
        id=str(uuid4()),
        repository_url="https://github.com/example/project",
        status=status,
        commit_hash=COMMIT,
    )
    if owner is not None:
        scan.owner_user_id = owner
    db.add(scan)
    db.flush()
    return scan


def _finding(db, scan, *, status="OPEN", verdict="CONFIRMED", grounded=True, title="Risk"):
    finding = FindingModel(
        id=str(uuid4()),
        scan_id=scan.id,
        title=title,
        description="Detected issue with " + REDACTABLE,
        severity="HIGH",
        status=status,
        rule_id="SEC-1",
        detector_id="python.test",
        source_tool="semgrep",
        verification_verdict=verdict,
    )
    finding.evidences.append(_evidence(grounded=grounded))
    db.add(finding)
    db.flush()
    return finding


def test_sarif_export_verified_findings_and_redaction(client, db_session):
    scan = _scan(db_session)
    _finding(db_session, scan, title="Credential " + REDACTABLE)
    _finding(db_session, scan, status="SUPPRESSED")
    _finding(db_session, scan, verdict="POSSIBLE")
    _finding(db_session, scan, grounded=False)
    db_session.commit()

    response = client.get(f"/api/v1/scans/{scan.id}/sarif")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/sarif+json")
    assert response.headers["cache-control"] == "private, no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert 'attachment;' in response.headers["content-disposition"]
    assert REDACTABLE not in response.text
    document = response.json()
    assert document["version"] == "2.1.0"
    assert len(document["runs"]) == 1
    run = document["runs"][0]
    assert len(run["results"]) == 1
    assert run["tool"]["driver"]["rules"][0]["id"] == "repolens/semgrep/python.test"
    result = run["results"][0]
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/lib%231.py"
    assert result["locations"][0]["physicalLocation"]["region"] == {"startLine": 3, "endLine": 3}
    assert len(result["partialFingerprints"]["repolens/v1"]) == 64
    assert "primaryLocationLineHash" not in result["partialFingerprints"]
    assert "safe = True" not in response.text


def test_sarif_is_stable_without_scan_or_finding_identifiers():
    def finding():
        return SimpleNamespace(
            id=str(uuid4()),
            title="Detected issue",
            description="Bad input",
            severity="MEDIUM",
            status="OPEN",
            rule_id="SEC-1",
            detector_id="python.test",
            source_tool="semgrep",
            evidences=[SimpleNamespace(
                file_path="src/a.py", start_line=4, end_line=4,
                code_snippet="bad()", id=str(uuid4()),
            )],
        )
    first = build_sarif([finding()], commit_sha=COMMIT)
    second = build_sarif([finding()], commit_sha=COMMIT)
    assert first == second
    assert first["runs"][0]["results"][0]["level"] == "warning"
    assert json.dumps(first)



def test_sarif_never_claims_github_source_line_hash_from_snippet_digest():
    """A stored snippet digest is not GitHub's source-line fingerprint."""
    finding = SimpleNamespace(
        title="Issue", description="Details", severity="HIGH", status="OPEN",
        source_tool="semgrep", detector_id="rule-1",
        evidences=[SimpleNamespace(
            file_path="src/a.py", start_line=4, end_line=4,
            code_snippet="alert()",
        )],
    )
    result = build_sarif([finding], commit_sha=COMMIT)["runs"][0]["results"][0]
    fingerprints = result["partialFingerprints"]
    assert "primaryLocationLineHash" not in fingerprints
    expected = hashlib.sha256(
        ("repolens/semgrep/rule-1\\0src/a.py\\0" + hashlib.sha256(b"alert()").hexdigest()).encode()
    ).hexdigest()
    assert fingerprints == {"repolens/v1": expected}


def test_sarif_does_not_expose_other_users_scan(client, db_session):
    scan = _scan(db_session, owner=str(uuid4()))
    _finding(db_session, scan)
    db_session.commit()
    assert client.get(f"/api/v1/scans/{scan.id}/sarif").status_code == 404


def test_sarif_requires_completed_scan(client, db_session):
    scan = _scan(db_session, status=ScanStatus.RUNNING.value)
    db_session.commit()
    response = client.get(f"/api/v1/scans/{scan.id}/sarif")
    assert response.status_code == 409
    assert response.json()["detail"]["error_code"] == "SCAN_NOT_EXPORTABLE"


def test_sarif_no_confirmed_findings_is_explicitly_empty(client, db_session):
    scan = _scan(db_session)
    _finding(db_session, scan, verdict="POSSIBLE")
    db_session.commit()
    response = client.get(f"/api/v1/scans/{scan.id}/sarif")
    assert response.status_code == 200
    assert response.json()["runs"][0]["results"] == []


def test_sarif_result_cap_fails_instead_of_truncating(client, db_session, monkeypatch):
    monkeypatch.setattr("app.api.routes.sarif.MAX_SARIF_RESULTS", 1)
    scan = _scan(db_session)
    _finding(db_session, scan)
    _finding(db_session, scan)
    db_session.commit()
    response = client.get(f"/api/v1/scans/{scan.id}/sarif")
    assert response.status_code == 413
    assert response.json()["detail"]["error_code"] == "SARIF_RESULT_LIMIT"


def test_sarif_byte_cap_fails_instead_of_truncating(client, db_session, monkeypatch):
    monkeypatch.setattr("app.api.routes.sarif.MAX_SARIF_BYTES", 50)
    scan = _scan(db_session)
    _finding(db_session, scan)
    db_session.commit()
    response = client.get(f"/api/v1/scans/{scan.id}/sarif")
    assert response.status_code == 413
    assert response.json()["detail"]["error_code"] == "SARIF_BYTE_LIMIT"
