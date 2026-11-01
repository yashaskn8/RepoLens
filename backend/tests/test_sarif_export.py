"""SARIF integration regression: tenant isolation, grounding, leak safety, bounds."""
import hashlib
from uuid import uuid4

from app.models.finding import EvidenceModel, FindingModel
from app.models.scan import ScanModel
from app.services.finding_grounding import build_grounding_context_notes
from app.reporting import sarif


COMMIT = "a" * 40


def _scan(db, *, owner=None, state="COMPLETED"):
    scan = ScanModel(
        id=str(uuid4()),
        repository_url="https://github.com/example/repo",
        commit_hash=COMMIT,
        status=state,
        owner_user_id=owner,
    )
    db.add(scan)
    db.flush()
    return scan


def _finding(db, scan, *, title="Verified issue", description="Use a safer pattern",
             verdict="CONFIRMED", state="OPEN", path="src/example.py",
             line=7, snippet="unsafe(value)"):
    finding = FindingModel(
        id=str(uuid4()),
        scan_id=scan.id,
        title=title,
        description=description,
        severity="HIGH",
        status=state,
        rule_id="example.rule",
        verification_verdict=verdict,
        source_tool="semgrep",
        detector_id="example.rule",
    )
    db.add(finding)
    db.flush()
    if snippet is not None:
        db.add(EvidenceModel(
            id=str(uuid4()),
            finding_id=finding.id,
            file_path=path,
            start_line=line,
            end_line=line,
            code_snippet=snippet,
            context_notes=build_grounding_context_notes(
                commit_sha=COMMIT,
                file_path=path,
                start_line=line,
                end_line=line,
                file_sha256="0" * 64,
                snippet_sha256=hashlib.sha256(snippet.encode()).hexdigest(),
            ),
        ))
    db.flush()
    return finding


def test_export_only_grounded_open_findings_and_redacts(client, db_session):
    scan = _scan(db_session)
    _finding(db_session, scan, title="Bearer abcdefghijklmnopqrstuvwxyz",
             description="Credential: Bearer abcdefghijklmnopqrstuvwxyz",
             path="src/my file.py")
    _finding(db_session, scan, title="Hypothesis", verdict="POSSIBLE")
    _finding(db_session, scan, title="No evidence", snippet=None)
    _finding(db_session, scan, title="Resolved", state="RESOLVED")
    response = client.get(f"/api/v1/scans/{scan.id}/report/sarif")
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/sarif+json")
    assert response.headers["cache-control"] == "private, no-store"
    report = response.json()
    assert report["version"] == "2.1.0"
    assert len(report["runs"][0]["results"]) == 1
    result = report["runs"][0]["results"][0]
    assert result["ruleId"] == "semgrep/example.rule"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/my%20file.py"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 7
    assert len(result["partialFingerprints"]["repolens/v1"]) == 64
    # A location digest must never impersonate GitHub's source-line hash.
    assert "primaryLocationLineHash" not in result["partialFingerprints"]
    assert "abcdefghijklmnopqrstuvwxyz" not in response.text
    assert "unsafe(value)" not in response.text
    assert response.text == client.get(f"/api/v1/scans/{scan.id}/report/sarif").text


def test_sarif_rejects_other_tenant_and_unfinished_scan(client, db_session):
    foreign = _scan(db_session, owner=str(uuid4()))
    assert client.get(f"/api/v1/scans/{foreign.id}/report/sarif").status_code == 404
    unfinished = _scan(db_session, state="RUNNING")
    response = client.get(f"/api/v1/scans/{unfinished.id}/report/sarif")
    assert response.status_code == 409
    assert response.json()["detail"]["error_code"] == "SCAN_NOT_COMPLETED"


def test_sarif_skips_invalid_attested_path_and_fails_without_commit(client, db_session):
    scan = _scan(db_session)
    _finding(db_session, scan, path="../private/file.py")
    response = client.get(f"/api/v1/scans/{scan.id}/report/sarif")
    assert response.status_code == 200
    assert response.json()["runs"][0]["results"] == []
    scan.commit_hash = "unknown"
    db_session.flush()
    response = client.get(f"/api/v1/scans/{scan.id}/report/sarif")
    assert response.status_code == 409
    assert response.json()["detail"]["error_code"] == "SCAN_COMMIT_UNAVAILABLE"


def test_sarif_rejects_truncation(monkeypatch):
    class FakeScan:
        commit_hash = COMMIT

    class FakeEvidence:
        file_path = "a.py"
        start_line = 1
        end_line = 1
        code_snippet = "x"
        context_notes = build_grounding_context_notes(
            commit_sha=COMMIT, file_path="a.py", start_line=1, end_line=1,
            file_sha256="0" * 64,
            snippet_sha256=hashlib.sha256(b"x").hexdigest(),
        )

    class FakeFinding:
        status = "OPEN"
        verification_verdict = "CONFIRMED"
        evidences = [FakeEvidence()]
        title = "Issue"
        description = "Verified"
        severity = "HIGH"
        source_tool = "test"
        detector_id = "rule"

    monkeypatch.setattr(sarif, "MAX_SARIF_FINDINGS", 1)
    try:
        sarif.build_verified_sarif(scan=FakeScan(), findings=[FakeFinding(), FakeFinding()])
        assert False, "Expected refusal to truncate"
    except sarif.SarifExportLimitExceeded:
        pass


def test_sarif_keeps_distinct_rule_ids_after_sanitization_and_truncation(client, db_session):
    scan = _scan(db_session)
    detectors = [
        ("semgrep", "example.rule"),
        ("semgrep", "rule?x"),
        ("semgrep", "rule#x"),
        ("semgrep", "x" * 160 + "a"),
        ("semgrep", "x" * 160 + "b"),
        ("scan?tool", "simple"),
        ("scan#tool", "simple"),
        # A slash inside either component previously blurred the tool/rule boundary.
        ("scan/tool", "rule"),
        ("scan", "tool/rule"),
        # A valid ID ending in the generated hash suffix could impersonate a lossy ID.
        ("semgrep", "rule_x-" + hashlib.sha256(b"rule?x").hexdigest()[:12]),
        ("scan_tool-" + hashlib.sha256(b"scan?tool").hexdigest()[:12], "simple"),
    ]
    for tool, detector in detectors:
        finding = _finding(db_session, scan)
        finding.source_tool = tool
        finding.detector_id = detector
    db_session.flush()

    response = client.get(f"/api/v1/scans/{scan.id}/report/sarif")
    assert response.status_code == 200, response.text
    run = response.json()["runs"][0]
    ids = [result["ruleId"] for result in run["results"]]
    assert len(ids) == len(detectors)
    assert len(set(ids)) == len(detectors)
    assert all(rule_id.count("/") == 1 for rule_id in ids)
    assert {rule["id"] for rule in run["tool"]["driver"]["rules"]} == set(ids)
    # Unmodified, safe detector identifiers keep their existing SARIF IDs.
    assert "semgrep/example.rule" in ids


def test_sarif_redacts_credentials_in_rule_identifiers(client, db_session):
    scan = _scan(db_session)
    tokens = ["ghp_" + "A" * 36, "ghp_" + "B" * 36]
    tool_token = "sk-" + "C" * 20
    for token in tokens:
        finding = _finding(db_session, scan)
        finding.detector_id = token
        finding.source_tool = tool_token
    db_session.flush()

    response = client.get(f"/api/v1/scans/{scan.id}/report/sarif")
    assert response.status_code == 200, response.text
    assert all(token not in response.text for token in [*tokens, tool_token])
    ids = [item["ruleId"] for item in response.json()["runs"][0]["results"]]
    assert len(ids) == len(set(ids)) == 2
    assert all("REDACTED" in rule_id for rule_id in ids)


def test_sarif_redacts_github_tokens_embedded_after_underscores(client, db_session):
    # A preceding underscore is a word character, so canonical \b token patterns
    # can miss an otherwise recognizable GitHub token.
    scan = _scan(db_session)
    token = "ghp_" + "Q" * 36
    finding = _finding(
        db_session, scan,
        title=f"Finding prefix_{token}",
        description=f"Detector prefix_{token}",
        path="src/safe.py",
    )
    finding.source_tool = f"tool_{token}"
    finding.detector_id = f"rule_{token}"
    _finding(db_session, scan, path=f"src/prefix_{token}/issue.py")
    db_session.flush()

    response = client.get(f"/api/v1/scans/{scan.id}/report/sarif")
    assert response.status_code == 200, response.text
    assert token not in response.text
    results = response.json()["runs"][0]["results"]
    assert len(results) == 1
    assert "REDACTED" in results[0]["ruleId"]
    assert "REDACTED" in results[0]["message"]["text"]
    assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/safe.py"



def test_sarif_redacts_embedded_github_app_tokens_across_export_fields(client, db_session):
    # Canonical word-boundary patterns miss these tokens when preceded by "_".
    scan = _scan(db_session)
    tokens = ["ghs_" + "S" * 24, "ghu_" + "U" * 24, "ghr_" + "R" * 24]
    for index, token in enumerate(tokens):
        finding = _finding(
            db_session, scan,
            title=f"Finding prefix_{token}",
            description=f"Detector prefix_{token}",
            path=f"src/safe-{index}.py",
        )
        finding.source_tool = f"tool_{token}"
        finding.detector_id = f"rule_{token}"
        _finding(db_session, scan, path=f"src/prefix_{token}/issue.py")
    _finding(db_session, scan, path="src/ordinary.py")
    db_session.flush()

    response = client.get(f"/api/v1/scans/{scan.id}/report/sarif")
    assert response.status_code == 200, response.text
    assert all(token not in response.text for token in tokens)
    results = response.json()["runs"][0]["results"]
    assert len(results) == 4
    assert sum("REDACTED" in result["ruleId"] for result in results) == 3
    assert sum("REDACTED" in result["message"]["text"] for result in results) == 3
    uris = {
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for result in results
    }
    assert uris == {"src/safe-0.py", "src/safe-1.py", "src/safe-2.py", "src/ordinary.py"}


def test_sarif_redacts_non_github_secrets_embedded_after_underscores(client, db_session):
    # Canonical word-boundary redaction misses these known credential families
    # when an underscore directly precedes the token or credential field.
    scan = _scan(db_session)
    tokens = [
        "sk-" + "S" * 20,
        "sk-or-v1-" + "V" * 20,
        "hf_" + "H" * 20,
        "gsk_" + "G" * 20,
        "nvapi-" + "N" * 20,
        "cfut_" + "F" * 20,
        "cohere_" + "C" * 20,
        "AIza" + "A" * 24,
        "eyJ" + "A" * 12 + ".eyJ" + "B" * 12 + "." + "C" * 12,
        "Bearer " + "D" * 20,
        'api_key="syntheticvalue123"',
    ]
    for index, token in enumerate(tokens):
        finding = _finding(
            db_session, scan,
            title=f"Finding prefix_{token}",
            description=f"Detector prefix_{token}",
            path=f"src/safe-{index}.py",
        )
        finding.source_tool = f"tool_{token}"
        finding.detector_id = f"rule_{token}"
        _finding(db_session, scan, path=f"src/prefix_{token}/issue.py")
    _finding(db_session, scan, path="src/ordinary.py")
    db_session.flush()

    response = client.get(f"/api/v1/scans/{scan.id}/report/sarif")
    assert response.status_code == 200, response.text
    assert all(token not in response.text for token in tokens)
    results = response.json()["runs"][0]["results"]
    assert len(results) == len(tokens) + 1
    assert sum("REDACTED" in result["ruleId"] for result in results) == len(tokens)
    assert sum("REDACTED" in result["message"]["text"] for result in results) == len(tokens)
    uris = {
        location["physicalLocation"]["artifactLocation"]["uri"]
        for result in results for location in result["locations"]
    }
    assert uris == {"src/ordinary.py"} | {
        f"src/safe-{index}.py" for index in range(len(tokens))
    }


def test_sarif_omits_secret_bearing_paths_without_leaking_credentials(client, db_session):
    scan = _scan(db_session)
    tokens = ["ghp_" + "Z" * 36, "sk-" + "D" * 20]
    for token in tokens:
        _finding(db_session, scan, path=f"src/{token}/issue.py")
    _finding(db_session, scan, path="src/safe.py")

    response = client.get(f"/api/v1/scans/{scan.id}/report/sarif")
    assert response.status_code == 200, response.text
    assert all(token not in response.text for token in tokens)
    results = response.json()["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/safe.py"



def test_sarif_redacts_structured_secrets_concatenated_to_identifier_text(client, db_session):
    # Word-boundary detection misses a token directly following a letter.
    # No repository source is executed; these credentials are synthetic.
    scan = _scan(db_session)
    tokens = ["sk-" + "S" * 20, "hf_" + "H" * 20]
    for index, token in enumerate(tokens):
        finding = _finding(
            db_session, scan,
            title=f"Finding prefix{token}",
            description=f"Detector prefix{token}",
            path=f"src/safe-{index}.py",
        )
        finding.source_tool = f"toolprefix{token}"
        finding.detector_id = f"ruleprefix{token}"
        _finding(db_session, scan, path=f"src/prefix{token}/issue.py")
    _finding(db_session, scan, path="src/ordinary.py")
    db_session.flush()

    response = client.get(f"/api/v1/scans/{scan.id}/report/sarif")
    assert response.status_code == 200, response.text
    assert all(token not in response.text for token in tokens)
    results = response.json()["runs"][0]["results"]
    assert len(results) == len(tokens) + 1
    assert sum("REDACTED" in result["ruleId"] for result in results) == len(tokens)
    assert sum("REDACTED" in result["message"]["text"] for result in results) == len(tokens)
    uris = {
        location["physicalLocation"]["artifactLocation"]["uri"]
        for result in results for location in result["locations"]
    }
    assert uris == {"src/ordinary.py", "src/safe-0.py", "src/safe-1.py"}


def test_sarif_redacts_complete_bearer_values_in_assignments(client, db_session):
    # Regression: matching only "Credential: Bearer" left the actual token exposed.
    scan = _scan(db_session)
    assignments = [
        "Credential: Bearer abcdefghijklmnopqrstuvwxyz",
        "authorization=Bearer syntheticauthvalue123",
        "access_token: Bearer syntheticaccessvalue456",
    ]
    for index, assignment in enumerate(assignments):
        finding = _finding(
            db_session, scan, title=f"Finding {assignment}",
            description=f"Detector {assignment}", path=f"src/safe-{index}.py",
        )
        finding.source_tool = f"tool_{assignment}"
        finding.detector_id = f"rule_{assignment}"
        _finding(db_session, scan, path=f"src/prefix_{assignment}/issue.py")
    db_session.flush()

    response = client.get(f"/api/v1/scans/{scan.id}/report/sarif")
    assert response.status_code == 200, response.text
    for secret in ("abcdefghijklmnopqrstuvwxyz", "syntheticauthvalue123", "syntheticaccessvalue456"):
        assert secret not in response.text
    results = response.json()["runs"][0]["results"]
    assert len(results) == len(assignments)
    assert all("REDACTED" in result["ruleId"] for result in results)
    assert all("REDACTED" in result["message"]["text"] for result in results)
    uris = {
        location["physicalLocation"]["artifactLocation"]["uri"]
        for result in results for location in result["locations"]
    }
    assert uris == {f"src/safe-{index}.py" for index in range(len(assignments))}



def test_sarif_redacts_complete_bearer_tokens_with_b64token_punctuation(client, db_session):
    # RFC 6750 bearer tokens may include +, /, ~ and = padding.
    # Redacting only the alphanumeric prefix would expose a credential suffix.
    scan = _scan(db_session)
    tokens = [
        "Bearer ABCDEFGHIJKLM+NOPQRSTUVWXYZ/12345==",
        "Bearer ABCDEFGHIJKLM~QRSTUVWXYZ12345",
    ]
    for index, token in enumerate(tokens):
        finding = _finding(
            db_session, scan, title=f"Finding {token}",
            description=f"Detector {token}", path=f"src/safe-{index}.py",
        )
        finding.source_tool = f"tool_{token}"
        finding.detector_id = f"rule_{token}"
        _finding(db_session, scan, path=f"src/prefix_{token}/issue.py")
    db_session.flush()

    response = client.get(f"/api/v1/scans/{scan.id}/report/sarif")
    assert response.status_code == 200, response.text
    for suffix in ("NOPQRSTUVWXYZ/12345==", "QRSTUVWXYZ12345"):
        assert suffix not in response.text
    results = response.json()["runs"][0]["results"]
    assert len(results) == len(tokens)
    assert all("REDACTED" in result["ruleId"] for result in results)
    assert all("REDACTED" in result["message"]["text"] for result in results)
    uris = {
        location["physicalLocation"]["artifactLocation"]["uri"]
        for result in results for location in result["locations"]
    }
    assert uris == {"src/safe-0.py", "src/safe-1.py"}



def test_sarif_redacts_basic_authorization_credentials(client, db_session):
    # HTTP Basic carries base64-encoded credentials, not ordinary public metadata.
    # Keep the synthetic credential out of text, rule IDs, and artifact paths.
    scan = _scan(db_session)
    credential = "c3ludGhldGljLXVzZXI6c3ludGhldGljLXBhc3M="
    assignments = [
        f"Authorization: Basic {credential}",
        f"authorization=Basic {credential}",
        f"AUTHORIZATION: BASIC {credential}",
        # Even very short base64 credentials are valid HTTP Basic credentials.
        "Authorization: Basic YTpi",
        "authorization=Basic dTo=",
        "Authorization: Basic Og==",
    ]
    for index, assignment in enumerate(assignments):
        finding = _finding(
            db_session, scan, title=f"Finding {assignment}",
            description=f"Detector {assignment}", path=f"src/safe-{index}.py",
        )
        finding.source_tool = f"tool_{assignment}"
        finding.detector_id = f"rule_{assignment}"
        _finding(db_session, scan, path=f"src/prefix_{assignment}/issue.py")
    db_session.flush()

    response = client.get(f"/api/v1/scans/{scan.id}/report/sarif")
    assert response.status_code == 200, response.text
    assert credential not in response.text
    assert all(secret not in response.text for secret in ("YTpi", "dTo=", "Og=="))
    # Ordinary prose must not be mistaken for an HTTP Basic credential.
    assert sarif._redact_export_text("Basic information about scanning") == "Basic information about scanning"
    results = response.json()["runs"][0]["results"]
    assert len(results) == len(assignments)
    assert all("REDACTED" in result["ruleId"] for result in results)
    assert all("REDACTED" in result["message"]["text"] for result in results)
    uris = {
        location["physicalLocation"]["artifactLocation"]["uri"]
        for result in results for location in result["locations"]
    }
    assert uris == {f"src/safe-{index}.py" for index in range(len(assignments))}


def test_sarif_redacts_unquoted_credential_assignments(client, db_session):
    # Unquoted credential values can be embedded after an identifier underscore.
    # These synthetic assignments must not escape into SARIF text or artifact URIs.
    scan = _scan(db_session)
    assignments = [
        "api_key=syntheticvalue123",
        "password=syntheticvalue123",
        "auth_token=syntheticvalue123",
        "access_token=syntheticvalue123",
        "refresh_token=syntheticvalue123",
        "authorization=syntheticvalue123",
        "password=p@ssword!123",
        "api_key=@synthetic!value",
        "token=syntheticvalue123",
        "secret_key=syntheticvalue123",
        "private_key=syntheticvalue123",
        "credential=syntheticvalue123",
        "passwd=syntheticvalue123",
        "AWS_SECRET_ACCESS_KEY=syntheticvalue123",
        "aws-secret-access-key=syntheticvalue123",
        'password="synthetic phrase 123"',
        "api_key='synthetic phrase 123'",
        'password:"synthetic phrase colon"',
        "api_key:'synthetic phrase colon'",
        'password="synthetic\\"phrasevalue"',
        "api_key='synthetic\\'secretpart'",
    ]
    for index, assignment in enumerate(assignments):
        finding = _finding(
            db_session, scan,
            title=f"Finding prefix_{assignment}",
            description=f"Detector prefix_{assignment}",
            path=f"src/safe-{index}.py",
        )
        finding.source_tool = f"tool_{assignment}"
        finding.detector_id = f"rule_{assignment}"
        _finding(db_session, scan, path=f"src/prefix_{assignment}/issue.py")
    _finding(db_session, scan, path="src/ordinary.py")
    db_session.flush()

    response = client.get(f"/api/v1/scans/{scan.id}/report/sarif")
    assert response.status_code == 200, response.text
    assert all(assignment not in response.text for assignment in assignments)
    # A partial quoted match must not expose the suffix after an escaped quote.
    assert "synthetic phrase colon" not in response.text
    assert "phrasevalue" not in response.text
    assert "secretpart" not in response.text
    results = response.json()["runs"][0]["results"]
    assert len(results) == len(assignments) + 1
    assert sum("REDACTED" in result["ruleId"] for result in results) == len(assignments)
    assert sum("REDACTED" in result["message"]["text"] for result in results) == len(assignments)
    uris = {
        location["physicalLocation"]["artifactLocation"]["uri"]
        for result in results for location in result["locations"]
    }
    assert uris == {"src/ordinary.py"} | {
        f"src/safe-{index}.py" for index in range(len(assignments))
    }

def test_sarif_redacts_short_credential_assignments_in_all_export_fields(client, db_session):
    # Explicit credential assignments can contain valid values shorter than six
    # characters. Redact them even when canonical redaction does not recognize them.
    scan = _scan(db_session)
    assignments = ['password="abc"', "api_key='xy'", "auth_token=xyz", "secret=x"]
    for index, assignment in enumerate(assignments):
        finding = _finding(
            db_session, scan, title=f"Finding {assignment}",
            description=f"Detector {assignment}", path=f"src/safe-{index}.py",
        )
        finding.source_tool = f"tool_{assignment}"
        finding.detector_id = f"rule_{assignment}"
        _finding(db_session, scan, path=f"src/unsafe_{assignment}/issue.py")
    db_session.flush()

    response = client.get(f"/api/v1/scans/{scan.id}/report/sarif")
    assert response.status_code == 200, response.text
    run = response.json()["runs"][0]
    results = run["results"]
    assert len(results) == len(assignments)
    assert all("REDACTED" in result["ruleId"] for result in results)
    assert all("REDACTED" in result["message"]["text"] for result in results)
    assert all("REDACTED" in rule["shortDescription"]["text"] for rule in run["tool"]["driver"]["rules"])
    uris = {
        location["physicalLocation"]["artifactLocation"]["uri"]
        for result in results for location in result["locations"]
    }
    assert uris == {f"src/safe-{index}.py" for index in range(len(assignments))}
    assert sarif._redact_export_text("Password policy is configured") == "Password policy is configured"
