"""SARIF must not emit credential-shaped repository paths or rule metadata."""

import json
from types import SimpleNamespace

import pytest

from app.reporting.sarif import build_sarif


COMMIT = "a" * 40
DUMMY_TOKEN = "ghp_" + "A" * 36  # Synthetic test value; not a credential.


def _finding(*, path="src/safe.py", detector_id="python.safe", source_tool="semgrep"):
    return SimpleNamespace(
        status="OPEN",
        source_tool=source_tool,
        detector_id=detector_id,
        rule_id="SAFE-1",
        title="Safe finding",
        description="Verified evidence",
        severity="HIGH",
        evidences=[
            SimpleNamespace(
                file_path=path,
                start_line=3,
                end_line=3,
                code_snippet="safe = True",
            )
        ],
    )


def test_sarif_does_not_export_credential_shaped_repository_path():
    report = build_sarif(
        [_finding(path=f"src/{DUMMY_TOKEN}.py")],
        commit_sha=COMMIT,
    )
    assert report["runs"][0]["results"] == []
    assert DUMMY_TOKEN not in json.dumps(report)


@pytest.mark.parametrize("field", ["detector_id", "source_tool"])
def test_sarif_rule_identifiers_are_opaque_for_credential_shaped_values(field):
    finding = _finding(**{field: DUMMY_TOKEN})
    first = build_sarif([finding], commit_sha=COMMIT)
    second = build_sarif([finding], commit_sha=COMMIT)
    assert first == second
    result = first["runs"][0]["results"][0]
    expected = "unclassified-" if field == "detector_id" else "internal-"
    assert expected in result["ruleId"]
    assert DUMMY_TOKEN not in json.dumps(first)


def test_sarif_keeps_normal_relative_path_and_rule_identifiers():
    report = build_sarif([_finding()], commit_sha=COMMIT)
    result = report["runs"][0]["results"][0]
    assert result["ruleId"] == "repolens/semgrep/python.safe"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/safe.py"
