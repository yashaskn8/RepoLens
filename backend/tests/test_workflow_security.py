"""Regression and hostile-input tests for passive workflow risk inspection."""

from pathlib import Path

import pytest

from app.analysis.workflow_security import (
    MAX_WORKFLOW_BYTES,
    MAX_WORKFLOW_FILES,
    analyze_workflow_repository,
)
from app.schemas.enums import Severity
from app.schemas.static_finding import ToolStatus


def _workflow(tmp_path: Path, text: str, name: str = "ci.yml") -> Path:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True, exist_ok=True)
    path = workflows / name
    path.write_text(text, encoding="utf-8")
    return path


def _rules(result):
    return [(finding.detector_id, finding.evidence.start_line) for finding in result.findings]


def test_clean_absent_workflows_is_not_a_failure(tmp_path):
    result = analyze_workflow_repository(str(tmp_path))
    assert result.status is ToolStatus.COMPLETED
    assert result.findings == []


def test_immutable_actions_and_least_privilege_are_clean(tmp_path):
    pinned = "a" * 40
    digest = "b" * 64
    _workflow(tmp_path, f"""on: push
permissions:
  contents: read
jobs:
  test:
    steps:
      - uses: actions/checkout@{pinned}
      - uses: docker://alpine@sha256:{digest}
      - uses: ./local-action
""")
    result = analyze_workflow_repository(str(tmp_path))
    assert result.status is ToolStatus.COMPLETED
    assert not result.findings


def test_mutable_actions_and_write_all_have_file_line_evidence(tmp_path):
    _workflow(tmp_path, """on: push
permissions: write-all
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
""")
    result = analyze_workflow_repository(str(tmp_path))
    assert _rules(result) == [
        ("github-actions.write-all-token", 2),
        ("github-actions.mutable-action-reference", 6),
    ]
    assert result.findings[0].evidence.file_path == ".github/workflows/ci.yml"
    assert result.findings[0].severity is Severity.HIGH
    assert result.findings[1].severity is Severity.MEDIUM


def test_privileged_pr_head_checkout_is_marked_contextual(tmp_path):
    _workflow(tmp_path, """on:
  pull_request_target:
jobs:
  review:
    steps:
      - uses: actions/checkout@""" + "a" * 40 + """
        with:
          ref: ${{ github.event.pull_request.head.sha }}
""")
    result = analyze_workflow_repository(str(tmp_path))
    assert _rules(result) == [
        ("github-actions.privileged-untrusted-checkout", 8),
    ]
    assert result.findings[0].confidence == "MEDIUM"


@pytest.mark.parametrize(
    "event_declaration",
    [
        "'on': [pull_request_target]",
        '"on":\n  "pull_request_target":',
        "'on':\n  'pull_request_target':",
    ],
)
def test_quoted_workflow_triggers_preserve_privileged_checkout_detection(tmp_path, event_declaration):
    source = (
        event_declaration
        + "\njobs:\n  review:\n    steps:\n      - uses: actions/checkout@"
        + "a" * 40
        + "\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
    )
    _workflow(tmp_path, source)
    result = analyze_workflow_repository(str(tmp_path))
    assert result.status is ToolStatus.COMPLETED
    assert [finding.detector_id for finding in result.findings] == [
        "github-actions.privileged-untrusted-checkout"
    ]

def test_non_privileged_pr_checkout_does_not_trigger_contextual_finding(tmp_path):
    _workflow(tmp_path, """on:
  pull_request:
jobs:
  test:
    steps:
      - uses: actions/checkout@""" + "a" * 40 + """
        with:
          ref: ${{ github.event.pull_request.head.sha }}
""")
    assert not analyze_workflow_repository(str(tmp_path)).findings


def test_comments_and_multiline_shell_data_are_not_actions(tmp_path):
    _workflow(tmp_path, """# permissions: write-all
jobs:
  build:
    steps:
      - run: |
          echo "uses: example/unsafe@v1"
          echo "permissions: write-all"
      # - uses: example/unsafe@v1
""")
    assert not analyze_workflow_repository(str(tmp_path)).findings


def test_mutable_docker_image_is_detected(tmp_path):
    _workflow(tmp_path, "jobs:\n  build:\n    steps:\n      - uses: docker://alpine:latest\n")
    assert _rules(analyze_workflow_repository(str(tmp_path))) == [
        ("github-actions.mutable-action-reference", 4)
    ]


def test_workflow_symlink_cannot_be_followed(tmp_path):
    target = tmp_path / "outside.yml"
    target.write_text("permissions: write-all\n")
    workflow = _workflow(tmp_path, "on: push\n")
    workflow.unlink()
    try:
        workflow.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("Filesystem does not support symlinks")
    result = analyze_workflow_repository(str(tmp_path))
    assert result.status is ToolStatus.INVALID_OUTPUT
    assert result.findings == []


def test_directory_symlink_fails_closed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    github = tmp_path / ".github"
    github.mkdir()
    try:
        (github / "workflows").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Filesystem does not support symlinks")
    assert analyze_workflow_repository(str(tmp_path)).status is ToolStatus.INVALID_OUTPUT


def test_oversized_workflow_is_incomplete(tmp_path):
    _workflow(tmp_path, "x" * (MAX_WORKFLOW_BYTES + 1))
    result = analyze_workflow_repository(str(tmp_path))
    assert result.status is ToolStatus.INVALID_OUTPUT
    assert not result.findings


def test_too_many_workflows_is_incomplete(tmp_path):
    for i in range(MAX_WORKFLOW_FILES + 1):
        _workflow(tmp_path, "on: push\n", name=f"{i:03d}.yml")
    assert analyze_workflow_repository(str(tmp_path)).status is ToolStatus.INVALID_OUTPUT


def test_invalid_utf8_is_incomplete(tmp_path):
    path = _workflow(tmp_path, "on: push\n")
    path.write_bytes(b"\xff\xfe")
    assert analyze_workflow_repository(str(tmp_path)).status is ToolStatus.INVALID_OUTPUT


def test_inaccessible_source_is_not_reported_as_clean(tmp_path, monkeypatch):
    _workflow(tmp_path, "permissions: write-all\n")
    import app.analysis.workflow_security as scanner
    def deny_open(*_args, **_kwargs):
        raise PermissionError("deliberately hidden secret")
    monkeypatch.setattr(scanner.os, "open", deny_open)
    result = scanner.analyze_workflow_repository(str(tmp_path))
    assert result.status is ToolStatus.INVALID_OUTPUT
    assert "secret" not in (result.error_message or "")


def test_repository_scripts_are_never_executed(tmp_path):
    marker = tmp_path / "EXECUTED"
    _workflow(tmp_path, f"""jobs:
  build:
    steps:
      - run: |
          echo unsafe > {marker}
          python -c 'raise RuntimeError("should not run")'
      - uses: actions/checkout@v4
""")
    result = analyze_workflow_repository(str(tmp_path))
    assert result.status is ToolStatus.COMPLETED
    assert not marker.exists()
    assert _rules(result) == [("github-actions.mutable-action-reference", 7)]


def test_missing_root_is_incomplete(tmp_path):
    assert analyze_workflow_repository(str(tmp_path / "nonexistent")).status is ToolStatus.INVALID_OUTPUT
