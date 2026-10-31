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



@pytest.mark.parametrize(
    "source",
    [
        "on: push\nenv:\n  permissions: write-all\n",
        "on: push\njobs:\n  test:\n    env:\n      permissions: write-all\n",
        (
            "on: push\njobs:\n  test:\n    steps:\n"
            "      - name: Inspect\n        env:\n"
            "          permissions: write-all\n        run: echo ok\n"
        ),
        (
            "on: push\njobs:\n  test:\n    steps:\n"
            "      - uses: example/action@" + "a" * 40 + "\n"
            "        with:\n          permissions: write-all\n"
        ),
    ],
)
def test_nested_permissions_key_does_not_grant_token_write_all(tmp_path, source):
    _workflow(tmp_path, source)
    result = analyze_workflow_repository(str(tmp_path))
    assert result.status is ToolStatus.COMPLETED
    assert "github-actions.write-all-token" not in [
        finding.detector_id for finding in result.findings
    ]


def test_job_write_all_still_detected_amid_environment_variables(tmp_path):
    _workflow(tmp_path, """on: push
env:
  permissions: write-all
jobs:
  build:
    permissions: write-all
    env:
      permissions: write-all
    steps:
      - name: Inspect
        env:
          permissions: write-all
        run: echo ok
""")
    result = analyze_workflow_repository(str(tmp_path))
    assert result.status is ToolStatus.COMPLETED
    assert _rules(result) == [("github-actions.write-all-token", 6)]


@pytest.mark.parametrize(
    "source",
    [
        "on: push\nenv:\n  uses: example/action@v1\n",
        (
            "on: push\njobs:\n  build:\n    env:\n"
            "      uses: example/action@v1\n"
            "    steps:\n      - uses: actions/checkout@" + "a" * 40 + "\n"
        ),
        (
            "on: push\njobs:\n  build:\n    steps:\n"
            "      - name: Check\n        uses: actions/checkout@" + "a" * 40 + "\n"
            "        with:\n          uses: example/action@v1\n"
        ),
    ],
)
def test_uses_data_in_env_or_with_is_not_an_action_reference(tmp_path, source):
    _workflow(tmp_path, source)
    result = analyze_workflow_repository(str(tmp_path))
    assert result.status is ToolStatus.COMPLETED
    assert "github-actions.mutable-action-reference" not in [
        finding.detector_id for finding in result.findings
    ]


def test_real_mutable_action_after_env_uses_still_detected(tmp_path):
    _workflow(tmp_path, """on: push
env:
  uses: example/action@v1
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
""")
    result = analyze_workflow_repository(str(tmp_path))
    assert result.status is ToolStatus.COMPLETED
    assert _rules(result) == [("github-actions.mutable-action-reference", 7)]


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


def test_checkout_step_env_ref_is_not_a_checkout_input(tmp_path):
    _workflow(tmp_path, """on:
  pull_request_target:
jobs:
  review:
    steps:
      - uses: actions/checkout@""" + "a" * 40 + """
        env:
          ref: ${{ github.event.pull_request.head.sha }}
""")
    result = analyze_workflow_repository(str(tmp_path))
    assert result.status is ToolStatus.COMPLETED
    assert "github-actions.privileged-untrusted-checkout" not in [
        finding.detector_id for finding in result.findings
    ]


def test_checkout_with_ref_still_warns_after_env_ref(tmp_path):
    _workflow(tmp_path, """on:
  pull_request_target:
jobs:
  review:
    steps:
      - uses: actions/checkout@""" + "a" * 40 + """
        env:
          ref: ${{ github.event.pull_request.head.sha }}
        with:
          ref: ${{ github.event.pull_request.head.sha }}
""")
    result = analyze_workflow_repository(str(tmp_path))
    assert result.status is ToolStatus.COMPLETED
    assert _rules(result) == [("github-actions.privileged-untrusted-checkout", 10)]

def test_named_checkout_step_detects_privileged_pr_head_ref(tmp_path):
    _workflow(tmp_path, (
        "on:\n  pull_request_target:\njobs:\n  review:\n    steps:\n"
        "      - name: Fetch PR head\n        uses: actions/checkout@"
        + "a" * 40
        + "\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
    ))
    result = analyze_workflow_repository(str(tmp_path))
    assert result.status is ToolStatus.COMPLETED
    assert _rules(result) == [("github-actions.privileged-untrusted-checkout", 9)]

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


def test_pr_head_ref_in_another_step_does_not_trigger_checkout_finding(tmp_path):
    _workflow(tmp_path, """on:
  pull_request_target:
jobs:
  review:
    steps:
      - uses: actions/checkout@""" + "a" * 40 + """
      - name: Configure something else
        with:
          ref: ${{ github.event.pull_request.head.sha }}
""")
    result = analyze_workflow_repository(str(tmp_path))
    assert result.status is ToolStatus.COMPLETED
    assert "github-actions.privileged-untrusted-checkout" not in [finding.detector_id for finding in result.findings]


def test_nested_push_branch_named_pull_request_target_is_not_an_event(tmp_path):
    _workflow(tmp_path, """on:
  push:
    branches:
      - pull_request_target
jobs:
  review:
    steps:
      - uses: actions/checkout@""" + "a" * 40 + """
        with:
          ref: ${{ github.event.pull_request.head.sha }}
""")
    result = analyze_workflow_repository(str(tmp_path))
    assert result.status is ToolStatus.COMPLETED
    assert "github-actions.privileged-untrusted-checkout" not in [
        finding.detector_id for finding in result.findings
    ]


def test_sibling_privileged_event_is_not_masked_by_nested_push_filter(tmp_path):
    _workflow(tmp_path, """on:
  push:
    branches:
      - pull_request_target
  pull_request_target:
jobs:
  review:
    steps:
      - uses: actions/checkout@""" + "a" * 40 + """
        with:
          ref: ${{ github.event.pull_request.head.sha }}
""")
    result = analyze_workflow_repository(str(tmp_path))
    assert result.status is ToolStatus.COMPLETED
    assert [finding.detector_id for finding in result.findings] == [
        "github-actions.privileged-untrusted-checkout"
    ]


def test_non_event_pr_target_key_is_not_treated_as_trigger(tmp_path):
    _workflow(tmp_path, """on: push
jobs:
  pull_request_target:
    steps:
      - uses: actions/checkout@""" + "a" * 40 + """
        with:
          ref: ${{ github.event.pull_request.head.sha }}
""")
    result = analyze_workflow_repository(str(tmp_path))
    assert "github-actions.privileged-untrusted-checkout" not in [finding.detector_id for finding in result.findings]


def test_inline_event_list_can_trigger_checkout_warning(tmp_path):
    _workflow(tmp_path, """on: [push, pull_request_target]
jobs:
  review:
    steps:
      - uses: actions/checkout@""" + "a" * 40 + """
        with:
          ref: ${{ github.event.pull_request.head.sha }}
""")
    result = analyze_workflow_repository(str(tmp_path))
    assert ("github-actions.privileged-untrusted-checkout", 7) in _rules(result)


@pytest.mark.asyncio
async def test_findings_flow_through_existing_evidence_store(tmp_path, monkeypatch):
    from app.analysis import service as intelligence_module
    from app.analysis.schemas import ScannerResult
    from app.ingestion.schemas import RepositoryManifest

    _workflow(tmp_path, """on: push
permissions: write-all
jobs:
  review:
    steps:
      - uses: actions/checkout@v4
""")
    manifest = RepositoryManifest(
        repository_url="https://github.com/example/example",
        commit_hash="a" * 40,
    )
    monkeypatch.setattr(intelligence_module, "build_manifest", lambda **kwargs: manifest)
    monkeypatch.setattr(
        intelligence_module, "analyze_core_repository",
        lambda *args: ScannerResult(tool="repolens-core", status=ToolStatus.COMPLETED),
    )
    monkeypatch.setattr(
        intelligence_module, "analyze_supply_chain_repository",
        lambda *args: ScannerResult(tool="chainbrain", status=ToolStatus.COMPLETED),
    )

    class FakeScanner:
        tool_name = "fake"
        async def scan(self, _repo_dir):
            return ScannerResult(tool=self.tool_name, status=ToolStatus.COMPLETED)

    result = await intelligence_module.RepositoryIntelligenceService(
        scanner_adapters=[FakeScanner()]
    ).analyze_repository(
        repo_dir=str(tmp_path),
        repository_url=manifest.repository_url,
        commit_hash=manifest.commit_hash,
    )
    assert result.scanner_results["repolens-workflow-security"].status is ToolStatus.COMPLETED
    assert len(result.get_findings(tool="repolens-workflow-security")) == 2
    assert result.get_summary()["findings_by_tool"]["repolens-workflow-security"] == 2


def test_unreadable_workflow_directory_is_not_a_clean_scan(tmp_path, monkeypatch):
    import app.analysis.workflow_security as scanner

    _workflow(tmp_path, "permissions: write-all\n")
    real_lstat = scanner.os.lstat

    def deny_workflow_dir(path, *args, **kwargs):
        if str(path).replace("\\", "/").endswith("/.github/workflows"):
            raise PermissionError("private file-system details")
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(scanner.os, "lstat", deny_workflow_dir)
    result = scanner.analyze_workflow_repository(str(tmp_path))
    assert result.status is ToolStatus.INVALID_OUTPUT
    assert result.findings == []
    assert "private" not in (result.error_message or "")


def test_windows_reparse_directory_is_rejected(tmp_path, monkeypatch):
    import stat
    from types import SimpleNamespace
    import app.analysis.workflow_security as scanner

    _workflow(tmp_path, "permissions: write-all\n")
    real_lstat = scanner.os.lstat

    def simulate_reparse(path, *args, **kwargs):
        if str(path).replace("\\", "/").endswith("/.github/workflows"):
            return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x0400)
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(scanner.os, "lstat", simulate_reparse)
    result = scanner.analyze_workflow_repository(str(tmp_path))
    assert result.status is ToolStatus.INVALID_OUTPUT
    assert not result.findings
