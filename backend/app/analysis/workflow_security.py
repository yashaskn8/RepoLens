"""Passive, bounded GitHub Actions workflow security inspection.

This analyzer never executes repository code, fetches actions, or evaluates YAML
expressions. It reports only source-attested checks; unsupported YAML semantics
remain outside its documented coverage.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

from app.analysis.schemas import ScannerResult, StaticFinding, ToolStatus
from app.schemas.enums import Severity
from app.schemas.evidence import Evidence

MAX_WORKFLOW_FILES = 64
MAX_WORKFLOW_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024
MAX_DIRECTORY_ENTRIES = 512
MAX_FINDINGS = 256
_SHA40 = re.compile(r"[0-9a-fA-F]{40}\Z")
_SHA256 = re.compile(r"sha256:[0-9a-fA-F]{64}\Z")
_USES = re.compile(r"^\s*(?:-\s*)?uses\s*:\s*(.*?)\s*$")
_BLOCK_START = re.compile(r"^(?P<indent>\s*)(?:-\s*)?[^:#\s][^:]*:\s*[|>][-+0-9]*\s*(?:#.*)?$")
_WRITE_ALL = re.compile(r"^\s*permissions\s*:\s*['\"]?write-all['\"]?\s*(?:#.*)?$")
_PR_TARGET = re.compile(r"^\s*(?:['\"]?on['\"]?\s*:\s*.*\bpull_request_target\b|['\"]?pull_request_target['\"]?\s*:)")
_HEAD_SHA = re.compile(r"^\s*ref\s*:\s*['\"]?\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)\s*\}\}")


class WorkflowInspectionIncomplete(Exception):
    """Source coverage is incomplete; callers must not report a clean scan."""


def _workflow_contents(repo_dir: str) -> list[tuple[str, str]]:
    root = Path(repo_dir)
    if root.is_symlink() or not root.is_dir():
        raise WorkflowInspectionIncomplete("Repository root is not a safe directory.")
    workflows = root
    for segment in (".github", "workflows"):
        workflows = workflows / segment
        if workflows.is_symlink():
            raise WorkflowInspectionIncomplete("Workflow directory link is unsupported.")
        if not workflows.exists():
            return []
        if not workflows.is_dir():
            raise WorkflowInspectionIncomplete("Workflow path is not a directory.")

    try:
        with os.scandir(workflows) as scan:
            entries = []
            for entry in scan:
                if len(entries) >= MAX_DIRECTORY_ENTRIES:
                    raise WorkflowInspectionIncomplete("Workflow directory entry limit exceeded.")
                entries.append(entry)
        paths = sorted(
            (entry for entry in entries if entry.name.lower().endswith((".yml", ".yaml"))),
            key=lambda entry: entry.name,
        )
        if len(paths) > MAX_WORKFLOW_FILES:
            raise WorkflowInspectionIncomplete("Workflow file limit exceeded.")
        contents: list[tuple[str, str]] = []
        total_bytes = 0
        for entry in paths:
            if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                raise WorkflowInspectionIncomplete("Workflow source is not a regular file.")
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            try:
                fd = os.open(entry.path, flags)
            except OSError as exc:
                raise WorkflowInspectionIncomplete("Workflow source could not be opened.") from exc
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_WORKFLOW_BYTES:
                    raise WorkflowInspectionIncomplete("Workflow source is unsafe or too large.")
                data = stream.read(MAX_WORKFLOW_BYTES + 1)
            if len(data) > MAX_WORKFLOW_BYTES:
                raise WorkflowInspectionIncomplete("Workflow source exceeds its byte limit.")
            total_bytes += len(data)
            if total_bytes > MAX_TOTAL_BYTES:
                raise WorkflowInspectionIncomplete("Total workflow byte limit exceeded.")
            try:
                source = data.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise WorkflowInspectionIncomplete("Workflow source is not valid UTF-8.") from exc
            if "\x00" in source:
                raise WorkflowInspectionIncomplete("Workflow source contains NUL bytes.")
            contents.append((f".github/workflows/{entry.name}", source))
        return contents
    except OSError as exc:
        raise WorkflowInspectionIncomplete("Workflow directory could not be inspected.") from exc


def _finding(path: str, line: int, rule: str, title: str, description: str,
             severity: Severity, mitigation: str, *, confidence: str = "HIGH") -> StaticFinding:
    return StaticFinding(
        tool="repolens-workflow-security", rule_id=rule, title=title,
        description=description, severity=severity, category="misconfiguration",
        evidence=Evidence(
            file_path=path, start_line=line, end_line=line,
            context_notes="passive_workflow_inspection=true; no_actions_executed=true",
        ),
        mitigation=mitigation, confidence=confidence,
        source_tool="repolens-workflow-security", detector_id=rule,
        detector_kind="static_scanner", raw_details={"workflow_rule": rule},
    )


def _has_privileged_pr_trigger(lines: list[str]) -> bool:
    """Recognize pull_request_target only in the top-level event declaration.

    This is conservative source inspection, not a complete YAML interpreter.
    """
    in_event_block = False
    for raw in lines:
        cleaned = raw.split(" #", 1)[0]
        stripped = cleaned.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent == 0:
            in_event_block = False
            event = re.match(r"^(?:on|'on'|\"on\")\s*:\s*(.*)$", stripped)
            if event is None:
                continue
            inline = event.group(1)
            if inline:
                if re.search(r"\bpull_request_target\b", inline):
                    return True
            else:
                in_event_block = True
        elif in_event_block and re.match(r"^(?:pull_request_target\s*:|-\s*pull_request_target\s*$)", stripped):
            return True
    return False


def _inspect_source(path: str, source: str) -> list[StaticFinding]:
    findings: list[StaticFinding] = []
    lines = source.splitlines()
    pull_request_target = _has_privileged_pr_trigger(lines)
    # A PR-head ref must be inside the same checkout step. An unrelated ref
    # elsewhere in the workflow is not enough evidence for this finding.
    checkout_step_indent: int | None = None
    block_indent: int | None = None
    for index, raw_line in enumerate(lines, 1):
        indentation = len(raw_line) - len(raw_line.lstrip(" "))
        if block_indent is not None:
            if not raw_line.strip() or indentation > block_indent:
                continue
            block_indent = None
        if block := _BLOCK_START.match(raw_line):
            block_indent = len(block.group("indent"))
            continue
        line = raw_line.split(" #", 1)[0]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if checkout_step_indent is not None and indentation <= checkout_step_indent:
            checkout_step_indent = None
        if pull_request_target and checkout_step_indent is not None and indentation > checkout_step_indent and _HEAD_SHA.search(line):
            findings.append(_finding(
                path, index, "github-actions.privileged-untrusted-checkout",
                "Privileged workflow may check out pull-request code",
                "A pull_request_target workflow checks out a pull-request head in the same action step. This is a contextual risk, not proof of untrusted code execution.",
                Severity.MEDIUM,
                "Do not check out PR-head code in privileged workflows; isolate privileged operations from untrusted code.",
                confidence="MEDIUM",
            ))
        if _WRITE_ALL.fullmatch(raw_line):
            findings.append(_finding(
                path, index, "github-actions.write-all-token",
                "GitHub Actions grants broad write permissions",
                "A workflow explicitly requests write-all token permissions.",
                Severity.HIGH,
                "Declare only the read/write token scopes required by each job.",
            ))
        match = _USES.match(line)
        if match is None:
            continue
        action = match.group(1).strip().strip("\"'")
        if action.startswith("./"):
            continue
        if action.startswith("docker://"):
            image_ref = action.split("@", 1)
            immutable = len(image_ref) == 2 and bool(_SHA256.fullmatch(image_ref[1]))
        elif "$" + "{{" in action:
            continue
        else:
            action_parts = action.rsplit("@", 1)
            if len(action_parts) != 2 or "/" not in action_parts[0]:
                continue
            immutable = bool(_SHA40.fullmatch(action_parts[1]))
            if action_parts[0].lower() == "actions/checkout" and line.lstrip().startswith("-"):
                checkout_step_indent = indentation
        if not immutable:
            findings.append(_finding(
                path, index, "github-actions.mutable-action-reference",
                "Workflow uses a mutable action reference",
                "An external action is not pinned to an immutable commit SHA or container digest.",
                Severity.MEDIUM,
                "Pin remote GitHub Actions to their full 40-character commit SHA and container images to a sha256 digest.",
            ))


def analyze_workflow_repository(repo_dir: str) -> ScannerResult:
    """Return evidence-backed findings or a truthful incomplete-coverage status."""
    try:
        files = _workflow_contents(repo_dir)
        findings: list[StaticFinding] = []
        for path, source in files:
            findings.extend(_inspect_source(path, source))
            if len(findings) > MAX_FINDINGS:
                raise WorkflowInspectionIncomplete("Workflow finding limit exceeded.")
    except WorkflowInspectionIncomplete as exc:
        return ScannerResult(
            tool="repolens-workflow-security", status=ToolStatus.INVALID_OUTPUT,
            error_message=str(exc),
        )
    return ScannerResult(
        tool="repolens-workflow-security", status=ToolStatus.COMPLETED,
        findings=sorted(findings, key=lambda finding: (
            finding.evidence.file_path, finding.evidence.start_line or 0,
            finding.detector_id or "",
        )),
    )


__all__ = ["analyze_workflow_repository"]
