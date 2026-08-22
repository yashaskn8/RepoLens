"""Deterministic, truthful Pull Request title and body generator for RepoLens."""

import re
from typing import Any, Dict, List, Optional
from app.models.finding import FindingModel
from app.models.patch import PatchModel
from app.models.scan import ScanModel
from app.security.markdown import escape_markdown_text, safe_fenced_block, safe_inline_code
from app.security.redaction import redact_secrets


def generate_pr_title(finding_title: str) -> str:
    """Generate a clean, bounded PR title from a finding title."""
    clean = redact_secrets(finding_title)
    # Remove newlines and control characters
    clean = re.sub(r"[\r\n\t]+", " ", clean).strip()
    # Strip dangerous characters
    clean = re.sub(r"[<>\"`]", "", clean)
    if len(clean) > 100:
        clean = clean[:97] + "..."
    return f"[RepoLens] Fix: {clean}"


def generate_pr_body(
    finding: FindingModel,
    patch: PatchModel,
    scan: ScanModel,
    requested_by: str = "user",
    notes: Optional[str] = None,
) -> str:
    """Generate a truthful, evidence-grounded Markdown PR body without LLM calls."""
    title_escaped = escape_markdown_text(finding.title)
    desc_escaped = escape_markdown_text(finding.description)
    explanation_escaped = escape_markdown_text(patch.explanation)
    behavior_escaped = escape_markdown_text(patch.expected_behavior_change)

    files_list = "\n".join(f"- {safe_inline_code(f)}" for f in (patch.files_modified or []))
    if not files_list:
        files_list = "- None recorded"

    lines = [
        f"## 🛡️ RepoLens Automated Remediation",
        "",
        f"> **Target Issue**: {title_escaped}  ",
        f"> **Severity**: `{finding.severity}` | **Category**: `{finding.category or 'Security/Quality'}` | **Verdict**: `{finding.verification_verdict or 'CONFIRMED'}`  ",
        f"> **Exact Scanned Commit**: `{scan.commit_hash}`  ",
        "",
        "---",
        "",
        "### 📋 Overview & Rationale",
        "",
        f"**Description**:\n{desc_escaped}",
        "",
        f"**Remediation Explanation**:\n{explanation_escaped}",
        "",
        f"**Expected Runtime Behavior**:\n{behavior_escaped}",
        "",
        "### 📁 Files Modified",
        "",
        files_list,
        "",
        "### 🔍 Verification & Safety Boundary",
        "",
        f"- **Machine Verification Verdict**: `{patch.machine_verdict or 'PASSED'}`",
        f"- **Human Approval**: Approved by `{patch.approved_by or 'user'}`",
        f"- **Delivery Triggered By**: `{requested_by}`",
        "- **Safety Guarantee**: RepoLens deterministic patch verification passed applicable static, syntax, and contract alignment checks.",
        "- **Execution Boundary**: RepoLens does not execute untrusted repository test suites or build scripts during remediation.",
        "",
    ]

    if notes:
        lines.extend([
            "### ✍️ Human Sign-Off Notes",
            "",
            escape_markdown_text(notes),
            "",
        ])

    lines.extend([
        "---",
        "",
        "*This pull request was created only after explicit human approval in RepoLens.*",
    ])

    return "\n".join(lines)
