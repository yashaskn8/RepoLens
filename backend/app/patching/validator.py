"""Deterministic unified diff parser and patch boundary validator."""

import re
from typing import List, Optional, Set, Tuple

from app.ingestion.schemas import RepositoryManifest
from app.patching.schemas import (
    PatchProposal,
    PatchValidationReport,
    PatchValidationStatus,
)
from app.planning.schemas import FixPlan


def parse_diff_files(unified_diff: str) -> List[str]:
    """Extract normalized relative file paths modified in a unified diff string."""
    files: List[str] = []
    lines = unified_diff.split("\n")

    for line in lines:
        if line.startswith("+++ "):
            # Match +++ b/path/to/file or +++ path/to/file
            target = line[4:].strip()
            if target.startswith("b/"):
                target = target[2:]
            clean = target.replace("\\", "/").lstrip("/")
            if clean and clean != "/dev/null" and clean not in files:
                files.append(clean)

    return files


def validate_patch_proposal(
    proposal: PatchProposal,
    fix_plan: Optional[FixPlan] = None,
    manifest: Optional[RepositoryManifest] = None,
    repo_files: Optional[Set[str]] = None,
) -> PatchValidationReport:
    """Rigorously validate unified diff syntax, repository file boundaries, and FixPlan constraints."""
    rejection_reasons: List[str] = []
    diff_text = proposal.unified_diff.strip()

    # =========================================================================
    # Rule 1: Non-Empty Diff & Basic Header Structure
    # =========================================================================
    if not diff_text:
        rejection_reasons.append("Patch proposal contains an empty unified diff.")
        return PatchValidationReport(
            status=PatchValidationStatus.REJECTED,
            is_valid=False,
            rejection_reasons=rejection_reasons,
        )

    # Check for presence of essential unified diff markers
    has_orig_header = bool(re.search(r"^--- (a/|\S+)", diff_text, re.MULTILINE))
    has_new_header = bool(re.search(r"^\+\+\+ (b/|\S+)", diff_text, re.MULTILINE))
    has_hunk_header = bool(re.search(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@", diff_text, re.MULTILINE))

    if not (has_orig_header and has_new_header and has_hunk_header):
        rejection_reasons.append(
            "Malformed unified diff: must contain valid '---', '+++', and '@@ -start,count +start,count @@' headers."
        )

    # Count hunks and change lines
    hunk_matches = re.findall(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@", diff_text, re.MULTILINE)
    hunks_count = len(hunk_matches)

    change_lines = [l for l in diff_text.split("\n") if (l.startswith("+") or l.startswith("-")) and not (l.startswith("+++") or l.startswith("---"))]
    if not change_lines:
        rejection_reasons.append("Malformed diff: contains headers but no actual line additions (+) or deletions (-).")

    # =========================================================================
    # Rule 2 & 3: Repository evidence and exact FixPlan authority
    # =========================================================================
    parsed_files = parse_diff_files(diff_text)
    known_repo_files: Set[str] = set()
    if repo_files is not None:
        known_repo_files.update(f.replace("\\", "/") for f in repo_files)
    if manifest is not None:
        known_repo_files.update(f.path.replace("\\", "/") for f in manifest.files)

    if fix_plan is not None:
        if proposal.finding_id != fix_plan.finding_id:
            rejection_reasons.append("Patch proposal targets a different finding than its FixPlan.")
        if proposal.plan_id != fix_plan.id:
            rejection_reasons.append("Patch proposal references a different FixPlan.")
        if fix_plan.validation_report is not None and not fix_plan.validation_report.is_valid:
            rejection_reasons.append("Patch proposal references a rejected FixPlan.")

    # Target files are approved exclusively by the declared plan scope. Step
    # targets cannot silently enlarge it.
    allowed_plan_files: Set[str] = (
        {f.replace("\\", "/") for f in fix_plan.files_expected_to_change}
        if fix_plan is not None else set()
    )

    # Both old and new diff headers are attack-controlled. A legitimate new
    # target cannot conceal an unrelated or absolute source-file edit.
    header_files: Set[str] = set()
    for line in diff_text.splitlines():
        if not (line.startswith("--- ") or line.startswith("+++ ")):
            continue
        raw_path = line[4:].split("\t", 1)[0].strip()
        if raw_path == "/dev/null":
            continue
        if raw_path.startswith(("a/", "b/")):
            raw_path = raw_path[2:]
        normalized = raw_path.replace("\\", "/")
        if (
            not normalized
            or normalized.startswith("/")
            or re.match(r"^[A-Za-z]:", normalized)
            or any(part in {"", ".", ".."} for part in normalized.split("/"))
            or any(ord(char) < 32 or ord(char) == 127 for char in normalized)
        ):
            rejection_reasons.append("Patch diff header contains an unsafe file path.")
            continue
        header_files.add(normalized)

    if set(proposal.files_modified) != set(parsed_files):
        rejection_reasons.append("Patch files_modified do not match the actual diff targets.")

    if not parsed_files:
        rejection_reasons.append("Patch diff does not identify a modified repository file.")

    for path in sorted(header_files | set(parsed_files)):
        if fix_plan is not None and path not in allowed_plan_files:
            rejection_reasons.append(
                f"Patch modifies unauthorized file '{path}' outside approved FixPlan."
            )
        if (repo_files is not None or manifest is not None) and path not in known_repo_files:
            rejection_reasons.append(
                f"Patch modifies fabricated file not present in repository: '{path}'"
            )


    is_valid = len(rejection_reasons) == 0
    status = PatchValidationStatus.VALID if is_valid else PatchValidationStatus.REJECTED

    return PatchValidationReport(
        status=status,
        is_valid=is_valid,
        rejection_reasons=rejection_reasons,
        parsed_files=parsed_files,
        hunks_count=hunks_count,
    )
