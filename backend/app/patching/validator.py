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
    # Rule 2 & 3: Fabricated File Paths & FixPlan Scope Confinement
    # =========================================================================
    parsed_files = parse_diff_files(diff_text)
    known_repo_files: Set[str] = set()

    if repo_files:
        known_repo_files.update(f.replace("\\", "/").lstrip("/") for f in repo_files)
    if manifest:
        known_repo_files.update(f.path.replace("\\", "/").lstrip("/") for f in manifest.files)

    allowed_plan_files: Set[str] = set()
    if fix_plan:
        allowed_plan_files = set(f.replace("\\", "/").lstrip("/") for f in fix_plan.files_expected_to_change)
        for step in fix_plan.ordered_changes:
            allowed_plan_files.add(step.target_file.replace("\\", "/").lstrip("/"))

    if known_repo_files:
        for f in parsed_files:
            if f not in known_repo_files and f not in allowed_plan_files:
                rejection_reasons.append(
                    f"Patch modifies fabricated file not present in repository: '{f}'"
                )

    if fix_plan:
        for f in parsed_files:
            if f not in allowed_plan_files:
                rejection_reasons.append(
                    f"Patch modifies unauthorized file '{f}' outside approved FixPlan. "
                    f"Approved files: {sorted(list(allowed_plan_files))}"
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
