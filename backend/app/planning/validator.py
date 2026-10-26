"""Deterministic validation rules rejecting invalid, invented, or overreaching fix plans."""

import re
from typing import List, Optional, Set

from app.context.schemas import ContextBundle
from app.graph.repository_graph import RepositoryGraph
from app.ingestion.schemas import RepositoryManifest
from app.planning.schemas import (
    FixPlan,
    PlanValidationReport,
    PlanValidationStatus,
)
from app.schemas.enums import FindingStatus, VerificationVerdict
from app.schemas.finding import Finding

# Forbidden anti-patterns in remediation planning
_ALIAS_WORKAROUND_PATTERNS = [
    r"add alias route",
    r"create alias endpoint",
    r"add route alias",
    r"add compatibility shim route",
    r"duplicate route to match",
    r"duplicate endpoint to hide",
    r"hide contract mismatch with alias",
    r"add alias to hide",
]


def validate_fix_plan(
    plan: FixPlan,
    finding: Finding,
    manifest: Optional[RepositoryManifest] = None,
    context_bundle: Optional[ContextBundle] = None,
    repository_graph: Optional[RepositoryGraph] = None,
) -> PlanValidationReport:
    """Rigorously validate a FixPlan against real repository evidence and deterministic rejection rules."""
    rejection_reasons: List[str] = []
    validated_files: List[str] = []
    validated_symbols: List[str] = []

    # =========================================================================
    # Rule 1: Strict Remediation Eligibility: Only CONFIRMED Findings Allowed
    # =========================================================================
    if finding.verification_verdict != VerificationVerdict.CONFIRMED:
        verdict_str = finding.verification_verdict.value if finding.verification_verdict else "NONE"
        rejection_reasons.append(
            f"Fix planning rejected: finding '{finding.id}' is not eligible for remediation planning. "
            f"Only findings with verification_verdict == CONFIRMED may produce a FixPlan "
            f"(current verdict: '{verdict_str}')."
        )

    # =========================================================================
    # Rule 2: Bind this plan to its selected finding and exact approved file set
    # =========================================================================
    if plan.finding_id != finding.id:
        rejection_reasons.append("Fix plan finding_id does not match the selected finding.")

    step_numbers = [step.step_number for step in plan.ordered_changes]
    if step_numbers != list(range(1, len(step_numbers) + 1)):
        rejection_reasons.append("Fix plan steps must be numbered consecutively from 1.")

    def safe_repo_path(raw: str) -> Optional[str]:
        # Never convert absolute/traversal paths into apparently valid repo paths.
        path = raw.replace("\\", "/")
        components = path.split("/")
        if (
            not path
            or path.startswith("/")
            or re.match(r"^[A-Za-z]:", path)
            or any(part in {"", ".", ".."} for part in components)
            or any(ord(char) < 32 or ord(char) == 127 for char in path)
        ):
            return None
        return path

    declared_files: Set[str] = set()
    all_targeted_files: Set[str] = set()
    for target in plan.files_expected_to_change:
        path = safe_repo_path(target)
        if path is None:
            rejection_reasons.append("Fix plan contains an unsafe target file path.")
        else:
            declared_files.add(path)
            all_targeted_files.add(path)

    for step in plan.ordered_changes:
        path = safe_repo_path(step.target_file)
        if path is None:
            rejection_reasons.append("Fix plan step contains an unsafe target file path.")
        elif path not in declared_files:
            rejection_reasons.append(
                f"Fix plan step modifies undeclared file '{path}'."
            )
        else:
            all_targeted_files.add(path)

    # Repository manifest is authoritative when supplied; retrieved context
    # must not augment its membership with stale/invented filenames.
    repo_files: Set[str] = set()
    if manifest is not None:
        repo_files.update(
            normalized
            for entry in manifest.files
            if (normalized := safe_repo_path(entry.path)) is not None
        )
    elif context_bundle is not None:
        repo_files.update(
            normalized
            for entry in context_bundle.relevant_chunks
            if (normalized := safe_repo_path(entry.chunk.file_path)) is not None
        )

    if not repo_files:
        rejection_reasons.append(
            "Fix plan cannot verify targeted files without repository source evidence."
        )
    else:
        for target_f in sorted(all_targeted_files):
            if target_f not in repo_files:
                rejection_reasons.append(
                    f"Plan references invented file not present in repository: '{target_f}'"
                )
            else:
                validated_files.append(target_f)

    # =========================================================================
    # Rule 3: No Alias Workarounds Hiding Contract Mismatches
    # =========================================================================
    combined_plan_text = " ".join([
        plan.objective,
        plan.root_cause,
        " ".join(s.description for s in plan.ordered_changes),
        " ".join(s.rationale for s in plan.ordered_changes),
    ]).lower()

    for pattern in _ALIAS_WORKAROUND_PATTERNS:
        if re.search(pattern, combined_plan_text):
            rejection_reasons.append(
                f"Plan rejected: detected forbidden alias workaround pattern ('{pattern}'). "
                "Must fix the mismatching route handler or client request directly."
            )
            break

    # =========================================================================
    # Rule 4: No Code Generation in Planning Stage
    # =========================================================================
    # Check for raw fenced code blocks or extensive code implementation in plan descriptions
    for step in plan.ordered_changes:
        if "```" in step.description or len(step.description.split("\n")) > 15:
            rejection_reasons.append(
                f"Plan step {step.step_number} contains raw code blocks. "
                "FixPlanner must define structured objectives without generating patches."
            )
            break

    # =========================================================================
    # Rule 5: Non-Empty Changes and Validation Plan
    # =========================================================================
    if not plan.ordered_changes:
        rejection_reasons.append("Plan must contain at least one ordered change step.")
    if not plan.validation_plan:
        rejection_reasons.append("Plan must provide a concrete validation plan.")

    is_valid = len(rejection_reasons) == 0
    status = PlanValidationStatus.VALID if is_valid else PlanValidationStatus.REJECTED

    return PlanValidationReport(
        status=status,
        is_valid=is_valid,
        rejection_reasons=rejection_reasons,
        validated_files=list(set(validated_files)),
        validated_symbols=list(set(validated_symbols)),
    )
