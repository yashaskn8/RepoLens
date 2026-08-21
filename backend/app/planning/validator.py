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
    # Rule 2: No Invented Files (All Targeted Files Must Actually Exist)
    # =========================================================================
    repo_files: Set[str] = set()
    if manifest:
        repo_files.update(f.path.replace("\\", "/").lstrip("/") for f in manifest.files)
    if context_bundle:
        repo_files.update(c.chunk.file_path.replace("\\", "/").lstrip("/") for c in context_bundle.relevant_chunks)

    all_targeted_files = set(f.replace("\\", "/").lstrip("/") for f in plan.files_expected_to_change)
    for step in plan.ordered_changes:
        all_targeted_files.add(step.target_file.replace("\\", "/").lstrip("/") )

    if repo_files:
        for target_f in all_targeted_files:
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
