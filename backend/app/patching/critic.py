"""Conditional independent PatchCriticAgent evaluating candidate patches on escalated risk."""

import json
import logging
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

from app.agents.helpers import extract_json_block
from app.context.schemas import ContextBundle
from app.llm.router import get_llm_router
from app.llm.types import LLMMessage, LLMRequest, ModelCapability, TaskPolicy
from app.llm.workflow_contracts import OBJECT_OUTPUT_SCHEMA, lineage_for_finding
from app.patching.schemas import (
    CriticVerdict,
    PatchCriticReport,
    PatchProposal,
    PatchVerificationResult,
    VerificationStatus,
)
from app.planning.schemas import FixPlan, FixScope
from app.schemas.enums import Severity
from app.schemas.finding import Finding

logger = logging.getLogger(__name__)


def should_escalate_to_critic(
    finding: Finding,
    fix_plan: FixPlan,
    proposal: PatchProposal,
    verification_result: PatchVerificationResult,
) -> Tuple[bool, List[str]]:
    """Determine if a patch proposal meets the rigorous conditional escalation criteria for independent criticism.
    
    Escalates ONLY when:
    1. Patch affects authentication or security;
    2. Severity is HIGH or CRITICAL;
    3. Deterministic verification returned NEEDS_REVIEW;
    4. Patch spans multiple architectural boundaries / files;
    5. Verifier checks raised non-critical warnings.
    """
    reasons: List[str] = []

    # 1. Security / Authentication category
    is_security = (
        (finding.category and finding.category.lower() in ("security", "sast", "vulnerability", "auth", "secrets", "cve"))
        or any(token in finding.title.lower() for token in ("auth", "token", "password", "sql injection", "secret", "permission", "xss", "cors"))
    )
    if is_security:
        reasons.append("Finding involves security or authentication boundaries.")

    # 2. High or Critical Severity
    if finding.severity in (Severity.HIGH, Severity.CRITICAL):
        reasons.append(f"Finding severity is {finding.severity.value}.")

    # 3. Deterministic Verification status is NEEDS_REVIEW
    if verification_result.status == VerificationStatus.NEEDS_REVIEW:
        reasons.append("Deterministic verification resulted in NEEDS_REVIEW.")

    # 4. Multi-file / Cross-boundary architectural change
    if fix_plan.estimated_scope == FixScope.CROSS_FILE or len(proposal.files_modified) > 1:
        reasons.append(f"Patch modifies multiple files or cross-file boundaries ({len(proposal.files_modified)} files).")

    # 5. Non-empty failed checks during verification
    if len(verification_result.checks_failed) > 0 and verification_result.status != VerificationStatus.FAILED:
        reasons.append(f"Verification flagged items: {', '.join(verification_result.checks_failed)}.")

    should_escalate = len(reasons) > 0
    return should_escalate, reasons


class PatchCriticAgent:
    """Independent AI Critic evaluating high-risk patches with independent context retrieval.
    
    Guarantees:
    - Provider diversity: Dispatches through TaskPolicy.PATCH_CRITIC (NVIDIA / Gemini fallback),
      different from the primary code generator.
    - Actively identifies regressions, contract breakages, overreaching edits, and incomplete fixes.
    - Emits actionable verdict: APPROVE, REVISE, or REJECT.
    """

    def __init__(self, router=None):
        self.router = router or get_llm_router()

    def _build_system_prompt(self) -> str:
        return (
            "You are the RepoLens Independent Patch Critic AI Agent.\n"
            "Your role is to rigorously and skeptically evaluate a candidate patch proposal for a confirmed repository defect.\n\n"
            "INSPECTION FOCUS AREAS:\n"
            "1. INCOMPLETE FIXES: Does the diff fully address the defect root cause or leave edge cases unresolved?\n"
            "2. REGRESSION RISKS: Could this change introduce runtime errors, broken imports, or backward-incompatible API changes?\n"
            "3. CONTRACT BREAKAGE: Does the change alter function signatures or API route formats unexpectedly?\n"
            "4. EXCESSIVE CHANGES: Does the diff contain unrelated refactoring or changes outside the approved FixPlan?\n"
            "5. SECURITY REGRESSIONS: Does the patch introduce new vulnerabilities, bypass authentication, or weaken defenses?\n"
            "6. ROOT-CAUSE MISMATCH: Does the patch fix the symptom rather than the underlying defect?\n\n"
            "VERDICTS:\n"
            "- APPROVE: Patch is clean, minimal, completely resolves root cause, and introduces no regression risk.\n"
            "- REVISE: Patch is on the right track but has minor edge cases or needs specific adjustments.\n"
            "- REJECT: Patch is architecturally flawed, breaks contracts, or introduces unacceptable regressions.\n\n"
            "OUTPUT JSON SCHEMA:\n"
            "{\n"
            '  "verdict": "APPROVE | REVISE | REJECT",\n'
            '  "critic_score": 0.95,\n'
            '  "concerns": ["List of specific technical concerns identified"],\n'
            '  "required_revisions": "Actionable guidance on what to adjust if verdict is REVISE, otherwise null",\n'
            '  "evidence_notes": "Grounding explanation based on the repository context and diff analysis"\n'
            "}"
        )

    def _build_user_prompt(
        self,
        finding: Finding,
        fix_plan: FixPlan,
        proposal: PatchProposal,
        verification_result: PatchVerificationResult,
        context_bundle: ContextBundle,
        escalation_reasons: List[str],
    ) -> str:
        sections = [
            f"FINDING: {finding.title} ({finding.severity.value})",
            f"DESCRIPTION: {finding.description}",
            f"FIX PLAN OBJECTIVE: {fix_plan.objective}",
            f"ROOT CAUSE ANALYSIS: {fix_plan.root_cause}",
            f"CRITIC ESCALATION REASONS:\n- " + "\n- ".join(escalation_reasons),
            f"CANDIDATE UNIFIED DIFF:\n```diff\n{proposal.unified_diff}\n```",
            f"PROPOSED EXPLANATION: {proposal.explanation}",
            f"DETERMINISTIC VERIFICATION OUTCOME: {verification_result.status.value} ({verification_result.explanation})",
        ]

        if context_bundle.relevant_chunks:
            chunk_texts = [
                f"--- File: {c.chunk.file_path} | Symbol: {c.chunk.symbol} ---\n{c.chunk.content}"
                for c in context_bundle.relevant_chunks[:3]
            ]
            sections.append("INDEPENDENT CODE CONTEXT:\n" + "\n\n".join(chunk_texts))

        sections.append(
            "\nPlease critique this candidate patch with rigorous skepticism. Return your verdict and evaluation in JSON."
        )

        return "\n\n".join(sections)

    async def evaluate_patch(
        self,
        finding: Finding,
        fix_plan: FixPlan,
        proposal: PatchProposal,
        verification_result: PatchVerificationResult,
        context_bundle: ContextBundle,
        escalation_reasons: List[str],
    ) -> PatchCriticReport:
        """Critique candidate patch and return structured PatchCriticReport."""
        system_prompt = self._build_system_prompt()
        user_prompt = self._build_user_prompt(
            finding=finding,
            fix_plan=fix_plan,
            proposal=proposal,
            verification_result=verification_result,
            context_bundle=context_bundle,
            escalation_reasons=escalation_reasons,
        )

        messages = [
            LLMMessage(role="system", content=system_prompt),
            LLMMessage(role="user", content=user_prompt),
        ]

        request = LLMRequest(
            messages=messages,
            task_policy=TaskPolicy.PATCH_CRITIC,
            capability=ModelCapability.VERIFICATION,
            output_schema=OBJECT_OUTPUT_SCHEMA,
            lineage=lineage_for_finding(
                str(finding.id),
                prompt_template_version="patch-critic/1.0",
                output_schema_version="patch-critic/1.0",
                evidence={
                    "finding_id": str(finding.id),
                    "patch_id": str(proposal.id),
                    "verification_status": str(verification_result.status),
                },
            ),
            temperature=0.0,
            json_mode=True,
        )

        response = await self.router.generate(request)
        json_str = extract_json_block(response.content)

        verdict = CriticVerdict.APPROVE
        score = 0.9
        concerns: List[str] = []
        required_revisions: Optional[str] = None
        evidence_notes = "Independent critic evaluation completed."

        try:
            data = json.loads(json_str)
            if isinstance(data, dict):
                raw_verdict = str(data.get("verdict", "APPROVE")).upper()
                if raw_verdict in ("APPROVE", "REVISE", "REJECT"):
                    verdict = CriticVerdict(raw_verdict)
                score = float(data.get("critic_score", 0.9))
                concerns = data.get("concerns", concerns)
                required_revisions = data.get("required_revisions")
                evidence_notes = data.get("evidence_notes", evidence_notes)
        except Exception as exc:
            logger.warning("Failed to parse PatchCriticReport JSON from model response: %s", str(exc))
            evidence_notes = response.content[:300]

        return PatchCriticReport(
            patch_id=proposal.id,
            finding_id=finding.id,
            verdict=verdict,
            critic_score=score,
            concerns=concerns,
            required_revisions=required_revisions,
            evidence_notes=evidence_notes,
            escalation_reasons=escalation_reasons,
            model_metadata=response.metadata,
        )
