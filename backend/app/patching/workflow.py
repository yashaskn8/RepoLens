"""End-to-end safe patch generation, verification, conditional criticism, and single-revision loop coordinator."""

import logging
from typing import Optional

from app.context.engine import ContextEngine
from app.ingestion.schemas import RepositoryManifest
from app.patching.agent import PatchGeneratorAgent
from app.patching.critic import PatchCriticAgent, should_escalate_to_critic
from app.patching.schemas import (
    CriticVerdict,
    PatchProposal,
    PatchVerificationResult,
    PatchWorkflowResult,
    VerificationStatus,
)
from app.patching.service import PatchService
from app.patching.verification import PatchVerificationService
from app.planning.schemas import FixPlan
from app.schemas.finding import Finding

logger = logging.getLogger(__name__)


class PatchWorkflowCoordinator:
    """Coordinates the deterministic generation, verification, conditional criticism, and single-revision workflow.
    
    Guarantees:
    - Conditional critic invocation (only on high-risk/security/multi-boundary patches).
    - Hard limit of at most ONE automatic revision.
    - Zero infinite debate loops.
    """

    def __init__(
        self,
        patch_service: Optional[PatchService] = None,
        verification_service: Optional[PatchVerificationService] = None,
        critic_agent: Optional[PatchCriticAgent] = None,
    ):
        self.patch_service = patch_service or PatchService()
        self.verification_service = verification_service or PatchVerificationService()
        self.critic_agent = critic_agent or PatchCriticAgent()

    async def execute_patch_workflow(
        self,
        finding: Finding,
        fix_plan: FixPlan,
        context_engine: ContextEngine,
        original_repo_dir: str,
        manifest: RepositoryManifest,
    ) -> PatchWorkflowResult:
        """Execute the end-to-end patch generation, sandbox verification, and conditional critic evaluation."""
        # 1. Generate initial candidate patch
        proposal = await self.patch_service.generate_patch_proposal(
            finding=finding,
            fix_plan=fix_plan,
            context_engine=context_engine,
            repo_dir=original_repo_dir,
            manifest=manifest,
        )

        # 2. Run deterministic sandbox verification
        verification_result = await self.verification_service.verify_patch(
            proposal=proposal,
            finding=finding,
            fix_plan=fix_plan,
            original_repo_dir=original_repo_dir,
            manifest=manifest,
        )

        # Immediate rejection if deterministic checks fail critically
        if verification_result.status == VerificationStatus.FAILED:
            return PatchWorkflowResult(
                finding_id=finding.id,
                proposal=proposal,
                verification_result=verification_result,
                critic_escalated=False,
                revision_count=0,
                final_verdict="REJECTED",
            )

        # 3. Check conditional escalation criteria
        should_escalate, escalation_reasons = should_escalate_to_critic(
            finding=finding,
            fix_plan=fix_plan,
            proposal=proposal,
            verification_result=verification_result,
        )

        if not should_escalate:
            # Low-risk patch passed verification cleanly -> Auto-approved without burning extra LLM calls
            return PatchWorkflowResult(
                finding_id=finding.id,
                proposal=proposal,
                verification_result=verification_result,
                critic_escalated=False,
                revision_count=0,
                final_verdict="APPROVED",
            )

        # 4. Independent Critic Evaluation (with independently retrieved ContextBundle)
        critic_context = await context_engine.build_context_bundle(
            scan_id=str(finding.scan_id),
            query=f"Independent criticism of patch for {finding.title}",
            analysis_intent="patch_critic",
            context_budget=2500,
        )

        critic_report = await self.critic_agent.evaluate_patch(
            finding=finding,
            fix_plan=fix_plan,
            proposal=proposal,
            verification_result=verification_result,
            context_bundle=critic_context,
            escalation_reasons=escalation_reasons,
        )

        if critic_report.verdict == CriticVerdict.APPROVE:
            return PatchWorkflowResult(
                finding_id=finding.id,
                proposal=proposal,
                verification_result=verification_result,
                critic_escalated=True,
                critic_report=critic_report,
                revision_count=0,
                final_verdict="APPROVED",
            )
        elif critic_report.verdict == CriticVerdict.REJECT:
            return PatchWorkflowResult(
                finding_id=finding.id,
                proposal=proposal,
                verification_result=verification_result,
                critic_escalated=True,
                critic_report=critic_report,
                revision_count=0,
                final_verdict="REJECTED",
            )

        # 5. Critic requested REVISE: Execute AT MOST ONE automatic revision
        logger.info("PatchCritic requested revision: %s. Applying single revision loop...", critic_report.required_revisions)

        # Construct revised FixPlan incorporating critic feedback
        revised_plan = fix_plan.model_copy(deep=True)
        if critic_report.required_revisions:
            revised_plan.objective = f"{fix_plan.objective} (Critic feedback: {critic_report.required_revisions})"

        revised_proposal = await self.patch_service.generate_patch_proposal(
            finding=finding,
            fix_plan=revised_plan,
            context_engine=context_engine,
            repo_dir=original_repo_dir,
            manifest=manifest,
        )

        revised_verification = await self.verification_service.verify_patch(
            proposal=revised_proposal,
            finding=finding,
            fix_plan=revised_plan,
            original_repo_dir=original_repo_dir,
            manifest=manifest,
        )

        revised_critic_report = await self.critic_agent.evaluate_patch(
            finding=finding,
            fix_plan=revised_plan,
            proposal=revised_proposal,
            verification_result=revised_verification,
            context_bundle=critic_context,
            escalation_reasons=escalation_reasons,
        )

        final_verdict = "APPROVED" if (
            revised_critic_report.verdict == CriticVerdict.APPROVE
            and revised_verification.status != VerificationStatus.FAILED
        ) else "NEEDS_HUMAN_REVIEW"

        return PatchWorkflowResult(
            finding_id=finding.id,
            proposal=revised_proposal,
            verification_result=revised_verification,
            critic_escalated=True,
            critic_report=revised_critic_report,
            revision_count=1,  # Hard cap
            final_verdict=final_verdict,
        )
