"""API endpoints for finding inspection, technical research, fix planning, and patch generation."""

import logging
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.analysis.service import get_intelligence_service
from app.analysis.store import EvidenceStore
from app.context.engine import ContextEngine
from app.context.runtime import ScanIntelligenceRuntime
from app.core.database import get_db
from app.ingestion.schemas import RepositoryManifest
from app.ingestion.snapshot import SnapshotError, get_snapshot_service
from app.models.finding import FindingModel
from app.models.patch import PatchModel
from app.models.scan import ScanModel
from app.agents.checkpointer import get_sqlite_checkpointer
from app.patching.critic import PatchCriticAgent
from app.patching.schemas import PatchProposal, PatchWorkflowResult
from app.patching.service import PatchService
from app.patching.verification import PatchVerificationService
from app.patching.workflow import PatchWorkflowCoordinator
from app.patching.workflow_graph import build_remediation_graph
from app.planning.schemas import FixPlan
from app.planning.service import FixPlanningService
from app.research.schemas import ResearchResult
from app.research.service import ResearchService
from app.schemas.enums import FindingStatus, PatchStatus, ScanStatus, Severity, VerificationVerdict
from app.schemas.evidence import Evidence
from app.schemas.finding import Finding
from app.schemas.metadata import ModelExecutionMetadata

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/findings", tags=["Findings & Remediation"])


def _finding_model_to_schema(fm: FindingModel) -> Finding:
    """Convert FindingModel ORM object into validated Finding domain schema."""
    evidences = [
        Evidence(
            id=UUID(em.id),
            file_path=em.file_path,
            start_line=em.start_line,
            end_line=em.end_line,
            code_snippet=em.code_snippet,
            context_notes=em.context_notes,
        )
        for em in fm.evidences
    ]
    metadata = None
    if fm.model_metadata and isinstance(fm.model_metadata, dict):
        try:
            metadata = ModelExecutionMetadata(**fm.model_metadata)
        except Exception:
            pass

    return Finding(
        id=UUID(fm.id),
        scan_id=UUID(fm.scan_id),
        title=fm.title,
        description=fm.description,
        severity=Severity(fm.severity),
        status=FindingStatus(fm.status),
        rule_id=fm.rule_id,
        category=fm.category,
        mitigation_guidance=fm.mitigation_guidance,
        verification_verdict=VerificationVerdict(fm.verification_verdict) if fm.verification_verdict else None,
        verification_reason=fm.verification_reason,
        evidences=evidences,
        model_metadata=metadata,
        created_at=fm.created_at,
        updated_at=fm.updated_at,
    )


def _get_verified_finding_and_scan(finding_id: UUID, db: Session) -> tuple[Finding, ScanModel]:
    """Retrieve finding and associated scan, validating scan completion and provenance."""
    fm = db.query(FindingModel).filter(FindingModel.id == str(finding_id)).first()
    if not fm:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding with ID '{finding_id}' not found.",
        )

    scan = db.query(ScanModel).filter(ScanModel.id == fm.scan_id).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Associated scan for finding '{finding_id}' not found.",
        )

    if scan.status != ScanStatus.COMPLETED.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Remediation rejected: Scan must be COMPLETED before remediation (current status: '{scan.status}').",
        )

    if str(fm.scan_id) != str(scan.id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Remediation rejected: Finding does not belong to the scan.",
        )

    if not scan.commit_hash or scan.commit_hash == "unknown":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Remediation rejected: Scan has invalid or unrecorded commit hash ('{scan.commit_hash}').",
        )

    # Strict remediation eligibility check: only CONFIRMED findings may enter remediation
    if fm.verification_verdict != VerificationVerdict.CONFIRMED.value:
        verdict_display = fm.verification_verdict or "NONE"
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Finding '{finding_id}' is not eligible for remediation: only findings with "
                f"verification_verdict == 'CONFIRMED' may enter research, fix planning, or patch generation "
                f"(current verdict: '{verdict_display}')."
            ),
        )

    return _finding_model_to_schema(fm), scan


@router.get("/{finding_id}", response_model=Finding)
def get_finding_by_id(finding_id: UUID, db: Session = Depends(get_db)) -> Finding:
    """Retrieve detailed information and evidence for a specific finding."""
    fm = db.query(FindingModel).filter(FindingModel.id == str(finding_id)).first()
    if not fm:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding with ID '{finding_id}' not found.",
        )
    return _finding_model_to_schema(fm)


@router.post("/{finding_id}/research", response_model=ResearchResult)
async def request_finding_research(
    finding_id: UUID,
    db: Session = Depends(get_db),
) -> ResearchResult:
    """Execute evidence-grounded technical research and upgrade intelligence against the exact analyzed repository."""
    finding_schema, scan = _get_verified_finding_and_scan(finding_id, db)
    snapshot_service = get_snapshot_service()

    try:
        async with snapshot_service.open_snapshot(scan_id=scan.id, db=db) as workspace_dir:
            intelligence_service = get_intelligence_service()
            evidence_store = await intelligence_service.analyze_repository(
                repo_dir=workspace_dir,
                repository_url=scan.repository_url,
                commit_hash=scan.commit_hash,
                branch=scan.branch,
            )

            service = ResearchService()
            return await service.research_finding(
                finding=finding_schema,
                manifest=evidence_store.manifest,
            )
    except SnapshotError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to materialize exact repository snapshot: {str(exc)}",
        )


@router.post("/{finding_id}/plan", response_model=FixPlan)
async def request_fix_plan(
    finding_id: UUID,
    db: Session = Depends(get_db),
) -> FixPlan:
    """Generate and validate a structured, minimal-scope FixPlan against the exact analyzed repository."""
    finding_schema, scan = _get_verified_finding_and_scan(finding_id, db)
    snapshot_service = get_snapshot_service()

    try:
        async with snapshot_service.open_snapshot(scan_id=scan.id, db=db) as workspace_dir:
            intelligence_service = get_intelligence_service()
            evidence_store = await intelligence_service.analyze_repository(
                repo_dir=workspace_dir,
                repository_url=scan.repository_url,
                commit_hash=scan.commit_hash,
                branch=scan.branch,
            )

            runtime = await ScanIntelligenceRuntime.build(
                evidence_store=evidence_store,
                repo_dir=workspace_dir,
            )

            service = FixPlanningService()
            return await service.create_fix_plan(
                finding=finding_schema,
                context_engine=runtime.context_engine,
                repository_graph=runtime.repository_graph,
                manifest=runtime.manifest,
            )
    except SnapshotError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to materialize exact repository snapshot: {str(exc)}",
        )


@router.post("/{finding_id}/patch", response_model=PatchWorkflowResult)
async def request_patch_generation(
    finding_id: UUID,
    db: Session = Depends(get_db),
) -> PatchWorkflowResult:
    """Generate, verify in sandbox, conditionally critique, and persist candidate patch against the exact analyzed repository."""
    finding_schema, scan = _get_verified_finding_and_scan(finding_id, db)
    snapshot_service = get_snapshot_service()

    try:
        async with snapshot_service.open_snapshot(scan_id=scan.id, db=db) as workspace_dir:
            intelligence_service = get_intelligence_service()
            evidence_store = await intelligence_service.analyze_repository(
                repo_dir=workspace_dir,
                repository_url=scan.repository_url,
                commit_hash=scan.commit_hash,
                branch=scan.branch,
            )

            runtime = await ScanIntelligenceRuntime.build(
                evidence_store=evidence_store,
                repo_dir=workspace_dir,
            )

            # 1. Generate FixPlan first
            planning_service = FixPlanningService()
            fix_plan = await planning_service.create_fix_plan(
                finding=finding_schema,
                context_engine=runtime.context_engine,
                repository_graph=runtime.repository_graph,
                manifest=runtime.manifest,
            )

            # 2. Execute Patch Workflow (Generator -> Sandbox Verifier -> Critic)
            coordinator = PatchWorkflowCoordinator()
            workflow_result = await coordinator.execute_patch_workflow(
                finding=finding_schema,
                fix_plan=fix_plan,
                context_engine=runtime.context_engine,
                original_repo_dir=workspace_dir,
                manifest=runtime.manifest,
            )

            proposal = workflow_result.proposal
            patch_status = PatchStatus.VERIFIED if workflow_result.final_verdict in ("PASSED", "APPROVED") else (
                PatchStatus.REJECTED if workflow_result.final_verdict == "REJECTED" else PatchStatus.NEEDS_REVIEW
            )

            # 3. Initialize durable LangGraph remediation thread paused at human approval interrupt
            remediation_thread_id = f"remediation-{proposal.id}"
            initial_remediation_state = {
                "scan_id": str(scan.id),
                "finding_id": str(finding_id),
                "patch_id": str(proposal.id),
                "thread_id": remediation_thread_id,
                "proposal_dict": proposal.model_dump(mode="json"),
                "verification_dict": workflow_result.verification_result.model_dump(mode="json") if workflow_result.verification_result else None,
                "critic_dict": workflow_result.critic_report.model_dump(mode="json") if workflow_result.critic_report else None,
                "patch_status": patch_status.value,
                "revision_count": 0,
            }
            try:
                async with get_sqlite_checkpointer() as checkpointer:
                    remediation_app = build_remediation_graph(checkpointer=checkpointer)
                    await remediation_app.ainvoke(
                        initial_remediation_state,
                        config={"configurable": {"thread_id": remediation_thread_id}},
                    )
            except Exception as exc:
                logger.warning("Notice initializing remediation thread %s: %s", remediation_thread_id, str(exc))

            # 4. Persist Patch Proposal into database
            patch_model = PatchModel(
                id=str(proposal.id),
                finding_id=str(finding_id),
                plan_id=str(proposal.plan_id) if proposal.plan_id else None,
                scan_id=str(scan.id),
                thread_id=remediation_thread_id,
                status=patch_status.value,
                unified_diff=proposal.unified_diff,
                files_modified=proposal.files_modified,
                explanation=proposal.explanation,
                expected_behavior_change=proposal.expected_behavior_change,
                generated_tests_or_test_plan=proposal.generated_tests_or_test_plan,
                verification_report=workflow_result.verification_result.model_dump(mode="json") if workflow_result.verification_result else None,
                critic_report=workflow_result.critic_report.model_dump(mode="json") if workflow_result.critic_report else None,
                model_metadata=proposal.model_metadata.model_dump(mode="json") if proposal.model_metadata else None,
            )
            db.add(patch_model)
            db.commit()

            return workflow_result
    except SnapshotError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to materialize exact repository snapshot: {str(exc)}",
        )

