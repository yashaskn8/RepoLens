"""API endpoints for finding inspection, technical research, fix planning, and patch generation."""

import logging
from typing import Optional
from uuid import UUID, uuid4

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
from app.analysis.service import get_intelligence_service
from app.analysis.store import EvidenceStore
from app.api.dependencies import get_current_user, verify_csrf
from app.context.engine import ContextEngine
from app.context.runtime import ScanIntelligenceRuntime
from app.core.database import get_db
from app.ingestion.schemas import RepositoryManifest
from app.ingestion.snapshot import SnapshotError, get_snapshot_service
from app.models.finding import FindingModel
from app.models.patch import PatchModel
from app.models.scan import ScanModel
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
from app.schemas.auth import CurrentUser
from app.schemas.enums import FindingStatus, PatchStatus, ScanStatus, Severity, UsageOperation, VerificationVerdict
from app.schemas.evidence import Evidence
from app.schemas.finding import Finding
from app.schemas.metadata import ModelExecutionMetadata
from app.schemas.workflow_event import WorkflowEventCreate, WorkflowEventType
from app.schemas.auth import get_user_id
from app.services.authorization_service import get_owned_finding_or_404
from app.services.domain_mapping import finding_model_to_schema
from app.services.quota_service import check_and_increment_quota
from app.services.workflow_event_service import WorkflowEventService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/findings", tags=["Findings & Remediation"])


def _get_verified_finding_and_scan(finding_id: UUID, current_user: CurrentUser, db: Session) -> tuple[Finding, ScanModel]:
    """Retrieve finding and associated scan, validating user ownership, scan completion, and provenance."""
    fm = get_owned_finding_or_404(db, str(finding_id), current_user)

    user_id = get_user_id(current_user)
    scan_query = db.query(ScanModel).filter(ScanModel.id == fm.scan_id)
    if user_id is not None:
        scan_query = scan_query.filter(ScanModel.owner_user_id == user_id)
    scan = scan_query.first()
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

    return finding_model_to_schema(fm), scan


@router.get("/{finding_id}", response_model=Finding)
def get_finding_by_id(
    finding_id: UUID,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Finding:
    """Retrieve detailed information and evidence for a specific finding."""
    fm = get_owned_finding_or_404(db, str(finding_id), current_user)
    return finding_model_to_schema(fm)


@router.post("/{finding_id}/research", response_model=ResearchResult)
async def request_finding_research(
    finding_id: UUID,
    current_user: CurrentUser = Depends(get_current_user),
    _csrf: None = Depends(verify_csrf),
    db: Session = Depends(get_db),
) -> ResearchResult:
    """Execute evidence-grounded technical research and upgrade intelligence against the exact analyzed repository."""
    finding_schema, scan = _get_verified_finding_and_scan(finding_id, current_user, db)
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
    current_user: CurrentUser = Depends(get_current_user),
    _csrf: None = Depends(verify_csrf),
    db: Session = Depends(get_db),
) -> FixPlan:
    """Generate and validate a structured, minimal-scope FixPlan against the exact analyzed repository."""
    finding_schema, scan = _get_verified_finding_and_scan(finding_id, current_user, db)
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
    current_user: CurrentUser = Depends(get_current_user),
    _csrf: None = Depends(verify_csrf),
    db: Session = Depends(get_db),
) -> PatchWorkflowResult:
    """Generate, verify in sandbox, conditionally critique, and persist candidate patch against the exact analyzed repository."""
    # 1. Quota check & increment
    check_and_increment_quota(db, current_user, UsageOperation.PATCH_GENERATE.value)

    finding_schema, scan = _get_verified_finding_and_scan(finding_id, current_user, db)
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
            if not isinstance(fix_plan, FixPlan):
                try:
                    fix_plan = FixPlan.model_validate(fix_plan)
                except Exception as e:
                    raise HTTPException(
                        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                        detail=f"PATCH_PLAN_PROVENANCE_MISMATCH: Invalid canonical FixPlan: {e}",
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
            if not (
                proposal.finding_id == fix_plan.finding_id
                and proposal.plan_id == fix_plan.id
                and fix_plan.finding_id == finding_schema.id
            ):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="PATCH_PLAN_PROVENANCE_MISMATCH: Patch proposal plan or finding identity does not match canonical FixPlan.",
                )

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
                plan_id=str(fix_plan.id),
                fix_plan_snapshot=fix_plan.model_dump(mode="json"),
                scan_id=str(scan.id),
                thread_id=remediation_thread_id,
                status=patch_status.value,
                machine_verdict=workflow_result.machine_verdict,
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
            db.refresh(patch_model)

            # 5. Emit PATCH_GENERATED and machine verification verdict events with actor attribution
            WorkflowEventService.emit(
                db=db,
                event=WorkflowEventCreate(
                    event_type=WorkflowEventType.PATCH_GENERATED,
                    scan_id=UUID(str(scan.id)),
                    finding_id=UUID(str(finding_id)),
                    patch_id=UUID(str(proposal.id)),
                    actor_user_id=get_user_id(current_user),
                    thread_id=remediation_thread_id,
                    commit_sha=scan.commit_hash,
                    stage="patch_generation",
                    message="Safe remediation patch candidate generated and verified in sandbox",
                    metadata_payload={"files_modified": proposal.files_modified},
                ),
            )

            verdict_event_type = (
                WorkflowEventType.PATCH_VERIFIED
                if workflow_result.machine_verdict == "PASSED"
                else (
                    WorkflowEventType.PATCH_REJECTED
                    if workflow_result.machine_verdict == "REJECTED"
                    else WorkflowEventType.PATCH_NEEDS_REVIEW
                )
            )
            WorkflowEventService.emit(
                db=db,
                event=WorkflowEventCreate(
                    event_type=verdict_event_type,
                    scan_id=UUID(str(scan.id)),
                    finding_id=UUID(str(finding_id)),
                    patch_id=UUID(str(proposal.id)),
                    actor_user_id=get_user_id(current_user),
                    thread_id=remediation_thread_id,
                    commit_sha=scan.commit_hash,
                    stage="patch_verification",
                    message=f"Machine verification verdict: {workflow_result.machine_verdict}",
                    metadata_payload={"machine_verdict": workflow_result.machine_verdict},
                ),
            )

            return workflow_result
    except SnapshotError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to materialize exact repository snapshot: {str(exc)}",
        )

