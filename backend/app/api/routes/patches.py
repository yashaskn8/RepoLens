"""API endpoints for patch inspection, human-in-the-loop approval, rejection, and revision."""

from datetime import datetime, timezone
import logging
from typing import List, Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.agents.checkpointer import get_sqlite_checkpointer
from app.core.database import get_db
from app.models.patch import PatchModel
from app.patching.workflow_graph import RemediationState, build_remediation_graph
from app.planning.schemas import FixPlan
from app.schemas.enums import PatchStatus
from app.schemas.patch import (
    PatchRejectRequest,
    PatchResponse,
    PatchReviewRequest,
    PatchReviseRequest,
)
from app.schemas.workflow_event import WorkflowEventCreate, WorkflowEventType
from app.services.workflow_event_service import WorkflowEventService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/patches", tags=["Patches"])


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@router.get("/{patch_id}", response_model=PatchResponse)
def get_patch_by_id(patch_id: str, db: Session = Depends(get_db)):
    """Retrieve details, unified diff, verification report, and approval status for a specific patch."""
    patch_model = db.query(PatchModel).filter(PatchModel.id == str(patch_id)).first()
    if not patch_model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Patch proposal '{patch_id}' not found.",
        )
    return patch_model


@router.get("/scan/{scan_id}", response_model=List[PatchResponse])
def get_patches_by_scan_id(scan_id: str, db: Session = Depends(get_db)):
    """Retrieve all patch proposals generated for a specific scan."""
    return db.query(PatchModel).filter(PatchModel.scan_id == str(scan_id)).all()


@router.post("/{patch_id}/approve", response_model=PatchResponse)
async def approve_patch(
    patch_id: str,
    payload: PatchReviewRequest,
    db: Session = Depends(get_db),
):
    """Explicit human approval endpoint for a candidate patch.

    Guarantees:
    - Enforces legal state transitions (REJECTED -> APPROVED directly fails; already APPROVED fails).
    - An LLM cannot approve its own patch; approval must originate from this human action.
    - Synchronizes human approval metadata across database and durable LangGraph checkpoint.
    - Resumes the corresponding LangGraph thread as APPROVED.
    - Never commits or pushes to the repository automatically.
    """
    patch_model = db.query(PatchModel).filter(PatchModel.id == str(patch_id)).first()
    if not patch_model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Patch proposal '{patch_id}' not found.",
        )

    # Transition validation
    if patch_model.status == PatchStatus.REJECTED.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot approve a patch that has been explicitly REJECTED. Generate a new revision first.",
        )

    if patch_model.status == PatchStatus.APPROVED.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Patch proposal is already APPROVED.",
        )

    thread_id = patch_model.thread_id or f"remediation-{patch_model.id}"
    config = {"configurable": {"thread_id": thread_id}}
    approved_at = _utc_now()
    approved_at_iso = approved_at.isoformat()

    # Resume the LangGraph thread as APPROVED
    async with get_sqlite_checkpointer() as checkpointer:
        workflow_app = build_remediation_graph(checkpointer=checkpointer)

        # Initialize thread if not yet present in checkpointer
        state = await workflow_app.aget_state(config)
        if not state or not state.values:
            initial_state: RemediationState = {
                "scan_id": str(patch_model.scan_id),
                "finding_id": str(patch_model.finding_id),
                "patch_id": str(patch_model.id),
                "thread_id": thread_id,
                "proposal_dict": {
                    "unified_diff": patch_model.unified_diff,
                    "files_modified": patch_model.files_modified,
                },
                "patch_status": patch_model.status,
                "revision_count": 0,
            }
            await workflow_app.ainvoke(initial_state, config=config)

        await workflow_app.aupdate_state(
            config,
            {
                "patch_status": PatchStatus.APPROVED.value,
                "approved_by": payload.approved_by,
                "approved_at": approved_at_iso,
                "user_feedback": payload.notes or patch_model.user_feedback,
            },
            as_node="human_approval_checkpoint",
        )
        await workflow_app.ainvoke(None, config=config)

    patch_model.status = PatchStatus.APPROVED.value
    patch_model.approved_by = payload.approved_by
    patch_model.approved_at = approved_at
    if payload.notes:
        patch_model.user_feedback = payload.notes
    patch_model.thread_id = thread_id

    # Emit durable human audit events
    WorkflowEventService.emit(
        db=db,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.HUMAN_APPROVED,
            scan_id=UUID(str(patch_model.scan_id)),
            finding_id=UUID(str(patch_model.finding_id)),
            patch_id=UUID(str(patch_model.id)),
            thread_id=thread_id,
            stage="human_review",
            message=f"Patch approved by {payload.approved_by}",
            metadata_payload={"approved_by": payload.approved_by, "notes": payload.notes},
        ),
        critical=True,
    )
    WorkflowEventService.emit(
        db=db,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.PATCH_APPROVED,
            scan_id=UUID(str(patch_model.scan_id)),
            finding_id=UUID(str(patch_model.finding_id)),
            patch_id=UUID(str(patch_model.id)),
            thread_id=thread_id,
            stage="human_review",
            message="Patch transitioned to APPROVED status",
            metadata_payload={"approved_by": payload.approved_by},
        ),
        critical=True,
    )

    db.commit()
    db.refresh(patch_model)
    return patch_model


@router.post("/{patch_id}/reject", response_model=PatchResponse)
async def reject_patch(
    patch_id: str,
    payload: PatchRejectRequest,
    db: Session = Depends(get_db),
):
    """Explicit human rejection endpoint for a candidate patch.

    Guarantees:
    - Enforces legal state transitions (cannot re-reject an already REJECTED patch).
    - Resumes the corresponding LangGraph thread as REJECTED.
    - Synchronizes human rejection metadata across database and durable LangGraph checkpoint.
    """
    patch_model = db.query(PatchModel).filter(PatchModel.id == str(patch_id)).first()
    if not patch_model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Patch proposal '{patch_id}' not found.",
        )

    # Transition validation
    if patch_model.status == PatchStatus.REJECTED.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Patch proposal is already REJECTED.",
        )

    thread_id = patch_model.thread_id or f"remediation-{patch_model.id}"
    config = {"configurable": {"thread_id": thread_id}}

    # Resume the LangGraph thread as REJECTED
    async with get_sqlite_checkpointer() as checkpointer:
        workflow_app = build_remediation_graph(checkpointer=checkpointer)

        state = await workflow_app.aget_state(config)
        if not state or not state.values:
            initial_state: RemediationState = {
                "scan_id": str(patch_model.scan_id),
                "finding_id": str(patch_model.finding_id),
                "patch_id": str(patch_model.id),
                "thread_id": thread_id,
                "proposal_dict": {
                    "unified_diff": patch_model.unified_diff,
                    "files_modified": patch_model.files_modified,
                },
                "patch_status": patch_model.status,
                "revision_count": 0,
            }
            await workflow_app.ainvoke(initial_state, config=config)

        await workflow_app.aupdate_state(
            config,
            {
                "patch_status": PatchStatus.REJECTED.value,
                "rejected_reason": payload.reason,
            },
            as_node="human_approval_checkpoint",
        )
        await workflow_app.ainvoke(None, config=config)

    patch_model.status = PatchStatus.REJECTED.value
    patch_model.rejected_reason = payload.reason
    patch_model.thread_id = thread_id

    # Emit durable human audit events
    WorkflowEventService.emit(
        db=db,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.HUMAN_REJECTED,
            scan_id=UUID(str(patch_model.scan_id)),
            finding_id=UUID(str(patch_model.finding_id)),
            patch_id=UUID(str(patch_model.id)),
            thread_id=thread_id,
            stage="human_review",
            message=f"Patch rejected: {payload.reason}",
            metadata_payload={"reason": payload.reason},
        ),
        critical=True,
    )
    WorkflowEventService.emit(
        db=db,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.PATCH_REJECTED,
            scan_id=UUID(str(patch_model.scan_id)),
            finding_id=UUID(str(patch_model.finding_id)),
            patch_id=UUID(str(patch_model.id)),
            thread_id=thread_id,
            stage="human_review",
            message="Patch transitioned to REJECTED status",
            metadata_payload={"reason": payload.reason},
        ),
        critical=True,
    )

    db.commit()
    db.refresh(patch_model)
    return patch_model


@router.post("/{patch_id}/revise", response_model=PatchResponse)
async def request_patch_revision(
    patch_id: str,
    payload: PatchReviseRequest,
    db: Session = Depends(get_db),
):
    """Request a real human-guided revision generating a new child PatchProposal.

    Guarantees:
    - Enforces legal state transitions (APPROVED -> REVISE fails; REJECTED -> REVISE fails).
    - Hard limit of at most ONE human-requested revision per patch lineage (revision_number >= 1 fails).
    - Database/service concurrency guard: rejects if a child revision already exists for this parent.
    - Rehydrates exact scan commit SHA and loads original CONFIRMED finding.
    - Injects human feedback into remediation prompt/plan to generate a fresh diff.
    - Executes strict sandbox validation, deterministic 12-check verification, and conditional critic.
    - Persists an immutable new child PatchModel referencing parent_patch_id and revision_number = 1.
    - Pauses in VERIFIED / NEEDS_REVIEW for explicit human approval or rejection.
    - Machine verification NEVER produces PatchStatus.APPROVED directly.
    """
    from app.analysis.service import get_intelligence_service
    from app.api.routes.findings import _get_verified_finding_and_scan
    from app.context.runtime import ScanIntelligenceRuntime
    from app.ingestion.snapshot import get_snapshot_service
    from app.patching.workflow import PatchWorkflowCoordinator
    from app.planning.service import FixPlanningService

    patch_model = db.query(PatchModel).filter(PatchModel.id == str(patch_id)).first()
    if not patch_model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Patch proposal '{patch_id}' not found.",
        )

    # 1. State transition and lineage validation
    if patch_model.status == PatchStatus.APPROVED.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot request revision on an already APPROVED patch.",
        )

    if patch_model.status == PatchStatus.REJECTED.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot request revision on a REJECTED patch. Generate a new revision from the finding instead.",
        )

    if (patch_model.revision_number or 0) >= 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum of 1 human revision allowed per patch lineage. Cannot revise a child revision.",
        )

    existing_child = db.query(PatchModel).filter(PatchModel.parent_patch_id == str(patch_id)).first()
    if existing_child:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A revision child has already been created for this patch proposal.",
        )

    finding_schema, scan = _get_verified_finding_and_scan(UUID(patch_model.finding_id), db)
    snapshot_service = get_snapshot_service()

    # 2. Materialize exact snapshot, rebuild intelligence runtime, and generate revised patch
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

        # Inject reviewer feedback into fix plan objective
        fix_plan.objective = f"{fix_plan.objective} (Human reviewer feedback: {payload.user_feedback})"

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
            proposal.plan_id == fix_plan.id
            and proposal.finding_id == fix_plan.finding_id
            and fix_plan.finding_id == finding_schema.id
        ):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="PATCH_PLAN_PROVENANCE_MISMATCH: Patch proposal plan or finding identity does not match canonical FixPlan.",
            )

        # Map machine verdict directly to status (never APPROVED without explicit human /approve)
        if workflow_result.machine_verdict == "PASSED" or (
            workflow_result.verification_result and workflow_result.verification_result.status.value == "PASSED"
        ):
            child_status = PatchStatus.VERIFIED
        elif workflow_result.machine_verdict == "REJECTED" or (
            workflow_result.verification_result and workflow_result.verification_result.status.value == "FAILED"
        ):
            child_status = PatchStatus.REJECTED
        else:
            child_status = PatchStatus.NEEDS_REVIEW

        # 3. Create durable LangGraph remediation thread for child patch
        child_thread_id = f"remediation-{proposal.id}"
        initial_remediation_state: RemediationState = {
            "scan_id": str(scan.id),
            "finding_id": str(finding_schema.id),
            "patch_id": str(proposal.id),
            "thread_id": child_thread_id,
            "proposal_dict": proposal.model_dump(mode="json"),
            "verification_dict": workflow_result.verification_result.model_dump(mode="json") if workflow_result.verification_result else None,
            "critic_dict": workflow_result.critic_report.model_dump(mode="json") if workflow_result.critic_report else None,
            "patch_status": child_status.value,
            "user_feedback": payload.user_feedback,
            "revision_count": (patch_model.revision_number or 0) + 1,
        }

        try:
            async with get_sqlite_checkpointer() as checkpointer:
                remediation_app = build_remediation_graph(checkpointer=checkpointer)
                await remediation_app.ainvoke(
                    initial_remediation_state,
                    config={"configurable": {"thread_id": child_thread_id}},
                )
        except Exception as exc:
            logger.warning("Notice initializing child remediation thread %s: %s", child_thread_id, str(exc))

        # 4. Persist child PatchModel with audit lineage
        child_patch_model = PatchModel(
            id=str(proposal.id),
            finding_id=str(finding_schema.id),
            plan_id=str(fix_plan.id),
            fix_plan_snapshot=fix_plan.model_dump(mode="json"),
            scan_id=str(scan.id),
            parent_patch_id=str(patch_model.id),
            revision_number=(patch_model.revision_number or 0) + 1,
            thread_id=child_thread_id,
            status=child_status.value,
            machine_verdict=workflow_result.machine_verdict,
            unified_diff=proposal.unified_diff,
            files_modified=proposal.files_modified,
            explanation=proposal.explanation,
            expected_behavior_change=proposal.expected_behavior_change,
            generated_tests_or_test_plan=proposal.generated_tests_or_test_plan,
            verification_report=workflow_result.verification_result.model_dump(mode="json") if workflow_result.verification_result else None,
            critic_report=workflow_result.critic_report.model_dump(mode="json") if workflow_result.critic_report else None,
            user_feedback=payload.user_feedback,
            model_metadata=proposal.model_metadata.model_dump(mode="json") if proposal.model_metadata else None,
        )
        db.add(child_patch_model)

        # 5. Emit durable human revision and child creation audit events
        WorkflowEventService.emit(
            db=db,
            event=WorkflowEventCreate(
                event_type=WorkflowEventType.HUMAN_REVISION_REQUESTED,
                scan_id=UUID(str(scan.id)),
                finding_id=UUID(str(finding_schema.id)),
                patch_id=UUID(str(patch_model.id)),
                thread_id=child_thread_id,
                stage="human_review",
                message="Human revision requested with feedback",
                metadata_payload={"user_feedback": payload.user_feedback, "parent_patch_id": str(patch_model.id)},
            ),
            critical=True,
        )
        WorkflowEventService.emit(
            db=db,
            event=WorkflowEventCreate(
                event_type=WorkflowEventType.PATCH_REVISION_CREATED,
                scan_id=UUID(str(scan.id)),
                finding_id=UUID(str(finding_schema.id)),
                patch_id=UUID(str(proposal.id)),
                thread_id=child_thread_id,
                stage="patch_generation",
                message="Child patch revision created and verified in sandbox",
                metadata_payload={
                    "parent_patch_id": str(patch_model.id),
                    "revision_number": (patch_model.revision_number or 0) + 1,
                    "machine_verdict": workflow_result.machine_verdict,
                },
            ),
            critical=True,
        )

        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A revision child has already been created for this patch proposal (concurrent conflict).",
            )
        db.refresh(child_patch_model)
        return child_patch_model
