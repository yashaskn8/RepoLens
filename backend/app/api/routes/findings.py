"""API endpoints for finding inspection, technical research, fix planning, and patch generation."""

import logging
from typing import Any, Optional, Union
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy.orm import sessionmaker

from app.api.dependencies import get_current_user, verify_csrf
from app.api.idempotency import idempotency_identity
from app.core.config import get_settings
from app.core.database import get_db
from app.execution.application import NewWorkPaused, WorkSubmissionService
from app.execution.dispatcher import DurableWorkDispatcher
from app.execution.errors import IdempotencyConflict
from app.execution.types import RequestBudget, ResourceProfile, WorkKind
from app.models.finding import FindingModel
from app.models.scan import ScanModel
from app.patching.schemas import PatchWorkflowResult
from app.planning.schemas import FixPlan
from app.research.schemas import ResearchResult
from app.remediation.service import RemediationExecutionService
from app.schemas.auth import CurrentUser
from app.schemas.auth import get_user_id
from app.schemas.enums import ScanStatus, UsageOperation, VerificationVerdict
from app.schemas.finding import Finding
from app.services.authorization_service import get_owned_finding_or_404
from app.services.domain_mapping import finding_model_to_schema
from app.services.quota_service import check_and_increment_quota

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/findings", tags=["Findings & Remediation"])


class RemediationAccepted(BaseModel):
    job_id: str
    state: str
    status_url: str
    result_url: str
    reused: bool


def _finding_artifact_id(model: FindingModel) -> str | None:
    metadata = model.model_metadata if isinstance(model.model_metadata, dict) else {}
    provenance = metadata.get("provenance") or (metadata.get("extra_metadata") or {}).get("provenance") or {}
    return provenance.get("finding_artifact_id")


async def _submit_remediation(
    *,
    finding_id: UUID,
    kind: WorkKind,
    request: Request | None,
    response: Response,
    current_user: CurrentUser,
    db: Session,
    idempotency_key: str | None,
    prefer: str | None,
) -> dict[str, Any] | RemediationAccepted:
    _, scan = _get_verified_finding_and_scan(finding_id, current_user, db)
    finding_model = get_owned_finding_or_404(db, str(finding_id), current_user)
    scope = kind.value.lower().replace("_", "-")
    client_identity = idempotency_identity(
        scope,
        idempotency_key,
        maximum=get_settings().IDEMPOTENCY_KEY_MAX_LENGTH,
    )
    semantic_identity = client_identity or f"{scope}:{finding_id}:{scan.commit_hash}"
    profile = ResourceProfile.PATCH_GENERATION if kind == WorkKind.PATCH_GENERATION else ResourceProfile.LLM_REASONING
    budget = RequestBudget(
        max_wall_clock_seconds=get_settings().MAX_SCAN_DURATION_SECONDS,
        max_ai_calls=6 if kind != WorkKind.PATCH_GENERATION else 10,
        max_input_tokens=250_000,
        max_output_tokens=50_000,
        max_escalation_tier=2,
        max_retrieval_context_tokens=125_000,
    )
    try:
        submission = WorkSubmissionService().submit(
            db,
            tenant_id=current_user.id,
            actor_id=current_user.id,
            request_id=getattr(getattr(request, "state", None), "request_id", str(uuid4())),
            work_kind=kind,
            resource_type="FINDING",
            resource_id=str(finding_id),
            request_payload={"finding_id": str(finding_id), "revision_id": scan.commit_hash},
            idempotency_key=semantic_identity,
            external_idempotency_key=client_identity,
            resource_profile=profile,
            budget=budget,
            input_artifact_id=_finding_artifact_id(finding_model),
        )
        if kind == WorkKind.PATCH_GENERATION and not submission.result.reused:
            check_and_increment_quota(db, current_user.id, UsageOperation.PATCH_GENERATE.value)
        db.commit()
    except NewWorkPaused as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail={"error_code": "NEW_JOBS_PAUSED", "message": str(exc)}) from exc
    except IdempotencyConflict as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail={"error_code": "IDEMPOTENCY_CONFLICT", "message": str(exc)}) from exc

    job_id = submission.result.work_item_id
    response.headers["X-Job-Location"] = f"/api/v1/jobs/{job_id}"
    response.headers["Idempotency-Replayed"] = "true" if submission.result.reused else "false"
    accepted = RemediationAccepted(
        job_id=job_id,
        state=submission.result.state.value,
        status_url=f"/api/v1/jobs/{job_id}",
        result_url=f"/api/v1/jobs/{job_id}/result",
        reused=submission.result.reused,
    )
    if prefer and "respond-async" in prefer.lower():
        response.status_code = status.HTTP_202_ACCEPTED
        DurableWorkDispatcher.nudge()
        return accepted

    execution = await DurableWorkDispatcher.execute_specific(
        job_id,
        session_factory=sessionmaker(
            bind=db.get_bind(),
            autoflush=False,
            expire_on_commit=False,
            join_transaction_mode="create_savepoint",
        ),
    )
    if (
        execution["state"] == "FAILED"
        and execution.get("failure_code") == "MODEL_INVALID_OUTPUT"
        and str(execution.get("failure_message") or "").startswith("PATCH_PLAN_PROVENANCE_MISMATCH:")
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(execution["failure_message"]),
        )
    if execution["state"] != "SUCCEEDED" or not execution["output_artifact_id"]:
        logger.warning(
            "Inline remediation did not complete: job=%s state=%s failure_code=%s failure=%s",
            job_id,
            execution["state"],
            execution.get("failure_code"),
            execution.get("failure_message"),
        )
        response.status_code = status.HTTP_202_ACCEPTED
        DurableWorkDispatcher.nudge()
        accepted.state = str(execution["state"])
        return accepted
    stored = RemediationExecutionService.load_result(
        db,
        tenant_id=current_user.id,
        artifact_id=str(execution["output_artifact_id"]),
    )
    return dict(stored["result"])


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


@router.post("/{finding_id}/research", response_model=Union[ResearchResult, RemediationAccepted])
async def request_finding_research(
    finding_id: UUID,
    request: Request = None,
    response: Response = None,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    prefer: str | None = Header(default=None, alias="Prefer"),
    current_user: CurrentUser = Depends(get_current_user),
    _csrf: None = Depends(verify_csrf),
    db: Session = Depends(get_db),
) -> ResearchResult | RemediationAccepted:
    """Execute through the shared durable engine; async callers may use Prefer: respond-async."""
    response = response or Response()
    result = await _submit_remediation(
        finding_id=finding_id,
        kind=WorkKind.RESEARCH,
        request=request,
        response=response,
        current_user=current_user,
        db=db,
        idempotency_key=idempotency_key,
        prefer=prefer,
    )
    return result if isinstance(result, RemediationAccepted) else ResearchResult.model_validate(result)


@router.post("/{finding_id}/plan", response_model=Union[FixPlan, RemediationAccepted])
async def request_fix_plan(
    finding_id: UUID,
    request: Request = None,
    response: Response = None,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    prefer: str | None = Header(default=None, alias="Prefer"),
    current_user: CurrentUser = Depends(get_current_user),
    _csrf: None = Depends(verify_csrf),
    db: Session = Depends(get_db),
) -> FixPlan | RemediationAccepted:
    response = response or Response()
    result = await _submit_remediation(
        finding_id=finding_id,
        kind=WorkKind.FIX_PLAN,
        request=request,
        response=response,
        current_user=current_user,
        db=db,
        idempotency_key=idempotency_key,
        prefer=prefer,
    )
    return result if isinstance(result, RemediationAccepted) else FixPlan.model_validate(result)


@router.post("/{finding_id}/patch", response_model=Union[PatchWorkflowResult, RemediationAccepted])
async def request_patch_generation(
    finding_id: UUID,
    request: Request = None,
    response: Response = None,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    prefer: str | None = Header(default=None, alias="Prefer"),
    current_user: CurrentUser = Depends(get_current_user),
    _csrf: None = Depends(verify_csrf),
    db: Session = Depends(get_db),
) -> PatchWorkflowResult | RemediationAccepted:
    response = response or Response()
    result = await _submit_remediation(
        finding_id=finding_id,
        kind=WorkKind.PATCH_GENERATION,
        request=request,
        response=response,
        current_user=current_user,
        db=db,
        idempotency_key=idempotency_key,
        prefer=prefer,
    )
    return result if isinstance(result, RemediationAccepted) else PatchWorkflowResult.model_validate(result)
