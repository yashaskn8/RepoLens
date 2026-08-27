"""Change Intelligence and PR Impact Analysis API routes."""

import asyncio
from datetime import datetime, timezone
import json
import logging
from typing import Any, AsyncGenerator, Dict, List, Optional
from urllib.parse import urlparse
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.analysis.workflow import execute_background_change_analysis
from app.core.database import get_db
from app.ingestion.github_pr import (
    GitHubPRForbiddenError,
    GitHubPRNotFoundError,
    GitHubPRRateLimitError,
    GitHubPRTimeoutError,
    InvalidPullRequestURLError,
    get_github_pr_resolver,
)
from app.models.change_analysis import ChangeAnalysisModel, ChangeImpactModel
from app.models.workflow_event import WorkflowEventModel
from app.schemas.change_analysis import (
    ChangeAnalysisPRRequest,
    ChangeAnalysisReportResponse,
    ChangeAnalysisRequest,
    ChangeAnalysisResponse,
    ChangeAnalysisSummary,
    ChangeImpact,
    ChangeReviewReport,
    ResolvedPullRequest,
)
from app.schemas.enums import ChangeAnalysisStatus, ChangeImpactType, ImpactVerificationStatus, Severity
from app.schemas.telemetry import ChangeAnalysisTelemetry
from app.schemas.workflow_event import WorkflowEventCreate, WorkflowEventResponse, WorkflowEventType
from app.services.workflow_event_service import WorkflowEventService


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/change-analyses", tags=["Change Analyses"])


def _extract_repo_owner_name(repo_url: str) -> tuple[str, str]:
    """Parse owner and repo name from canonical GitHub URL."""
    parsed = urlparse(repo_url)
    parts = parsed.path.strip("/").split("/")
    owner = parts[0] if len(parts) > 0 else "unknown"
    repo = parts[1] if len(parts) > 1 else "unknown"
    if repo.endswith(".git"):
        repo = repo[:-4]
    return owner, repo


def _serialize_analysis(model: ChangeAnalysisModel) -> ChangeAnalysisResponse:
    """Map ChangeAnalysisModel to ChangeAnalysisResponse schema."""
    impacts = [
        ChangeImpact(
            id=UUID(imp.id),
            analysis_id=UUID(imp.analysis_id),
            impact_type=ChangeImpactType(imp.impact_type),
            severity=Severity(imp.severity),
            title=imp.title,
            description=imp.description,
            source_file=imp.source_file,
            source_symbol=imp.source_symbol,
            affected_file=imp.affected_file,
            affected_symbol=imp.affected_symbol,
            evidence_payload=imp.evidence_payload or {},
            confidence=imp.confidence,
            verification_status=ImpactVerificationStatus(imp.verification_status),
            created_at=imp.created_at,
        )
        for imp in (model.impacts or [])
    ]

    return ChangeAnalysisResponse(
        id=UUID(model.id),
        repository_url=model.repository_url,
        repository_owner=model.repository_owner,
        repository_name=model.repository_name,
        base_ref=model.base_ref,
        base_commit_sha=model.base_commit_sha,
        head_ref=model.head_ref,
        head_commit_sha=model.head_commit_sha,
        status=ChangeAnalysisStatus(model.status),
        changed_files_count=model.changed_files_count,
        changed_symbols_count=model.changed_symbols_count,
        impacted_symbols_count=model.impacted_symbols_count,
        risk_level=model.risk_level,
        failure_code=model.failure_code,
        failure_message=model.failure_message,
        model_metadata=model.model_metadata or {},
        impacts=impacts,
        created_at=model.created_at,
        updated_at=model.updated_at,
        completed_at=model.completed_at,
    )


@router.post(
    "",
    response_model=ChangeAnalysisResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start change analysis between two exact commit SHAs",
)
async def create_change_analysis(
    payload: ChangeAnalysisRequest,
    db: Session = Depends(get_db),
) -> ChangeAnalysisResponse:
    """Initiate asynchronous change intelligence analysis between two exact commit SHAs."""
    owner, repo = _extract_repo_owner_name(payload.repository_url)
    analysis_id = str(uuid4())

    analysis_model = ChangeAnalysisModel(
        id=analysis_id,
        repository_url=payload.repository_url,
        repository_owner=owner,
        repository_name=repo,
        base_ref=payload.base_ref,
        base_commit_sha=payload.base_commit_sha,
        head_ref=payload.head_ref,
        head_commit_sha=payload.head_commit_sha,
        status=ChangeAnalysisStatus.PENDING.value,
        model_metadata={},
    )
    db.add(analysis_model)
    db.commit()
    db.refresh(analysis_model)

    WorkflowEventService.emit(
        db=db,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.CHANGE_ANALYSIS_REQUESTED,
            change_analysis_id=UUID(analysis_id),
            message=f"Change analysis requested for {owner}/{repo} ({payload.base_commit_sha[:8]} -> {payload.head_commit_sha[:8]})",
            metadata_payload={
                "repository_url": payload.repository_url,
                "base_sha": payload.base_commit_sha,
                "head_sha": payload.head_commit_sha,
            },
        ),
    )

    # Launch background durable workflow task
    asyncio.create_task(execute_background_change_analysis(analysis_id=analysis_id))

    return _serialize_analysis(analysis_model)


@router.post(
    "/from-pr",
    response_model=ChangeAnalysisResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start change analysis from a public GitHub pull request URL",
)
async def create_change_analysis_from_pr(
    payload: ChangeAnalysisPRRequest,
    db: Session = Depends(get_db),
) -> ChangeAnalysisResponse:
    """Resolve public GitHub PR metadata, persist immutable base/head commit SHAs, and start asynchronous analysis."""
    resolver = get_github_pr_resolver()

    try:
        resolved_pr: ResolvedPullRequest = await resolver.resolve_pr(payload.pr_url)
    except InvalidPullRequestURLError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=exc.message)
    except GitHubPRNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.message)
    except (GitHubPRForbiddenError, GitHubPRRateLimitError) as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN if isinstance(exc, GitHubPRForbiddenError) else status.HTTP_429_TOO_MANY_REQUESTS,
            detail=exc.message,
        )
    except GitHubPRTimeoutError as exc:
        raise HTTPException(status_code=status.HTTP_504_GATEWAY_TIMEOUT, detail=exc.message)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"Failed to resolve GitHub PR: {str(exc)}")

    analysis_id = str(uuid4())

    metadata = {
        "pr_url": payload.pr_url,
        "pr_number": resolved_pr.pr_number,
        "pr_title": resolved_pr.title,
        "head_repo_url": resolved_pr.head_repo_url,
        "is_fork": resolved_pr.is_fork,
        "pr_state": resolved_pr.state,
    }

    analysis_model = ChangeAnalysisModel(
        id=analysis_id,
        repository_url=resolved_pr.repository_url,
        repository_owner=resolved_pr.repository_owner,
        repository_name=resolved_pr.repository_name,
        base_ref=resolved_pr.base_branch,
        base_commit_sha=resolved_pr.base_commit_sha,
        head_ref=resolved_pr.head_branch,
        head_commit_sha=resolved_pr.head_commit_sha,
        status=ChangeAnalysisStatus.PENDING.value,
        model_metadata=metadata,
    )
    db.add(analysis_model)
    db.commit()
    db.refresh(analysis_model)

    WorkflowEventService.emit(
        db=db,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.CHANGE_ANALYSIS_REQUESTED,
            change_analysis_id=UUID(analysis_id),
            message=f"Change analysis requested for PR #{resolved_pr.pr_number}: '{resolved_pr.title}' ({resolved_pr.base_commit_sha[:8]} -> {resolved_pr.head_commit_sha[:8]})",
            metadata_payload=metadata,
        ),
    )

    # Launch background durable workflow task
    asyncio.create_task(execute_background_change_analysis(analysis_id=analysis_id))

    return _serialize_analysis(analysis_model)


@router.get(
    "",
    response_model=List[ChangeAnalysisSummary],
    summary="List change analyses",
)
def list_change_analyses(
    repository_url: Optional[str] = Query(None, description="Filter by repository URL"),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> List[ChangeAnalysisSummary]:
    """Retrieve list of change intelligence analyses."""
    query = db.query(ChangeAnalysisModel)
    if repository_url:
        query = query.filter(ChangeAnalysisModel.repository_url == repository_url)
    
    records = query.order_by(ChangeAnalysisModel.created_at.desc()).offset(offset).limit(limit).all()
    return [
        ChangeAnalysisSummary(
            id=UUID(r.id),
            repository_url=r.repository_url,
            repository_owner=r.repository_owner,
            repository_name=r.repository_name,
            base_ref=r.base_ref,
            base_commit_sha=r.base_commit_sha,
            head_ref=r.head_ref,
            head_commit_sha=r.head_commit_sha,
            status=ChangeAnalysisStatus(r.status),
            changed_files_count=r.changed_files_count,
            changed_symbols_count=r.changed_symbols_count,
            impacted_symbols_count=r.impacted_symbols_count,
            risk_level=r.risk_level,
            failure_code=r.failure_code,
            failure_message=r.failure_message,
            created_at=r.created_at,
            updated_at=r.updated_at,
            completed_at=r.completed_at,
        )
        for r in records
    ]


@router.get(
    "/{analysis_id}",
    response_model=ChangeAnalysisResponse,
    summary="Get change analysis details",
)
def get_change_analysis(
    analysis_id: UUID,
    db: Session = Depends(get_db),
) -> ChangeAnalysisResponse:
    """Retrieve complete change intelligence analysis by ID."""
    model = db.query(ChangeAnalysisModel).filter(ChangeAnalysisModel.id == str(analysis_id)).first()
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Change analysis '{analysis_id}' not found",
        )
    return _serialize_analysis(model)


@router.get(
    "/{analysis_id}/impacts",
    response_model=List[ChangeImpact],
    summary="Get blast radius impact records for analysis",
)
def get_change_analysis_impacts(
    analysis_id: UUID,
    db: Session = Depends(get_db),
) -> List[ChangeImpact]:
    """Retrieve structured blast radius impact records for a specific change analysis."""
    model = db.query(ChangeAnalysisModel).filter(ChangeAnalysisModel.id == str(analysis_id)).first()
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Change analysis '{analysis_id}' not found",
        )
    
    return [
        ChangeImpact(
            id=UUID(imp.id),
            analysis_id=UUID(imp.analysis_id),
            impact_type=ChangeImpactType(imp.impact_type),
            severity=Severity(imp.severity),
            title=imp.title,
            description=imp.description,
            source_file=imp.source_file,
            source_symbol=imp.source_symbol,
            affected_file=imp.affected_file,
            affected_symbol=imp.affected_symbol,
            evidence_payload=imp.evidence_payload or {},
            confidence=imp.confidence,
            verification_status=ImpactVerificationStatus(imp.verification_status),
            created_at=imp.created_at,
        )
        for imp in (model.impacts or [])
    ]


@router.get(
    "/{analysis_id}/review",
    response_model=Dict[str, Any],
    summary="Get verified AI change review report",
)
def get_change_analysis_review(
    analysis_id: UUID,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Retrieve verified AI change review report for a specific change analysis."""
    model = db.query(ChangeAnalysisModel).filter(ChangeAnalysisModel.id == str(analysis_id)).first()
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Change analysis '{analysis_id}' not found",
        )
    
    meta = model.model_metadata or {}
    review_report = meta.get("review_report")
    if not review_report:
        return {
            "analysis_id": str(analysis_id),
            "summary": "AI review not available or still in progress",
            "findings": [],
            "rejected_findings": [],
            "total_findings": 0,
            "overall_risk_level": model.risk_level or "LOW",
        }
    return review_report


@router.get(
    "/{analysis_id}/diff",
    response_model=Dict[str, Any],
    summary="Get structural diff result for analysis",
)
def get_change_analysis_diff(
    analysis_id: UUID,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Retrieve deterministic structural diff facts including file, symbol, route, and schema deltas."""
    model = db.query(ChangeAnalysisModel).filter(ChangeAnalysisModel.id == str(analysis_id)).first()
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Change analysis '{analysis_id}' not found",
        )
    meta = model.model_metadata or {}
    diff_data = meta.get("diff_result")
    if not diff_data:
        return {
            "base_commit_sha": model.base_commit_sha,
            "head_commit_sha": model.head_commit_sha,
            "repository_url": model.repository_url,
            "changed_files": [],
            "changed_symbols": [],
            "route_deltas": [],
            "schema_deltas": [],
            "dependency_deltas": [],
            "config_deltas": [],
            "summary": {},
        }
    return diff_data


@router.get(
    "/{analysis_id}/report",
    response_model=ChangeAnalysisReportResponse,
    summary="Get comprehensive Change Intelligence Report (Structured JSON + Markdown)",
)
def get_change_analysis_report(
    analysis_id: UUID,
    db: Session = Depends(get_db),
) -> ChangeAnalysisReportResponse:
    """Generate and retrieve authoritative Change Intelligence Report."""
    from app.analysis.report_generator import generate_change_analysis_report

    model = db.query(ChangeAnalysisModel).filter(ChangeAnalysisModel.id == str(analysis_id)).first()
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Change analysis '{analysis_id}' not found",
        )
    return generate_change_analysis_report(model)


@router.get(
    "/{analysis_id}/markdown",
    response_class=Response,
    summary="Download Change Analysis Report as raw Markdown",
)
def get_change_analysis_markdown_report(
    analysis_id: UUID,
    db: Session = Depends(get_db),
) -> Response:
    """Download deterministic Markdown Change Intelligence Report."""
    from app.analysis.report_generator import generate_change_analysis_report

    model = db.query(ChangeAnalysisModel).filter(ChangeAnalysisModel.id == str(analysis_id)).first()
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Change analysis '{analysis_id}' not found",
        )
    report = generate_change_analysis_report(model)
    return Response(
        content=report.markdown_report,
        media_type="text/markdown",
        headers={
            "Content-Disposition": f"attachment; filename=repolens_change_report_{str(analysis_id)[:8]}.md"
        },
    )


@router.get(
    "/{analysis_id}/telemetry",
    response_model=ChangeAnalysisTelemetry,
    summary="Get authoritative Change Analysis operational telemetry",
)
def get_change_analysis_telemetry_endpoint(
    analysis_id: UUID,
    db: Session = Depends(get_db),
) -> ChangeAnalysisTelemetry:
    """Retrieve authoritative operational metrics aggregated for Change Analysis without secrets."""
    from app.analysis.report_generator import generate_change_analysis_telemetry

    model = db.query(ChangeAnalysisModel).filter(ChangeAnalysisModel.id == str(analysis_id)).first()
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Change analysis '{analysis_id}' not found",
        )
    return generate_change_analysis_telemetry(model)



@router.get(
    "/{analysis_id}/events",
    summary="Get workflow events or subscribe to SSE stream",
)
async def get_change_analysis_events(
    analysis_id: UUID,
    request: Request,
    accept: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """Retrieve durable workflow events or stream real-time updates via Server-Sent Events (SSE)."""
    model = db.query(ChangeAnalysisModel).filter(ChangeAnalysisModel.id == str(analysis_id)).first()
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Change analysis '{analysis_id}' not found",
        )

    # If client requests SSE stream
    if accept and "text/event-stream" in accept:
        async def event_generator() -> AsyncGenerator[str, None]:
            last_event_id = 0
            while True:
                if await request.is_disconnected():
                    break

                events = WorkflowEventService.list_after_id_for_change_analysis(
                    db=db,
                    change_analysis_id=str(analysis_id),
                    after_id=last_event_id,
                )

                for ev in events:
                    last_event_id = max(last_event_id, ev.id)
                    ev_data = {
                        "id": str(ev.id),
                        "event_type": ev.event_type,
                        "stage": ev.stage,
                        "message": ev.message,
                        "metadata_payload": ev.metadata_payload,
                        "created_at": ev.created_at.isoformat() if ev.created_at else None,
                    }
                    yield f"event: workflow_event\ndata: {json.dumps(ev_data)}\n\n"

                # Check if terminal state reached
                curr_model = db.query(ChangeAnalysisModel).filter(ChangeAnalysisModel.id == str(analysis_id)).first()
                if curr_model and curr_model.status in (ChangeAnalysisStatus.COMPLETED.value, ChangeAnalysisStatus.FAILED.value):
                    yield f"event: completed\ndata: {json.dumps({'status': curr_model.status})}\n\n"
                    break

                await asyncio.sleep(0.5)

        return StreamingResponse(event_generator(), media_type="text/event-stream")

    # Otherwise return JSON list of events
    events = WorkflowEventService.list_for_change_analysis(db=db, change_analysis_id=str(analysis_id))
    return [
        WorkflowEventResponse(
            id=ev.id,
            event_type=ev.event_type,
            scan_id=UUID(ev.scan_id) if ev.scan_id else None,
            change_analysis_id=UUID(ev.change_analysis_id) if ev.change_analysis_id else None,
            finding_id=UUID(ev.finding_id) if ev.finding_id else None,
            patch_id=UUID(ev.patch_id) if ev.patch_id else None,
            delivery_id=UUID(ev.delivery_id) if ev.delivery_id else None,
            thread_id=ev.thread_id,
            commit_sha=ev.commit_sha,
            stage=ev.stage,
            tool_name=ev.tool_name,
            provider=ev.provider,
            model_name=ev.model_name,
            message=ev.message,
            metadata_payload=ev.metadata_payload or {},
            created_at=ev.created_at,
        )
        for ev in events
    ]

