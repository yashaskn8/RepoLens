"""Scans API endpoints and asynchronous execution coordinator."""

import asyncio
from datetime import datetime, timezone
import logging
import os
import shutil
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.agents.graph import run_analysis_workflow
from app.analysis.service import get_intelligence_service
from app.context.runtime import ScanIntelligenceRuntime
from app.core.database import SessionLocal, get_db
from app.ingestion.clone import InvalidRepositoryURLError, clone_repository, validate_github_url
from app.models.finding import EvidenceModel, FindingModel
from app.models.scan import ScanModel
from app.schemas.enums import FindingStatus, ScanStatus, Severity, VerificationVerdict
from app.schemas.evidence import Evidence
from app.schemas.finding import Finding
from app.schemas.metadata import ModelExecutionMetadata
from app.schemas.scan import Scan, ScanCreate

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/scans", tags=["Scans"])


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


async def execute_background_scan(scan_id: str, repo_url: str, branch: Optional[str]):
    """Asynchronously execute repository cloning, intelligence analysis, and multi-agent workflow."""
    db: Session = SessionLocal()
    workspace_dir: Optional[str] = None

    try:
        # 1. Update status to RUNNING
        scan_model = db.query(ScanModel).filter(ScanModel.id == scan_id).first()
        if not scan_model:
            return
        scan_model.status = ScanStatus.RUNNING.value
        db.commit()

        # 2. Clone repository safely
        workspace_dir, commit_sha = await asyncio.to_thread(
            clone_repository,
            repo_url=repo_url,
            branch=branch,
        )

        scan_model.commit_hash = commit_sha
        db.commit()

        # 3. Run deterministic intelligence service (manifest + scanners)
        service = get_intelligence_service()
        evidence_store = await service.analyze_repository(
            repo_dir=workspace_dir,
            repository_url=repo_url,
            commit_hash=commit_sha,
            branch=branch,
        )

        # 4. Assemble canonical ScanIntelligenceRuntime from EvidenceStore
        runtime = await ScanIntelligenceRuntime.build(
            evidence_store=evidence_store,
            repo_dir=workspace_dir,
        )

        # 5. Run LangGraph multi-agent analysis & verification workflow with ContextEngine and RepositoryGraph
        final_state = await run_analysis_workflow(
            evidence_store=evidence_store,
            scan_id=scan_id,
            repo_dir=workspace_dir,
            context_engine=runtime.context_engine,
            repository_graph=runtime.repository_graph,
        )

        # 5. Persist verified findings into database
        verified_findings: List[Finding] = final_state.get("verified_findings", [])
        for f in verified_findings:
            finding_model = FindingModel(
                id=str(f.id),
                scan_id=scan_id,
                title=f.title,
                description=f.description,
                severity=f.severity.value,
                status=f.status.value,
                rule_id=f.rule_id,
                category=f.category,
                mitigation_guidance=f.mitigation_guidance,
                verification_verdict=f.verification_verdict.value if f.verification_verdict else None,
                verification_reason=f.verification_reason,
                model_metadata=f.model_metadata.model_dump() if f.model_metadata else None,
            )

            for ev in f.evidences:
                ev_model = EvidenceModel(
                    id=str(ev.id),
                    finding_id=str(f.id),
                    file_path=ev.file_path,
                    start_line=ev.start_line,
                    end_line=ev.end_line,
                    code_snippet=ev.code_snippet,
                    context_notes=ev.context_notes,
                )
                finding_model.evidences.append(ev_model)

            db.add(finding_model)

        # 6. Mark scan COMPLETED
        scan_model.status = ScanStatus.COMPLETED.value
        scan_model.completed_at = _utc_now()
        scan_model.model_metadata = {
            "architecture_overview": final_state.get("architecture_overview"),
            "languages": final_state.get("languages", {}),
            "frameworks": final_state.get("frameworks", []),
            "total_files": evidence_store.manifest.total_files,
            "total_size_bytes": evidence_store.manifest.total_size_bytes,
        }
        db.commit()

    except Exception as exc:
        logger.error(f"Scan {scan_id} failed: {str(exc)}", exc_info=True)
        try:
            scan_model = db.query(ScanModel).filter(ScanModel.id == scan_id).first()
            if scan_model:
                scan_model.status = ScanStatus.FAILED.value
                scan_model.completed_at = _utc_now()
                scan_model.model_metadata = {"error": str(exc)}
                db.commit()
        except Exception:
            pass
    finally:
        db.close()
        # Clean up temporary workspace directory
        if workspace_dir and os.path.exists(workspace_dir):
            shutil.rmtree(workspace_dir, ignore_errors=True)


@router.post("", response_model=Scan, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(payload: ScanCreate, db: Session = Depends(get_db)) -> Scan:
    """Initiate a new repository scan asynchronously, returning scan ID immediately."""
    # 1. Validate GitHub URL strictly
    try:
        normalized_url = validate_github_url(payload.repository_url)
    except InvalidRepositoryURLError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid repository URL: {str(exc)}",
        )

    # 2. Create Scan record in DB
    scan_model = ScanModel(
        repository_url=normalized_url,
        branch=payload.branch or "main",
        status=ScanStatus.PENDING.value,
        created_at=_utc_now(),
    )
    db.add(scan_model)
    db.commit()
    db.refresh(scan_model)

    # 3. Launch background async execution
    asyncio.create_task(
        execute_background_scan(
            scan_id=scan_model.id,
            repo_url=normalized_url,
            branch=payload.branch,
        )
    )

    return Scan(
        id=UUID(scan_model.id),
        repository_url=scan_model.repository_url,
        branch=scan_model.branch,
        commit_hash=scan_model.commit_hash,
        status=ScanStatus(scan_model.status),
        findings_count=0,
        findings=[],
        created_at=scan_model.created_at,
        completed_at=scan_model.completed_at,
    )


@router.get("/{scan_id}", response_model=Scan)
def get_scan(scan_id: UUID, db: Session = Depends(get_db)) -> Scan:
    """Retrieve scan status, metadata, and progress by ID."""
    scan_model = db.query(ScanModel).filter(ScanModel.id == str(scan_id)).first()
    if not scan_model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found.",
        )

    findings_count = db.query(FindingModel).filter(FindingModel.scan_id == str(scan_id)).count()

    model_metadata = None
    if scan_model.model_metadata and isinstance(scan_model.model_metadata, dict):
        model_metadata = ModelExecutionMetadata(
            model_name="RepoLens-MultiAgent",
            extra_metadata=scan_model.model_metadata,
        )

    return Scan(
        id=UUID(scan_model.id),
        repository_url=scan_model.repository_url,
        branch=scan_model.branch,
        commit_hash=scan_model.commit_hash,
        status=ScanStatus(scan_model.status),
        findings_count=findings_count,
        findings=[],
        model_metadata=model_metadata,
        created_at=scan_model.created_at,
        completed_at=scan_model.completed_at,
    )


@router.get("/{scan_id}/findings", response_model=List[Finding])
def get_scan_findings(scan_id: UUID, db: Session = Depends(get_db)) -> List[Finding]:
    """Retrieve verified findings for a completed or ongoing scan."""
    scan_model = db.query(ScanModel).filter(ScanModel.id == str(scan_id)).first()
    if not scan_model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found.",
        )

    finding_models = db.query(FindingModel).filter(FindingModel.scan_id == str(scan_id)).all()
    results: List[Finding] = []

    for fm in finding_models:
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

        results.append(
            Finding(
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
        )

    return results
