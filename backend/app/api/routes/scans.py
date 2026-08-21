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

from app.agents.checkpointer import get_sqlite_checkpointer
from app.agents.graph import run_analysis_workflow
from app.analysis.service import get_intelligence_service
from app.context.runtime import ScanIntelligenceRuntime
from app.core.database import SessionLocal, get_db
from app.ingestion.clone import (
    InvalidRepositoryURLError,
    clone_repository,
    get_git_resolved_branch_or_ref,
    validate_github_url,
)
from app.ingestion.snapshot import get_snapshot_service
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


async def execute_background_scan(
    scan_id: str,
    repo_url: str,
    branch: Optional[str],
    checkpoint_db_path: Optional[str] = None,
):
    """Asynchronously execute repository cloning, intelligence analysis, and durable multi-agent workflow."""
    db: Session = SessionLocal()
    workspace_dir: Optional[str] = None

    try:
        # 1. Update status to RUNNING
        scan_model = db.query(ScanModel).filter(ScanModel.id == scan_id).first()
        if not scan_model:
            return
        scan_model.status = ScanStatus.RUNNING.value
        db.commit()

        # 2. Materialize exact snapshot if commit_hash already exists (e.g. on resume), or clone safely
        snapshot_service = get_snapshot_service()
        requested_branch = branch
        resolved_branch = None

        if scan_model.commit_hash and scan_model.commit_hash != "unknown" and len(scan_model.commit_hash.strip()) >= 7:
            workspace_dir = await asyncio.to_thread(
                snapshot_service.materialize_snapshot_from_metadata,
                repository_url=repo_url,
                commit_hash=scan_model.commit_hash,
                branch=branch,
            )
            commit_sha = scan_model.commit_hash
            resolved_branch = f"HEAD@{commit_sha[:8]}"
        else:
            workspace_dir, commit_sha = await asyncio.to_thread(
                clone_repository,
                repo_url=repo_url,
                branch=branch,
            )
            resolved_branch = get_git_resolved_branch_or_ref(workspace_dir)
            scan_model.commit_hash = commit_sha
            scan_model.branch = resolved_branch or requested_branch
            meta = scan_model.model_metadata or {}
            meta.update({
                "requested_branch": requested_branch,
                "resolved_branch_or_ref": resolved_branch,
                "commit_sha": commit_sha,
            })
            scan_model.model_metadata = meta
            db.commit()

        # 3. Run deterministic intelligence service (manifest + scanners)
        service = get_intelligence_service()
        evidence_store = await service.analyze_repository(
            repo_dir=workspace_dir,
            repository_url=repo_url,
            commit_hash=commit_sha,
            branch=resolved_branch or requested_branch,
            requested_branch=requested_branch,
            resolved_branch_or_ref=resolved_branch,
        )

        # 4. Assemble canonical ScanIntelligenceRuntime from EvidenceStore
        runtime = await ScanIntelligenceRuntime.build(
            evidence_store=evidence_store,
            repo_dir=workspace_dir,
        )

        # 5. Run durable LangGraph multi-agent analysis workflow using canonical SQLite checkpointer
        async with get_sqlite_checkpointer(db_path=checkpoint_db_path) as checkpointer:
            final_state = await run_analysis_workflow(
                evidence_store=evidence_store,
                scan_id=scan_id,
                repo_dir=workspace_dir,
                checkpointer=checkpointer,
                resume_if_exists=True,
                context_engine=runtime.context_engine,
                repository_graph=runtime.repository_graph,
            )

        # 6. Check for terminal workflow failure
        if final_state.get("status") == "FAILED":
            scan_model.status = ScanStatus.FAILED.value
            scan_model.completed_at = _utc_now()
            errors = final_state.get("errors", [])
            scan_model.model_metadata = {
                "error": "; ".join(errors) if errors else "Terminal workflow failure"
            }
            db.commit()
            return

        # 7. Persist verified findings into database (idempotent, no duplicates on resume)
        existing_finding_ids = {
            f_id for (f_id,) in db.query(FindingModel.id).filter(FindingModel.scan_id == scan_id).all()
        }
        raw_verified_findings = final_state.get("verified_findings", [])
        for item in raw_verified_findings:
            if isinstance(item, dict):
                f = Finding.model_validate(item)
            else:
                f = item

            if str(f.id) in existing_finding_ids:
                continue

            sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            stat_val = f.status.value if hasattr(f.status, "value") else str(f.status)
            verdict_val = None
            if f.verification_verdict is not None:
                verdict_val = f.verification_verdict.value if hasattr(f.verification_verdict, "value") else str(f.verification_verdict)

            finding_model = FindingModel(
                id=str(f.id),
                scan_id=scan_id,
                title=f.title,
                description=f.description,
                severity=sev_val,
                status=stat_val,
                rule_id=f.rule_id,
                category=f.category,
                mitigation_guidance=f.mitigation_guidance,
                verification_verdict=verdict_val,
                verification_reason=f.verification_reason,
                model_metadata=f.model_metadata.model_dump() if f.model_metadata and hasattr(f.model_metadata, "model_dump") else (f.model_metadata if isinstance(f.model_metadata, dict) else None),
            )

            for ev in f.evidences:
                if isinstance(ev, dict):
                    ev_id = str(ev.get("id", uuid4()))
                    ev_fp = ev.get("file_path", "")
                    ev_sl = ev.get("start_line")
                    ev_el = ev.get("end_line")
                    ev_cs = ev.get("code_snippet")
                    ev_cn = ev.get("context_notes")
                else:
                    ev_id = str(ev.id)
                    ev_fp = ev.file_path
                    ev_sl = ev.start_line
                    ev_el = ev.end_line
                    ev_cs = ev.code_snippet
                    ev_cn = ev.context_notes

                ev_model = EvidenceModel(
                    id=ev_id,
                    finding_id=str(f.id),
                    file_path=ev_fp,
                    start_line=ev_sl,
                    end_line=ev_el,
                    code_snippet=ev_cs,
                    context_notes=ev_cn,
                )
                finding_model.evidences.append(ev_model)

            db.add(finding_model)

        # 8. Mark scan COMPLETED
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

    # 2. Create Scan record in DB without pre-assuming "main"
    req_branch = payload.requested_branch if payload.requested_branch is not None else payload.branch
    scan_model = ScanModel(
        repository_url=normalized_url,
        branch=req_branch,
        status=ScanStatus.PENDING.value,
        created_at=_utc_now(),
        model_metadata={"requested_branch": req_branch} if req_branch else {},
    )
    db.add(scan_model)
    db.commit()
    db.refresh(scan_model)

    # 3. Launch background async execution
    asyncio.create_task(
        execute_background_scan(
            scan_id=scan_model.id,
            repo_url=normalized_url,
            branch=req_branch,
        )
    )

    return Scan(
        id=UUID(scan_model.id),
        repository_url=scan_model.repository_url,
        branch=scan_model.branch,
        requested_branch=req_branch,
        resolved_branch_or_ref=scan_model.branch,
        commit_hash=scan_model.commit_hash,
        commit_sha=scan_model.commit_hash,
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

    meta = scan_model.model_metadata or {}
    req_branch = meta.get("requested_branch") if isinstance(meta, dict) else None
    res_branch = meta.get("resolved_branch_or_ref") if isinstance(meta, dict) else None

    return Scan(
        id=UUID(scan_model.id),
        repository_url=scan_model.repository_url,
        branch=scan_model.branch,
        requested_branch=req_branch,
        resolved_branch_or_ref=res_branch or scan_model.branch,
        commit_hash=scan_model.commit_hash,
        commit_sha=scan_model.commit_hash,
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
