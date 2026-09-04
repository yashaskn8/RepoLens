"""Scans API endpoints and asynchronous execution coordinator."""

import asyncio
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
import shutil
from typing import List, Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from app.agents.checkpointer import get_sqlite_checkpointer
from app.agents.graph import run_analysis_workflow
from app.analysis.service import get_intelligence_service
from app.artifacts.scan_provenance import (
    publish_analysis_artifacts,
    publish_finding_provenance,
    publish_graph_artifacts,
    publish_repository_revision,
)
from app.api.dependencies import get_current_user, verify_csrf
from app.api.idempotency import idempotency_identity
from app.context.runtime import ScanIntelligenceRuntime
from app.core.config import get_settings
from app.core.database import SessionLocal, get_db
from app.execution.application import (
    NewWorkPaused,
    WorkSubmissionService,
    deterministic_resource_id,
)
from app.execution.dispatcher import DurableWorkDispatcher
from app.execution.errors import IdempotencyConflict
from app.execution.types import RequestBudget, ResourceProfile, WorkKind
from app.governance.taxonomy import FailureCode as GovernanceFailureCode, safe_failure
from app.governance.events import AuditLedger, DomainOutbox
from app.ingestion.clone import (
    InvalidRepositoryURLError,
    clone_repository,
    get_git_resolved_branch_or_ref,
    validate_github_url,
)
from app.ingestion.snapshot import get_snapshot_service
from app.models.finding import EvidenceModel, FindingModel
from app.models.scan import ScanModel
from app.schemas.auth import CurrentUser
from app.schemas.enums import FindingStatus, ScanStatus, Severity, UsageOperation, VerificationVerdict
from app.schemas.evidence import Evidence
from app.schemas.finding import Finding
from app.schemas.metadata import ModelExecutionMetadata
from app.schemas.scan import Scan, ScanCreate
from app.schemas.static_finding import ToolStatus
from app.schemas.workflow_event import WorkflowEventCreate, WorkflowEventType
from app.security.redaction import redact_secrets
from app.schemas.auth import get_user_id
from app.services.authorization_service import get_owned_scan_or_404
from app.services.finding_grounding import (
    canonicalize_repository_evidences,
    is_canonical_confirmed_finding,
)
from app.services.quota_service import check_and_increment_quota
from app.services.workflow_event_service import WorkflowEventService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/scans", tags=["Scans"])


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _scan_request_budget() -> RequestBudget:
    settings = get_settings()
    return RequestBudget(
        max_wall_clock_seconds=settings.MAX_SCAN_DURATION_SECONDS,
        max_analyzer_seconds=settings.MAX_SCAN_DURATION_SECONDS,
        max_ai_calls=12,
        max_input_tokens=500_000,
        max_output_tokens=100_000,
        max_escalation_tier=2,
        max_retrieval_context_tokens=250_000,
    )


def _scan_resource(db: Session, scan_model: ScanModel) -> Scan:
    candidate_findings = (
        db.query(FindingModel)
        .filter(
            FindingModel.scan_id == scan_model.id,
            FindingModel.verification_verdict == VerificationVerdict.CONFIRMED.value,
        )
        .all()
    )
    findings_count = sum(
        1
        for finding in candidate_findings
        if is_canonical_confirmed_finding(
            finding,
            expected_commit_sha=scan_model.commit_hash or "__missing_commit__",
        )
    )
    metadata = scan_model.model_metadata if isinstance(scan_model.model_metadata, dict) else {}
    model_metadata = (
        ModelExecutionMetadata(model_name="RepoLens-MultiAgent", extra_metadata=metadata)
        if metadata
        else None
    )
    requested_branch = metadata.get("requested_branch")
    resolved_branch = metadata.get("resolved_branch_or_ref")
    return Scan(
        id=UUID(scan_model.id),
        repository_url=scan_model.repository_url,
        branch=scan_model.branch,
        requested_branch=requested_branch,
        resolved_branch_or_ref=resolved_branch or scan_model.branch,
        commit_hash=scan_model.commit_hash,
        commit_sha=scan_model.commit_hash,
        status=ScanStatus(scan_model.status),
        findings_count=findings_count,
        findings=[],
        model_metadata=model_metadata,
        created_at=scan_model.created_at,
        completed_at=scan_model.completed_at,
    )


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
        # 1. Update status to RUNNING and emit SCAN_STARTED
        scan_model = db.query(ScanModel).filter(ScanModel.id == scan_id).first()
        if not scan_model:
            return
        scan_model.status = ScanStatus.RUNNING.value
        db.commit()
        WorkflowEventService.emit(
            db=db,
            event=WorkflowEventCreate(
                event_type=WorkflowEventType.SCAN_STARTED,
                scan_id=UUID(scan_id),
                message="Repository clone and scan execution started",
                metadata_payload={"repository_url": repo_url, "branch": branch},
            ),
        )

        # 2. Materialize exact snapshot if commit_hash already exists (e.g. on resume), or clone safely
        snapshot_service = get_snapshot_service()
        requested_branch = branch
        resolved_branch = None

        if scan_model.commit_hash and scan_model.commit_hash != "unknown" and len(scan_model.commit_hash.strip()) == 40:
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
            meta = dict(scan_model.model_metadata or {})
            meta.update({
                "requested_branch": requested_branch,
                "resolved_branch_or_ref": resolved_branch,
                "commit_sha": commit_sha,
            })
            scan_model.model_metadata = meta
            flag_modified(scan_model, "model_metadata")
            db.commit()

        revision_artifact_id = publish_repository_revision(
            db,
            scan=scan_model,
            commit_sha=commit_sha,
            resolved_branch=resolved_branch or requested_branch,
        )
        revision_meta = dict(scan_model.model_metadata or {})
        revision_meta["repository_revision_artifact_id"] = revision_artifact_id
        scan_model.model_metadata = revision_meta
        flag_modified(scan_model, "model_metadata")
        db.commit()

        # 3. Run deterministic intelligence service (manifest + scanners)
        WorkflowEventService.emit(
            db=db,
            event=WorkflowEventCreate(
                event_type=WorkflowEventType.STAGE_STARTED,
                scan_id=UUID(scan_id),
                stage="intelligence_analysis",
                commit_sha=commit_sha,
                message="Deterministic repository parsing and static scanner execution started",
            ),
        )

        service = get_intelligence_service()
        evidence_store = await service.analyze_repository(
            repo_dir=workspace_dir,
            repository_url=repo_url,
            commit_hash=commit_sha,
            branch=resolved_branch or requested_branch,
            requested_branch=requested_branch,
            resolved_branch_or_ref=resolved_branch,
        )

        # Build scanner summary and update scan metadata
        scanner_summary = []
        tool_events_to_emit = []
        for tool_name, result in (evidence_store.scanner_results or {}).items():
            findings_count = len(result.findings) if result.findings else 0
            if result.status == ToolStatus.COMPLETED:
                evt_type = WorkflowEventType.TOOL_COMPLETED
                msg = f"Deterministic scanner {tool_name} completed with {findings_count} findings"
            elif result.status == ToolStatus.UNAVAILABLE:
                evt_type = WorkflowEventType.TOOL_UNAVAILABLE
                msg = f"Deterministic scanner {tool_name} is unavailable on host"
            elif result.status == ToolStatus.TIMEOUT:
                evt_type = WorkflowEventType.TOOL_FAILED
                msg = f"Deterministic scanner {tool_name} timed out"
            elif result.status == ToolStatus.INVALID_OUTPUT:
                evt_type = WorkflowEventType.TOOL_FAILED
                msg = f"Deterministic scanner {tool_name} produced invalid output"
            else:
                evt_type = WorkflowEventType.TOOL_FAILED
                msg = f"Deterministic scanner {tool_name} failed execution"

            safe_reason = None
            if result.error_message:
                safe_reason = redact_secrets(str(result.error_message))[:512]

            safe_payload = {
                "status": result.status.value,
                "findings_count": findings_count,
            }
            if safe_reason:
                safe_payload["reason"] = safe_reason

            tool_events_to_emit.append(
                WorkflowEventCreate(
                    event_type=evt_type,
                    scan_id=UUID(scan_id),
                    stage="intelligence_analysis",
                    tool_name=tool_name,
                    commit_sha=commit_sha,
                    message=msg,
                    metadata_payload=safe_payload,
                )
            )

            scanner_summary.append({
                "tool": tool_name,
                "status": result.status.value,
                "findings_count": findings_count,
                "failure_reason": safe_reason,
            })

        # Update scan metadata with analysis scope and scanner coverage
        meta = dict(scan_model.model_metadata or {})
        meta["scanner_coverage"] = scanner_summary
        if evidence_store.manifest.analysis_scope:
            meta["analysis_scope"] = evidence_store.manifest.analysis_scope.model_dump()
        if evidence_store.manifest.languages:
            meta["languages"] = evidence_store.manifest.languages
        if evidence_store.manifest.frameworks:
            meta["frameworks"] = [f.name for f in evidence_store.manifest.frameworks]
        artifact_projection = publish_analysis_artifacts(
            db,
            scan=scan_model,
            commit_sha=commit_sha,
            revision_artifact_id=revision_artifact_id,
            scanner_summary=scanner_summary,
            manifest_summary={
                "total_files": evidence_store.manifest.total_files,
                "total_size_bytes": evidence_store.manifest.total_size_bytes,
                "languages": evidence_store.manifest.languages,
                "frameworks": [f.name for f in (evidence_store.manifest.frameworks or [])],
                "analysis_scope": (
                    evidence_store.manifest.analysis_scope.model_dump(mode="json")
                    if evidence_store.manifest.analysis_scope
                    else None
                ),
            },
        )
        meta.update(artifact_projection)
        meta["artifact_lineage"] = [
            artifact_projection["repository_revision_artifact_id"],
            artifact_projection["analyzer_run_artifact_id"],
            artifact_projection["coverage_artifact_id"],
            *artifact_projection["scanner_artifact_ids"].values(),
        ]
        scan_model.model_metadata = meta
        flag_modified(scan_model, "model_metadata")
        db.commit()

        # Emit tool events and stage completion independently
        for tool_event in tool_events_to_emit:
            WorkflowEventService.emit(db=db, event=tool_event)

        WorkflowEventService.emit(
            db=db,
            event=WorkflowEventCreate(
                event_type=WorkflowEventType.STAGE_COMPLETED,
                scan_id=UUID(scan_id),
                stage="intelligence_analysis",
                commit_sha=commit_sha,
                message="Deterministic static scanners completed",
                metadata_payload={"total_files": evidence_store.manifest.total_files},
            ),
        )

        # 4. Assemble canonical ScanIntelligenceRuntime from EvidenceStore
        runtime = await ScanIntelligenceRuntime.build(
            evidence_store=evidence_store,
            repo_dir=workspace_dir,
        )
        graph_projection = publish_graph_artifacts(
            db,
            scan=scan_model,
            commit_sha=commit_sha,
            revision_artifact_id=revision_artifact_id,
            analyzer_artifact_id=artifact_projection["analyzer_run_artifact_id"],
            graph_data=runtime.repository_graph.to_domain_data(),
        )
        graph_meta = dict(scan_model.model_metadata or {})
        graph_meta.update(graph_projection)
        graph_meta["artifact_lineage"] = [
            *(graph_meta.get("artifact_lineage") or []),
            graph_projection["symbol_index_artifact_id"],
            graph_projection["contract_artifact_id"],
        ]
        scan_model.model_metadata = graph_meta
        flag_modified(scan_model, "model_metadata")
        db.commit()

        # 5. Run durable LangGraph multi-agent analysis workflow using canonical SQLite checkpointer
        WorkflowEventService.emit(
            db=db,
            event=WorkflowEventCreate(
                event_type=WorkflowEventType.STAGE_STARTED,
                scan_id=UUID(scan_id),
                stage="multi_agent_workflow",
                commit_sha=commit_sha,
                message="LangGraph multi-agent analysis workflow started",
            ),
        )
        db.commit()

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

        WorkflowEventService.emit(
            db=db,
            event=WorkflowEventCreate(
                event_type=WorkflowEventType.STAGE_COMPLETED,
                scan_id=UUID(scan_id),
                stage="multi_agent_workflow",
                commit_sha=commit_sha,
                message="LangGraph multi-agent analysis workflow completed",
            ),
        )
        db.commit()

        # 6. Check for terminal workflow failure
        if final_state.get("status") == "FAILED":
            scan_model.status = ScanStatus.FAILED.value
            scan_model.completed_at = _utc_now()
            errors = final_state.get("errors", [])
            existing_meta = dict(scan_model.model_metadata or {})
            existing_meta["error"] = "; ".join(errors) if errors else "Terminal workflow failure"
            scan_model.model_metadata = existing_meta
            flag_modified(scan_model, "model_metadata")
            db.commit()
            WorkflowEventService.emit(
                db=db,
                event=WorkflowEventCreate(
                    event_type=WorkflowEventType.SCAN_FAILED,
                    scan_id=UUID(scan_id),
                    commit_sha=commit_sha,
                    message="Terminal workflow failure",
                    metadata_payload={"errors": errors},
                ),
            )
            return

        # 7. Persist verified findings into database (idempotent, no duplicates on resume)
        existing_finding_models = db.query(FindingModel).filter(FindingModel.scan_id == scan_id).all()
        existing_findings_by_id = {str(existing.id): existing for existing in existing_finding_models}
        existing_finding_ids = set(existing_findings_by_id)
        existing_canonical_count = sum(
            1
            for existing in existing_finding_models
            if is_canonical_confirmed_finding(existing, expected_commit_sha=commit_sha)
        )
        raw_verified_findings = list(final_state.get("verified_findings", []) or [])
        newly_persisted_findings: list[Finding] = []
        excluded_candidate_keys: set[str] = set()
        for index, item in enumerate(raw_verified_findings):
            try:
                f = Finding.model_validate(item) if isinstance(item, dict) else item
                verdict = getattr(f.verification_verdict, "value", f.verification_verdict)
                canonical_evidences = canonicalize_repository_evidences(
                    repo_dir=workspace_dir,
                    commit_sha=commit_sha,
                    evidences=f.evidences,
                )
            except (TypeError, ValueError, OSError):
                candidate_id = item.get("id") if isinstance(item, dict) else getattr(item, "id", None)
                excluded_candidate_keys.add(str(candidate_id or f"invalid:{index}"))
                continue

            # The workflow's list name is not an authority boundary.  Only an
            # explicit CONFIRMED verdict with source re-read from the exact
            # repository snapshot can enter canonical persistence.
            if str(verdict or "").upper() != VerificationVerdict.CONFIRMED.value or not canonical_evidences:
                excluded_candidate_keys.add(str(f.id))
                continue
            f.evidences = canonical_evidences

            if str(f.id) in existing_finding_ids:
                if not is_canonical_confirmed_finding(
                    existing_findings_by_id[str(f.id)],
                    expected_commit_sha=commit_sha,
                ):
                    excluded_candidate_keys.add(str(f.id))
                continue

            provenance = publish_finding_provenance(
                db,
                scan=scan_model,
                commit_sha=commit_sha,
                revision_artifact_id=revision_artifact_id,
                analyzer_artifact_id=artifact_projection["analyzer_run_artifact_id"],
                finding=f,
            )

            sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            stat_val = f.status.value if hasattr(f.status, "value") else str(f.status)
            verdict_val = None
            if f.verification_verdict is not None:
                verdict_val = f.verification_verdict.value if hasattr(f.verification_verdict, "value") else str(f.verification_verdict)

            finding_metadata = (
                f.model_metadata.model_dump(mode="json")
                if f.model_metadata and hasattr(f.model_metadata, "model_dump")
                else (dict(f.model_metadata) if isinstance(f.model_metadata, dict) else {})
            )
            if "model_name" in finding_metadata:
                extra_metadata = dict(finding_metadata.get("extra_metadata") or {})
                extra_metadata["provenance"] = provenance
                finding_metadata["extra_metadata"] = extra_metadata
            else:
                finding_metadata["provenance"] = provenance

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
                source_tool=getattr(f, "source_tool", None),
                detector_id=getattr(f, "detector_id", None),
                detector_kind=getattr(f, "detector_kind", None),
                model_metadata=finding_metadata,
            )

            for ev in f.evidences:
                if isinstance(ev, dict):
                    ev_id = str(ev.get("id") or uuid4())
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
            newly_persisted_findings.append(f)
            finding_state_digest = hashlib.sha256(json.dumps(
                {
                    "finding_id": str(f.id),
                    "scan_id": scan_id,
                    "severity": sev_val,
                    "status": stat_val,
                    "verification_verdict": verdict_val,
                    "finding_artifact_id": provenance["finding_artifact_id"],
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")).hexdigest()
            AuditLedger.append(
                db,
                tenant_id=str(scan_model.owner_user_id or "legacy-local"),
                actor_id=scan_model.owner_user_id,
                event_type="FINDING_VALIDATED",
                resource_type="FINDING",
                resource_id=str(f.id),
                state_digest=finding_state_digest,
                payload={
                    "scan_id": scan_id,
                    "verification_verdict": verdict_val,
                    "finding_artifact_id": provenance["finding_artifact_id"],
                },
            )
            DomainOutbox.append(
                db,
                tenant_id=str(scan_model.owner_user_id or "legacy-local"),
                aggregate_type="FINDING",
                aggregate_id=str(f.id),
                event_type="FINDING_VALIDATED",
                deduplication_key=f"finding:{f.id}:validated",
                payload={
                    "scan_id": scan_id,
                    "finding_artifact_id": provenance["finding_artifact_id"],
                },
            )

        for index, item in enumerate(final_state.get("rejected_findings", []) or []):
            if isinstance(item, dict):
                candidate_id = item.get("finding_id") or item.get("id")
            else:
                candidate_id = getattr(item, "finding_id", None) or getattr(item, "id", None)
            excluded_candidate_keys.add(str(candidate_id or f"diagnostic:{index}"))

        # 8. Mark scan COMPLETED and preserve merged metadata
        scan_model.status = ScanStatus.COMPLETED.value
        scan_model.completed_at = _utc_now()
        existing_meta = dict(scan_model.model_metadata or {})
        existing_meta.update({
            "architecture_overview": final_state.get("architecture_overview"),
            "languages": final_state.get("languages", {}),
            "frameworks": final_state.get("frameworks", []),
            "total_files": evidence_store.manifest.total_files,
            "total_size_bytes": evidence_store.manifest.total_size_bytes,
            "analysis_scope": evidence_store.manifest.analysis_scope.model_dump() if getattr(evidence_store.manifest, "analysis_scope", None) else None,
            "ai_admission": final_state.get("ai_admission", {}),
            "ai_cloud_budget": final_state.get("ai_cloud_budget", {}),
            "verification_summary": {
                "canonical_confirmed_findings": existing_canonical_count + len(newly_persisted_findings),
                "excluded_noncanonical_findings": len(excluded_candidate_keys),
            },
        })
        scan_model.model_metadata = existing_meta
        flag_modified(scan_model, "model_metadata")
        db.commit()

        # Emit finding confirmed events and scan completed event independently
        for f in newly_persisted_findings:
            sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            WorkflowEventService.emit(
                db=db,
                event=WorkflowEventCreate(
                    event_type=WorkflowEventType.FINDING_CONFIRMED,
                    scan_id=UUID(scan_id),
                    finding_id=UUID(str(f.id)),
                    commit_sha=commit_sha,
                    message=f"Confirmed grounded finding: {f.title} ({sev_val})",
                    metadata_payload={"severity": sev_val, "category": f.category, "source_tool": getattr(f, "source_tool", None)},
                ),
            )

        WorkflowEventService.emit(
            db=db,
            event=WorkflowEventCreate(
                event_type=WorkflowEventType.SCAN_COMPLETED,
                scan_id=UUID(scan_id),
                commit_sha=commit_sha,
                message="Scan completed successfully",
                metadata_payload={
                    "findings_count": existing_canonical_count + len(newly_persisted_findings),
                    "excluded_noncanonical_findings": len(excluded_candidate_keys),
                },
            ),
        )

    except Exception as exc:
        failure = safe_failure(exc, default=GovernanceFailureCode.INTERNAL_INVARIANT_VIOLATION)
        logger.error("Scan %s failed (%s)", scan_id, failure.code.value, exc_info=True)
        try:
            scan_model = db.query(ScanModel).filter(ScanModel.id == scan_id).first()
            if scan_model:
                scan_model.status = ScanStatus.FAILED.value
                scan_model.completed_at = _utc_now()
                meta = dict(scan_model.model_metadata or {})
                meta["failure_code"] = failure.code.value
                meta["failure_message"] = failure.message
                scan_model.model_metadata = meta
                flag_modified(scan_model, "model_metadata")
                db.commit()
                WorkflowEventService.emit(
                    db=db,
                    event=WorkflowEventCreate(
                        event_type=WorkflowEventType.SCAN_FAILED,
                        scan_id=UUID(scan_id),
                        message=f"Scan execution failed: {failure.message}",
                        metadata_payload={"failure_code": failure.code.value},
                    ),
                )
        except Exception:
            pass
    finally:
        db.close()
        # Clean up temporary workspace directory
        if workspace_dir and os.path.exists(workspace_dir):
            shutil.rmtree(workspace_dir, ignore_errors=True)


@router.post("", response_model=Scan, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(
    payload: ScanCreate,
    request: Request,
    response: Response,
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    current_user: CurrentUser = Depends(get_current_user),
    _csrf: None = Depends(verify_csrf),
    db: Session = Depends(get_db),
) -> Scan:
    """Initiate a new repository scan asynchronously, returning scan ID immediately."""
    # Validate before consuming quota or creating an idempotency identity.
    try:
        normalized_url = validate_github_url(payload.repository_url)
    except InvalidRepositoryURLError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid repository URL: {str(exc)}",
        )

    req_branch = payload.requested_branch if payload.requested_branch is not None else payload.branch
    external_identity = idempotency_identity(
        "scan-create",
        idempotency_key,
        maximum=get_settings().IDEMPOTENCY_KEY_MAX_LENGTH,
    )
    scan_id = (
        deterministic_resource_id(current_user.id, "scan", external_identity)
        if external_identity
        else str(uuid4())
    )
    request_payload = {"repository_url": normalized_url, "branch": req_branch}
    submission_service = WorkSubmissionService()

    if external_identity:
        existing_work = submission_service.find_by_external_identity(
            db,
            tenant_id=current_user.id,
            work_kind=WorkKind.SCAN,
            identity=external_identity,
        )
        if existing_work is not None:
            try:
                submission = submission_service.submit(
                    db,
                    tenant_id=current_user.id,
                    actor_id=current_user.id,
                    request_id=getattr(request.state, "request_id", str(uuid4())),
                    work_kind=WorkKind.SCAN,
                    resource_type="SCAN",
                    resource_id=scan_id,
                    request_payload=request_payload,
                    idempotency_key=external_identity,
                    external_idempotency_key=external_identity,
                    resource_profile=ResourceProfile.SMALL_REPO_SCAN,
                    budget=_scan_request_budget(),
                    allow_when_paused=True,
                )
            except IdempotencyConflict as exc:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail={"error_code": "IDEMPOTENCY_CONFLICT", "message": str(exc)},
                ) from exc
            existing_scan = db.query(ScanModel).filter(
                ScanModel.id == existing_work.resource_id,
                ScanModel.owner_user_id == current_user.id,
            ).first()
            if existing_scan is None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail={
                        "error_code": "IDEMPOTENCY_STATE_MISMATCH",
                        "message": "The existing job no longer has a resolvable scan resource.",
                    },
                )
            db.commit()
            response.headers["Location"] = f"/api/v1/jobs/{submission.result.work_item_id}"
            response.headers["Idempotency-Replayed"] = "true"
            return _scan_resource(db, existing_scan)

    check_and_increment_quota(db, current_user.id, UsageOperation.SCAN_CREATE.value)
    scan_model = ScanModel(
        id=scan_id,
        repository_url=normalized_url,
        branch=req_branch,
        owner_user_id=get_user_id(current_user),
        status=ScanStatus.PENDING.value,
        created_at=_utc_now(),
        model_metadata={"requested_branch": req_branch} if req_branch else {},
    )
    db.add(scan_model)
    try:
        submission = submission_service.submit(
            db,
            tenant_id=current_user.id,
            actor_id=current_user.id,
            request_id=getattr(request.state, "request_id", str(uuid4())),
            work_kind=WorkKind.SCAN,
            resource_type="SCAN",
            resource_id=scan_id,
            request_payload=request_payload,
            idempotency_key=external_identity or f"scan:{scan_id}",
            external_idempotency_key=external_identity,
            resource_profile=ResourceProfile.SMALL_REPO_SCAN,
            budget=_scan_request_budget(),
        )
    except NewWorkPaused as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error_code": "NEW_JOBS_PAUSED", "message": str(exc)},
        ) from exc
    except IdempotencyConflict as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error_code": "IDEMPOTENCY_CONFLICT", "message": str(exc)},
        ) from exc

    WorkflowEventService.emit_critical(
        db=db,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.SCAN_CREATED,
            scan_id=UUID(scan_model.id),
            actor_user_id=get_user_id(current_user),
            message="Scan registered and queued for execution",
            metadata_payload={"repository_url": normalized_url, "branch": req_branch},
        ),
    )
    db.commit()
    db.refresh(scan_model)

    DurableWorkDispatcher.nudge()
    response.headers["Location"] = f"/api/v1/jobs/{submission.result.work_item_id}"
    response.headers["Idempotency-Replayed"] = "false"
    return _scan_resource(db, scan_model)


@router.get("", response_model=List[Scan])
def list_scans(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[Scan]:
    """List the authenticated user's most recent repository scans."""
    rows = (
        db.query(ScanModel)
        .filter(ScanModel.owner_user_id == get_user_id(current_user))
        .order_by(ScanModel.created_at.desc(), ScanModel.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [_scan_resource(db, row) for row in rows]


@router.get("/{scan_id}", response_model=Scan)
def get_scan(
    scan_id: UUID,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Scan:
    """Retrieve scan status, metadata, and progress by ID."""
    scan_model = get_owned_scan_or_404(db, str(scan_id), current_user)

    return _scan_resource(db, scan_model)


@router.get("/{scan_id}/findings", response_model=List[Finding])
def get_scan_findings(
    scan_id: UUID,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[Finding]:
    """Retrieve verified findings for a completed or ongoing scan."""
    scan_model = get_owned_scan_or_404(db, str(scan_id), current_user)

    finding_models = (
        db.query(FindingModel)
        .filter(
            FindingModel.scan_id == str(scan_id),
            FindingModel.verification_verdict == VerificationVerdict.CONFIRMED.value,
        )
        .order_by(FindingModel.created_at.desc(), FindingModel.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    results: List[Finding] = []

    for fm in finding_models:
        if not is_canonical_confirmed_finding(
            fm,
            expected_commit_sha=scan_model.commit_hash or "__missing_commit__",
        ):
            continue
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
                source_tool=fm.source_tool,
                detector_id=fm.detector_id,
                detector_kind=fm.detector_kind,
                evidences=evidences,
                model_metadata=metadata,
                created_at=fm.created_at,
                updated_at=fm.updated_at,
            )
        )

    return results


@router.get("/{scan_id}/events")
async def stream_scan_events(
    scan_id: UUID,
    request: Request,
    current_user: CurrentUser = Depends(get_current_user),
    last_event_id: Optional[str] = Header(default=None, alias="Last-Event-ID"),
    after_id: Optional[int] = Query(default=None),
    db: Session = Depends(get_db),
):
    """Server-Sent Events (SSE) stream delivering durable workflow events in near real time."""
    import json
    from fastapi.responses import StreamingResponse
    from app.schemas.workflow_event import WorkflowEventResponse

    # 1. Verify scan exists and belongs to current user
    scan_model = get_owned_scan_or_404(db, str(scan_id), current_user)

    # 2. Parse starting event offset
    start_id = 0
    if last_event_id is not None and last_event_id.strip():
        try:
            start_id = int(last_event_id.strip())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid Last-Event-ID header value: '{last_event_id}'. Expected integer ID.",
            )
    elif after_id is not None:
        start_id = max(0, after_id)

    from sqlalchemy.orm import sessionmaker

    # Helper to obtain a short-lived session against the active database engine
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=db.bind) if db and db.bind else SessionLocal

    async def event_generator():
        current_id = start_id
        heartbeat_ticks = 0

        while True:
            if await request.is_disconnected():
                break

            poll_db = session_factory()
            try:
                events = WorkflowEventService.list_after_id(
                    db=poll_db,
                    scan_id=str(scan_id),
                    after_id=current_id,
                    limit=100,
                )
                current_scan = poll_db.query(ScanModel).filter(ScanModel.id == str(scan_id)).first()
                is_terminal = (
                    current_scan.status in (ScanStatus.COMPLETED.value, ScanStatus.FAILED.value)
                    if current_scan
                    else False
                )
            finally:
                poll_db.close()

            if events:
                for evt in events:
                    current_id = evt.id
                    payload = WorkflowEventResponse.model_validate(evt).model_dump(mode="json")
                    data_str = json.dumps(payload)
                    yield f"id: {evt.id}\nevent: {evt.event_type}\ndata: {data_str}\n\n"
                heartbeat_ticks = 0
            else:
                if is_terminal:
                    # All events for completed/failed scan have been delivered
                    break

                heartbeat_ticks += 1
                if heartbeat_ticks >= 15:  # Every ~7.5s on 0.5s poll
                    yield ": heartbeat\n\n"
                    heartbeat_ticks = 0

            await asyncio.sleep(0.5)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/{scan_id}/report", response_model=None)
def get_scan_report(
    scan_id: UUID,
    format: str = Query(default="json", pattern="^(json|markdown)$"),
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve complete, evidence-grounded scan report in Markdown or JSON format."""
    from fastapi.responses import Response
    from app.services.report_service import ScanReportService

    get_owned_scan_or_404(db, str(scan_id), current_user)
    report = ScanReportService.build_scan_report(db=db, scan_id=str(scan_id))
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found.",
        )

    if format == "markdown":
        md_content = ScanReportService.render_markdown(report)
        return Response(
            content=md_content,
            media_type="text/markdown; charset=utf-8",
            headers={
                "Content-Disposition": f'inline; filename="repolens-report-{scan_id}.md"',
            },
        )

    return report


@router.get("/{scan_id}/report/markdown", response_class=Response)
def get_scan_report_markdown(
    scan_id: UUID,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve full GFM Markdown export report for a scan."""
    from fastapi.responses import Response
    from app.services.report_service import ScanReportService

    get_owned_scan_or_404(db, str(scan_id), current_user)
    report = ScanReportService.build_scan_report(db=db, scan_id=str(scan_id))
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found.",
        )

    md_content = ScanReportService.render_markdown(report)
    return Response(
        content=md_content,
        media_type="text/markdown; charset=utf-8",
        headers={
            "Content-Disposition": f'inline; filename="repolens-report-{scan_id}.md"',
        },
    )


@router.get("/{scan_id}/report/json", response_model=None)
def get_scan_report_json(
    scan_id: UUID,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve full structured JSON export report for a scan."""
    from app.services.report_service import ScanReportService

    get_owned_scan_or_404(db, str(scan_id), current_user)
    report = ScanReportService.build_scan_report(db=db, scan_id=str(scan_id))
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found.",
        )

    return report


@router.get("/{scan_id}/telemetry", response_model=None)
def get_scan_telemetry(
    scan_id: UUID,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve detailed execution telemetry and metric aggregation for a scan."""
    from app.services.report_service import ScanReportService

    get_owned_scan_or_404(db, str(scan_id), current_user)
    telemetry = ScanReportService.build_scan_telemetry(db=db, scan_id=str(scan_id))
    if not telemetry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found.",
        )

    return telemetry
