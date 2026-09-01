"""Application service for remediation work owned by the shared execution engine."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.analysis.service import get_intelligence_service
from app.artifacts.schemas import (
    ArtifactCoverage,
    ArtifactSensitivity,
    ArtifactType,
    CoverageStatus,
    LineageRelation,
    RetentionClass,
)
from app.artifacts.service import CanonicalArtifactService, get_artifact_store
from app.context.runtime import ScanIntelligenceRuntime
from app.execution.context import new_execution_session as SessionLocal
from app.execution.types import WorkKind
from app.governance.events import AuditLedger, DomainOutbox
from app.ingestion.snapshot import get_snapshot_service
from app.models.artifact import ArtifactModel, ArtifactReferenceModel
from app.models.execution import WorkItemModel
from app.models.finding import FindingModel
from app.models.patch import PatchModel
from app.models.scan import ScanModel
from app.patching.schemas import PatchWorkflowResult
from app.patching.workflow import PatchWorkflowCoordinator
from app.planning.schemas import FixPlan
from app.planning.service import FixPlanningService
from app.research.service import ResearchService
from app.schemas.enums import PatchStatus, ScanStatus, VerificationVerdict
from app.schemas.workflow_event import WorkflowEventCreate, WorkflowEventType
from app.services.domain_mapping import finding_model_to_schema
from app.services.workflow_event_service import WorkflowEventService


@dataclass(frozen=True)
class RemediationExecutionResult:
    artifact_id: str
    artifact_digest: str
    result_kind: str
    patch_id: str | None = None
    reused: bool = False


class RemediationInvariantError(RuntimeError):
    pass


class RemediationExecutionService:
    """Execute and artifactize one remediation request against an exact revision."""

    async def execute(self, work_item_id: str) -> RemediationExecutionResult:
        db = SessionLocal()
        try:
            work = db.query(WorkItemModel).filter(WorkItemModel.id == work_item_id).first()
            if work is None:
                raise RemediationInvariantError("Remediation work item does not exist.")
            cached = self._existing_result(db, work)
            if cached is not None:
                return cached

            finding_id, parent_patch = self._resolve_subject(db, work)
            finding_model = (
                db.query(FindingModel)
                .join(ScanModel, ScanModel.id == FindingModel.scan_id)
                .filter(
                    FindingModel.id == finding_id,
                    ScanModel.owner_user_id == work.tenant_id,
                )
                .first()
            )
            if finding_model is None:
                raise RemediationInvariantError("Finding is missing or violates its tenant boundary.")
            scan = finding_model.scan
            if scan.status != ScanStatus.COMPLETED.value or not scan.commit_hash or scan.commit_hash == "unknown":
                raise RemediationInvariantError("Remediation requires a completed, revision-pinned scan.")
            if finding_model.verification_verdict != VerificationVerdict.CONFIRMED.value:
                raise RemediationInvariantError("Only confirmed findings may enter remediation.")
            finding = finding_model_to_schema(finding_model)

            async with get_snapshot_service().open_snapshot(scan_id=scan.id, db=db) as workspace_dir:
                evidence_store = await get_intelligence_service().analyze_repository(
                    repo_dir=workspace_dir,
                    repository_url=scan.repository_url,
                    commit_hash=scan.commit_hash,
                    branch=scan.branch,
                )
                if work.work_kind == WorkKind.RESEARCH.value:
                    result = await ResearchService().research_finding(
                        finding=finding,
                        manifest=evidence_store.manifest,
                    )
                    result_kind = "RESEARCH"
                    patch_id = None
                else:
                    runtime = await ScanIntelligenceRuntime.build(
                        evidence_store=evidence_store,
                        repo_dir=workspace_dir,
                    )
                    fix_plan = await FixPlanningService().create_fix_plan(
                        finding=finding,
                        context_engine=runtime.context_engine,
                        repository_graph=runtime.repository_graph,
                        manifest=runtime.manifest,
                    )
                    if not isinstance(fix_plan, FixPlan):
                        fix_plan = FixPlan.model_validate(fix_plan)
                    if work.work_kind == WorkKind.FIX_PLAN.value:
                        result = fix_plan
                        result_kind = "FIX_PLAN"
                        patch_id = None
                    else:
                        feedback = str((work.request_payload or {}).get("user_feedback") or "").strip()
                        if feedback:
                            fix_plan.objective = f"{fix_plan.objective} (Human reviewer feedback: {feedback})"
                        workflow_result = await PatchWorkflowCoordinator().execute_patch_workflow(
                            finding=finding,
                            fix_plan=fix_plan,
                            context_engine=runtime.context_engine,
                            original_repo_dir=workspace_dir,
                            manifest=runtime.manifest,
                        )
                        self._validate_patch_lineage(workflow_result, fix_plan, finding.id)
                        result = workflow_result
                        result_kind = "PATCH_REVISION" if parent_patch is not None else "PATCH_GENERATION"
                        patch_id = str(workflow_result.proposal.id)

            payload = self._result_payload(result)
            artifact = self._publish_result(
                db,
                work=work,
                scan=scan,
                finding=finding_model,
                result_kind=result_kind,
                payload=payload,
            )
            if work.work_kind == WorkKind.PATCH_GENERATION.value:
                self._persist_patch(
                    db,
                    work=work,
                    scan=scan,
                    fix_plan=fix_plan,
                    result=result,
                    result_artifact_id=artifact.artifact.artifact_id,
                    parent=parent_patch,
                )
            db.commit()
            return RemediationExecutionResult(
                artifact_id=artifact.artifact.artifact_id,
                artifact_digest=artifact.artifact.content_digest,
                result_kind=result_kind,
                patch_id=patch_id,
                reused=artifact.reused,
            )
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def load_result(db: Session, *, tenant_id: str, artifact_id: str) -> dict[str, Any]:
        record = CanonicalArtifactService(db).registry.get(
            tenant_id=tenant_id,
            artifact_id=artifact_id,
            include_tombstoned=False,
        )
        stream = get_artifact_store().get(record.payload_locator)
        try:
            payload = stream.read()
        finally:
            stream.close()
        if len(payload) > 16 * 1024 * 1024:
            raise RemediationInvariantError("Remediation result exceeds the API materialization limit.")
        if record.content_digest != hashlib.sha256(payload).hexdigest():
            raise RemediationInvariantError("Remediation artifact failed digest verification.")
        return json.loads(payload.decode("utf-8"))

    @staticmethod
    def _resolve_subject(db: Session, work: WorkItemModel) -> tuple[str, PatchModel | None]:
        if work.resource_type == "PATCH_REVISION":
            parent = db.query(PatchModel).filter(PatchModel.id == work.resource_id).first()
            if parent is None:
                raise RemediationInvariantError("Revision parent patch no longer exists.")
            return str(parent.finding_id), parent
        return str(work.resource_id), None

    @staticmethod
    def _existing_result(db: Session, work: WorkItemModel) -> RemediationExecutionResult | None:
        reference = (
            db.query(ArtifactReferenceModel, ArtifactModel)
            .join(ArtifactModel, ArtifactModel.id == ArtifactReferenceModel.artifact_id)
            .filter(
                ArtifactReferenceModel.tenant_id == work.tenant_id,
                ArtifactReferenceModel.referrer_kind == "WORK_ITEM",
                ArtifactReferenceModel.referrer_id == work.id,
                ArtifactModel.artifact_type == ArtifactType.REMEDIATION_RESULT.value,
            )
            .first()
        )
        if reference is None:
            return None
        _, artifact = reference
        patch = db.query(PatchModel).filter(PatchModel.generation_work_item_id == work.id).first()
        return RemediationExecutionResult(
            artifact_id=artifact.id,
            artifact_digest=artifact.content_digest,
            result_kind=("PATCH_REVISION" if work.resource_type == "PATCH_REVISION" else work.work_kind),
            patch_id=patch.id if patch is not None else None,
            reused=True,
        )

    @staticmethod
    def _finding_artifact_id(finding: FindingModel, work: WorkItemModel) -> str | None:
        if work.input_artifact_id:
            return str(work.input_artifact_id)
        metadata = finding.model_metadata if isinstance(finding.model_metadata, dict) else {}
        provenance = metadata.get("provenance") or (metadata.get("extra_metadata") or {}).get("provenance") or {}
        return provenance.get("finding_artifact_id")

    def _publish_result(
        self,
        db: Session,
        *,
        work: WorkItemModel,
        scan: ScanModel,
        finding: FindingModel,
        result_kind: str,
        payload: dict[str, Any],
    ):
        upstream = self._finding_artifact_id(finding, work)
        lineage = [(LineageRelation.DERIVED_FROM, upstream)] if upstream else []
        return CanonicalArtifactService(db).publish_json(
            tenant_id=work.tenant_id,
            repository_id=hashlib.sha256(scan.repository_url.encode("utf-8")).hexdigest()[:32],
            revision_id=scan.commit_hash,
            artifact_type=ArtifactType.REMEDIATION_RESULT,
            payload={"result_kind": result_kind, "result": payload},
            producer="repolens-remediation-service",
            producer_version="1.0",
            policy_snapshot_id=work.policy_snapshot_id,
            lineage=lineage,
            coverage=(
                ArtifactCoverage(
                    status=CoverageStatus.SUCCESSFULLY_ANALYZED,
                    discovered_count=1,
                    analyzed_count=1,
                )
                if upstream
                else ArtifactCoverage(
                    status=CoverageStatus.UNAVAILABLE,
                    discovered_count=1,
                    analyzed_count=0,
                    failed_count=1,
                    explanation="Legacy finding predates canonical artifact provenance; result is revision-bound but upstream finding lineage is unavailable.",
                )
            ),
            sensitivity=ArtifactSensitivity.SECURITY_SENSITIVE,
            retention_class=RetentionClass.ANALYSIS_ARTIFACT,
            referrer=("WORK_ITEM", work.id),
            actor_id=work.requested_by,
            request_id=work.request_id,
        )

    @staticmethod
    def _result_payload(result: Any) -> dict[str, Any]:
        if hasattr(result, "model_dump"):
            payload = result.model_dump(mode="json")
            if isinstance(payload, dict):
                return payload
        proposal = result.proposal
        return {
            "finding_id": str(proposal.finding_id),
            "proposal": proposal.model_dump(mode="json"),
            "verification_result": (
                result.verification_result.model_dump(mode="json")
                if result.verification_result is not None
                else None
            ),
            "critic_escalated": bool(getattr(result, "critic_report", None)),
            "critic_report": (
                result.critic_report.model_dump(mode="json")
                if getattr(result, "critic_report", None) is not None
                else None
            ),
            "revision_count": 0,
            "machine_verdict": str(result.machine_verdict),
            "final_verdict": str(result.machine_verdict),
        }

    @staticmethod
    def _validate_patch_lineage(result: PatchWorkflowResult, fix_plan: FixPlan, finding_id: UUID) -> None:
        proposal = result.proposal
        if not (
            proposal.plan_id == fix_plan.id
            and proposal.finding_id == fix_plan.finding_id
            and fix_plan.finding_id == finding_id
        ):
            raise RemediationInvariantError("Patch proposal lineage does not match the canonical fix plan.")

    @staticmethod
    def _persist_patch(
        db: Session,
        *,
        work: WorkItemModel,
        scan: ScanModel,
        fix_plan: FixPlan,
        result: Any,
        result_artifact_id: str,
        parent: PatchModel | None,
    ) -> PatchModel:
        existing = db.query(PatchModel).filter(PatchModel.generation_work_item_id == work.id).first()
        if existing is not None:
            return existing
        proposal = result.proposal
        verification_status = (
            result.verification_result.status.value
            if result.verification_result is not None
            else None
        )
        patch_status = (
            PatchStatus.VERIFIED
            if result.machine_verdict == "PASSED" or verification_status == "PASSED"
            else PatchStatus.REJECTED
            if result.machine_verdict == "REJECTED" or verification_status == "FAILED"
            else PatchStatus.NEEDS_REVIEW
        )
        revision_number = (parent.revision_number or 0) + 1 if parent is not None else 0
        model = PatchModel(
            id=str(proposal.id),
            finding_id=str(proposal.finding_id),
            plan_id=str(fix_plan.id),
            fix_plan_snapshot=fix_plan.model_dump(mode="json"),
            scan_id=str(scan.id),
            parent_patch_id=str(parent.id) if parent is not None else None,
            revision_number=revision_number,
            thread_id=f"remediation-{proposal.id}",
            generation_work_item_id=work.id,
            result_artifact_id=result_artifact_id,
            status=patch_status.value,
            machine_verdict=result.machine_verdict,
            unified_diff=proposal.unified_diff,
            files_modified=proposal.files_modified,
            explanation=proposal.explanation,
            expected_behavior_change=proposal.expected_behavior_change,
            generated_tests_or_test_plan=proposal.generated_tests_or_test_plan,
            verification_report=(
                result.verification_result.model_dump(mode="json")
                if result.verification_result is not None
                else None
            ),
            critic_report=result.critic_report.model_dump(mode="json") if result.critic_report else None,
            user_feedback=str((work.request_payload or {}).get("user_feedback") or "") or None,
            model_metadata=proposal.model_metadata.model_dump(mode="json") if proposal.model_metadata else None,
        )
        db.add(model)
        event_type = WorkflowEventType.PATCH_REVISION_CREATED if parent is not None else WorkflowEventType.PATCH_GENERATED
        WorkflowEventService.emit_critical(
            db=db,
            event=WorkflowEventCreate(
                event_type=event_type,
                scan_id=UUID(str(scan.id)),
                finding_id=proposal.finding_id,
                patch_id=proposal.id,
                actor_user_id=work.requested_by,
                thread_id=model.thread_id,
                commit_sha=scan.commit_hash,
                stage="patch_generation",
                message="Patch candidate generated and deterministically verified",
                metadata_payload={"machine_verdict": result.machine_verdict, "result_artifact_id": result_artifact_id},
            ),
        )
        DomainOutbox.append(
            db,
            tenant_id=work.tenant_id,
            aggregate_type="PATCH",
            aggregate_id=model.id,
            event_type=event_type.value,
            deduplication_key=f"patch:{model.id}:generated",
            payload={"work_item_id": work.id, "result_artifact_id": result_artifact_id},
        )
        AuditLedger.append(
            db,
            tenant_id=work.tenant_id,
            actor_id=work.requested_by,
            request_id=work.request_id,
            event_type="PATCH_GENERATED",
            resource_type="PATCH",
            resource_id=model.id,
            payload={"work_item_id": work.id, "revision_number": revision_number},
        )
        return model


__all__ = [
    "RemediationExecutionResult",
    "RemediationExecutionService",
    "RemediationInvariantError",
]
