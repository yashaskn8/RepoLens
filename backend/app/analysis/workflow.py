"""Canonical Change Analysis Workflow Coordinator.

Coordinates background execution of the Phase 6 LangGraph change intelligence workflow,
managing database state transitions, impact persistence, workflow event emissions, and safe workspace cleanup.
"""

import asyncio
from datetime import datetime, timezone
import logging
from typing import Any, Dict, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from app.analysis.workflow_graph import build_change_analysis_graph
from app.core.database import SessionLocal
from app.ingestion.comparison_snapshot import get_comparison_snapshot_service
from app.models.change_analysis import ChangeAnalysisModel, ChangeImpactModel
from app.schemas.change_analysis import (
    BlastRadiusReport,
    ChangeAnalysisStatus,
    ChangeImpact,
    ChangeReviewReport,
    StructuralDiffResult,
)
from app.schemas.enums import ChangeRiskLevel
from app.schemas.workflow_event import WorkflowEventCreate, WorkflowEventType
from app.services.workflow_event_service import WorkflowEventService

logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


async def execute_background_change_analysis(
    analysis_id: str,
    checkpoint_db_path: Optional[str] = None,
) -> None:
    """Execute complete change intelligence pipeline in background with durable state persistence and event streaming."""
    db: Session = SessionLocal()
    snapshot_service = get_comparison_snapshot_service()

    try:
        analysis_model = db.query(ChangeAnalysisModel).filter(ChangeAnalysisModel.id == analysis_id).first()
        if not analysis_model:
            logger.error(f"ChangeAnalysisModel {analysis_id} not found")
            return

        # 1. Update status to ACQUIRING & emit CHANGE_REVISIONS_ACQUIRED stage started
        analysis_model.status = ChangeAnalysisStatus.ACQUIRING.value
        db.commit()

        WorkflowEventService.emit(
            db=db,
            event=WorkflowEventCreate(
                event_type=WorkflowEventType.STAGE_STARTED,
                change_analysis_id=UUID(analysis_id),
                stage="ACQUIRE",
                message=f"Acquiring base ({analysis_model.base_commit_sha[:8]}) and head ({analysis_model.head_commit_sha[:8]}) revisions",
                metadata_payload={
                    "repository_url": analysis_model.repository_url,
                    "base_sha": analysis_model.base_commit_sha,
                    "head_sha": analysis_model.head_commit_sha,
                },
            ),
        )

        # 2. Acquire dual workspaces using safe context manager
        async with snapshot_service.comparison_context(
            repository_url=analysis_model.repository_url,
            base_commit_sha=analysis_model.base_commit_sha,
            head_commit_sha=analysis_model.head_commit_sha,
            base_ref=analysis_model.base_ref,
            head_ref=analysis_model.head_ref,
        ) as (base_ws, head_ws):

            WorkflowEventService.emit(
                db=db,
                event=WorkflowEventCreate(
                    event_type=WorkflowEventType.CHANGE_REVISIONS_ACQUIRED,
                    change_analysis_id=UUID(analysis_id),
                    stage="ACQUIRE",
                    message="Base and head comparison workspaces verified and acquired",
                ),
            )

            # Update status to DIFFING
            analysis_model.status = ChangeAnalysisStatus.DIFFING.value
            db.commit()

            # Compile LangGraph workflow
            graph = build_change_analysis_graph()

            initial_state = {
                "analysis_id": analysis_id,
                "repository_url": analysis_model.repository_url,
                "base_commit_sha": analysis_model.base_commit_sha,
                "head_commit_sha": analysis_model.head_commit_sha,
                "base_ref": analysis_model.base_ref,
                "head_ref": analysis_model.head_ref,
                "base_workspace": base_ws,
                "head_workspace": head_ws,
                "completed_nodes": ["acquire"],
            }

            final_state = await graph.ainvoke(initial_state)

            # Extract results from final state
            diff_res: Optional[StructuralDiffResult] = final_state.get("diff_result")
            blast_radius: Optional[BlastRadiusReport] = final_state.get("blast_radius")
            review_rep: Optional[ChangeReviewReport] = final_state.get("review_report")

            # 3. Persist diff summary counts to DB
            if diff_res:
                analysis_model.changed_files_count = len(diff_res.changed_files)
                analysis_model.changed_symbols_count = len(diff_res.changed_symbols)
                WorkflowEventService.emit(
                    db=db,
                    event=WorkflowEventCreate(
                        event_type=WorkflowEventType.CHANGE_DIFF_COMPLETED,
                        change_analysis_id=UUID(analysis_id),
                        stage="DIFF",
                        message=f"Structural diff complete: {len(diff_res.changed_files)} files, {len(diff_res.changed_symbols)} symbols changed",
                        metadata_payload=diff_res.summary,
                    ),
                )

            # 4. Persist impact records to DB
            if blast_radius:
                analysis_model.impacted_symbols_count = blast_radius.total_impacts
                analysis_model.risk_level = blast_radius.overall_risk_level.value

                # Delete old impacts if resuming/retrying
                db.query(ChangeImpactModel).filter(ChangeImpactModel.analysis_id == analysis_id).delete()

                for imp in blast_radius.impacts:
                    imp_row = ChangeImpactModel(
                        id=str(imp.id),
                        analysis_id=analysis_id,
                        impact_type=imp.impact_type.value,
                        severity=imp.severity.value,
                        title=imp.title,
                        description=imp.description,
                        source_file=imp.source_file,
                        source_symbol=imp.source_symbol,
                        affected_file=imp.affected_file,
                        affected_symbol=imp.affected_symbol,
                        evidence_payload=imp.evidence_payload,
                        confidence=imp.confidence,
                        verification_status=imp.verification_status.value,
                        created_at=imp.created_at,
                    )
                    db.add(imp_row)

                WorkflowEventService.emit(
                    db=db,
                    event=WorkflowEventCreate(
                        event_type=WorkflowEventType.CHANGE_IMPACT_ANALYZED,
                        change_analysis_id=UUID(analysis_id),
                        stage="IMPACT",
                        message=f"Blast radius analysis complete: {blast_radius.total_impacts} impacts identified",
                        metadata_payload={
                            "total_impacts": blast_radius.total_impacts,
                            "direct_impacts": blast_radius.direct_impacts_count,
                            "transitive_impacts": blast_radius.transitive_impacts_count,
                            "risk_level": blast_radius.overall_risk_level.value,
                        },
                    ),
                )

            # 5. Persist review findings to model_metadata
            meta = dict(analysis_model.model_metadata or {})
            if review_rep:
                meta["review_report"] = review_rep.model_dump(mode="json")
                if review_rep.overall_risk_level != ChangeRiskLevel.LOW:
                    analysis_model.risk_level = review_rep.overall_risk_level.value
            analysis_model.model_metadata = meta

            # 6. Mark COMPLETED
            analysis_model.status = ChangeAnalysisStatus.COMPLETED.value
            analysis_model.completed_at = _utc_now()
            db.commit()

            WorkflowEventService.emit(
                db=db,
                event=WorkflowEventCreate(
                    event_type=WorkflowEventType.CHANGE_ANALYSIS_COMPLETED,
                    change_analysis_id=UUID(analysis_id),
                    stage="COMPLETE",
                    message="Change intelligence analysis completed successfully",
                    metadata_payload={
                        "risk_level": analysis_model.risk_level,
                        "impacts_count": analysis_model.impacted_symbols_count,
                    },
                ),
            )

    except Exception as exc:
        logger.error(f"Change intelligence analysis {analysis_id} failed: {str(exc)}", exc_info=True)
        try:
            analysis_model = db.query(ChangeAnalysisModel).filter(ChangeAnalysisModel.id == analysis_id).first()
            if analysis_model:
                analysis_model.status = ChangeAnalysisStatus.FAILED.value
                analysis_model.failure_code = "ANALYSIS_FAILED"
                analysis_model.failure_message = str(exc)[:500]
                analysis_model.completed_at = _utc_now()
                db.commit()

                WorkflowEventService.emit(
                    db=db,
                    event=WorkflowEventCreate(
                        event_type=WorkflowEventType.CHANGE_ANALYSIS_FAILED,
                        change_analysis_id=UUID(analysis_id),
                        message=f"Change analysis failed: {str(exc)[:200]}",
                        metadata_payload={"error": str(exc)},
                    ),
                )
        except Exception as db_err:
            logger.critical(f"Failed to record failure state for analysis {analysis_id}: {str(db_err)}")
    finally:
        db.close()
