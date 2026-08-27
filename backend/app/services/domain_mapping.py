"""Canonical domain mapping functions for SQLAlchemy ORM models to Pydantic schemas."""

from typing import Optional
from uuid import UUID

from app.models.finding import FindingModel
from app.schemas.enums import FindingStatus, Severity, VerificationVerdict
from app.schemas.evidence import Evidence
from app.schemas.finding import Finding
from app.schemas.metadata import ModelExecutionMetadata


def finding_model_to_schema(fm: FindingModel) -> Finding:
    """Convert FindingModel ORM object into validated Finding domain schema preserving full provenance."""
    evidences = [
        Evidence(
            id=UUID(em.id),
            file_path=em.file_path,
            start_line=em.start_line,
            end_line=em.end_line,
            code_snippet=em.code_snippet,
            context_notes=em.context_notes,
        )
        for em in (fm.evidences or [])
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
        description=fm.description or "",
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
