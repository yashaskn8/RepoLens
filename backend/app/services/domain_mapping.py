"""Canonical domain mapping functions for SQLAlchemy ORM models to Pydantic schemas."""

from typing import Optional
from uuid import UUID

from app.models.finding import FindingModel
from app.schemas.enums import FindingStatus, Severity, VerificationVerdict
from app.schemas.evidence import Evidence
from app.schemas.finding import Finding
from app.schemas.metadata import ModelExecutionMetadata
from app.security.redaction import redact_secrets


def finding_model_to_schema(fm: FindingModel) -> Finding:
    """Convert FindingModel ORM object into validated Finding domain schema preserving full provenance."""
    evidences = [
        Evidence(
            id=UUID(em.id),
            file_path=em.file_path,
            start_line=em.start_line,
            end_line=em.end_line,
            code_snippet=redact_secrets(em.code_snippet) if em.code_snippet else None,
            context_notes=redact_secrets(em.context_notes) if em.context_notes else None,
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
        title=redact_secrets(fm.title),
        description=redact_secrets(fm.description or ""),
        severity=Severity(fm.severity),
        status=FindingStatus(fm.status),
        rule_id=fm.rule_id,
        category=fm.category,
        mitigation_guidance=redact_secrets(fm.mitigation_guidance) if fm.mitigation_guidance else None,
        verification_verdict=VerificationVerdict(fm.verification_verdict) if fm.verification_verdict else None,
        verification_reason=redact_secrets(fm.verification_reason) if fm.verification_reason else None,
        source_tool=fm.source_tool,
        detector_id=fm.detector_id,
        detector_kind=fm.detector_kind,
        evidences=evidences,
        model_metadata=metadata,
        created_at=fm.created_at,
        updated_at=fm.updated_at,
    )
