"""Canonical schemas for evidence-grounded technical research and framework upgrade intelligence."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field

from app.schemas.metadata import ModelExecutionMetadata


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SourceTier(int, Enum):
    """Source authority ranking tiers according to RepoLens research policy."""

    OFFICIAL_DOCS = 1         # e.g., fastapi.tiangolo.com, react.dev, docs.python.org
    RELEASE_NOTES = 2         # e.g., github.com/org/repo/releases, CHANGELOG.md
    SECURITY_ADVISORY = 3     # e.g., osv.dev, nvd.nist.gov, github.com/advisories
    VENDOR_DOCS = 4           # e.g., developer.mozilla.org, cloud.google.com
    COMMUNITY = 5             # Other public engineering resources


class ResearchEvidence(BaseModel):
    """Single evidence citation backing a research claim or migration recommendation."""

    source_url: str = Field(..., description="Canonical HTTP/HTTPS URL of the cited source")
    source_title: str = Field(..., description="Title or header of the cited resource")
    retrieved_date: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        description="Date when the evidence was retrieved/verified",
    )
    supported_claim: str = Field(..., description="Specific technical assertion or API change supported by this source")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Verification confidence score")
    source_tier: SourceTier = Field(default=SourceTier.COMMUNITY, description="Authority tier of the source")


class ResearchQuery(BaseModel):
    """Targeted query payload supplied to ResearchAgent."""

    finding_id: Optional[UUID] = Field(default=None, description="Optional associated Finding UUID")
    target_framework: str = Field(..., description="Target library, framework, or runtime name (e.g. FastAPI, React, Pydantic)")
    detected_version: Optional[str] = Field(default=None, description="Detected version in repository manifest")
    issue_summary: str = Field(..., description="Specific technical question or issue description (e.g. deprecated route decorator syntax)")
    affected_file: Optional[str] = Field(default=None, description="Repository file path where pattern is used")
    affected_symbols: List[str] = Field(default_factory=list, description="Symbol names related to the research query")
    code_snippet: Optional[str] = Field(default=None, description="Minimal localized code snippet illustrating the usage")
    minimal_context: Optional[str] = Field(default=None, description="Bounded contextual notes from repository manifest")


class ResearchResult(BaseModel):
    """Structured, evidence-grounded research result and repository-specific migration impact."""

    id: UUID = Field(default_factory=uuid4, description="Unique research result identifier")
    finding_id: Optional[UUID] = Field(default=None, description="Associated Finding UUID if linked to a finding")
    target_framework: str = Field(..., description="Target framework or package investigated")
    detected_version: Optional[str] = Field(default=None, description="Detected version in repository manifest")
    recommended_version: Optional[str] = Field(default=None, description="Recommended target version with breaking changes resolved")
    migration_summary: str = Field(..., description="Technical summary of relevant API changes, deprecations, or security fixes")
    repository_impact: str = Field(..., description="Explanation of why this change specifically matters to THIS repository and its code patterns")
    evidences: List[ResearchEvidence] = Field(default_factory=list, description="Prioritized authoritative citations backing the findings")
    model_metadata: Optional[ModelExecutionMetadata] = Field(default=None, description="LLM execution metadata and grounding telemetry")
    created_at: datetime = Field(default_factory=_utc_now, description="Timestamp of research generation")
