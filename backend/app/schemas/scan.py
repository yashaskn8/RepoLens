"""Scan schema representing a repository analysis lifecycle and results."""

from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, HttpUrl
from app.schemas.enums import ScanStatus
from app.schemas.finding import Finding
from app.schemas.metadata import ModelExecutionMetadata


def _utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


class ScanBase(BaseModel):
    """Base fields for a scan request."""

    repository_url: str = Field(..., description="URL or identifier of the repository analyzed")
    branch: Optional[str] = Field(default=None, description="Resolved branch or ref targeted for analysis")
    requested_branch: Optional[str] = Field(default=None, description="Explicitly requested branch if supplied")
    resolved_branch_or_ref: Optional[str] = Field(default=None, description="Actual resolved branch or ref from repository")
    commit_hash: Optional[str] = Field(default=None, description="Authoritative 40-character commit SHA")
    commit_sha: Optional[str] = Field(default=None, description="Authoritative 40-character commit SHA alias")


class ScanCreate(ScanBase):
    """Schema for initiating a new scan."""

    pass


class Scan(ScanBase):
    """Canonical domain schema for a Scan entity."""

    id: UUID = Field(default_factory=uuid4, description="Unique identifier of the scan")
    status: ScanStatus = Field(default=ScanStatus.PENDING, description="Current scan lifecycle status")
    findings_count: int = Field(default=0, ge=0, description="Total count of findings detected")
    findings: List[Finding] = Field(default_factory=list, description="Findings associated with this scan")
    model_metadata: Optional[ModelExecutionMetadata] = Field(default=None, description="Telemetry metadata for model execution")
    created_at: datetime = Field(default_factory=_utc_now, description="Timestamp when scan was queued")
    completed_at: Optional[datetime] = Field(default=None, description="Timestamp when scan finished")

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "example": {
                "id": "e2c3a5f9-3d71-4be5-a83d-9d7a9602e1c9",
                "repository_url": "https://github.com/org/sample-repo",
                "branch": "main",
                "commit_hash": "a1b2c3d4e5f67890",
                "status": "COMPLETED",
                "findings_count": 1,
                "findings": [],
                "created_at": "2026-08-20T10:00:00Z",
                "completed_at": "2026-08-20T10:01:15Z"
            }
        }
    }
