"""Pydantic schemas for operational telemetry and health monitoring."""

from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class ProviderTelemetry(BaseModel):
    """Configuration and availability state for an LLM provider."""
    provider: str
    configured: bool
    default_model: str


class StorageTelemetry(BaseModel):
    """Storage filesystem health and checkpointer accessibility."""
    snapshot_storage_writable: bool
    checkpointer_storage_accessible: bool


class MetricsTelemetry(BaseModel):
    """System-wide operational counts."""
    total_scans: int = 0
    completed_scans: int = 0
    failed_scans: int = 0
    running_scans: int = 0
    pending_scans: int = 0
    total_findings: int = 0
    total_patches: int = 0
    approved_patches: int = 0
    rejected_patches: int = 0
    total_deliveries: int = 0
    pull_requests_created: int = 0
    total_workflow_events: int = 0


class TelemetryReport(BaseModel):
    """Comprehensive operational telemetry and observability report."""
    service: str
    version: str
    status: str
    environment: str
    database: str
    providers: List[ProviderTelemetry] = Field(default_factory=list)
    storage: StorageTelemetry
    metrics: MetricsTelemetry
    timestamp: datetime


class ScanTelemetry(BaseModel):
    """Detailed telemetry and metric aggregation for a single scan."""
    scan_id: str
    commit_sha: Optional[str] = None
    status: str

    total_duration_ms: Optional[int] = None

    event_count: int = 0
    stage_count: int = 0

    tools_completed: int = 0
    tools_failed: int = 0
    tools_unavailable: int = 0

    llm_calls: Optional[int] = None
    llm_retries: Optional[int] = None
    provider_fallbacks: Optional[int] = None

    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    total_tokens: Optional[int] = None

    confirmed_findings: int = 0
    possible_findings: int = 0
    rejected_findings: int = 0

    patches_generated: int = 0
    patches_verified: int = 0
    patches_needing_review: int = 0
    patches_approved: int = 0
    patches_rejected: int = 0

    deliveries_requested: int = 0
    deliveries_blocked: int = 0
    pull_requests_created: int = 0
    delivery_failures: int = 0

    analysis_truncated: bool = False
    analysis_truncation_reason: Optional[str] = None


class ChangeAnalysisTelemetry(BaseModel):
    """Authoritative operational telemetry and metrics aggregated for a Change Analysis."""

    analysis_id: str
    repository_url: str
    base_commit_sha: str
    head_commit_sha: str
    status: str
    risk_level: Optional[str] = None

    duration_ms: Optional[int] = None

    files_changed: int = 0
    symbols_changed: int = 0
    impacted_symbols: int = 0

    direct_impacts: int = 0
    transitive_impacts: int = 0
    contract_breaks: int = 0
    security_impacts: int = 0

    impacts_by_type: Dict[str, int] = Field(default_factory=dict)
    impacts_by_severity: Dict[str, int] = Field(default_factory=dict)
    impacts_by_verification_status: Dict[str, int] = Field(default_factory=dict)

    review_findings_count: int = 0
    confirmed_findings: int = 0
    supported_inferences: int = 0
    rejected_findings: int = 0

    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    total_tokens: Optional[int] = None

    is_truncated: bool = False
    truncation_reason: Optional[str] = None


