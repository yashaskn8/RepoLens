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
    snapshot_dir: str
    writable: bool
    checkpointer_db_path: str
    checkpointer_accessible: bool


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
