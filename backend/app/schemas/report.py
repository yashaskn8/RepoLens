"""Pydantic schemas for structured exportable evidence and audit reports."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.enums import FindingStatus, PatchStatus, ScanStatus, Severity, VerificationVerdict


class ReportEvidence(BaseModel):
    """Grounded source evidence within a file."""
    id: str
    file_path: str
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    code_snippet: Optional[str] = None
    context_notes: Optional[str] = None


class ReportPatch(BaseModel):
    """Candidate patch proposal with machine verdict and human review status."""
    id: str
    finding_id: str
    plan_id: Optional[str] = None
    parent_patch_id: Optional[str] = None
    revision_number: int = 0
    status: str
    machine_verdict: Optional[str] = None
    unified_diff: str
    files_modified: List[str] = Field(default_factory=list)
    explanation: str
    expected_behavior_change: str
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    rejected_reason: Optional[str] = None
    user_feedback: Optional[str] = None
    created_at: datetime


class ReportFinding(BaseModel):
    """Verified finding with attached evidences and generated patches."""
    id: str
    title: str
    description: str
    severity: str
    status: str
    rule_id: Optional[str] = None
    category: Optional[str] = None
    mitigation_guidance: Optional[str] = None
    verification_verdict: Optional[str] = None
    verification_reason: Optional[str] = None
    source_tool: Optional[str] = None
    detector_id: Optional[str] = None
    evidences: List[ReportEvidence] = Field(default_factory=list)
    patches: List[ReportPatch] = Field(default_factory=list)
    created_at: datetime


class ReportSummary(BaseModel):
    """Executive metrics breakdown for the scan."""
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    confirmed_findings: int = 0
    total_patches: int = 0
    approved_patches: int = 0
    rejected_patches: int = 0
    revised_patches: int = 0


class ReportWorkflowEvent(BaseModel):
    """Durable workflow event summary."""
    id: int
    event_type: str
    stage: Optional[str] = None
    tool_name: Optional[str] = None
    message: Optional[str] = None
    created_at: datetime


class ReportAnalysisScope(BaseModel):
    """Analysis boundary and truncation status."""
    truncated: bool = False
    reason: Optional[str] = None
    files_processed: int = 0
    source_bytes_processed: int = 0
    total_observed_files: int = 0
    total_observed_bytes: int = 0


class ReportScannerCoverage(BaseModel):
    """Execution status and finding counts for deterministic scanners."""
    tool: str
    status: str
    findings_count: int = 0
    execution_time_ms: Optional[int] = None
    failure_reason: Optional[str] = None


class ScanReport(BaseModel):
    """Complete, evidence-grounded exportable repository report."""
    scan_id: str
    repository_url: str
    requested_branch: Optional[str] = None
    resolved_branch: Optional[str] = None
    commit_sha: Optional[str] = None
    status: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    architecture_overview: Optional[str] = None
    languages: Dict[str, int] = Field(default_factory=dict)
    frameworks: List[str] = Field(default_factory=list)
    analysis_scope: Optional[ReportAnalysisScope] = None
    scanner_coverage: List[ReportScannerCoverage] = Field(default_factory=list)
    summary: ReportSummary
    findings: List[ReportFinding] = Field(default_factory=list)
    events_audit_trail: List[ReportWorkflowEvent] = Field(default_factory=list)

