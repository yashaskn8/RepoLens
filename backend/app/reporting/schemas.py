"""Immutable, renderer-independent report domain models.

These models are a stable projection of canonical scan truth. Renderers consume
only ``ReportDocument`` and must never query ORM entities or determine finding
truth, severity, or remediation order.
"""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


REPORT_SCHEMA_VERSION = "1.0"
REPORT_TYPE_SCAN = "SCAN_SECURITY"


class ReportStatus(str, Enum):
    REQUESTED = "REQUESTED"
    ASSEMBLING = "ASSEMBLING"
    RENDERING = "RENDERING"
    READY = "READY"
    FAILED = "FAILED"


class FrozenReportModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ReportMetadata(FrozenReportModel):
    report_id: str
    tenant_id: str
    scan_id: str
    report_type: str = REPORT_TYPE_SCAN
    repository: str
    branch: Optional[str] = None
    commit_sha: Optional[str] = None
    analysis_timestamp: Optional[datetime] = None
    generated_at: datetime
    report_schema_version: str = REPORT_SCHEMA_VERSION
    renderer_version: str
    analysis_policy_version: str
    application_version: str
    coverage_artifact_id: Optional[str] = None
    finding_ids: List[str] = Field(default_factory=list)
    evidence_digest: str
    artifact_lineage: List[str] = Field(default_factory=list)
    tool_versions: Dict[str, str] = Field(default_factory=dict)


class ReportScope(FrozenReportModel):
    files_discovered: Optional[int] = None
    files_analyzed: Optional[int] = None
    source_bytes_analyzed: Optional[int] = None
    source_bytes_discovered: Optional[int] = None
    languages: Dict[str, int] = Field(default_factory=dict)
    unsupported_areas: List[str] = Field(default_factory=list)
    truncated: bool = False
    truncation_reason: Optional[str] = None
    limits_encountered: List[str] = Field(default_factory=list)


class AnalyzerCoverage(FrozenReportModel):
    analyzer: str
    status: str
    findings_count: int = 0
    execution_time_ms: Optional[int] = None
    limitation: Optional[str] = None


class ReportCoverage(FrozenReportModel):
    status: Literal["FULL", "PARTIAL", "DEGRADED", "UNKNOWN"]
    analyzers: List[AnalyzerCoverage] = Field(default_factory=list)
    distinction: str


class ReportEvidenceReference(FrozenReportModel):
    evidence_id: str
    finding_id: str
    file_path: str
    symbol: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    excerpt: Optional[str] = None
    context: Optional[str] = None
    analyzer: Optional[str] = None
    artifact_id: Optional[str] = None
    excerpt_truncated: bool = False


class ReportRemediationStep(FrozenReportModel):
    recommendation: str
    validation_steps: List[str] = Field(default_factory=list)
    availability: Literal["VERIFIED_PATCH", "CANDIDATE_PATCH", "GUIDANCE", "NONE"]
    patch_ids: List[str] = Field(default_factory=list)


class ReportFinding(FrozenReportModel):
    finding_id: str
    title: str
    severity: str
    lifecycle_status: str
    verification_verdict: Optional[str] = None
    category: str
    rule_id: Optional[str] = None
    detector_id: Optional[str] = None
    analyzer: Optional[str] = None
    affected_files: List[str] = Field(default_factory=list)
    symbol: Optional[str] = None
    technical_explanation: str
    potential_impact: str
    evidence: List[ReportEvidenceReference] = Field(default_factory=list)
    evidence_strength: Literal["STRONG", "MODERATE", "LIMITED", "NONE"]
    security_impact: bool = False
    blast_radius: int = 0
    dependency_ids: List[str] = Field(default_factory=list)
    remediation: ReportRemediationStep
    cwe: Optional[str] = None
    cve: Optional[str] = None
    package: Optional[str] = None
    affected_version: Optional[str] = None
    claim_class: Literal[
        "DETERMINISTIC_FACT",
        "VERIFIED_FINDING",
        "VERIFIED_REUSED_FINDING",
        "AI_EXPLANATION_GROUNDED",
        "UNCERTAIN",
        "LIMITATION",
    ] = "VERIFIED_FINDING"
    provenance: Dict[str, object] = Field(default_factory=dict)


class ReportPriorityItem(FrozenReportModel):
    finding_id: str
    title: str
    severity: str
    priority_rank: int
    priority_band: Literal["FIX FIRST", "FIX NEXT", "FIX LATER"]
    priority_reason: str
    dependency_ids: List[str] = Field(default_factory=list)


class ReportRiskSummary(FrozenReportModel):
    highest_severity: Optional[str] = None
    severity_counts: Dict[str, int] = Field(default_factory=dict)
    verdict_counts: Dict[str, int] = Field(default_factory=dict)
    security_findings: int = 0
    contract_findings: int = 0


class ReportExecutiveSummary(FrozenReportModel):
    overall_result: str
    risk: ReportRiskSummary
    major_risks: List[str] = Field(default_factory=list)
    important_limitations: List[str] = Field(default_factory=list)


class ReportFindingSection(FrozenReportModel):
    title: str
    finding_ids: List[str] = Field(default_factory=list)


class ReportSecuritySection(FrozenReportModel):
    vulnerability_finding_ids: List[str] = Field(default_factory=list)
    inconsistency_finding_ids: List[str] = Field(default_factory=list)


class ReportContractSection(FrozenReportModel):
    finding_ids: List[str] = Field(default_factory=list)


class ReportArchitectureSection(FrozenReportModel):
    overview: Optional[str] = None
    frameworks: List[str] = Field(default_factory=list)
    finding_ids: List[str] = Field(default_factory=list)


class ReportRoadmapStep(FrozenReportModel):
    sequence: int
    title: str
    finding_ids: List[str] = Field(default_factory=list)
    dependency_ids: List[str] = Field(default_factory=list)


class ReportAppendix(FrozenReportModel):
    evidence: List[ReportEvidenceReference] = Field(default_factory=list)
    omitted_finding_count: int = 0
    omitted_evidence_count: int = 0


class ReportDocument(FrozenReportModel):
    metadata: ReportMetadata
    scope: ReportScope
    executive_summary: ReportExecutiveSummary
    coverage: ReportCoverage
    prioritized_fix_plan: List[ReportPriorityItem] = Field(default_factory=list)
    finding_sections: List[ReportFindingSection] = Field(default_factory=list)
    findings: List[ReportFinding] = Field(default_factory=list)
    security: ReportSecuritySection
    contracts: ReportContractSection
    architecture: ReportArchitectureSection
    remediation_roadmap: List[ReportRoadmapStep] = Field(default_factory=list)
    appendix: ReportAppendix
    limitations: List[str] = Field(default_factory=list)


class ReportResource(BaseModel):
    """Public status resource. Storage locators are intentionally excluded."""

    id: str
    scan_id: str
    report_type: str
    status: ReportStatus
    repository: str
    branch: Optional[str] = None
    commit_sha: Optional[str] = None
    report_schema_version: str
    renderer_version: str
    created_at: datetime
    generated_at: Optional[datetime] = None
    failure_code: Optional[str] = None
    failure_message: Optional[str] = None
    retryable: bool = False
    content_digest: Optional[str] = None
    file_size_bytes: Optional[int] = None
    page_count: Optional[int] = None
    download_url: Optional[str] = None
    reused: bool = False
