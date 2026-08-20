"""Schemas for deterministic static analysis tools, results, and evidence normalization."""

from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field

from app.schemas.enums import Severity
from app.schemas.evidence import Evidence


class ToolStatus(str, Enum):
    """Execution status of a deterministic analysis tool."""

    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    DISABLED = "DISABLED"
    TIMEOUT = "TIMEOUT"
    FAILED = "FAILED"
    COMPLETED = "COMPLETED"


class StaticFinding(BaseModel):
    """Canonical normalized finding produced by deterministic static analysis tools."""

    id: UUID = Field(default_factory=uuid4, description="Unique identifier for the static finding")
    tool: str = Field(..., description="Scanner tool name (e.g. semgrep, trivy, osv-scanner)")
    rule_id: Optional[str] = Field(default=None, description="Detector rule ID or CVE identifier")
    title: str = Field(..., description="Short summary title of the finding")
    description: str = Field(..., description="Detailed description of the issue")
    severity: Severity = Field(..., description="Normalized severity level")
    category: str = Field(default="sast", description="Category: sast, vulnerability, secret, misconfiguration, dependency")
    evidence: Evidence = Field(..., description="Localized code location and snippet evidence")
    mitigation: Optional[str] = Field(default=None, description="Remediation advice if provided by the tool")
    confidence: Optional[str] = Field(default=None, description="Confidence level: HIGH, MEDIUM, LOW")
    raw_details: Dict[str, Any] = Field(default_factory=dict, description="Raw tool-specific payload extract")

    model_config = {
        "from_attributes": True,
    }


class ScannerResult(BaseModel):
    """Aggregated output from a single scanner adapter execution."""

    tool: str = Field(..., description="Name of the scanner tool")
    status: ToolStatus = Field(..., description="Tool execution status")
    findings: List[StaticFinding] = Field(default_factory=list, description="Extracted and normalized static findings")
    error_message: Optional[str] = Field(default=None, description="Error explanation if execution failed")
    execution_time_ms: float = Field(default=0.0, ge=0.0, description="Scanner execution time in milliseconds")
