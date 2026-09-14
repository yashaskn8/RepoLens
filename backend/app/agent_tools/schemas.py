"""Stable JSON-compatible contracts for deterministic RepoLens agent tools."""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.ingestion.schemas import SymbolKind
from app.schemas.change_analysis import StructuralDiffResult


AGENT_TOOL_CONTRACT_VERSION = "1.0.0"
AGENT_TOOL_VERSION = "1.0.0"


class ToolModel(BaseModel):
    """Closed, serializable base model for the public tool boundary."""

    model_config = ConfigDict(extra="forbid")


class ToolResultStatus(str, Enum):
    SUCCESS = "SUCCESS"
    NOT_FOUND = "NOT_FOUND"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    INVALID_INPUT = "INVALID_INPUT"
    UNSUPPORTED = "UNSUPPORTED"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class VerificationVerdict(str, Enum):
    SUPPORTED = "SUPPORTED"
    UNSUPPORTED = "UNSUPPORTED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    INVALID_CLAIM = "INVALID_CLAIM"


class FlowOutcome(str, Enum):
    FOUND = "FOUND"
    NOT_FOUND = "NOT_FOUND"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class EvidenceType(str, Enum):
    SOURCE_LOCATION = "SOURCE_LOCATION"
    AST_FACT = "AST_FACT"
    GRAPH_EDGE = "GRAPH_EDGE"
    CALL_RELATIONSHIP = "CALL_RELATIONSHIP"
    DATAFLOW_PATH = "DATAFLOW_PATH"
    SCANNER_FINDING = "SCANNER_FINDING"
    CHANGE_FACT = "CHANGE_FACT"
    IMPACT_RELATIONSHIP = "IMPACT_RELATIONSHIP"


class ToolCapability(str, Enum):
    REPOSITORY = "REPOSITORY"
    SYMBOLS = "SYMBOLS"
    GRAPH = "GRAPH"
    FLOW = "FLOW"
    SECURITY = "SECURITY"
    CHANGES = "CHANGES"
    IMPACT = "IMPACT"
    VERIFICATION = "VERIFICATION"


class TimeoutClass(str, Enum):
    FAST = "FAST"
    BOUNDED = "BOUNDED"
    EXPENSIVE = "EXPENSIVE"


class ToolError(ToolModel):
    code: str = Field(min_length=1, max_length=64)
    message: str = Field(min_length=1, max_length=512)
    details: dict[str, Any] = Field(default_factory=dict)


class EvidenceRecord(ToolModel):
    evidence_id: str = Field(min_length=1, max_length=512)
    evidence_type: EvidenceType
    source_component: str = Field(min_length=1, max_length=128)
    file_path: str | None = Field(default=None, max_length=1024)
    symbol: str | None = Field(default=None, max_length=1024)
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    relationship: str | None = Field(default=None, max_length=128)
    source_id: str | None = Field(default=None, max_length=1024)
    target_id: str | None = Field(default=None, max_length=1024)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolProvenance(ToolModel):
    production_components: list[str] = Field(min_length=1)
    component_versions: dict[str, str] = Field(default_factory=dict)
    repository_snapshot: str = Field(min_length=1, max_length=128)
    analysis_stage: str = Field(min_length=1, max_length=128)
    deterministic: Literal[True] = True


class ToolInvocationResult(ToolModel):
    """Common deterministic envelope; ``result`` is validated by each tool spec."""

    contract_version: Literal["1.0.0"] = AGENT_TOOL_CONTRACT_VERSION
    tool: str = Field(min_length=1, max_length=128)
    tool_version: str = Field(min_length=1, max_length=32)
    status: ToolResultStatus
    deterministic: Literal[True] = True
    result: dict[str, Any] | None = None
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    provenance: ToolProvenance | None = None
    warnings: list[ToolError] = Field(default_factory=list)
    errors: list[ToolError] = Field(default_factory=list)


class ToolMetadata(ToolModel):
    tool_name: str
    tool_version: str
    description: str
    read_only: Literal[True] = True
    deterministic: Literal[True] = True
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    capability: ToolCapability
    timeout_class: TimeoutClass
    evidence_required: bool


class SnapshotInput(ToolModel):
    snapshot_id: str | None = Field(default=None, min_length=1, max_length=128)


class InspectFileInput(SnapshotInput):
    file_path: str = Field(min_length=1, max_length=1024)


class SearchMode(str, Enum):
    EXACT = "EXACT"
    PREFIX = "PREFIX"
    CONTAINS = "CONTAINS"


class SearchSymbolInput(SnapshotInput):
    query: str = Field(min_length=1, max_length=256)
    kind: SymbolKind | None = None
    file_path: str | None = Field(default=None, min_length=1, max_length=1024)
    match_mode: SearchMode = SearchMode.EXACT
    max_results: int = Field(default=50, ge=1, le=500)


class InspectSymbolInput(SnapshotInput):
    symbol_id: str = Field(min_length=1, max_length=2048)


class RelationshipInput(InspectSymbolInput):
    max_results: int = Field(default=100, ge=1, le=500)


class TraceDataflowInput(SnapshotInput):
    source_symbol_id: str = Field(min_length=1, max_length=2048)
    sink_category: str | None = Field(default=None, min_length=1, max_length=128)
    max_depth: int = Field(default=2, ge=0, le=8)
    max_paths: int = Field(default=16, ge=1, le=64)


class ScanSecurityInput(SnapshotInput):
    file_path: str | None = Field(default=None, min_length=1, max_length=1024)
    symbol_id: str | None = Field(default=None, min_length=1, max_length=2048)
    rules: list[str] = Field(default_factory=list, max_length=64)
    categories: list[str] = Field(default_factory=list, max_length=32)
    analyzers: list[str] = Field(default_factory=list, max_length=16)
    max_results: int = Field(default=100, ge=1, le=500)


class AnalyzeChangeInput(ToolModel):
    base_snapshot_id: str = Field(min_length=1, max_length=128)
    head_snapshot_id: str = Field(min_length=1, max_length=128)
    scope_paths: list[str] = Field(default_factory=list, max_length=100)
    max_results: int = Field(default=200, ge=1, le=1000)


class AnalyzeImpactInput(AnalyzeChangeInput):
    changed_symbol_id: str | None = Field(default=None, min_length=1, max_length=2048)
    max_depth: int = Field(default=3, ge=1, le=8)


class ClaimType(str, Enum):
    SECURITY_FINDING = "SECURITY_FINDING"
    DATAFLOW = "DATAFLOW"
    CALL_RELATIONSHIP = "CALL_RELATIONSHIP"
    STRUCTURAL_CHANGE = "STRUCTURAL_CHANGE"


class ProposedFinding(ToolModel):
    claim_type: ClaimType
    snapshot_id: str | None = Field(default=None, min_length=1, max_length=128)
    base_snapshot_id: str | None = Field(default=None, min_length=1, max_length=128)
    head_snapshot_id: str | None = Field(default=None, min_length=1, max_length=128)
    rule: str | None = Field(default=None, min_length=1, max_length=512)
    file_path: str | None = Field(default=None, min_length=1, max_length=1024)
    symbol_id: str | None = Field(default=None, min_length=1, max_length=2048)
    source_symbol_id: str | None = Field(default=None, min_length=1, max_length=2048)
    target_symbol_id: str | None = Field(default=None, min_length=1, max_length=2048)
    sink_category: str | None = Field(default=None, min_length=1, max_length=128)
    relationship_type: str | None = Field(default=None, min_length=1, max_length=128)
    change_type: str | None = Field(default=None, min_length=1, max_length=128)
    evidence_refs: list[str] = Field(default_factory=list, max_length=64)


class VerifyFindingInput(ToolModel):
    claim: ProposedFinding


class SymbolRecord(ToolModel):
    symbol_id: str
    qualified_name: str
    name: str
    kind: SymbolKind
    file_path: str
    start_line: int
    end_line: int
    start_column: int | None = None
    end_column: int | None = None
    signature: str | None = None
    return_type: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class FileInspectionOutput(ToolModel):
    file_path: str
    language: str | None
    size_bytes: int
    lines_count: int
    is_binary: bool
    skipped_reason: str | None
    symbols: list[SymbolRecord]
    imports: list[SymbolRecord]
    manifest_scope_complete: bool


class SymbolSearchOutput(ToolModel):
    query: str
    match_mode: SearchMode
    matches: list[SymbolRecord]
    total_matches: int
    returned_matches: int
    truncated: bool


class GraphEntityRecord(ToolModel):
    entity_id: str
    kind: str
    label: str
    file_path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class GraphRelationship(ToolModel):
    relationship: str
    source: GraphEntityRecord
    target: GraphEntityRecord
    evidence_file: str | None = None
    evidence_line: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class SymbolInspectionOutput(ToolModel):
    symbol: SymbolRecord
    parents: list[SymbolRecord] = Field(default_factory=list)
    incoming: list[GraphRelationship] = Field(default_factory=list)
    outgoing: list[GraphRelationship] = Field(default_factory=list)
    graph_complete: bool


class RelationshipOutput(ToolModel):
    symbol: SymbolRecord
    relationships: list[GraphRelationship]
    total_relationships: int
    returned_relationships: int
    graph_complete: bool
    truncated: bool


class DataflowEndpoint(ToolModel):
    fact_id: str
    kind: str
    name: str
    file_path: str
    symbol: str
    start_line: int
    end_line: int
    certainty: str


class DataflowSupportingFact(ToolModel):
    fact_id: str
    kind: str
    name: str
    file_path: str
    symbol: str
    start_line: int
    end_line: int


class DataflowEdge(ToolModel):
    source_fact_id: str
    target_fact_id: str
    relation: str
    certainty: str


class DataflowPath(ToolModel):
    source: DataflowEndpoint
    sink: DataflowEndpoint
    transformations: list[str]
    sanitizers: list[DataflowSupportingFact]
    guards: list[DataflowSupportingFact]
    edges: list[DataflowEdge]
    opaque_calls: list[str]
    certainty: str
    evidence_refs: list[str]
    call_depth: int


class TraceDataflowOutput(ToolModel):
    outcome: FlowOutcome
    source_symbol_id: str
    paths: list[DataflowPath]
    total_paths: int
    returned_paths: int
    coverage: dict[str, Any]
    truncated: bool


class SecurityFindingRecord(ToolModel):
    finding_id: str
    analyzer: str
    rule: str | None
    title: str
    description: str
    severity: str
    category: str
    file_path: str
    start_line: int | None
    end_line: int | None
    certainty: str | None
    source_analyzer: str
    detector_kind: str | None


class SecurityScanOutput(ToolModel):
    findings: list[SecurityFindingRecord]
    total_findings: int
    returned_findings: int
    analyzer_status: dict[str, str]
    coverage_complete: bool
    truncated: bool


class AnalyzeChangeOutput(ToolModel):
    fact_classification: Literal["STRUCTURAL_FACT"] = "STRUCTURAL_FACT"
    defect_findings: list[dict[str, Any]] = Field(default_factory=list, max_length=0)
    diff: StructuralDiffResult
    total_facts: int
    returned_facts: int
    truncated: bool


class ImpactRecord(ToolModel):
    impact_type: str
    severity: str
    title: str
    description: str
    source_file: str | None
    source_symbol: str | None
    affected_file: str | None
    affected_symbol: str | None
    direction: str
    depth: int | None
    confidence: float
    verification_status: str
    evidence_payload: dict[str, Any]


class AnalyzeImpactOutput(ToolModel):
    impacts: list[ImpactRecord]
    total_impacts: int
    returned_impacts: int
    direct_impacts: int
    transitive_impacts: int
    max_depth_reached: int
    overall_risk_level: str
    truncated: bool
    truncation_reason: str | None


class VerifyFindingOutput(ToolModel):
    verdict: VerificationVerdict
    claim_type: ClaimType
    matched_evidence_refs: list[str]
    reason_code: str
