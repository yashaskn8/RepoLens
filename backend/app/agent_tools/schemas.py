"""Stable JSON-compatible contracts for deterministic RepoLens agent tools."""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.ingestion.schemas import SymbolKind
from app.schemas.change_analysis import FileChangeType, StructuralDiffResult, SymbolChangeType


AGENT_TOOL_CONTRACT_VERSION = "2.0.0"
AGENT_TOOL_VERSION = "2.0.0"
MAX_PUBLIC_PATH_LENGTH = 1024


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
    SOURCE_SLICE = "SOURCE_SLICE"
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
    evidence_id: str = Field(min_length=1, max_length=128)
    evidence_type: EvidenceType
    source_component: str = Field(min_length=1, max_length=128)
    file_path: str | None = Field(default=None, max_length=MAX_PUBLIC_PATH_LENGTH)
    symbol: str | None = Field(default=None, max_length=1024)
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    relationship: str | None = Field(default=None, max_length=128)
    source_id: str | None = Field(default=None, max_length=2048)
    target_id: str | None = Field(default=None, max_length=2048)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolProvenance(ToolModel):
    production_components: list[str] = Field(min_length=1)
    component_versions: dict[str, str] = Field(default_factory=dict)
    component_version_trust: Literal["DECLARED"] = "DECLARED"
    repository_snapshot: str = Field(min_length=1, max_length=128)
    snapshot_identity_trust: Literal["DECLARED"] = "DECLARED"
    snapshot_artifact_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    analysis_stage: str = Field(min_length=1, max_length=128)
    deterministic: Literal[True] = True


class ToolInvocationResult(ToolModel):
    """Common deterministic envelope; ``result`` is validated by each tool spec."""

    contract_version: Literal["2.0.0"] = AGENT_TOOL_CONTRACT_VERSION
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
    file_path: str = Field(min_length=1, max_length=MAX_PUBLIC_PATH_LENGTH)


class ReadSourceSliceInput(InspectFileInput):
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)

    @model_validator(mode="after")
    def validate_line_order(self) -> "ReadSourceSliceInput":
        if self.end_line < self.start_line:
            raise ValueError("end_line must be greater than or equal to start_line")
        return self


class SearchMode(str, Enum):
    EXACT = "EXACT"
    PREFIX = "PREFIX"
    CONTAINS = "CONTAINS"


class SearchSymbolInput(SnapshotInput):
    query: str = Field(min_length=1, max_length=256)
    kind: SymbolKind | None = None
    file_path: str | None = Field(default=None, min_length=1, max_length=MAX_PUBLIC_PATH_LENGTH)
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
    rules: list[Annotated[str, Field(min_length=1, max_length=512)]] = Field(default_factory=list, max_length=64)
    categories: list[Annotated[str, Field(min_length=1, max_length=128)]] = Field(default_factory=list, max_length=32)
    analyzers: list[Annotated[str, Field(min_length=1, max_length=128)]] = Field(default_factory=list, max_length=16)
    max_results: int = Field(default=100, ge=1, le=500)


class AnalyzeChangeInput(ToolModel):
    base_snapshot_id: str = Field(min_length=1, max_length=128)
    head_snapshot_id: str = Field(min_length=1, max_length=128)
    scope_paths: list[Annotated[str, Field(min_length=1, max_length=1024)]] = Field(default_factory=list, max_length=100)
    max_results: int = Field(default=200, ge=1, le=1000)


class AnalyzeImpactInput(AnalyzeChangeInput):
    changed_symbol_id: str | None = Field(default=None, min_length=1, max_length=2048)
    max_depth: int = Field(default=3, ge=1, le=8)


class ClaimType(str, Enum):
    SECURITY_FINDING = "SECURITY_FINDING"
    DATAFLOW = "DATAFLOW"
    CALL_RELATIONSHIP = "CALL_RELATIONSHIP"
    STRUCTURAL_CHANGE = "STRUCTURAL_CHANGE"


class SecurityFindingClaim(ToolModel):
    claim_type: Literal[ClaimType.SECURITY_FINDING]
    snapshot_id: str = Field(min_length=1, max_length=128)
    rule: str = Field(min_length=1, max_length=512)
    file_path: str = Field(min_length=1, max_length=1024)
    symbol_id: str | None = Field(default=None, min_length=1, max_length=2048)
    evidence_refs: list[Annotated[str, Field(min_length=1, max_length=128)]] = Field(min_length=1, max_length=64)


class DataflowClaim(ToolModel):
    claim_type: Literal[ClaimType.DATAFLOW]
    snapshot_id: str = Field(min_length=1, max_length=128)
    source_symbol_id: str = Field(min_length=1, max_length=2048)
    sink_category: str = Field(min_length=1, max_length=128)
    evidence_refs: list[Annotated[str, Field(min_length=1, max_length=128)]] = Field(min_length=1, max_length=64)


# -- JSON Schema extra: encode the "exactly one" XOR rules for source/target endpoints
# so schema-only consumers (MCP, OpenAPI, etc.) see structural constraints, not just
# four independent optional fields.  The runtime model_validator remains the authority.
_CALL_RELATIONSHIP_SCHEMA_EXTRA = {
    "allOf": [
        {
            "oneOf": [
                {
                    "required": ["source_symbol_id"],
                    "properties": {
                        "source_symbol_id": {"not": {"type": "null"}},
                        "source_entity_id": {"type": "null"},
                    },
                },
                {
                    "required": ["source_entity_id"],
                    "properties": {
                        "source_entity_id": {"not": {"type": "null"}},
                        "source_symbol_id": {"type": "null"},
                    },
                },
            ]
        },
        {
            "oneOf": [
                {
                    "required": ["target_symbol_id"],
                    "properties": {
                        "target_symbol_id": {"not": {"type": "null"}},
                        "target_entity_id": {"type": "null"},
                    },
                },
                {
                    "required": ["target_entity_id"],
                    "properties": {
                        "target_entity_id": {"not": {"type": "null"}},
                        "target_symbol_id": {"type": "null"},
                    },
                },
            ]
        },
    ]
}


class CallRelationshipClaim(ToolModel):
    model_config = ConfigDict(extra="forbid", json_schema_extra=_CALL_RELATIONSHIP_SCHEMA_EXTRA)

    claim_type: Literal[ClaimType.CALL_RELATIONSHIP]
    snapshot_id: str = Field(min_length=1, max_length=128)
    source_symbol_id: str | None = Field(default=None, min_length=1, max_length=2048)
    target_symbol_id: str | None = Field(default=None, min_length=1, max_length=2048)
    source_entity_id: str | None = Field(default=None, min_length=1, max_length=2048)
    target_entity_id: str | None = Field(default=None, min_length=1, max_length=2048)
    relationship_type: Literal["CALLS"] = "CALLS"
    call_site_file: str | None = Field(default=None, min_length=1, max_length=MAX_PUBLIC_PATH_LENGTH)
    call_site_line: int | None = Field(default=None, ge=1)
    evidence_refs: list[Annotated[str, Field(min_length=1, max_length=128)]] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def validate_endpoints(self) -> CallRelationshipClaim:
        has_source_symbol = self.source_symbol_id is not None
        has_source_entity = self.source_entity_id is not None
        if has_source_symbol == has_source_entity:
            if has_source_symbol:
                raise ValueError("CallRelationshipClaim cannot contain both source_symbol_id and source_entity_id")
            raise ValueError("CallRelationshipClaim must contain exactly one of source_symbol_id or source_entity_id")

        has_target_symbol = self.target_symbol_id is not None
        has_target_entity = self.target_entity_id is not None
        if has_target_symbol == has_target_entity:
            if has_target_symbol:
                raise ValueError("CallRelationshipClaim cannot contain both target_symbol_id and target_entity_id")
            raise ValueError("CallRelationshipClaim must contain exactly one of target_symbol_id or target_entity_id")

        return self


class StructuralChangeClaim(ToolModel):
    claim_type: Literal[ClaimType.STRUCTURAL_CHANGE]
    base_snapshot_id: str = Field(min_length=1, max_length=128)
    head_snapshot_id: str = Field(min_length=1, max_length=128)
    file_path: str = Field(min_length=1, max_length=MAX_PUBLIC_PATH_LENGTH)
    change_type: FileChangeType | SymbolChangeType
    symbol_id: str | None = Field(default=None, min_length=1, max_length=2048)
    evidence_refs: list[Annotated[str, Field(min_length=1, max_length=128)]] = Field(min_length=1, max_length=64)


ProposedFinding = SecurityFindingClaim | DataflowClaim | CallRelationshipClaim | StructuralChangeClaim


class VerifyFindingInput(ToolModel):
    claim: Annotated[ProposedFinding, Field(discriminator="claim_type")]


class SymbolRecord(ToolModel):
    symbol_id: str = Field(pattern=r"^symbol:[0-9a-f]{64}$", max_length=71)
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
    total_symbols: int
    returned_symbols: int
    truncated: bool
    manifest_scope_complete: bool


class ReadSourceSliceOutput(ToolModel):
    repository_snapshot: str = Field(min_length=1, max_length=128)
    file_path: str = Field(min_length=1, max_length=MAX_PUBLIC_PATH_LENGTH)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    content: str = Field(max_length=12_000)
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    truncated: bool


class SymbolSearchOutput(ToolModel):
    query: str
    match_mode: SearchMode
    matches: list[SymbolRecord]
    total_matches: int
    returned_matches: int
    truncated: bool
    manifest_scope_complete: bool


class GraphEntityRecord(ToolModel):
    entity_id: str = Field(min_length=1, max_length=2048)
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
    total_parents: int
    returned_parents: int
    incoming: list[GraphRelationship] = Field(default_factory=list)
    outgoing: list[GraphRelationship] = Field(default_factory=list)
    total_relationships: int
    returned_relationships: int
    graph_complete: bool
    truncated: bool


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
    limit_clamped: bool = False


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
    coverage: "ImpactCoverage"


class ImpactCoverage(ToolModel):
    complete: bool
    structural_diff_complete: bool
    base_graph_complete: bool
    head_graph_complete: bool
    traversal_complete: bool
    limit_clamped: bool = False
    stop_reasons: list[str] = Field(default_factory=list)


class VerifyFindingOutput(ToolModel):
    verdict: VerificationVerdict
    claim_type: ClaimType
    matched_evidence_refs: list[str]
    unresolved_evidence_refs: list[str]
    duplicate_evidence_refs: list[str]
    evidence_refs_complete: bool
    reason_code: str
