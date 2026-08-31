"""Canonical Pydantic contracts for Change Intelligence and PR Impact Analysis."""

from datetime import datetime, timezone
from enum import Enum
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
from uuid import UUID, uuid4



from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas.enums import (
    ChangeAnalysisStatus,
    ChangeImpactType,
    ChangeRiskLevel,
    ImpactVerificationStatus,
    Severity,
)
from app.schemas.metadata import ModelExecutionMetadata


_GITHUB_URL_REGEX = re.compile(
    r"^https://github\.com/([a-zA-Z0-9_\-\.]+)/([a-zA-Z0-9_\-\.]+)$"
)
_GITHUB_PR_URL_REGEX = re.compile(
    r"^https://github\.com/([a-zA-Z0-9_\-\.]+)/([a-zA-Z0-9_\-\.]+)/pull/(\d+)/?$"
)
_HEX_40_REGEX = re.compile(r"^[0-9a-fA-F]{40}$")
_DISALLOWED_CHARS = re.compile(r"[;`$&|><\n\r\t]")


def _normalize_and_validate_github_url(v: str) -> str:
    if not isinstance(v, str):
        raise ValueError("repository_url must be a string")
    
    url = v.strip()
    if not url:
        raise ValueError("repository_url cannot be empty")
    
    if _DISALLOWED_CHARS.search(url):
        raise ValueError("repository_url contains forbidden shell or injection characters")
    
    if "@" in url:
        raise ValueError("repository_url must not contain authentication credentials or tokens")
    
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise ValueError("repository_url must use https scheme")
    
    if parsed.netloc.lower() not in ("github.com", "www.github.com"):
        raise ValueError("repository_url must be a github.com domain")
    
    clean_path = parsed.path.rstrip("/")
    if clean_path.endswith(".git"):
        clean_path = clean_path[:-4]
    
    canonical_url = f"https://github.com{clean_path}"
    match = _GITHUB_URL_REGEX.match(canonical_url)
    if not match:
        raise ValueError("repository_url must follow format: https://github.com/owner/repository")
    
    owner, repo = match.groups()
    if not owner or not repo:
        raise ValueError("repository_url must specify both owner and repository name")
    
    return canonical_url


def _normalize_and_validate_github_pr_url(v: str) -> Tuple[str, str, str, int]:
    """Validate and parse a GitHub pull request URL.
    
    Returns:
        (canonical_pr_url, owner, repo, pr_number)
    """
    if not isinstance(v, str):
        raise ValueError("pr_url must be a string")
    url = v.strip()
    if not url:
        raise ValueError("pr_url cannot be empty")
    if _DISALLOWED_CHARS.search(url):
        raise ValueError("pr_url contains forbidden shell or injection characters")
    if "@" in url:
        raise ValueError("pr_url must not contain credentials")
    
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise ValueError("pr_url must use https scheme")
    if parsed.netloc.lower() not in ("github.com", "www.github.com"):
        raise ValueError("pr_url must be a github.com domain")
    
    clean_path = parsed.path.rstrip("/")
    canonical_url = f"https://github.com{clean_path}"
    match = _GITHUB_PR_URL_REGEX.match(canonical_url)
    if not match:
        raise ValueError("pr_url must follow format: https://github.com/owner/repository/pull/number")
    
    owner, repo, pr_num_str = match.groups()
    if repo.endswith(".git"):
        repo = repo[:-4]
    pr_number = int(pr_num_str)
    if pr_number < 1:
        raise ValueError("pr_number must be greater than 0")
    
    canonical_url = f"https://github.com/{owner}/{repo}/pull/{pr_number}"
    return canonical_url, owner, repo, pr_number


def _normalize_and_validate_sha(sha: str, field_name: str) -> str:
    if not isinstance(sha, str):
        raise ValueError(f"{field_name} must be a string")
    
    clean_sha = sha.strip()
    if not _HEX_40_REGEX.match(clean_sha):
        raise ValueError(f"{field_name} must be an exact 40-character hexadecimal commit SHA")
    
    return clean_sha.lower()


class ChangeAnalysisRequest(BaseModel):
    """Canonical request payload to trigger change intelligence analysis between two exact revisions."""

    repository_url: str = Field(
        ...,
        description="Public HTTPS GitHub repository URL (e.g., https://github.com/owner/repo)",
        examples=["https://github.com/fastapi/fastapi"],
    )
    base_commit_sha: str = Field(
        ...,
        description="Exact 40-character hexadecimal commit SHA for the base/target revision",
        examples=["1111111111111111111111111111111111111111"],
    )
    head_commit_sha: str = Field(
        ...,
        description="Exact 40-character hexadecimal commit SHA for the head/source revision",
        examples=["2222222222222222222222222222222222222222"],
    )
    base_ref: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Optional human-readable base branch or tag name (e.g., main)",
    )
    head_ref: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Optional human-readable head branch or ref name (e.g., feature/auth-refactor)",
    )

    @field_validator("repository_url")
    @classmethod
    def validate_repo_url(cls, v: str) -> str:
        return _normalize_and_validate_github_url(v)

    @field_validator("base_commit_sha")
    @classmethod
    def validate_base_sha(cls, v: str) -> str:
        return _normalize_and_validate_sha(v, "base_commit_sha")

    @field_validator("head_commit_sha")
    @classmethod
    def validate_head_sha(cls, v: str) -> str:
        return _normalize_and_validate_sha(v, "head_commit_sha")

    @model_validator(mode="after")
    def validate_distinct_shas(self) -> "ChangeAnalysisRequest":
        if self.base_commit_sha == self.head_commit_sha:
            raise ValueError("base_commit_sha and head_commit_sha must be distinct revisions")
        return self


class ChangeAnalysisPRRequest(BaseModel):
    """Request payload to initiate change analysis from a public GitHub pull request URL."""

    pr_url: str = Field(
        ...,
        description="Public HTTPS GitHub Pull Request URL (e.g., https://github.com/fastapi/fastapi/pull/123)",
        examples=["https://github.com/fastapi/fastapi/pull/1234"],
    )

    @field_validator("pr_url")
    @classmethod
    def validate_pr_url(cls, v: str) -> str:
        canonical_url, _, _, _ = _normalize_and_validate_github_pr_url(v)
        return canonical_url


class ResolvedPullRequest(BaseModel):
    """Normalized, immutable pull request metadata resolved from GitHub REST API."""

    repository_url: str = Field(..., description="Canonical repository URL")
    repository_owner: str = Field(..., description="Repository owner/org")
    repository_name: str = Field(..., description="Repository name")
    pr_number: int = Field(..., description="Pull request number")
    title: str = Field(..., description="Pull request title")
    base_branch: str = Field(..., description="Target base branch name")
    base_commit_sha: str = Field(..., description="Exact 40-character base commit SHA")
    head_branch: str = Field(..., description="Source head branch or ref name")
    head_commit_sha: str = Field(..., description="Exact 40-character head commit SHA")
    head_repo_url: Optional[str] = Field(default=None, description="Head repository URL (different if from fork)")
    is_fork: bool = Field(default=False, description="True if pull request is from a fork")
    state: str = Field(default="open", description="Pull request state: open, closed, or merged")



class ChangeImpactEvidence(BaseModel):
    """Structured evidence backing a specific change impact claim."""

    file_path: str = Field(..., description="Target repository file path")
    symbol_name: Optional[str] = Field(default=None, description="Target symbol identifier (function/class/method)")
    base_line_range: Optional[List[int]] = Field(default=None, description="Line range [start, end] in base revision")
    head_line_range: Optional[List[int]] = Field(default=None, description="Line range [start, end] in head revision")
    edge_type: Optional[str] = Field(default=None, description="Graph dependency edge type (e.g. CALLS, IMPORTS, ROUTE)")
    caller_file: Optional[str] = Field(default=None, description="Calling file path if representing caller impact")
    caller_symbol: Optional[str] = Field(default=None, description="Calling symbol name")
    callee_file: Optional[str] = Field(default=None, description="Callee file path")
    callee_symbol: Optional[str] = Field(default=None, description="Callee symbol name")
    contract_name: Optional[str] = Field(default=None, description="API route or schema contract identifier")
    code_snippet: Optional[str] = Field(default=None, description="Code snippet demonstrating change or impact")
    context_notes: Optional[str] = Field(default=None, description="Deterministic context or reasoning notes")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional structured evidence telemetry")


class ChangeImpact(BaseModel):
    """Structured, evidence-backed impact record detailing a discrete semantic change effect."""

    id: UUID = Field(..., description="Unique impact record identifier")
    analysis_id: UUID = Field(..., description="Parent ChangeAnalysis identifier")
    impact_type: ChangeImpactType = Field(..., description="Semantic category of impact")
    severity: Severity = Field(default=Severity.MEDIUM, description="Assessed impact severity")
    title: str = Field(..., max_length=256, description="Concise impact summary title")
    description: str = Field(..., max_length=2048, description="Detailed explanation of semantic impact")
    source_file: Optional[str] = Field(default=None, max_length=512, description="Originating file where change occurred")
    source_symbol: Optional[str] = Field(default=None, max_length=256, description="Originating symbol name")
    affected_file: Optional[str] = Field(default=None, max_length=512, description="Downstream affected file path")
    affected_symbol: Optional[str] = Field(default=None, max_length=256, description="Downstream affected symbol name")
    evidence_payload: Dict[str, Any] = Field(default_factory=dict, description="Structured evidence details")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence score from 0.0 to 1.0")
    verification_status: ImpactVerificationStatus = Field(
        default=ImpactVerificationStatus.FACT,
        description="Epistemic status: FACT, INFERENCE, or ASSUMPTION",
    )
    created_at: datetime = Field(..., description="Creation timestamp")

    model_config = ConfigDict(from_attributes=True)


class ChangeAnalysisSummary(BaseModel):
    """High-level summary of a change intelligence analysis."""

    id: UUID = Field(..., description="Unique change analysis ID")
    repository_url: str = Field(..., description="Canonical repository URL")
    repository_owner: str = Field(..., description="GitHub repository owner/org")
    repository_name: str = Field(..., description="GitHub repository name")
    base_ref: Optional[str] = Field(default=None, description="Base branch or ref name")
    base_commit_sha: str = Field(..., description="Exact 40-character base commit SHA")
    head_ref: Optional[str] = Field(default=None, description="Head branch or ref name")
    head_commit_sha: str = Field(..., description="Exact 40-character head commit SHA")
    status: ChangeAnalysisStatus = Field(..., description="Analysis lifecycle status")
    changed_files_count: int = Field(default=0, ge=0, description="Count of modified/added/deleted files")
    changed_symbols_count: int = Field(default=0, ge=0, description="Count of directly changed symbols")
    impacted_symbols_count: int = Field(default=0, ge=0, description="Count of transitively impacted symbols/callers")
    risk_level: Optional[ChangeRiskLevel] = Field(default=None, description="Overall risk level rating")
    failure_code: Optional[str] = Field(default=None, description="Failure reason code if status is FAILED")
    failure_message: Optional[str] = Field(default=None, description="Sanitized failure description")
    created_at: datetime = Field(..., description="Analysis creation timestamp")
    updated_at: datetime = Field(..., description="Last status update timestamp")
    completed_at: Optional[datetime] = Field(default=None, description="Completion timestamp")

    model_config = ConfigDict(from_attributes=True)


class ChangeAnalysisResponse(ChangeAnalysisSummary):
    """Complete serialized change analysis response including structured impact records."""

    impacts: List[ChangeImpact] = Field(
        default_factory=list,
        description="List of structured, evidence-backed impact records",
    )
    model_metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional model execution metadata and token telemetry",
    )

    model_config = ConfigDict(from_attributes=True)


# =========================================================================
# Structural Diff Contracts (Phase 6C)
# =========================================================================


class FileChangeType(str, Enum):
    """Classification of file modifications in comparison diff."""

    ADDED = "ADDED"
    DELETED = "DELETED"
    MODIFIED = "MODIFIED"
    RENAMED = "RENAMED"
    UNMODIFIED = "UNMODIFIED"


class SymbolChangeType(str, Enum):
    """Classification of structural symbol modifications."""

    ADDED = "ADDED"
    DELETED = "DELETED"
    MODIFIED = "MODIFIED"
    SIGNATURE_CHANGED = "SIGNATURE_CHANGED"
    RENAMED = "RENAMED"


class FileDiffFact(BaseModel):
    """Deterministic structural fact regarding a file change between two revisions."""

    file_path: str = Field(..., description="Normalized relative file path in head revision")
    old_path: Optional[str] = Field(default=None, description="Original relative file path if renamed")
    change_type: FileChangeType = Field(..., description="Categorized file change type")
    is_binary: bool = Field(default=False, description="True if file is binary (never parsed as text)")
    is_parsed: bool = Field(default=True, description="True if file was parsed by AST parser")
    skipped_reason: Optional[str] = Field(default=None, description="Reason file parsing was skipped (e.g. BINARY, UNSUPPORTED_LANGUAGE)")
    language: Optional[str] = Field(default=None, description="Detected source language")
    changed_line_ranges: List[List[int]] = Field(default_factory=list, description="1-indexed [start, end] line ranges in head")
    base_line_ranges: List[List[int]] = Field(default_factory=list, description="1-indexed [start, end] line ranges in base")


class SymbolDiffFact(BaseModel):
    """Deterministic structural fact regarding a symbol addition, deletion, or modification."""

    file_path: str = Field(..., description="Relative file path containing symbol")
    symbol_name: str = Field(..., description="Symbol identifier or signature name")
    symbol_kind: str = Field(..., description="Kind of symbol (FUNCTION, METHOD, CLASS, ROUTE, etc.)")
    change_type: SymbolChangeType = Field(..., description="Categorized symbol change type")
    base_location: Optional[Dict[str, Any]] = Field(default=None, description="Location in base revision {start_line, end_line, ...}")
    head_location: Optional[Dict[str, Any]] = Field(default=None, description="Location in head revision {start_line, end_line, ...}")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Deterministic evidence payload (parameters, return type, diffs)")


class DependencyDelta(BaseModel):
    """Deterministic package dependency change detected in manifest files."""

    manifest_file: str = Field(..., description="Manifest path (e.g. package.json, requirements.txt, pyproject.toml)")
    package_name: str = Field(..., description="Dependency package name")
    base_version: Optional[str] = Field(default=None, description="Version in base revision")
    head_version: Optional[str] = Field(default=None, description="Version in head revision")
    change_type: str = Field(..., description="ADDED, REMOVED, or UPDATED")


class ConfigDelta(BaseModel):
    """Deterministic configuration or environment variable definition change with zero raw secrets."""

    file_path: str = Field(..., description="Configuration file path (e.g. .env.example, config.yaml, settings.py)")
    key: str = Field(..., description="Config key or environment variable name")
    change_type: str = Field(..., description="ADDED, REMOVED, or MODIFIED")
    base_present: bool = Field(default=False, description="Whether key was present in base revision")
    head_present: bool = Field(default=False, description="Whether key is present in head revision")
    value_changed: bool = Field(default=False, description="Whether value changed between revisions")
    base_fingerprint: Optional[str] = Field(default=None, description="One-way non-reversible hash of base value if present")
    head_fingerprint: Optional[str] = Field(default=None, description="One-way non-reversible hash of head value if present")
    base_value: Optional[str] = Field(default=None, description="Deprecated compatibility field (always None)")
    head_value: Optional[str] = Field(default=None, description="Deprecated compatibility field (always None)")


class RouteContractDelta(BaseModel):
    """Deterministic API route contract or client invocation change."""

    file_path: str = Field(..., description="Source file defining route or client call")
    route_type: str = Field(..., description="FASTAPI_ROUTE, EXPRESS_ROUTE, FETCH_CALL, or AXIOS_CALL")
    route_name: str = Field(..., description="Route identifier or call signature")
    base_http_method: Optional[str] = Field(default=None, description="HTTP method in base revision")
    head_http_method: Optional[str] = Field(default=None, description="HTTP method in head revision")
    base_path: Optional[str] = Field(default=None, description="Path or target in base revision")
    head_path: Optional[str] = Field(default=None, description="Path or target in head revision")
    change_type: str = Field(..., description="ADDED, REMOVED, PATH_CHANGED, METHOD_CHANGED, or TARGET_CHANGED")
    details: str = Field(default="", description="Detailed human-actionable summary of contract change")


class SchemaModelDelta(BaseModel):
    """Deterministic model/schema definition field change (Pydantic, SQLAlchemy, etc.)."""

    file_path: str = Field(..., description="Source file defining model")
    model_name: str = Field(..., description="Model class name")
    model_kind: str = Field(default="MODEL", description="PYDANTIC_MODEL, SQLALCHEMY_MODEL, or SCHEMA")
    field_name: str = Field(..., description="Target model attribute or field name")
    base_type: Optional[str] = Field(default=None, description="Field type in base revision")
    head_type: Optional[str] = Field(default=None, description="Field type in head revision")
    change_type: str = Field(..., description="ADDED_FIELD, REMOVED_FIELD, MODIFIED_TYPE, or CONSTRAINT_CHANGED")
    details: str = Field(default="", description="Field change explanation")


class StructuralDiffResult(BaseModel):
    """Aggregated deterministic structural change facts between base and head revisions."""

    base_commit_sha: str = Field(..., description="Exact 40-character base commit SHA")
    head_commit_sha: str = Field(..., description="Exact 40-character head commit SHA")
    repository_url: str = Field(..., description="Repository URL")
    changed_files: List[FileDiffFact] = Field(default_factory=list, description="All analyzed files with change classifications")
    added_files: List[str] = Field(default_factory=list, description="List of newly added relative file paths")
    deleted_files: List[str] = Field(default_factory=list, description="List of deleted relative file paths")
    renamed_files: List[List[str]] = Field(default_factory=list, description="List of [old_path, new_path] pairs")
    modified_files: List[str] = Field(default_factory=list, description="List of modified existing file paths")
    changed_symbols: List[SymbolDiffFact] = Field(default_factory=list, description="All changed symbols")
    added_symbols: List[SymbolDiffFact] = Field(default_factory=list, description="Added symbols")
    deleted_symbols: List[SymbolDiffFact] = Field(default_factory=list, description="Deleted symbols")
    modified_symbols: List[SymbolDiffFact] = Field(default_factory=list, description="Modified symbols")
    dependency_deltas: List[DependencyDelta] = Field(default_factory=list, description="Package dependency manifest deltas")
    config_deltas: List[ConfigDelta] = Field(default_factory=list, description="Config and environment variable deltas")
    route_deltas: List[RouteContractDelta] = Field(default_factory=list, description="API route and client call deltas")
    schema_deltas: List[SchemaModelDelta] = Field(default_factory=list, description="Data model and schema deltas")
    summary: Dict[str, int] = Field(default_factory=dict, description="Numerical summary of all detected changes")


# =========================================================================
# Graph-Aware Blast Radius Contracts (Phase 6D)
# =========================================================================


class BlastRadiusReport(BaseModel):
    """Aggregated report of graph-aware blast radius analysis."""

    analysis_id: UUID = Field(..., description="Parent ChangeAnalysis identifier")
    impacts: List[ChangeImpact] = Field(default_factory=list, description="Computed structured change impact records")
    total_impacts: int = Field(default=0, description="Total impact records generated")
    direct_impacts_count: int = Field(default=0, description="Count of direct (depth 1) impacts")
    transitive_impacts_count: int = Field(default=0, description="Count of multi-hop (depth > 1) impacts")
    is_truncated: bool = Field(default=False, description="True if traversal reached max depth or max results limit")
    truncation_reason: Optional[str] = Field(default=None, description="Reason traversal was truncated if applicable")
    max_depth_reached: int = Field(default=0, description="Maximum traversal depth reached during exploration")
    overall_risk_level: ChangeRiskLevel = Field(default=ChangeRiskLevel.LOW, description="Aggregated risk level rating")
    summary_by_type: Dict[str, int] = Field(default_factory=dict, description="Count of impacts by ChangeImpactType")
    summary_by_severity: Dict[str, int] = Field(default_factory=dict, description="Count of impacts by Severity")


# =========================================================================
# Grounded AI Change Review Contracts (Phase 6E)
# =========================================================================


class ChangeReviewVerdict(str, Enum):
    """Verification verdict for AI change review findings."""

    CONFIRMED = "CONFIRMED"
    SUPPORTED_INFERENCE = "SUPPORTED_INFERENCE"
    REJECTED = "REJECTED"


class ChangeReviewRiskType(str, Enum):
    """Taxonomy of risk types identified by AI change reviewer."""

    API_CONTRACT_BREAK = "API_CONTRACT_BREAK"
    REGRESSION_RISK = "REGRESSION_RISK"
    SECURITY_REGRESSION = "SECURITY_REGRESSION"
    BEHAVIORAL_CHANGE = "BEHAVIORAL_CHANGE"
    RESOURCE_LEAK = "RESOURCE_LEAK"
    UNHANDLED_EDGE_CASE = "UNHANDLED_EDGE_CASE"
    PERFORMANCE_DEGRADATION = "PERFORMANCE_DEGRADATION"
    CONFIG_MISMATCH = "CONFIG_MISMATCH"
    DEPENDENCY_INCOMPATIBILITY = "DEPENDENCY_INCOMPATIBILITY"
    SCHEMA_INCOMPATIBILITY = "SCHEMA_INCOMPATIBILITY"


class ChangeReviewFinding(BaseModel):
    """A structured AI change review finding grounded in deterministic diff and impact facts."""

    id: UUID = Field(default_factory=uuid4, description="Unique finding identifier")
    title: str = Field(..., max_length=256, description="Concise title summarizing the identified change risk")
    risk_type: str = Field(..., description="Categorized risk type (e.g. API_CONTRACT_BREAK, REGRESSION_RISK)")
    severity: Severity = Field(default=Severity.MEDIUM, description="Assessed finding severity")
    reasoning_summary: str = Field(..., description="Step-by-step reasoning connecting facts to the identified risk")
    evidence_refs: List[str] = Field(default_factory=list, description="Explicit deterministic evidence identifiers or references (diff facts, symbols, files, lines)")
    affected_files: List[str] = Field(default_factory=list, description="List of affected repository relative file paths")
    affected_symbols: List[str] = Field(default_factory=list, description="List of affected symbol identifiers or function/class names")
    confidence: float = Field(default=0.8, ge=0.0, le=1.0, description="Reviewer confidence score (0.0 to 1.0)")
    assumptions: List[str] = Field(default_factory=list, description="Explicitly disclosed assumptions or preconditions")
    verdict: ChangeReviewVerdict = Field(default=ChangeReviewVerdict.SUPPORTED_INFERENCE, description="Verification verdict: CONFIRMED, SUPPORTED_INFERENCE, or REJECTED")
    verification_reason: Optional[str] = Field(default=None, description="Deterministic verifier justification")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Timestamp")

    model_config = ConfigDict(from_attributes=True)


class ChangeReviewReport(BaseModel):
    """Complete structured AI change review report produced by ChangeReviewAgent and verified by ChangeReviewVerifier."""

    analysis_id: UUID = Field(..., description="Parent ChangeAnalysis identifier")
    findings: List[ChangeReviewFinding] = Field(default_factory=list, description="Verified AI review findings")
    rejected_findings: List[Dict[str, Any]] = Field(default_factory=list, description="Findings rejected by deterministic verifier with rejection reasons")
    summary: str = Field(default="", description="Executive summary of the change review")
    total_findings: int = Field(default=0, description="Total verified findings count")
    facts_count: int = Field(default=0, description="Count of directly verified facts")
    inferences_count: int = Field(default=0, description="Count of supported inferences")
    assumptions_count: int = Field(default=0, description="Count of disclosed assumptions")
    confirmed_count: int = Field(default=0, description="Count of CONFIRMED findings")
    supported_inference_count: int = Field(default=0, description="Count of SUPPORTED_INFERENCE findings")
    rejected_count: int = Field(default=0, description="Count of REJECTED findings")
    overall_risk_level: ChangeRiskLevel = Field(default=ChangeRiskLevel.LOW, description="Aggregated risk assessment")
    model_metadata: Optional[ModelExecutionMetadata] = Field(default=None, description="LLM execution telemetry and token usage")

    model_config = ConfigDict(from_attributes=True)


# =========================================================================
# Change Analysis Report Contracts (Phase 6G)
# =========================================================================


class ChangeAnalysisReportResponse(BaseModel):
    """Comprehensive structured and Markdown change intelligence report."""

    analysis_id: UUID = Field(..., description="Unique change analysis identifier")
    repository_url: str = Field(..., description="Canonical repository URL")
    repository_owner: str = Field(..., description="Repository owner/organization")
    repository_name: str = Field(..., description="Repository name")
    base_commit_sha: str = Field(..., description="Exact 40-character base commit SHA")
    head_commit_sha: str = Field(..., description="Exact 40-character head commit SHA")
    base_ref: Optional[str] = Field(default=None, description="Base branch or ref name")
    head_ref: Optional[str] = Field(default=None, description="Head branch or ref name")
    pr_number: Optional[int] = Field(default=None, description="GitHub pull request number if analyzed from PR")
    pr_title: Optional[str] = Field(default=None, description="GitHub pull request title")
    status: ChangeAnalysisStatus = Field(..., description="Analysis lifecycle status")
    risk_level: Optional[ChangeRiskLevel] = Field(default=None, description="Deterministic risk level rating")
    risk_explanation: str = Field(default="", description="Deterministic justification for assigned risk level")
    created_at: datetime = Field(..., description="Analysis creation timestamp")
    completed_at: Optional[datetime] = Field(default=None, description="Analysis completion timestamp")
    duration_seconds: Optional[float] = Field(default=None, description="Total execution duration in seconds")

    # Metrics
    files_changed_count: int = Field(default=0, ge=0, description="Total changed files count")
    symbols_changed_count: int = Field(default=0, ge=0, description="Total changed symbols count")
    impacted_symbols_count: int = Field(default=0, ge=0, description="Total impacted symbols/callers count")
    contract_breaks_count: int = Field(default=0, ge=0, description="Identified contract break impacts count")
    security_impacts_count: int = Field(default=0, ge=0, description="Identified security-sensitive impacts count")

    # Contract Deltas
    route_deltas: List[RouteContractDelta] = Field(default_factory=list, description="API route contract deltas")
    schema_deltas: List[SchemaModelDelta] = Field(default_factory=list, description="Data schema and model deltas")
    dependency_deltas: List[DependencyDelta] = Field(default_factory=list, description="Manifest dependency deltas")
    config_deltas: List[ConfigDelta] = Field(default_factory=list, description="Configuration and environment deltas")

    # Blast Radius & Findings
    impacts: List[ChangeImpact] = Field(default_factory=list, description="All evidence-backed impact records")
    review_findings: List[ChangeReviewFinding] = Field(default_factory=list, description="Verified AI review findings")

    # Tooling and Evidence Limitations
    tool_availability: Dict[str, bool] = Field(default_factory=dict, description="Availability state of analysis engines")
    limitations: List[str] = Field(default_factory=list, description="Disclosed analysis constraints and epistemic limitations")

    # Deterministic Markdown Render
    markdown_report: str = Field(..., description="Deterministic, human-readable Markdown change report")

    model_config = ConfigDict(from_attributes=True)




