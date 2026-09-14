"""Versioned benchmark-case, capability, and evaluation schemas for RepoLens."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class EvaluationStage(str, Enum):
    """Native output stage of the evaluated detector or subsystem."""

    STATIC_FINDING = "STATIC_FINDING"
    ANALYSIS_CANDIDATE = "ANALYSIS_CANDIDATE"
    CHANGE_FACT = "CHANGE_FACT"
    IMPACT_FACT = "IMPACT_FACT"
    PUBLISHED_FINDING = "PUBLISHED_FINDING"


class RuleType(str, Enum):
    """Whether a rule emits an issue/defect signal or a neutral structural fact."""

    ISSUE_SIGNAL = "ISSUE_SIGNAL"
    STRUCTURAL_FACT = "STRUCTURAL_FACT"


class BenchmarkCategory(str, Enum):
    """High-level orthogonal problem domain."""

    SECURITY = "SECURITY"
    CORRECTNESS = "CORRECTNESS"
    CONTRACT = "CONTRACT"
    CHANGE_IMPACT = "CHANGE_IMPACT"


class ExpectedVerdict(str, Enum):
    """Ground-truth expected outcome for the unit under evaluation."""

    ISSUE = "ISSUE"
    CLEAN = "CLEAN"
    UNKNOWN = "UNKNOWN"


class BenchmarkDifficulty(str, Enum):
    """Difficulty classification based on reasoning depth and structural context."""

    EASY = "EASY"
    MEDIUM = "MEDIUM"
    HARD = "HARD"


class BenchmarkSplit(str, Enum):
    """Partitioning split for scientific evaluation holdout."""

    DEV = "DEV"
    FROZEN_PUBLIC_EVAL = "FROZEN_PUBLIC_EVAL"


class TargetPipeline(str, Enum):
    """Which RepoLens production analysis pathway processes this case."""

    REPOSITORY_SCAN = "REPOSITORY_SCAN"
    CHANGE_ANALYSIS = "CHANGE_ANALYSIS"


class EvaluationScope(str, Enum):
    """Scope of assertions for clean cases."""

    RULE_SCOPED = "RULE_SCOPED"
    ALL_SUPPORTED = "ALL_SUPPORTED"


class AbstentionOutcome(str, Enum):
    """Fine-grained classification of system behavior on UNKNOWN cases."""

    EXPLICIT_CORRECT_ABSTENTION = "EXPLICIT_CORRECT_ABSTENTION"
    NO_POSITIVE_PUBLICATION = "NO_POSITIVE_PUBLICATION"
    INCORRECT_CONFIDENT_POSITIVE = "INCORRECT_CONFIDENT_POSITIVE"
    INCORRECT_CONFIDENT_NEGATIVE = "INCORRECT_CONFIDENT_NEGATIVE"
    PIPELINE_NOT_EVALUABLE = "PIPELINE_NOT_EVALUABLE"


class ExecutionStatus(str, Enum):
    """Status of the benchmark run."""

    COMPLETED = "COMPLETED"
    PARTIAL_RUN = "PARTIAL_RUN"
    FAILED = "FAILED"


class ExecutionScope(str, Enum):
    """Explicit scope classification for benchmark executions."""

    OFFICIAL_DEV = "OFFICIAL_DEV"
    OFFICIAL_PUBLIC_EVAL = "OFFICIAL_PUBLIC_EVAL"
    OFFICIAL_FULL_DIAGNOSTIC = "OFFICIAL_FULL_DIAGNOSTIC"
    CUSTOM = "CUSTOM"


class ContractChangeSemantic(str, Enum):
    """Semantic classification of contract compatibility."""

    BREAKING = "BREAKING"
    NON_BREAKING = "NON_BREAKING"
    CONDITIONALLY_BREAKING = "CONDITIONALLY_BREAKING"
    UNKNOWN = "UNKNOWN"


class StructuredImpactMetrics(BaseModel):
    """Graph-structured impact evaluation metrics comparing affected nodes and edges."""

    impact_node_tp: int = 0
    impact_node_fp: int = 0
    impact_node_fn: int = 0
    impact_node_precision: Optional[float] = None
    impact_node_recall: Optional[float] = None
    impact_node_f1: Optional[float] = None

    impact_edge_tp: int = 0
    impact_edge_fp: int = 0
    impact_edge_fn: int = 0
    impact_edge_precision: Optional[float] = None
    impact_edge_recall: Optional[float] = None
    impact_edge_f1: Optional[float] = None


class BenchmarkContract(BaseModel):
    """Cryptographic binding contract identifying dataset, evaluator, and execution parameters."""

    benchmark_version: str = "1.0.1"
    dataset_canonical_hash: str = "1611efec9c34421b19d862427241fde5061170d7268602103fd5585e66b317bf"
    catalog_hash: str = "835c22b4f9355738413b0c390c29e6f78b4b082c6a76151161388256b3d1b1ab"
    matcher_version: str = "1.0.1"
    metrics_version: str = "1.0.1"
    git_commit_sha: str = "aede4587ca195a7b072210589b1a3daa3b4d6778"
    execution_scope: ExecutionScope
    benchmark_contract_id: str


class FindingClaimSpec(BaseModel):
    """Explicit structural specification for an expected ground-truth claim."""

    rule_id: str = Field(..., description="Target rule identifier from capability catalog")
    permitted_files: List[str] = Field(..., min_length=1, description="Repository-relative paths where evidence must reside")
    permitted_symbols: List[str] = Field(default_factory=list, description="Permitted symbol names")
    permitted_spans: List[List[int]] = Field(default_factory=list, description="Permitted [start_line, end_line] intervals")
    required_structural_facts: Dict[str, Any] = Field(default_factory=dict, description="Required structural properties")
    forbidden_structural_facts: Dict[str, Any] = Field(default_factory=dict, description="Properties that must NOT be present")
    expected_severity: Optional[str] = Field(default=None, description="Expected severity if objectively defined")

    model_config = ConfigDict(extra="forbid")


class EvaluationAnnotation(BaseModel):
    """Curated ground-truth label and provenance, isolated from analysis input."""

    expected_verdict: ExpectedVerdict = Field(..., description="Target ground truth verdict")
    evaluation_scope: EvaluationScope = Field(default=EvaluationScope.RULE_SCOPED, description="Evaluation scope for CLEAN cases")
    target_rule_ids: List[str] = Field(default_factory=list, description="Target rules to evaluate for this case")
    claims: List[FindingClaimSpec] = Field(default_factory=list, description="Expected findings if verdict is ISSUE")
    expected_impact_count: Optional[int] = Field(default=None, description="Expected blast radius impact count if applicable")
    how_established: str = Field(..., description="Methodology used to establish ground truth")
    fixture_source: str = Field(..., description="Origin of the test code pattern")
    mutation_identifier: Optional[str] = Field(default=None, description="Identifier of mutation variant if applicable")
    human_authored_explanation: str = Field(..., description="Human technical rationale for the label")

    model_config = ConfigDict(extra="forbid")


class RepositoryFixture(BaseModel):
    """Repository code contents under test, completely decoupled from evaluation labels."""

    files: Dict[str, str] = Field(default_factory=dict, description="Relative path -> file content for repository scan")
    base_files: Optional[Dict[str, str]] = Field(default=None, description="Base repo files for change analysis")
    head_files: Optional[Dict[str, str]] = Field(default=None, description="Head repo files for change analysis")
    description: str = Field(default="", description="Neutral technical description with no outcome labels")

    model_config = ConfigDict(extra="forbid")


class AnalysisInput(BaseModel):
    """Untrusted analysis input provided to the system under evaluation."""

    case_id: str
    target_pipeline: TargetPipeline
    fixture: RepositoryFixture


class BenchmarkCase(BaseModel):
    """Complete, self-contained, machine-readable benchmark case."""

    case_id: str = Field(..., description="Unique case identifier (e.g. SEC-SQLI-01A)")
    benchmark_version: str = Field(default="1.0.0", description="Benchmark schema version")
    case_family: str = Field(..., description="Case family identifier (e.g. SEC-SQLI-01)")
    category: BenchmarkCategory = Field(..., description="Orthogonal problem category")
    difficulty: BenchmarkDifficulty = Field(default=BenchmarkDifficulty.MEDIUM)
    split: BenchmarkSplit = Field(..., description="DEV or FROZEN_PUBLIC_EVAL split")
    target_pipeline: TargetPipeline = Field(..., description="REPOSITORY_SCAN or CHANGE_ANALYSIS")
    evaluation_stage: EvaluationStage = Field(..., description="Native output stage to evaluate against")
    benchmark_languages: List[str] = Field(..., min_length=1, description="Languages empirically benchmarked in this case")
    fixture: RepositoryFixture = Field(..., description="Pure code fixture")
    annotation: EvaluationAnnotation = Field(..., description="Ground truth and provenance annotations")
    tags: List[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")
