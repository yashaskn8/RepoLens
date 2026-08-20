"""Schemas for reproducible evaluation harness, ground truth benchmarks, and metrics."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class IssueCategory(str, Enum):
    """Ground truth issue categories."""

    ROUTE_MISMATCH = "route_mismatch"
    METHOD_MISMATCH = "method_mismatch"
    SECURITY = "security"
    CORRECTNESS = "correctness"


class RetrievalVariant(str, Enum):
    """Retrieval pipeline variant configurations to benchmark."""

    LEXICAL_ONLY = "A. lexical only"
    VECTOR_ONLY = "B. vector only"
    LEXICAL_VECTOR = "C. lexical + vector"
    LEXICAL_VECTOR_GRAPH = "D. lexical + vector + graph"
    HYBRID_GRAPH_RERANKER = "E. hybrid + graph + reranker"


class GroundTruthIssue(BaseModel):
    """Explicit ground-truth label for a documented repository issue."""

    issue_id: str = Field(..., description="Unique issue identifier")
    category: IssueCategory = Field(..., description="Issue classification category")
    title: str = Field(..., description="Standard issue title")
    description: str = Field(..., description="Detailed description of defect")
    expected_file: str = Field(..., description="Normalized relative file path where defect exists")
    expected_start_line: int = Field(..., ge=1, description="Expected start line of defect")
    expected_end_line: int = Field(..., ge=1, description="Expected end line of defect")
    query: str = Field(..., description="Representative search query for this issue")
    expected_chunk_ids: List[str] = Field(default_factory=list, description="Target chunk IDs representing ground truth")


class VariantEvaluationResult(BaseModel):
    """Measured retrieval performance metrics for a specific variant."""

    variant: RetrievalVariant
    recall_at_k: float = Field(..., ge=0.0, le=1.0, description="Fraction of ground-truth chunks retrieved in top K")
    mrr: float = Field(..., ge=0.0, le=1.0, description="Mean Reciprocal Rank of first relevant chunk")
    avg_latency_ms: float = Field(..., ge=0.0, description="Average retrieval execution latency in milliseconds")
    total_queries: int = Field(..., ge=1)
    k: int = Field(default=5, ge=1)


class FindingEvaluationResult(BaseModel):
    """Measured multi-agent analysis and verification performance metrics."""

    total_ground_truth: int
    detected_candidates: int
    confirmed_findings: int
    rejected_findings: int
    precision: float = Field(..., ge=0.0, le=1.0, description="Confirmed true positives / total confirmed")
    recall: float = Field(..., ge=0.0, le=1.0, description="Confirmed true positives / total ground truth")
    false_positive_rate: float = Field(..., ge=0.0, le=1.0, description="False positives / total detected")
    evidence_localization_accuracy: float = Field(..., ge=0.0, le=1.0, description="Fraction of findings with correct file/line bounds")
    verifier_rejection_rate: float = Field(..., ge=0.0, le=1.0, description="Rejected findings / total candidate findings")
    model_call_count: int = Field(default=0, ge=0)


class BenchmarkReport(BaseModel):
    """Complete machine-readable evaluation harness benchmark report."""

    timestamp: datetime = Field(default_factory=_utc_now)
    fixtures_evaluated: List[str] = Field(default_factory=list)
    retrieval_results: Dict[str, VariantEvaluationResult] = Field(default_factory=dict)
    finding_results: FindingEvaluationResult
    markdown_summary: str = Field(..., description="Concise human-readable comparison table and report")
