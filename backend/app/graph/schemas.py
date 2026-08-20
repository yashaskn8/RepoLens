"""Schemas and domain models for the deterministic Repository Relationship Graph."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class NodeKind(str, Enum):
    """Canonical node kinds in the repository graph."""

    FILE = "FILE"
    SYMBOL = "SYMBOL"
    ROUTE = "ROUTE"
    FRONTEND_REQUEST = "FRONTEND_REQUEST"
    DEPENDENCY = "DEPENDENCY"
    TEST = "TEST"


class EdgeKind(str, Enum):
    """Canonical edge kinds connecting repository graph nodes."""

    CONTAINS = "CONTAINS"
    IMPORTS = "IMPORTS"
    CALLS = "CALLS"
    EXPOSES_ROUTE = "EXPOSES_ROUTE"
    REQUESTS_ROUTE = "REQUESTS_ROUTE"
    MATCHES_ROUTE = "MATCHES_ROUTE"
    DEPENDS_ON = "DEPENDS_ON"
    TESTS = "TESTS"


class ContractMatchStatus(str, Enum):
    """Classification status for cross-layer frontend/backend route contract matching."""

    MATCHED = "MATCHED"
    UNMATCHED_FRONTEND_REQUEST = "UNMATCHED_FRONTEND_REQUEST"
    METHOD_MISMATCH = "METHOD_MISMATCH"
    PATH_MISMATCH = "PATH_MISMATCH"
    AMBIGUOUS_MATCH = "AMBIGUOUS_MATCH"


class GraphNode(BaseModel):
    """A typed node in the repository relationship graph."""

    id: str = Field(..., description="Unique deterministic identifier for the node")
    kind: NodeKind = Field(..., description="Node classification kind")
    label: str = Field(..., description="Human-readable label or name")
    file_path: Optional[str] = Field(default=None, description="Associated file path if applicable")
    start_line: Optional[int] = Field(default=None, description="Starting line number in source file")
    end_line: Optional[int] = Field(default=None, description="Ending line number in source file")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary typed metadata")


class GraphEdge(BaseModel):
    """A typed, directed edge connecting two repository graph nodes."""

    source: str = Field(..., description="Source node ID")
    target: str = Field(..., description="Target node ID")
    kind: EdgeKind = Field(..., description="Edge relationship kind")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Evidence and relationship metadata")


class RouteContractMatch(BaseModel):
    """Cross-layer frontend/backend API route contract evaluation."""

    frontend_request_id: str
    frontend_method: str
    frontend_url: str
    frontend_file: str
    frontend_line: Optional[int] = None
    status: ContractMatchStatus
    matched_route_ids: List[str] = Field(default_factory=list)
    matched_backend_paths: List[str] = Field(default_factory=list)
    matched_backend_methods: List[str] = Field(default_factory=list)
    details: str = Field(default="", description="Human-actionable explanation of match or mismatch")


class ContractMatchReport(BaseModel):
    """Aggregated report of cross-layer contract matching."""

    total_frontend_requests: int = 0
    total_backend_routes: int = 0
    matched_count: int = 0
    unmatched_count: int = 0
    method_mismatch_count: int = 0
    ambiguous_count: int = 0
    matches: List[RouteContractMatch] = Field(default_factory=list)


class RepositoryGraphData(BaseModel):
    """Serialized export of the full repository relationship graph."""

    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    total_nodes: int = 0
    total_edges: int = 0
    node_counts_by_kind: Dict[str, int] = Field(default_factory=dict)
    edge_counts_by_kind: Dict[str, int] = Field(default_factory=dict)
    contract_report: Optional[ContractMatchReport] = None
