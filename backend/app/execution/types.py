"""Stable types for the shared durable execution boundary."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Mapping, Optional


class ExecutionState(str, Enum):
    QUEUED = "QUEUED"
    ADMITTED = "ADMITTED"
    READY = "READY"
    LEASED = "LEASED"
    RUNNING = "RUNNING"
    RETRY_WAIT = "RETRY_WAIT"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"


TERMINAL_STATES = frozenset(
    {
        ExecutionState.SUCCEEDED,
        ExecutionState.FAILED,
        ExecutionState.CANCELLED,
        ExecutionState.TIMED_OUT,
    }
)
ACTIVE_STATES = frozenset({ExecutionState.LEASED, ExecutionState.RUNNING})


class DomainOutcome(str, Enum):
    COMPLETE = "COMPLETE"
    DEGRADED = "DEGRADED"
    BOUNDED = "BOUNDED"


class WorkKind(str, Enum):
    SCAN = "SCAN"
    CHANGE_ANALYSIS = "CHANGE_ANALYSIS"
    RESEARCH = "RESEARCH"
    FIX_PLAN = "FIX_PLAN"
    PATCH_GENERATION = "PATCH_GENERATION"
    REPORT_GENERATION = "REPORT_GENERATION"
    REVIEW_PUBLICATION = "REVIEW_PUBLICATION"
    GITHUB_DELIVERY = "GITHUB_DELIVERY"


class SideEffectClass(str, Enum):
    SAFE_RECOMPUTATION = "SAFE_RECOMPUTATION"
    EXTERNAL_SIDE_EFFECT = "EXTERNAL_SIDE_EFFECT"


class LeaseState(str, Enum):
    ACTIVE = "ACTIVE"
    RELEASED = "RELEASED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class ReservationState(str, Enum):
    ACTIVE = "ACTIVE"
    RELEASED = "RELEASED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class ResourceDimension(str, Enum):
    WORKER = "WORKER"
    SCANNER = "SCANNER"
    AI = "AI"
    RENDERER = "RENDERER"
    LARGE_REPOSITORY = "LARGE_REPOSITORY"
    EMBEDDING = "EMBEDDING"
    PATCH = "PATCH"
    GITHUB_WRITE = "GITHUB_WRITE"
    TENANT_ACTIVE_JOB = "TENANT_ACTIVE_JOB"


class ResourceProfile(str, Enum):
    SMALL_REPO_SCAN = "SMALL_REPO_SCAN"
    LARGE_REPO_SCAN = "LARGE_REPO_SCAN"
    SCANNER_IO = "SCANNER_IO"
    CHANGE_ANALYSIS = "CHANGE_ANALYSIS"
    EMBEDDING_BATCH = "EMBEDDING_BATCH"
    LLM_REASONING = "LLM_REASONING"
    PATCH_GENERATION = "PATCH_GENERATION"
    REPORT_RENDER = "REPORT_RENDER"
    GITHUB_WRITE = "GITHUB_WRITE"


RESOURCE_PROFILE_REQUIREMENTS: Mapping[ResourceProfile, Mapping[ResourceDimension, int]] = {
    ResourceProfile.SMALL_REPO_SCAN: {ResourceDimension.WORKER: 1, ResourceDimension.SCANNER: 1},
    ResourceProfile.LARGE_REPO_SCAN: {
        ResourceDimension.WORKER: 1,
        ResourceDimension.SCANNER: 1,
        ResourceDimension.LARGE_REPOSITORY: 1,
    },
    ResourceProfile.SCANNER_IO: {ResourceDimension.WORKER: 1, ResourceDimension.SCANNER: 1},
    ResourceProfile.CHANGE_ANALYSIS: {ResourceDimension.WORKER: 1},
    ResourceProfile.EMBEDDING_BATCH: {
        ResourceDimension.WORKER: 1,
        ResourceDimension.AI: 1,
        ResourceDimension.EMBEDDING: 1,
    },
    ResourceProfile.LLM_REASONING: {ResourceDimension.WORKER: 1, ResourceDimension.AI: 1},
    ResourceProfile.PATCH_GENERATION: {
        ResourceDimension.WORKER: 1,
        ResourceDimension.AI: 1,
        ResourceDimension.PATCH: 1,
    },
    ResourceProfile.REPORT_RENDER: {ResourceDimension.WORKER: 1, ResourceDimension.RENDERER: 1},
    ResourceProfile.GITHUB_WRITE: {ResourceDimension.WORKER: 1, ResourceDimension.GITHUB_WRITE: 1},
}


DEFAULT_RESOURCE_CAPACITIES: Mapping[ResourceDimension, int] = {
    ResourceDimension.WORKER: 1,
    ResourceDimension.SCANNER: 1,
    ResourceDimension.AI: 1,
    ResourceDimension.RENDERER: 1,
    ResourceDimension.LARGE_REPOSITORY: 1,
    ResourceDimension.EMBEDDING: 1,
    ResourceDimension.PATCH: 1,
    ResourceDimension.GITHUB_WRITE: 1,
}


class FailureCode(str, Enum):
    USER_INPUT_ERROR = "USER_INPUT_ERROR"
    REPOSITORY_UNAVAILABLE = "REPOSITORY_UNAVAILABLE"
    REPOSITORY_LIMIT_EXCEEDED = "REPOSITORY_LIMIT_EXCEEDED"
    SNAPSHOT_POLICY_VIOLATION = "SNAPSHOT_POLICY_VIOLATION"
    ANALYZER_UNAVAILABLE = "ANALYZER_UNAVAILABLE"
    ANALYZER_TIMEOUT = "ANALYZER_TIMEOUT"
    ANALYZER_INVALID_OUTPUT = "ANALYZER_INVALID_OUTPUT"
    PROVIDER_RATE_LIMITED = "PROVIDER_RATE_LIMITED"
    PROVIDER_AUTH_FAILURE = "PROVIDER_AUTH_FAILURE"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    MODEL_CONTEXT_LIMIT = "MODEL_CONTEXT_LIMIT"
    MODEL_INVALID_OUTPUT = "MODEL_INVALID_OUTPUT"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    WORKFLOW_TIMEOUT = "WORKFLOW_TIMEOUT"
    WORKER_LOST = "WORKER_LOST"
    CANCELLED_BY_USER = "CANCELLED_BY_USER"
    EXTERNAL_STATE_UNCERTAIN = "EXTERNAL_STATE_UNCERTAIN"
    INTERNAL_INVARIANT_VIOLATION = "INTERNAL_INVARIANT_VIOLATION"


FAILURE_CATEGORIES: Mapping[FailureCode, str] = {
    FailureCode.USER_INPUT_ERROR: "USER",
    FailureCode.REPOSITORY_UNAVAILABLE: "REPOSITORY",
    FailureCode.REPOSITORY_LIMIT_EXCEEDED: "REPOSITORY",
    FailureCode.SNAPSHOT_POLICY_VIOLATION: "REPOSITORY",
    FailureCode.ANALYZER_UNAVAILABLE: "ANALYZER",
    FailureCode.ANALYZER_TIMEOUT: "ANALYZER",
    FailureCode.ANALYZER_INVALID_OUTPUT: "ANALYZER",
    FailureCode.PROVIDER_RATE_LIMITED: "PROVIDER",
    FailureCode.PROVIDER_AUTH_FAILURE: "PROVIDER",
    FailureCode.PROVIDER_UNAVAILABLE: "PROVIDER",
    FailureCode.MODEL_CONTEXT_LIMIT: "MODEL",
    FailureCode.MODEL_INVALID_OUTPUT: "MODEL",
    FailureCode.BUDGET_EXHAUSTED: "BUDGET",
    FailureCode.WORKFLOW_TIMEOUT: "WORKFLOW",
    FailureCode.WORKER_LOST: "WORKER",
    FailureCode.CANCELLED_BY_USER: "WORKFLOW",
    FailureCode.EXTERNAL_STATE_UNCERTAIN: "EXTERNAL",
    FailureCode.INTERNAL_INVARIANT_VIOLATION: "INTERNAL",
}


@dataclass(frozen=True)
class RequestBudget:
    max_wall_clock_seconds: int
    max_analyzer_seconds: int = 0
    max_ai_calls: int = 0
    max_input_tokens: int = 0
    max_output_tokens: int = 0
    max_escalation_tier: int = 0
    max_retrieval_context_tokens: int = 0
    max_embedding_calls: int = 0
    max_report_bytes: int = 0
    max_report_pages: int = 0

    def __post_init__(self) -> None:
        if self.max_wall_clock_seconds <= 0:
            raise ValueError("max_wall_clock_seconds must be positive")
        for name, value in vars(self).items():
            if name != "max_wall_clock_seconds" and value < 0:
                raise ValueError(f"{name} cannot be negative")


@dataclass(frozen=True)
class BudgetConsumption:
    analyzer_seconds: int = 0
    ai_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    escalation_tier: int = 0
    retrieval_context_tokens: int = 0
    embedding_calls: int = 0
    report_bytes: int = 0
    report_pages: int = 0

    def __post_init__(self) -> None:
        if any(value < 0 for value in vars(self).values()):
            raise ValueError("budget consumption values cannot be negative")


@dataclass(frozen=True)
class EnqueueRequest:
    tenant_id: str
    request_id: str
    requested_by: str
    policy_snapshot_id: str
    work_kind: WorkKind
    resource_type: str
    resource_id: str
    idempotency_key: str
    request_digest: str
    resource_profile: ResourceProfile
    budget: RequestBudget
    side_effect_class: SideEffectClass = SideEffectClass.SAFE_RECOMPUTATION
    external_idempotency_key: Optional[str] = None
    input_artifact_id: Optional[str] = None
    coverage_artifact_id: Optional[str] = None
    priority: int = 50
    max_attempts: int = 3


@dataclass(frozen=True)
class EnqueueResult:
    work_item_id: str
    state: ExecutionState
    reused: bool


@dataclass(frozen=True)
class ClaimedWork:
    work_item_id: str
    attempt_id: str
    attempt_number: int
    lease_token: str
    lease_expires_at: datetime
    tenant_id: str
    work_kind: WorkKind
    resource_type: str
    resource_id: str
    policy_snapshot_id: str
    input_artifact_id: Optional[str]


@dataclass(frozen=True)
class HeartbeatResult:
    active: bool
    cancel_requested: bool = False
    budget_exhausted: bool = False
    state: Optional[ExecutionState] = None


@dataclass(frozen=True)
class BudgetDecision:
    allowed: bool
    exhausted_dimension: Optional[str] = None
    state: Optional[ExecutionState] = None


@dataclass(frozen=True)
class RecoveryResult:
    recovered: int = 0
    retry_wait: int = 0
    cancelled: int = 0
    timed_out: int = 0
    uncertain: int = 0
    recovered_work_item_ids: tuple[str, ...] = field(default_factory=tuple)


__all__ = [
    "ACTIVE_STATES",
    "BudgetConsumption",
    "BudgetDecision",
    "ClaimedWork",
    "DEFAULT_RESOURCE_CAPACITIES",
    "DomainOutcome",
    "EnqueueRequest",
    "EnqueueResult",
    "ExecutionState",
    "FAILURE_CATEGORIES",
    "FailureCode",
    "HeartbeatResult",
    "LeaseState",
    "RESOURCE_PROFILE_REQUIREMENTS",
    "RecoveryResult",
    "RequestBudget",
    "ReservationState",
    "ResourceDimension",
    "ResourceProfile",
    "SideEffectClass",
    "TERMINAL_STATES",
    "WorkKind",
]
