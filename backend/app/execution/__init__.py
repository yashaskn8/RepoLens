"""Shared durable execution boundary for RepoLens workflows."""

from app.execution.engine import DurableExecutionEngine
from app.execution.errors import (
    ExecutionError,
    ExecutionInvariantViolation,
    IdempotencyConflict,
    InvalidExecutionTransition,
    LeaseLost,
    ResourceCapacityUnavailable,
)
from app.execution.types import (
    BudgetConsumption,
    BudgetDecision,
    ClaimedWork,
    DomainOutcome,
    EnqueueRequest,
    EnqueueResult,
    ExecutionState,
    FailureCode,
    HeartbeatResult,
    RecoveryResult,
    RequestBudget,
    ResourceDimension,
    ResourceProfile,
    SideEffectClass,
    WorkKind,
)

__all__ = [
    "BudgetConsumption",
    "BudgetDecision",
    "ClaimedWork",
    "DomainOutcome",
    "DurableExecutionEngine",
    "EnqueueRequest",
    "EnqueueResult",
    "ExecutionError",
    "ExecutionInvariantViolation",
    "ExecutionState",
    "FailureCode",
    "HeartbeatResult",
    "IdempotencyConflict",
    "InvalidExecutionTransition",
    "LeaseLost",
    "RecoveryResult",
    "RequestBudget",
    "ResourceCapacityUnavailable",
    "ResourceDimension",
    "ResourceProfile",
    "SideEffectClass",
    "WorkKind",
]
