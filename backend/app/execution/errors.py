"""Errors exposed by the durable execution application boundary."""


class ExecutionError(RuntimeError):
    """Base class for stable execution errors."""


class IdempotencyConflict(ExecutionError):
    """The same idempotency identity was reused for different input."""


class InvalidExecutionTransition(ExecutionError):
    """The requested transition is not valid for the current durable state."""


class LeaseLost(ExecutionError):
    """The caller no longer owns a live lease for this work item."""


class ResourceCapacityUnavailable(ExecutionError):
    """A bounded resource pool cannot currently satisfy a profile."""


class ExecutionInvariantViolation(ExecutionError):
    """Persisted execution state violates an internal invariant."""


__all__ = [
    "ExecutionError",
    "ExecutionInvariantViolation",
    "IdempotencyConflict",
    "InvalidExecutionTransition",
    "LeaseLost",
    "ResourceCapacityUnavailable",
]
