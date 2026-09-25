"""Context-local bridge from a durable attempt to nested analysis services."""

from __future__ import annotations

from contextvars import ContextVar, Token
from typing import TYPE_CHECKING, Callable

from app.execution.types import BudgetConsumption, ClaimedWork

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


_current_claim: ContextVar[ClaimedWork | None] = ContextVar("repolens_current_work_claim", default=None)
_current_session_factory: ContextVar[Callable[[], "Session"] | None] = ContextVar(
    "repolens_execution_session_factory", default=None
)


def bind_claim(claim: ClaimedWork) -> Token:
    return _current_claim.set(claim)


def reset_claim(token: Token) -> None:
    _current_claim.reset(token)


def current_claim() -> ClaimedWork | None:
    return _current_claim.get()


def assert_current_claim(
    *,
    work_kind: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    tenant_id: str | None = None,
    required: bool = False,
    db: "Session | None" = None,
) -> ClaimedWork | None:
    """Validate execution identity and the active SQL lease at a domain boundary.

    When ``db`` is supplied, the lease-row lock is held in the caller's
    transaction through its next commit. Development/test callers without a
    durable claim remain supported unless ``required`` is set.
    """

    claim = current_claim()
    if claim is None:
        if required:
            from app.execution.errors import LeaseLost

            raise LeaseLost("canonical execution claim required")
        return None

    claimed_kind = getattr(claim.work_kind, "value", str(claim.work_kind))
    if (
        (work_kind is not None and claimed_kind != work_kind)
        or (resource_type is not None and claim.resource_type != resource_type)
        or (resource_id is not None and claim.resource_id != resource_id)
        or (tenant_id is not None and claim.tenant_id != tenant_id)
    ):
        from app.execution.errors import LeaseLost

        raise LeaseLost("execution claim identity mismatch")

    from app.core.config import get_settings
    from app.execution.engine import DurableExecutionEngine

    owned_db = db is None
    session = db or new_execution_session()
    try:
        DurableExecutionEngine(
            session,
            lease_seconds=get_settings().EXECUTION_LEASE_SECONDS,
            auto_commit=False,
        ).assert_active_lease(claim.work_item_id, claim.lease_token)
    finally:
        if owned_db:
            session.close()
    return claim


def bind_execution_session_factory(factory: Callable[[], "Session"] | None) -> Token:
    return _current_session_factory.set(factory)


def reset_execution_session_factory(token: Token) -> None:
    _current_session_factory.reset(token)


def new_execution_session() -> "Session":
    factory = _current_session_factory.get()
    if factory is not None:
        return factory()
    from app.core.database import SessionLocal

    return SessionLocal()


def consume_current_budget(
    consumption: BudgetConsumption,
    *,
    coverage_explanation: str,
) -> bool:
    claim = current_claim()
    if claim is None:
        return True
    from app.core.config import get_settings
    from app.execution.engine import DurableExecutionEngine

    db = new_execution_session()
    try:
        decision = DurableExecutionEngine(
            db,
            lease_seconds=get_settings().EXECUTION_LEASE_SECONDS,
        ).consume_budget(
            claim.work_item_id,
            claim.lease_token,
            consumption,
            coverage_explanation=coverage_explanation,
        )
        return decision.allowed
    finally:
        db.close()


def mark_current_side_effect_started(
    *,
    external_operation_id: str | None = None,
    db: "Session | None" = None,
) -> bool:
    """Fence an external write before its first mutating provider call."""
    claim = current_claim()
    if claim is None:
        return False
    from app.core.config import get_settings
    from app.execution.engine import DurableExecutionEngine

    owned_db = db is None
    session = db or new_execution_session()
    try:
        DurableExecutionEngine(
            session,
            lease_seconds=get_settings().EXECUTION_LEASE_SECONDS,
            auto_commit=owned_db,
        ).mark_side_effect_started(
            claim.work_item_id,
            claim.lease_token,
            external_operation_id=external_operation_id,
        )
        return True
    finally:
        if owned_db:
            session.close()


def mark_current_side_effect_completed(
    *,
    external_operation_id: str,
    db: "Session | None" = None,
) -> bool:
    """Fence completed remote state in the caller's domain transaction."""
    claim = current_claim()
    if claim is None:
        return False
    from app.core.config import get_settings
    from app.execution.engine import DurableExecutionEngine

    owned_db = db is None
    session = db or new_execution_session()
    try:
        DurableExecutionEngine(
            session,
            lease_seconds=get_settings().EXECUTION_LEASE_SECONDS,
            auto_commit=owned_db,
        ).mark_side_effect_completed(
            claim.work_item_id,
            claim.lease_token,
            external_operation_id=external_operation_id,
        )
        return True
    finally:
        if owned_db:
            session.close()


__all__ = [
    "bind_claim",
    "bind_execution_session_factory",
    "assert_current_claim",
    "consume_current_budget",
    "current_claim",
    "mark_current_side_effect_completed",
    "mark_current_side_effect_started",
    "new_execution_session",
    "reset_claim",
    "reset_execution_session_factory",
]
