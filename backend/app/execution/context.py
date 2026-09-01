"""Context-local bridge from a durable attempt to nested analysis services."""

from __future__ import annotations

from contextvars import ContextVar, Token

from app.execution.types import BudgetConsumption, ClaimedWork


_current_claim: ContextVar[ClaimedWork | None] = ContextVar("repolens_current_work_claim", default=None)


def bind_claim(claim: ClaimedWork) -> Token:
    return _current_claim.set(claim)


def reset_claim(token: Token) -> None:
    _current_claim.reset(token)


def current_claim() -> ClaimedWork | None:
    return _current_claim.get()


def consume_current_budget(
    consumption: BudgetConsumption,
    *,
    coverage_explanation: str,
) -> bool:
    claim = current_claim()
    if claim is None:
        return True
    from app.core.config import get_settings
    from app.core.database import SessionLocal
    from app.execution.engine import DurableExecutionEngine

    db = SessionLocal()
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


__all__ = ["bind_claim", "consume_current_budget", "current_claim", "reset_claim"]
