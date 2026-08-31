"""Durable daily usage quota enforcement for expensive operations.

Atomic transactional increment with first-insert race handling.
Quotas are per-user per-UTC-calendar-day per-operation.
"""

import logging
from datetime import date, datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from fastapi import HTTPException, status
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.models.user import UsageCounterModel, UserModel
from app.schemas.auth import CurrentUser
from app.schemas.enums import UsageOperation

logger = logging.getLogger(__name__)


def _today_utc() -> date:
    return datetime.now(timezone.utc).date()


def _get_limit(settings: Settings, operation: str) -> int:
    """Return the configured daily limit for the given operation."""
    limits = {
        UsageOperation.SCAN_CREATE.value: settings.MAX_DAILY_SCANS_PER_USER,
        UsageOperation.CHANGE_ANALYSIS_CREATE.value: settings.MAX_DAILY_CHANGE_ANALYSES_PER_USER,
        UsageOperation.PATCH_GENERATE.value: settings.MAX_DAILY_PATCH_GENERATIONS_PER_USER,
    }
    return limits.get(operation, 999999)


def _resolve_user_id(user_or_id: Any) -> str:
    """Extract string user ID from string, CurrentUser, UserModel, or return empty string."""
    if user_or_id is None:
        return ""
    if isinstance(user_or_id, CurrentUser):
        return user_or_id.id.strip() if user_or_id.id else ""
    if isinstance(user_or_id, UserModel):
        return str(user_or_id.id).strip() if user_or_id.id else ""
    if isinstance(user_or_id, (str, UUID)):
        return str(user_or_id).strip()
    return ""


def get_usage_count(db: Session, user_id: Any, operation: str) -> int:
    """Return the current day's usage count for the given user and operation."""
    resolved_user_id = _resolve_user_id(user_id)
    if not resolved_user_id:
        return 0
    today = _today_utc()
    counter = db.query(UsageCounterModel).filter(
        UsageCounterModel.user_id == resolved_user_id,
        UsageCounterModel.bucket_date == today,
        UsageCounterModel.operation == operation,
    ).first()
    return counter.count if counter else 0


def check_and_increment_quota(
    db: Session,
    user_id: Any,
    operation: str,
    settings: Settings | None = None,
) -> int:
    """Check and atomically increment usage quota. Raises 429 if exceeded.

    Uses atomic conditional DB UPDATE (WHERE count < limit) with first-insert savepoint handling.
    Fails closed on missing or invalid user_id.
    """
    resolved_user_id = _resolve_user_id(user_id)
    if not resolved_user_id or resolved_user_id.startswith("<") or resolved_user_id == "default-test-user":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error_code": "AUTH_REQUIRED", "message": "Valid user ID required for quota enforcement"},
        )

    app_settings = settings or get_settings()
    limit = _get_limit(app_settings, operation)
    today = _today_utc()

    # Step 1: Ensure counter row exists (handle first insert race safely with savepoint)
    counter = db.query(UsageCounterModel).filter(
        UsageCounterModel.user_id == resolved_user_id,
        UsageCounterModel.bucket_date == today,
        UsageCounterModel.operation == operation,
    ).first()

    if counter is None:
        try:
            with db.begin_nested():
                new_row = UsageCounterModel(
                    id=str(uuid4()),
                    user_id=resolved_user_id,
                    bucket_date=today,
                    operation=operation,
                    count=0,
                )
                db.add(new_row)
                db.flush()
        except IntegrityError:
            # First insert race occurred concurrently; row now exists
            pass

    # Step 2: Atomic conditional UPDATE in the DB engine
    stmt = (
        update(UsageCounterModel)
        .where(
            UsageCounterModel.user_id == resolved_user_id,
            UsageCounterModel.bucket_date == today,
            UsageCounterModel.operation == operation,
            UsageCounterModel.count < limit,
        )
        .values(count=UsageCounterModel.count + 1)
    )
    result = db.execute(stmt)
    db.flush()

    if result.rowcount == 0:
        _raise_quota_exceeded(operation)

    # Return the newly incremented count
    updated = db.query(UsageCounterModel).filter(
        UsageCounterModel.user_id == resolved_user_id,
        UsageCounterModel.bucket_date == today,
        UsageCounterModel.operation == operation,
    ).first()
    return updated.count if updated else 1


def _raise_quota_exceeded(operation: str) -> None:
    """Raise 429 with safe quota-exceeded message."""
    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=f"DAILY_QUOTA_EXCEEDED: Daily quota exceeded for {operation}. Try again after midnight UTC.",
    )
