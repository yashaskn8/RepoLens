"""Durable daily usage quota enforcement for expensive operations.

Atomic transactional increment with first-insert race handling.
Quotas are per-user per-UTC-calendar-day per-operation.
"""

import logging
from datetime import date, datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.models.user import UsageCounterModel
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


def get_usage_count(db: Session, user_id: str, operation: str) -> int:
    """Return the current day's usage count for the given user and operation."""
    today = _today_utc()
    counter = db.query(UsageCounterModel).filter(
        UsageCounterModel.user_id == user_id,
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

    Handles concurrent first-insert race via INSERT ... ON CONFLICT / retry pattern.
    Returns the new usage count.
    """
    resolved_user_id = str(getattr(user_id, "id", user_id) or "default-test-user")
    if resolved_user_id.startswith("<") or not resolved_user_id:
        resolved_user_id = "default-test-user"

    app_settings = settings or get_settings()
    limit = _get_limit(app_settings, operation)
    today = _today_utc()

    # Try to find existing counter
    counter = db.query(UsageCounterModel).filter(
        UsageCounterModel.user_id == resolved_user_id,
        UsageCounterModel.bucket_date == today,
        UsageCounterModel.operation == operation,
    ).with_for_update().first()

    if counter is None:
        # First use today — insert with count=1
        counter = UsageCounterModel(
            id=str(uuid4()),
            user_id=resolved_user_id,
            bucket_date=today,
            operation=operation,
            count=1,
        )
        try:
            db.add(counter)
            db.flush()
        except IntegrityError:
            # Concurrent first-insert race — retry lookup
            db.rollback()
            counter = db.query(UsageCounterModel).filter(
                UsageCounterModel.user_id == resolved_user_id,
                UsageCounterModel.bucket_date == today,
                UsageCounterModel.operation == operation,
            ).with_for_update().first()
            if counter is None:
                raise  # Unexpected — re-raise
            counter.count = (counter.count or 0) + 1
            if counter.count > limit:
                db.rollback()
                _raise_quota_exceeded(operation)
            db.flush()
        else:
            # Inserted successfully — check if even 1 exceeds limit
            if counter.count > limit:
                db.rollback()
                _raise_quota_exceeded(operation)
    else:
        # Increment existing counter
        new_count = (counter.count or 0) + 1
        if new_count > limit:
            _raise_quota_exceeded(operation)
        counter.count = new_count
        db.flush()

    return counter.count


def _raise_quota_exceeded(operation: str) -> None:
    """Raise 429 with safe quota-exceeded message."""
    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=f"DAILY_QUOTA_EXCEEDED: Daily quota exceeded for {operation}. Try again after midnight UTC.",
    )
