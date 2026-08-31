"""Durable daily usage quota enforcement for expensive operations.

Atomic transactional increment with first-insert race handling.
Quotas are per-user per-UTC-calendar-day per-operation.

Canonical quota API: user_id must be a valid UUID string.
Routes pass current_user.id — no CurrentUser/UserModel/UUID-object polymorphism.
"""

import logging
from datetime import date, datetime, timezone
from uuid import UUID, uuid4

from fastapi import HTTPException, status
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.models.user import UsageCounterModel
from app.schemas.enums import UsageOperation

logger = logging.getLogger(__name__)

_QUOTA_AUTH_REQUIRED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail={"error_code": "AUTH_REQUIRED", "message": "Valid user ID required for quota enforcement"},
)


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


def _validate_user_id(user_id: str) -> str:
    """Validate user_id is a real UUID string. Raises 401 on any invalid input.

    Runtime isinstance check ensures non-string types (CurrentUser, UserModel,
    UUID objects, None, dicts) are rejected even if Python type annotations
    are bypassed at the call site.
    """
    if not isinstance(user_id, str):
        raise _QUOTA_AUTH_REQUIRED

    try:
        return str(UUID(user_id.strip()))
    except (ValueError, AttributeError, TypeError):
        raise _QUOTA_AUTH_REQUIRED


def get_usage_count(db: Session, user_id: str, operation: str) -> int:
    """Return the current day's usage count for the given user and operation."""
    validated_user_id = _validate_user_id(user_id)
    today = _today_utc()
    counter = db.query(UsageCounterModel).filter(
        UsageCounterModel.user_id == validated_user_id,
        UsageCounterModel.bucket_date == today,
        UsageCounterModel.operation == operation,
    ).first()
    return counter.count if counter else 0


def check_and_increment_quota(
    db: Session,
    user_id: str,
    operation: str,
    settings: Settings | None = None,
) -> int:
    """Check and atomically increment usage quota. Raises 429 if exceeded.

    Uses atomic conditional DB UPDATE (WHERE count < limit) with first-insert savepoint handling.
    Fails closed on missing or invalid user_id.

    user_id must be a valid UUID string (e.g. current_user.id from routes).
    """
    validated_user_id = _validate_user_id(user_id)

    app_settings = settings or get_settings()
    limit = _get_limit(app_settings, operation)
    today = _today_utc()

    # Step 1: Ensure counter row exists (handle first insert race safely with savepoint)
    counter = db.query(UsageCounterModel).filter(
        UsageCounterModel.user_id == validated_user_id,
        UsageCounterModel.bucket_date == today,
        UsageCounterModel.operation == operation,
    ).first()

    if counter is None:
        try:
            with db.begin_nested():
                new_row = UsageCounterModel(
                    id=str(uuid4()),
                    user_id=validated_user_id,
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
            UsageCounterModel.user_id == validated_user_id,
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
        UsageCounterModel.user_id == validated_user_id,
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
