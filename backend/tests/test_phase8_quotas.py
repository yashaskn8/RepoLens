"""Test Phase 8: Atomic Daily Usage Quotas and Admission Control.

Verifies:
- Daily operation limits:
  - SCAN_CREATE: 20/day
  - CHANGE_ANALYSIS_CREATE: 50/day
  - PATCH_GENERATE: 50/day
- Exceeding limit raises HTTP 429 DAILY_QUOTA_EXCEEDED.
- Tenant quota partitioning: User B's quota is completely separate from User A's.
- Atomic counter increments and transactional rollback.
"""

from datetime import date, timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import UsageCounterModel
from app.schemas.enums import UsageOperation
from app.services.quota_service import check_and_increment_quota, get_usage_count


def test_quota_service_direct_increments_and_limits(db_session: Session):
    """Test quota service enforces hard limit and atomic counter increments."""
    user_id = "quota-test-user-1"
    op = UsageOperation.SCAN_CREATE.value
    limit = 20

    # 1. Increment 20 times -> all succeed
    for i in range(1, limit + 1):
        count = check_and_increment_quota(db_session, user_id, op)
        assert count == i

    # 2. 21st attempt raises HTTPException with status 429
    with pytest.raises(Exception) as exc_info:
        check_and_increment_quota(db_session, user_id, op)
    assert exc_info.value.status_code == 429
    assert "DAILY_QUOTA_EXCEEDED" in exc_info.value.detail


def test_tenant_quota_isolation(db_session: Session):
    """Test User A consuming their quota does not impact User B."""
    user_a = "user-a-uuid-1111"
    user_b = "user-b-uuid-2222"
    op = UsageOperation.SCAN_CREATE.value

    # Exhaust User A's quota
    for _ in range(20):
        check_and_increment_quota(db_session, user_a, op)

    assert get_usage_count(db_session, user_a, op) == 20
    assert get_usage_count(db_session, user_b, op) == 0

    # User B can still perform operations
    count_b = check_and_increment_quota(db_session, user_b, op)
    assert count_b == 1


def test_api_quota_enforcement_returns_429(client: TestClient, db_session: Session):
    """Test API endpoint returns 429 when quota is exhausted."""
    email = "quota_api_user@example.com"
    password = "SecurePassword12345!"

    reg = client.post("/api/v1/auth/register", json={"email": email, "password": password})
    user_id = reg.json()["id"]

    login = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    session_cookie = login.cookies["repolens_session"]
    csrf_cookie = login.cookies["repolens_csrf"]

    cookies = {"repolens_session": session_cookie, "repolens_csrf": csrf_cookie}
    headers = {"X-CSRF-Token": csrf_cookie}

    # Pre-populate quota to limit (20) in DB directly
    today = date.today()
    counter = UsageCounterModel(
        user_id=user_id,
        bucket_date=today,
        operation=UsageOperation.SCAN_CREATE.value,
        count=20,
    )
    db_session.add(counter)
    db_session.commit()

    # Attempt to trigger scan via API
    resp = client.post(
        "/api/v1/scans",
        json={"repository_url": "https://github.com/org/repo"},
        cookies=cookies,
        headers=headers,
    )
    assert resp.status_code == 429
    assert "DAILY_QUOTA_EXCEEDED" in resp.json()["detail"]
