"""Acquisition-dependent work must be rejected before admission when disabled."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from app.core.config import get_settings
from app.execution.application import WorkSubmissionService
from app.execution.dispatcher import DurableWorkDispatcher
from app.execution.types import RequestBudget, ResourceProfile, WorkKind
from app.ingestion.acquisition_boundary import AcquisitionEnforcementUnavailable
from app.models.change_analysis import ChangeAnalysisModel
from app.models.execution import WorkItemModel
from app.models.scan import ScanModel
from app.models.user import UserModel
from app.schemas.change_analysis import ResolvedPullRequest


def _production_settings():
    settings = get_settings()
    return SimpleNamespace(**settings.model_dump(), is_production=True)


@pytest.mark.parametrize(
    ("path", "payload", "route_module", "resource_model"),
    [
        (
            "/api/v1/scans",
            {"repository_url": "https://github.com/fastapi/fastapi"},
            "app.api.routes.scans",
            ScanModel,
        ),
        (
            "/api/v1/change-analyses",
            {
                "repository_url": "https://github.com/fastapi/fastapi",
                "base_commit_sha": "1" * 40,
                "head_commit_sha": "2" * 40,
            },
            "app.api.routes.change_analysis",
            ChangeAnalysisModel,
        ),
    ],
)
def test_unavailable_acquisition_is_rejected_before_quota_or_work(
    client, db_session, monkeypatch, path, payload, route_module, resource_model
):
    """A new request must not queue a job that production workers cannot execute."""
    monkeypatch.setattr(
        f"{route_module}.get_settings",
        _production_settings,
    )
    resource_count = db_session.query(resource_model).count()
    work_count = db_session.query(WorkItemModel).count()

    with (
        patch(f"{route_module}.check_and_increment_quota") as quota,
        patch(f"{route_module}.DurableWorkDispatcher.nudge") as nudge,
    ):
        response = client.post(path, json=payload)

    assert response.status_code == 503, response.text
    assert response.json()["detail"]["error_code"] == "ACQUISITION_ENFORCEMENT_UNAVAILABLE"
    quota.assert_not_called()
    nudge.assert_not_called()
    assert db_session.query(resource_model).count() == resource_count
    assert db_session.query(WorkItemModel).count() == work_count


def test_unavailable_acquisition_rejects_pr_request_before_resolution_or_quota(
    client, db_session, monkeypatch
):
    monkeypatch.setattr(
        "app.api.routes.change_analysis.get_settings",
        _production_settings,
    )
    resource_count = db_session.query(ChangeAnalysisModel).count()
    work_count = db_session.query(WorkItemModel).count()

    with (
        patch("app.api.routes.change_analysis.check_and_increment_quota") as quota,
        patch("app.api.routes.change_analysis.DurableWorkDispatcher.nudge") as nudge,
        patch(
            "app.api.routes.change_analysis.get_github_pr_resolver",
            return_value=SimpleNamespace(
                resolve_pr=AsyncMock(
                    return_value=ResolvedPullRequest(
                        repository_url="https://github.com/fastapi/fastapi",
                        repository_owner="fastapi",
                        repository_name="fastapi",
                        pr_number=1,
                        title="Test pull request",
                        base_branch="main",
                        base_commit_sha="1" * 40,
                        head_branch="feature/test",
                        head_commit_sha="2" * 40,
                        is_fork=False,
                    )
                )
            ),
        ) as resolver,
    ):
        response = client.post(
            "/api/v1/change-analyses/from-pr",
            json={"pr_url": "https://github.com/fastapi/fastapi/pull/1"},
        )

    assert response.status_code == 503, response.text
    assert response.json()["detail"]["error_code"] == "ACQUISITION_ENFORCEMENT_UNAVAILABLE"
    quota.assert_not_called()
    nudge.assert_not_called()
    resolver.assert_not_called()
    assert db_session.query(ChangeAnalysisModel).count() == resource_count
    assert db_session.query(WorkItemModel).count() == work_count


def test_work_submission_service_blocks_new_production_acquisition_work(db_session):
    service = WorkSubmissionService(settings=_production_settings())
    work_count = db_session.query(WorkItemModel).count()

    with pytest.raises(AcquisitionEnforcementUnavailable):
        service.submit(
            db_session,
            tenant_id="tenant-test",
            actor_id="operator-test",
            request_id="request-test",
            work_kind=WorkKind.SCAN,
            resource_type="SCAN",
            resource_id="scan-test",
            request_payload={"repository_url": "https://github.com/fastapi/fastapi.git"},
            idempotency_key="scan:scan-test",
            resource_profile=ResourceProfile.SMALL_REPO_SCAN,
            budget=RequestBudget(max_wall_clock_seconds=30),
        )

    assert db_session.query(WorkItemModel).count() == work_count


def test_existing_idempotent_scan_replay_remains_available_when_acquisition_is_disabled(
    client, db_session, monkeypatch
):
    headers = {"Idempotency-Key": "existing-scan-replay"}
    payload = {"repository_url": "https://github.com/fastapi/fastapi"}
    with patch("app.api.routes.scans.DurableWorkDispatcher.nudge"):
        first = client.post("/api/v1/scans", json=payload, headers=headers)
    assert first.status_code == 202
    scan_count = db_session.query(ScanModel).count()
    work_count = db_session.query(WorkItemModel).count()

    monkeypatch.setattr("app.api.routes.scans.get_settings", _production_settings)
    with (
        patch("app.api.routes.scans.check_and_increment_quota") as quota,
        patch("app.api.routes.scans.DurableWorkDispatcher.nudge") as nudge,
    ):
        replay = client.post("/api/v1/scans", json=payload, headers=headers)

    assert replay.status_code == 202
    assert replay.headers["Idempotency-Replayed"] == "true"
    assert replay.json()["id"] == first.json()["id"]
    quota.assert_not_called()
    nudge.assert_not_called()
    assert db_session.query(ScanModel).count() == scan_count
    assert db_session.query(WorkItemModel).count() == work_count


def test_production_orphan_recovery_skips_unavailable_acquisition_work(
    client, db_session, monkeypatch
):
    owner = db_session.query(UserModel).filter_by(email="default_test_user@example.com").one()
    orphan = ScanModel(
        id="orphan-scan",
        owner_user_id=owner.id,
        repository_url="https://github.com/fastapi/fastapi.git",
        status="PENDING",
    )
    db_session.add(orphan)
    db_session.commit()
    monkeypatch.setattr(
        "app.execution.dispatcher.SessionLocal",
        lambda: db_session.__class__(bind=db_session.get_bind()),
    )
    monkeypatch.setattr("app.execution.dispatcher.get_settings", _production_settings)

    created = DurableWorkDispatcher.reconcile_orphaned_domain_work()

    assert created == 0
    assert db_session.query(WorkItemModel).filter_by(resource_id="orphan-scan").count() == 0
    assert db_session.get(ScanModel, "orphan-scan").status == "PENDING"
