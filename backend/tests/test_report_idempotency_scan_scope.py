"""Regression for externally supplied report idempotency keys across scans."""

from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.report import ReportModel
from app.models.scan import ScanModel
from app.models.user import UserModel
from app.schemas.enums import ScanStatus


def test_report_idempotency_key_cannot_replay_another_scans_report(
    client: TestClient,
    db_session: Session,
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("REPORT_ARTIFACT_DIR", str(tmp_path / "report-staging"))
    monkeypatch.setenv("ARTIFACT_ROOT_DIR", str(tmp_path / "canonical-artifacts"))
    get_settings.cache_clear()
    try:
        # The test client is already authenticated as this user. Both scans
        # belong to the SAME tenant: this exercises resource identity, not
        # merely the existing cross-tenant ownership check.
        owner = db_session.query(UserModel).filter_by(
            email="default_test_user@example.com"
        ).one()
        scans = [
            ScanModel(
                id=str(uuid4()),
                owner_user_id=owner.id,
                repository_url=f"https://github.com/example/report-scope-{index}",
                branch="main",
                commit_hash=str(index + 1) * 40,
                status=ScanStatus.COMPLETED.value,
                model_metadata={},
            )
            for index in range(2)
        ]
        db_session.add_all(scans)
        db_session.commit()

        monkeypatch.setattr(
            "app.api.routes.reports.DurableWorkDispatcher.nudge",
            lambda: None,
        )
        headers = {"Idempotency-Key": "report-key-shared-across-scans"}
        first = client.post(f"/api/v1/scans/{scans[0].id}/reports", headers=headers)
        assert first.status_code == 202, first.text
        first_id = first.json()["id"]

        # A replay of the exact same scan remains valid and returns its
        # original resource, rather than creating duplicate durable work.
        same_scan = client.post(f"/api/v1/scans/{scans[0].id}/reports", headers=headers)
        assert same_scan.status_code in (200, 202), same_scan.text
        assert same_scan.json()["id"] == first_id

        # Before the fix, this returned first_id with 202 and silently
        # mislabeled scan B's request as scan A's report.
        different_scan = client.post(
            f"/api/v1/scans/{scans[1].id}/reports", headers=headers
        )
        assert different_scan.status_code == 409, different_scan.text
        assert different_scan.json()["detail"]["error_code"] == "IDEMPOTENCY_CONFLICT"
        assert db_session.query(ReportModel).filter_by(scan_id=scans[1].id).count() == 0

        # A distinct key must still allow an independent report for scan B.
        independent = client.post(
            f"/api/v1/scans/{scans[1].id}/reports",
            headers={"Idempotency-Key": "report-key-for-second-scan"},
        )
        assert independent.status_code == 202, independent.text
        assert independent.json()["id"] != first_id
        assert db_session.query(ReportModel).filter_by(scan_id=scans[1].id).count() == 1
    finally:
        get_settings.cache_clear()
