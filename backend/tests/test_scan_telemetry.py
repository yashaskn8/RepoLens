"""Comprehensive tests for scan-specific telemetry endpoint and aggregation service."""

from datetime import datetime, timezone
from uuid import UUID, uuid4
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.finding import FindingModel
from app.models.patch import PatchModel
from app.models.scan import ScanModel
from app.models.workflow_event import WorkflowEventModel
from app.schemas.enums import FindingStatus, PatchStatus, ScanStatus, Severity, VerificationVerdict
from app.schemas.workflow_event import WorkflowEventCreate, WorkflowEventType
from app.services.report_service import ScanReportService
from app.services.workflow_event_service import WorkflowEventService


def test_scan_telemetry_unknown_scan_returns_404(client: TestClient):
    """Verify requesting telemetry for non-existent scan ID returns 404."""
    random_id = uuid4()
    resp = client.get(f"/api/v1/scans/{random_id}/telemetry")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_scan_telemetry_completed_scan_aggregation(client: TestClient, db_session: Session):
    """Verify telemetry correctly aggregates completed scan metrics without fabricating missing values."""
    scan_id = str(uuid4())
    start_time = datetime(2026, 8, 22, 10, 0, 0, tzinfo=timezone.utc)
    end_time = datetime(2026, 8, 22, 10, 0, 5, 500000, tzinfo=timezone.utc)

    scan = ScanModel(
        id=scan_id,
        repository_url="https://github.com/org/repo-telemetry",
        commit_hash="abcd1234ef567890",
        status=ScanStatus.COMPLETED.value,
        created_at=start_time,
        completed_at=end_time,
        model_metadata={
            "analysis_scope": {
                "truncated": False,
                "files_processed": 42,
                "total_observed_files": 42,
            }
        },
    )
    db_session.add(scan)

    # Add findings with VALID FindingStatus + verification_verdict combinations
    f1 = FindingModel(
        id=str(uuid4()),
        scan_id=scan_id,
        title="SQL Injection",
        description="Concat in query",
        severity=Severity.HIGH.value,
        status=FindingStatus.OPEN.value,
        verification_verdict=VerificationVerdict.CONFIRMED.value,
    )
    f2 = FindingModel(
        id=str(uuid4()),
        scan_id=scan_id,
        title="Potential XSS",
        description="Unescaped output",
        severity=Severity.MEDIUM.value,
        status=FindingStatus.OPEN.value,
        verification_verdict=VerificationVerdict.POSSIBLE.value,
    )
    f3 = FindingModel(
        id=str(uuid4()),
        scan_id=scan_id,
        title="False Alarm",
        description="Benign test code",
        severity=Severity.LOW.value,
        status=FindingStatus.FALSE_POSITIVE.value,
        verification_verdict=VerificationVerdict.REJECTED.value,
    )
    db_session.add_all([f1, f2, f3])

    # Add patches with various statuses
    p1 = PatchModel(
        id=str(uuid4()),
        finding_id=f1.id,
        scan_id=scan_id,
        status=PatchStatus.APPROVED.value,
        machine_verdict="PASSED",
        unified_diff="--- a\n+++ b\n",
        files_modified=["app/db.py"],
        explanation="Parameterized query",
        expected_behavior_change="Fix",
        revision_number=0,
    )
    p2 = PatchModel(
        id=str(uuid4()),
        finding_id=f2.id,
        scan_id=scan_id,
        status=PatchStatus.NEEDS_REVIEW.value,
        machine_verdict="NEEDS_REVIEW",
        unified_diff="--- a\n+++ b\n",
        files_modified=["app/views.py"],
        explanation="HTML escape",
        expected_behavior_change="Fix",
        revision_number=0,
    )
    db_session.add_all([p1, p2])

    # Add workflow events with tool outcomes
    WorkflowEventService.emit(
        db=db_session,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.SCAN_CREATED,
            scan_id=UUID(scan_id),
            message="Scan registered",
        ),
    )
    WorkflowEventService.emit(
        db=db_session,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.STAGE_STARTED,
            scan_id=UUID(scan_id),
            stage="intelligence_analysis",
            message="Analysis started",
        ),
    )
    WorkflowEventService.emit(
        db=db_session,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.TOOL_COMPLETED,
            scan_id=UUID(scan_id),
            tool_name="semgrep",
            message="Semgrep completed with findings",
        ),
    )
    WorkflowEventService.emit(
        db=db_session,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.TOOL_UNAVAILABLE,
            scan_id=UUID(scan_id),
            tool_name="trivy",
            message="Trivy binary not found on host",
        ),
    )
    WorkflowEventService.emit(
        db=db_session,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.TOOL_FAILED,
            scan_id=UUID(scan_id),
            tool_name="osv",
            message="OSV scanner returned invalid output",
        ),
    )
    WorkflowEventService.emit(
        db=db_session,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.SCAN_COMPLETED,
            scan_id=UUID(scan_id),
            message="Scan completed successfully",
        ),
    )
    db_session.commit()

    resp = client.get(f"/api/v1/scans/{scan_id}/telemetry")
    assert resp.status_code == 200
    data = resp.json()

    assert data["scan_id"] == scan_id
    assert data["commit_sha"] == "abcd1234ef567890"
    assert data["status"] == "COMPLETED"
    assert data["total_duration_ms"] == 5500

    assert data["event_count"] == 6
    assert data["stage_count"] >= 1

    assert data["tools_completed"] == 1
    assert data["tools_unavailable"] == 1
    assert data["tools_failed"] == 1

    assert data["confirmed_findings"] == 1
    assert data["possible_findings"] == 1
    assert data["rejected_findings"] == 1

    assert data["patches_generated"] == 2
    assert data["patches_approved"] == 1
    assert data["patches_needing_review"] == 1
    assert data["patches_rejected"] == 0

    assert data["analysis_truncated"] is False
    assert data["analysis_truncation_reason"] is None

    # Verify unrecorded LLM metrics remain null rather than fabricated 0
    assert data["llm_retries"] is None
    assert data["provider_fallbacks"] is None
    assert data["prompt_tokens"] is None
    assert data["completion_tokens"] is None
    assert data["total_tokens"] is None


def test_scan_telemetry_failed_scan_and_truncation(client: TestClient, db_session: Session):
    """Verify telemetry handles failed scans and truncated analysis metadata."""
    scan_id = str(uuid4())
    scan = ScanModel(
        id=scan_id,
        repository_url="https://github.com/org/huge-repo",
        commit_hash="fedcba9876543210",
        status=ScanStatus.FAILED.value,
        created_at=datetime(2026, 8, 22, 11, 0, 0, tzinfo=timezone.utc),
        completed_at=datetime(2026, 8, 22, 11, 0, 2, tzinfo=timezone.utc),
        model_metadata={
            "analysis_scope": {
                "truncated": True,
                "reason": "Max file count of 1000 exceeded",
                "files_processed": 1000,
                "total_observed_files": 3400,
            }
        },
    )
    db_session.add(scan)
    db_session.commit()

    resp = client.get(f"/api/v1/scans/{scan_id}/telemetry")
    assert resp.status_code == 200
    data = resp.json()

    assert data["scan_id"] == scan_id
    assert data["status"] == "FAILED"
    assert data["analysis_truncated"] is True
    assert data["analysis_truncation_reason"] == "Max file count of 1000 exceeded"
    assert data["event_count"] == 0
    assert data["confirmed_findings"] == 0


def test_scan_telemetry_llm_metrics_derivation(client: TestClient, db_session: Session):
    """Verify LLM retry, fallback, and token counts are aggregated when recorded in model metadata."""
    scan_id = str(uuid4())
    scan = ScanModel(
        id=scan_id,
        repository_url="https://github.com/org/llm-telemetry-repo",
        status=ScanStatus.COMPLETED.value,
        model_metadata={
            "prompt_tokens": 1500,
            "completion_tokens": 450,
            "total_tokens": 1950,
            "retry_count": 2,
            "fallbacks_attempted": 1,
            "llm_calls": 3,
        },
    )
    db_session.add(scan)
    db_session.commit()

    resp = client.get(f"/api/v1/scans/{scan_id}/telemetry")
    assert resp.status_code == 200
    data = resp.json()

    assert data["llm_calls"] == 3
    assert data["llm_retries"] == 2
    assert data["provider_fallbacks"] == 1
    assert data["prompt_tokens"] == 1500
    assert data["completion_tokens"] == 450
    assert data["total_tokens"] == 1950


# ──────────────────────────────────────────────────────────────────────────────
# FIX 1 — Explicit verdict vs lifecycle status separation tests
# ──────────────────────────────────────────────────────────────────────────────


def test_verdict_counts_use_verification_verdict_not_status(client: TestClient, db_session: Session):
    """Explicitly verify: OPEN + CONFIRMED => confirmed +1, OPEN + POSSIBLE => possible +1,
    FALSE_POSITIVE + REJECTED => rejected +1."""
    scan_id = str(uuid4())
    scan = ScanModel(
        id=scan_id,
        repository_url="https://github.com/org/verdict-separation-test",
        status=ScanStatus.COMPLETED.value,
    )
    db_session.add(scan)

    # OPEN + CONFIRMED → confirmed_findings + 1
    db_session.add(FindingModel(
        id=str(uuid4()), scan_id=scan_id,
        title="Confirmed Finding", description="d",
        severity=Severity.HIGH.value,
        status=FindingStatus.OPEN.value,
        verification_verdict=VerificationVerdict.CONFIRMED.value,
    ))
    # OPEN + POSSIBLE → possible_findings + 1
    db_session.add(FindingModel(
        id=str(uuid4()), scan_id=scan_id,
        title="Possible Finding", description="d",
        severity=Severity.MEDIUM.value,
        status=FindingStatus.OPEN.value,
        verification_verdict=VerificationVerdict.POSSIBLE.value,
    ))
    # FALSE_POSITIVE + REJECTED → rejected_findings + 1
    db_session.add(FindingModel(
        id=str(uuid4()), scan_id=scan_id,
        title="Rejected Finding", description="d",
        severity=Severity.LOW.value,
        status=FindingStatus.FALSE_POSITIVE.value,
        verification_verdict=VerificationVerdict.REJECTED.value,
    ))
    db_session.commit()

    resp = client.get(f"/api/v1/scans/{scan_id}/telemetry")
    assert resp.status_code == 200
    data = resp.json()

    assert data["confirmed_findings"] == 1
    assert data["possible_findings"] == 1
    assert data["rejected_findings"] == 1


def test_open_finding_without_verdict_is_not_confirmed(client: TestClient, db_session: Session):
    """OPEN finding with verification_verdict=None must NOT be counted as confirmed."""
    scan_id = str(uuid4())
    scan = ScanModel(
        id=scan_id,
        repository_url="https://github.com/org/no-verdict-test",
        status=ScanStatus.COMPLETED.value,
    )
    db_session.add(scan)

    # OPEN with no verification_verdict — must not appear in any verdict count
    db_session.add(FindingModel(
        id=str(uuid4()), scan_id=scan_id,
        title="Unverified Finding", description="d",
        severity=Severity.MEDIUM.value,
        status=FindingStatus.OPEN.value,
        verification_verdict=None,
    ))
    db_session.commit()

    resp = client.get(f"/api/v1/scans/{scan_id}/telemetry")
    assert resp.status_code == 200
    data = resp.json()

    assert data["confirmed_findings"] == 0
    assert data["possible_findings"] == 0
    assert data["rejected_findings"] == 0


def test_lifecycle_status_alone_never_determines_verdict_count(client: TestClient, db_session: Session):
    """Lifecycle status values (OPEN, RESOLVED, FALSE_POSITIVE, SUPPRESSED) must never
    influence verdict counts. Only verification_verdict drives those."""
    scan_id = str(uuid4())
    scan = ScanModel(
        id=scan_id,
        repository_url="https://github.com/org/lifecycle-isolation-test",
        status=ScanStatus.COMPLETED.value,
    )
    db_session.add(scan)

    # All valid FindingStatus values, all with verification_verdict=None
    for status_val in FindingStatus:
        db_session.add(FindingModel(
            id=str(uuid4()), scan_id=scan_id,
            title=f"Finding with status {status_val.value}", description="d",
            severity=Severity.INFO.value,
            status=status_val.value,
            verification_verdict=None,
        ))
    db_session.commit()

    resp = client.get(f"/api/v1/scans/{scan_id}/telemetry")
    assert resp.status_code == 200
    data = resp.json()

    # No verification_verdict set → all verdict counts must be 0
    assert data["confirmed_findings"] == 0
    assert data["possible_findings"] == 0
    assert data["rejected_findings"] == 0


# ──────────────────────────────────────────────────────────────────────────────
# FIX 2 — LLM fallback metadata shape handling tests
# ──────────────────────────────────────────────────────────────────────────────


def test_list_shaped_fallbacks_single_entry(client: TestClient, db_session: Session):
    """Canonical LLMRouter stores fallbacks_attempted as a list of error records.
    A single entry → provider_fallbacks == 1."""
    scan_id = str(uuid4())
    scan = ScanModel(
        id=scan_id,
        repository_url="https://github.com/org/list-fallback-test",
        status=ScanStatus.COMPLETED.value,
        model_metadata={
            "fallbacks_attempted": [
                {
                    "provider": "gemini",
                    "model": "gemini-3.7-flash",
                    "error": "rate limit",
                }
            ],
        },
    )
    db_session.add(scan)
    db_session.commit()

    resp = client.get(f"/api/v1/scans/{scan_id}/telemetry")
    assert resp.status_code == 200
    data = resp.json()
    assert data["provider_fallbacks"] == 1


def test_list_shaped_fallbacks_two_entries(client: TestClient, db_session: Session):
    """Two fallback error records → provider_fallbacks == 2."""
    scan_id = str(uuid4())
    scan = ScanModel(
        id=scan_id,
        repository_url="https://github.com/org/two-fallback-test",
        status=ScanStatus.COMPLETED.value,
        model_metadata={
            "fallbacks_attempted": [
                {"provider": "groq", "model": "llama-4-scout", "error": "timeout"},
                {"provider": "nvidia", "model": "llama-3.3-70b-instruct", "error": "server error"},
            ],
        },
    )
    db_session.add(scan)
    db_session.commit()

    resp = client.get(f"/api/v1/scans/{scan_id}/telemetry")
    assert resp.status_code == 200
    data = resp.json()
    assert data["provider_fallbacks"] == 2


def test_integer_provider_fallbacks(client: TestClient, db_session: Session):
    """provider_fallbacks stored as an integer is also supported."""
    scan_id = str(uuid4())
    scan = ScanModel(
        id=scan_id,
        repository_url="https://github.com/org/int-fallback-test",
        status=ScanStatus.COMPLETED.value,
        model_metadata={
            "provider_fallbacks": 3,
        },
    )
    db_session.add(scan)
    db_session.commit()

    resp = client.get(f"/api/v1/scans/{scan_id}/telemetry")
    assert resp.status_code == 200
    data = resp.json()
    assert data["provider_fallbacks"] == 3


def test_malformed_fallback_metadata_does_not_crash(client: TestClient, db_session: Session):
    """Malformed metadata (e.g. fallbacks_attempted as a string) must not cause HTTP 500."""
    scan_id = str(uuid4())
    scan = ScanModel(
        id=scan_id,
        repository_url="https://github.com/org/malformed-fallback-test",
        status=ScanStatus.COMPLETED.value,
        model_metadata={
            "fallbacks_attempted": "this is invalid",
        },
    )
    db_session.add(scan)
    db_session.commit()

    resp = client.get(f"/api/v1/scans/{scan_id}/telemetry")
    assert resp.status_code == 200
    data = resp.json()
    # Malformed value is safely ignored
    assert data["provider_fallbacks"] == 0


def test_retry_count_integer_aggregation(client: TestClient, db_session: Session):
    """Integer retry_count is correctly aggregated."""
    scan_id = str(uuid4())
    scan = ScanModel(
        id=scan_id,
        repository_url="https://github.com/org/retry-count-test",
        status=ScanStatus.COMPLETED.value,
        model_metadata={
            "retry_count": 4,
        },
    )
    db_session.add(scan)
    db_session.commit()

    resp = client.get(f"/api/v1/scans/{scan_id}/telemetry")
    assert resp.status_code == 200
    data = resp.json()
    assert data["llm_retries"] == 4


def test_token_metadata_without_llm_calls_remains_none(client: TestClient, db_session: Session):
    """Token metadata without explicit llm_calls recorded → llm_calls must remain None, not fabricated."""
    scan_id = str(uuid4())
    scan = ScanModel(
        id=scan_id,
        repository_url="https://github.com/org/no-llm-calls-test",
        status=ScanStatus.COMPLETED.value,
        model_metadata={
            "prompt_tokens": 500,
            "completion_tokens": 200,
            "total_tokens": 700,
            "retry_count": 1,
        },
    )
    db_session.add(scan)
    db_session.commit()

    resp = client.get(f"/api/v1/scans/{scan_id}/telemetry")
    assert resp.status_code == 200
    data = resp.json()

    # Token metrics are present
    assert data["prompt_tokens"] == 500
    assert data["completion_tokens"] == 200
    assert data["total_tokens"] == 700
    assert data["llm_retries"] == 1
    # llm_calls was NOT recorded → must be None, not fabricated as 1
    assert data["llm_calls"] is None
