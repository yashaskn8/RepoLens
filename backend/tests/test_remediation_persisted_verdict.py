"""Persisted remediation status must honor both verifier and critic verdicts."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from app.patching.schemas import VerificationStatus
from app.remediation.service import RemediationExecutionService
from app.schemas.enums import PatchStatus


@pytest.mark.parametrize(
    ("machine_verdict", "verification_status", "expected"),
    [
        ("REJECTED", VerificationStatus.PASSED, PatchStatus.REJECTED),
        ("NEEDS_REVIEW", VerificationStatus.PASSED, PatchStatus.NEEDS_REVIEW),
        ("PASSED", VerificationStatus.FAILED, PatchStatus.REJECTED),
        ("PASSED", VerificationStatus.NEEDS_REVIEW, PatchStatus.NEEDS_REVIEW),
        ("PASSED", VerificationStatus.PASSED, PatchStatus.VERIFIED),
    ],
)
def test_persisted_patch_status_does_not_override_rejection_or_review(
    machine_verdict, verification_status, expected
):
    """A passing verifier cannot turn a critic-rejected patch into VERIFIED."""
    proposal = SimpleNamespace(
        id=uuid4(),
        finding_id=uuid4(),
        plan_id=uuid4(),
        unified_diff="--- a/app.py\n+++ b/app.py\n",
        files_modified=["app.py"],
        explanation="Candidate fix",
        expected_behavior_change="Safer behavior",
        generated_tests_or_test_plan=[],
        model_metadata=None,
    )
    result = SimpleNamespace(
        proposal=proposal,
        machine_verdict=machine_verdict,
        verification_result=SimpleNamespace(
            status=verification_status,
            model_dump=lambda **_: {"status": verification_status.value},
        ),
        critic_report=None,
    )
    fix_plan = SimpleNamespace(
        id=proposal.plan_id,
        model_dump=lambda **_: {"id": str(proposal.plan_id)},
    )
    work = SimpleNamespace(
        id=str(uuid4()),
        tenant_id="tenant-test",
        requested_by="user-test",
        request_id="request-test",
        request_payload={},
    )
    scan = SimpleNamespace(id=str(uuid4()), commit_hash="a" * 40)
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = None

    with (
        patch("app.remediation.service.WorkflowEventService.emit_critical"),
        patch("app.remediation.service.DomainOutbox.append"),
        patch("app.remediation.service.AuditLedger.append"),
    ):
        persisted = RemediationExecutionService._persist_patch(
            db,
            work=work,
            scan=scan,
            fix_plan=fix_plan,
            result=result,
            result_artifact_id="artifact-test",
            parent=None,
        )

    assert persisted.status == expected.value
    assert persisted.machine_verdict == machine_verdict
    db.add.assert_called_once_with(persisted)
