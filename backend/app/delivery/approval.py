"""Canonical, content-bound human approval for repository patch delivery."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any


APPROVAL_BINDING_VERSION = "patch-approval/1.1"


def _digest(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def patch_artifact_digest(patch: Any) -> str:
    """Hash all persisted patch/provenance material presented for human approval."""
    return _digest({
        "schema": "patch-artifact/1.1",
        "patch_id": str(patch.id),
        "finding_id": str(patch.finding_id),
        "plan_id": str(patch.plan_id) if patch.plan_id is not None else None,
        "fix_plan_snapshot": patch.fix_plan_snapshot,
        "unified_diff_sha256": hashlib.sha256((patch.unified_diff or "").encode("utf-8")).hexdigest(),
        "files_modified": sorted(str(path) for path in (patch.files_modified or [])),
        "explanation": patch.explanation or "",
        "expected_behavior_change": patch.expected_behavior_change or "",
        "machine_verdict": patch.machine_verdict,
        # These fields are visible in the reviewer workflow and can affect
        # whether the patch is approved. They therefore share the artifact
        # binding instead of remaining mutable after approval.
        "generated_tests_or_test_plan": patch.generated_tests_or_test_plan,
        "verification_report": patch.verification_report,
        "critic_report": patch.critic_report,
        "user_feedback": patch.user_feedback,
    })


def compute_patch_approval_digest(
    patch: Any,
    scan: Any,
    *,
    tenant_id: str,
    actor_id: str,
    approved_at: datetime,
) -> str:
    """Bind approval to exact patch bytes, provenance, repository revision, and actor."""
    return _digest({
        "schema": APPROVAL_BINDING_VERSION,
        "patch_artifact_digest": patch_artifact_digest(patch),
        "patch_id": str(patch.id),
        "finding_id": str(patch.finding_id),
        "plan_id": str(patch.plan_id) if patch.plan_id is not None else None,
        "scan_id": str(scan.id),
        "base_revision": str(scan.commit_hash or ""),
        "base_branch": str(scan.branch or ""),
        "repository_url": str(scan.repository_url or ""),
        "tenant_id": str(tenant_id),
        "approval_actor": str(actor_id),
        "approval_timestamp": _timestamp(approved_at),
    })


def patch_approval_binding_is_valid(patch: Any, scan: Any) -> bool:
    """Return true only when a persisted approval still matches its approved artifact."""
    if (
        not patch.approval_digest
        or not patch.approved_by
        or patch.approved_at is None
        or not scan.owner_user_id
    ):
        return False
    try:
        expected = compute_patch_approval_digest(
            patch,
            scan,
            tenant_id=scan.owner_user_id,
            actor_id=patch.approved_by,
            approved_at=patch.approved_at,
        )
    except (TypeError, ValueError, AttributeError):
        return False
    return hmac.compare_digest(patch.approval_digest, expected)


__all__ = [
    "APPROVAL_BINDING_VERSION",
    "compute_patch_approval_digest",
    "patch_artifact_digest",
    "patch_approval_binding_is_valid",
]
