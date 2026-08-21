"""Unit tests for target-specific route remediation verification."""

import os
import tempfile
import pytest
from uuid import uuid4

from app.ingestion.manifest import build_manifest
from app.patching.schemas import CheckStatus, PatchProposal
from app.patching.verification import PatchVerificationService
from app.planning.schemas import FixPlan
from app.schemas.enums import Severity
from app.schemas.evidence import Evidence
from app.schemas.finding import Finding


def _create_route_mismatch_repo(tmpdir: str):
    fe_dir = os.path.join(tmpdir, "frontend", "src")
    os.makedirs(fe_dir, exist_ok=True)
    with open(os.path.join(fe_dir, "api.ts"), "w", encoding="utf-8") as f:
        f.write(
            "// Frontend API client\n"
            "export async function fetchUserProfile(userId: string) {\n"
            "    return fetch(`/api/v1/users/${userId}/profile`, { method: 'GET' });\n"
            "}\n"
        )

    be_dir = os.path.join(tmpdir, "backend", "app")
    os.makedirs(be_dir, exist_ok=True)
    with open(os.path.join(be_dir, "routes.py"), "w", encoding="utf-8") as f:
        f.write(
            "from fastapi import APIRouter\n\n"
            "router = APIRouter()\n\n"
            "# Route Mismatch: Frontend calls GET, backend registers POST\n"
            "@router.post('/api/v1/users/{user_id}/profile')\n"
            "def get_user_profile(user_id: str):\n"
            "    return {'user_id': user_id, 'name': 'Alice'}\n"
        )


@pytest.mark.asyncio
async def test_route_verification_passes_when_target_route_fixed():
    """Verify check_7 passes when the patch aligns the frontend call with the backend route."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _create_route_mismatch_repo(tmpdir)
        manifest = build_manifest(tmpdir, "https://github.com/org/repo.git", "abcdef1234567890abcdef1234567890abcdef12")

        finding = Finding(
            id=uuid4(),
            scan_id=uuid4(),
            title="Route Contract Mismatch: /api/v1/users/{userId}/profile",
            description="Frontend requests GET but backend registers POST",
            severity=Severity.HIGH,
            category="route_mismatch",
            source_tool="route_contract",
            detector_id="route_contract:frontend/src/api.ts:GET:/api/v1/users/{param}/profile",
            detector_kind="contract_matcher",
            evidences=[Evidence(file_path="frontend/src/api.ts", start_line=3, end_line=3, code_snippet="return fetch(`/api/v1/users/${userId}/profile`, { method: 'GET' });")],
        )

        from app.planning.schemas import OrderedChangeStep
        plan = FixPlan(
            finding_id=finding.id,
            root_cause="Mismatched HTTP method",
            objective="Align frontend HTTP method to POST",
            files_expected_to_change=["frontend/src/api.ts"],
            ordered_changes=[
                OrderedChangeStep(
                    step_number=1,
                    target_file="frontend/src/api.ts",
                    description="Fix HTTP method",
                    rationale="Match route",
                )
            ],
            validation_plan=["pytest"],
        )

        # Fix frontend to call with POST method
        diff = (
            "--- a/frontend/src/api.ts\n"
            "+++ b/frontend/src/api.ts\n"
            "@@ -3,1 +3,1 @@\n"
            "-    return fetch(`/api/v1/users/${userId}/profile`, { method: 'GET' });\n"
            "+    return fetch(`/api/v1/users/${userId}/profile`, { method: 'POST' });\n"
        )

        proposal = PatchProposal(
            finding_id=finding.id,
            plan_id=plan.id,
            unified_diff=diff,
            files_modified=["frontend/src/api.ts"],
            explanation="Fixed endpoint URL",
            expected_behavior_change="Matches backend route",
        )

        service = PatchVerificationService(scanner_adapters=[])
        result = await service.verify_patch(
            proposal=proposal,
            finding=finding,
            fix_plan=plan,
            original_repo_dir=tmpdir,
            manifest=manifest,
        )

        for c in result.checks:
            print(f"CHECK {c.check_name}: {c.status} -> {c.details}")
        c7 = next(c for c in result.checks if c.check_name == "check_7_route_contracts")
        assert c7.status == CheckStatus.PASSED
        assert "Target route defect resolved" in c7.details
