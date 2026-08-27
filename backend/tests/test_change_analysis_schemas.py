"""Unit tests for Change Intelligence Pydantic schemas and request validation."""

from datetime import datetime, timezone
from uuid import uuid4
import pytest
from pydantic import ValidationError

from app.schemas.change_analysis import (
    ChangeAnalysisRequest,
    ChangeAnalysisResponse,
    ChangeAnalysisSummary,
    ChangeImpact,
    ChangeImpactEvidence,
)
from app.schemas.enums import (
    ChangeAnalysisStatus,
    ChangeImpactType,
    ChangeRiskLevel,
    ImpactVerificationStatus,
    Severity,
)


class TestChangeAnalysisRequestValidation:
    """Test suite for ChangeAnalysisRequest contract validation."""

    def test_valid_request_canonical_normalization(self):
        req = ChangeAnalysisRequest(
            repository_url="https://github.com/fastapi/fastapi.git",
            base_commit_sha="1111111111111111111111111111111111111111",
            head_commit_sha="2222222222222222222222222222222222222222",
            base_ref="main",
            head_ref="feature/async-workers",
        )
        assert req.repository_url == "https://github.com/fastapi/fastapi"
        assert req.base_commit_sha == "1111111111111111111111111111111111111111"
        assert req.head_commit_sha == "2222222222222222222222222222222222222222"
        assert req.base_ref == "main"
        assert req.head_ref == "feature/async-workers"

    def test_uppercase_hex_sha_normalized_to_lowercase(self):
        req = ChangeAnalysisRequest(
            repository_url="https://github.com/owner/repo",
            base_commit_sha="ABCDEF0123456789ABCDEF0123456789ABCDEF01",
            head_commit_sha="1234567890ABCDEF1234567890ABCDEF12345678",
        )
        assert req.base_commit_sha == "abcdef0123456789abcdef0123456789abcdef01"
        assert req.head_commit_sha == "1234567890abcdef1234567890abcdef12345678"

    def test_same_sha_rejected(self):
        same_sha = "1111111111111111111111111111111111111111"
        with pytest.raises(ValidationError) as exc:
            ChangeAnalysisRequest(
                repository_url="https://github.com/owner/repo",
                base_commit_sha=same_sha,
                head_commit_sha=same_sha,
            )
        assert "must be distinct" in str(exc.value)

    def test_non_hex_sha_rejected(self):
        with pytest.raises(ValidationError) as exc:
            ChangeAnalysisRequest(
                repository_url="https://github.com/owner/repo",
                base_commit_sha="111111111111111111111111111111111111111Z",
                head_commit_sha="2222222222222222222222222222222222222222",
            )
        assert "exact 40-character hexadecimal commit SHA" in str(exc.value)

    def test_short_sha_rejected(self):
        with pytest.raises(ValidationError) as exc:
            ChangeAnalysisRequest(
                repository_url="https://github.com/owner/repo",
                base_commit_sha="1111111",
                head_commit_sha="2222222222222222222222222222222222222222",
            )
        assert "exact 40-character hexadecimal commit SHA" in str(exc.value)

    def test_long_sha_rejected(self):
        with pytest.raises(ValidationError) as exc:
            ChangeAnalysisRequest(
                repository_url="https://github.com/owner/repo",
                base_commit_sha="1111111111111111111111111111111111111111000",
                head_commit_sha="2222222222222222222222222222222222222222",
            )
        assert "exact 40-character hexadecimal commit SHA" in str(exc.value)

    def test_invalid_urls_rejected(self):
        invalid_urls = [
            "http://github.com/owner/repo",
            "https://gitlab.com/owner/repo",
            "https://bitbucket.org/owner/repo",
            "https://github.com/",
            "https://github.com/onlyowner",
            "https://user:token@github.com/owner/repo",
            "https://github.com/owner/repo; rm -rf /",
            "https://github.com/owner/repo && echo hi",
            "file:///tmp/repo",
            "/path/to/repo",
            "",
        ]
        base_sha = "1111111111111111111111111111111111111111"
        head_sha = "2222222222222222222222222222222222222222"
        for url in invalid_urls:
            with pytest.raises(ValidationError):
                ChangeAnalysisRequest(
                    repository_url=url,
                    base_commit_sha=base_sha,
                    head_commit_sha=head_sha,
                )


class TestChangeAnalysisEnumsAndEvidence:
    """Test suite for enums, evidence contracts, and response schemas."""

    def test_change_analysis_statuses(self):
        expected_statuses = {"PENDING", "ACQUIRING", "DIFFING", "ANALYZING", "VERIFYING", "COMPLETED", "FAILED"}
        actual_statuses = {s.value for s in ChangeAnalysisStatus}
        assert actual_statuses == expected_statuses

    def test_change_impact_types(self):
        expected_types = {
            "SYMBOL_CHANGE",
            "CALLER_IMPACT",
            "API_CONTRACT_CHANGE",
            "SCHEMA_CHANGE",
            "DEPENDENCY_CHANGE",
            "CONFIG_CHANGE",
            "SECURITY_SENSITIVE_CHANGE",
        }
        actual_types = {t.value for t in ChangeImpactType}
        assert actual_types == expected_types

    def test_impact_verification_statuses(self):
        expected = {"FACT", "INFERENCE", "ASSUMPTION"}
        actual = {v.value for v in ImpactVerificationStatus}
        assert actual == expected

    def test_change_risk_levels(self):
        expected = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}
        actual = {r.value for r in ChangeRiskLevel}
        assert actual == expected

    def test_change_impact_evidence_structure(self):
        ev = ChangeImpactEvidence(
            file_path="app/auth/router.py",
            symbol_name="authenticate_user",
            base_line_range=[45, 60],
            head_line_range=[45, 72],
            edge_type="CALLS",
            caller_file="app/api/v1/auth.py",
            caller_symbol="login_endpoint",
            callee_file="app/auth/router.py",
            callee_symbol="authenticate_user",
            contract_name="POST /api/v1/auth/login",
            code_snippet="def authenticate_user(...):",
            context_notes="Signature modified to require mandatory MFA token",
            metadata={"breaking": True},
        )
        assert ev.file_path == "app/auth/router.py"
        assert ev.edge_type == "CALLS"
        assert ev.metadata["breaking"] is True

    def test_change_impact_schema_round_trip(self):
        analysis_id = uuid4()
        impact_id = uuid4()
        now = datetime.now(timezone.utc)

        impact = ChangeImpact(
            id=impact_id,
            analysis_id=analysis_id,
            impact_type=ChangeImpactType.API_CONTRACT_CHANGE,
            severity=Severity.HIGH,
            title="Breaking change in /api/v1/login response schema",
            description="Field 'token' renamed to 'access_token' in JSON response",
            source_file="backend/app/auth/schemas.py",
            source_symbol="TokenResponse",
            affected_file="frontend/src/services/api.ts",
            affected_symbol="loginClient",
            evidence_payload={
                "base_schema": {"token": "str"},
                "head_schema": {"access_token": "str"},
                "breaking": True,
            },
            confidence=1.0,
            verification_status=ImpactVerificationStatus.FACT,
            created_at=now,
        )
        data = impact.model_dump(mode="json")
        rehydrated = ChangeImpact.model_validate(data)

        assert rehydrated.id == impact_id
        assert rehydrated.impact_type == ChangeImpactType.API_CONTRACT_CHANGE
        assert rehydrated.severity == Severity.HIGH
        assert rehydrated.verification_status == ImpactVerificationStatus.FACT
        assert rehydrated.evidence_payload["breaking"] is True

    def test_change_analysis_response_schema(self):
        analysis_id = uuid4()
        now = datetime.now(timezone.utc)

        response = ChangeAnalysisResponse(
            id=analysis_id,
            repository_url="https://github.com/org/repo",
            repository_owner="org",
            repository_name="repo",
            base_ref="main",
            base_commit_sha="1111111111111111111111111111111111111111",
            head_ref="feature/auth",
            head_commit_sha="2222222222222222222222222222222222222222",
            status=ChangeAnalysisStatus.COMPLETED,
            changed_files_count=3,
            changed_symbols_count=5,
            impacted_symbols_count=12,
            risk_level=ChangeRiskLevel.HIGH,
            failure_code=None,
            failure_message=None,
            created_at=now,
            updated_at=now,
            completed_at=now,
            impacts=[
                ChangeImpact(
                    id=uuid4(),
                    analysis_id=analysis_id,
                    impact_type=ChangeImpactType.SECURITY_SENSITIVE_CHANGE,
                    severity=Severity.CRITICAL,
                    title="Modified authorization policy",
                    description="Changed role requirement on admin route",
                    source_file="app/policies.py",
                    evidence_payload={"line": 42},
                    confidence=1.0,
                    verification_status=ImpactVerificationStatus.FACT,
                    created_at=now,
                )
            ],
            model_metadata={"duration_ms": 1250},
        )
        assert response.status == ChangeAnalysisStatus.COMPLETED
        assert len(response.impacts) == 1
        assert response.impacts[0].impact_type == ChangeImpactType.SECURITY_SENSITIVE_CHANGE
        assert response.risk_level == ChangeRiskLevel.HIGH
