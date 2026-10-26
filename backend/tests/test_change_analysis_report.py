"""Unit and API tests for Change Intelligence Report & Telemetry Generation (Phase 6G)."""

from datetime import datetime, timezone
from uuid import UUID, uuid4
import pytest
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.analysis.report_generator import generate_change_analysis_report, generate_change_analysis_telemetry
from app.models.change_analysis import ChangeAnalysisModel, ChangeImpactModel
from app.schemas.change_analysis import ChangeRiskLevel


@pytest.fixture
def sample_completed_analysis(db_session: Session) -> ChangeAnalysisModel:
    """Create sample completed analysis in database with impacts and review report."""
    analysis_id = str(uuid4())
    analysis = ChangeAnalysisModel(
        id=analysis_id,
        repository_url="https://github.com/fastapi/fastapi",
        repository_owner="fastapi",
        repository_name="fastapi",
        base_commit_sha="1111111111111111111111111111111111111111",
        head_commit_sha="2222222222222222222222222222222222222222",
        base_ref="main",
        head_ref="feature/auth-overhaul",
        status="COMPLETED",
        risk_level="HIGH",
        changed_files_count=3,
        changed_symbols_count=5,
        impacted_symbols_count=8,
        completed_at=datetime.now(timezone.utc),
        model_metadata={
            "pr_number": 456,
            "pr_title": "Overhaul OAuth2 and JWT authentication",
            "diff_result": {
                "base_commit_sha": "1111111111111111111111111111111111111111",
                "head_commit_sha": "2222222222222222222222222222222222222222",
                "repository_url": "https://github.com/fastapi/fastapi",
                "route_deltas": [
                    {
                        "file_path": "app/api/auth.py",
                        "route_type": "FASTAPI_ROUTE",
                        "route_name": "login_access_token",
                        "base_http_method": "POST",
                        "head_http_method": "POST",
                        "base_path": "/api/v1/login/token",
                        "head_path": "/api/v1/auth/token",
                        "change_type": "PATH_CHANGED",
                        "details": "Route path updated from /login/token to /auth/token",
                    }
                ],
                "schema_deltas": [
                    {
                        "file_path": "app/schemas/token.py",
                        "model_name": "TokenPayload",
                        "field_name": "sub",
                        "base_type": "Optional[str]",
                        "head_type": "str",
                        "change_type": "MODIFIED_TYPE",
                        "details": "Field 'sub' made non-optional",
                    }
                ],
                "dependency_deltas": [
                    {
                        "manifest_file": "pyproject.toml",
                        "package_name": "pyjwt",
                        "base_version": "2.4.0",
                        "head_version": "2.8.0",
                        "change_type": "UPDATED",
                    }
                ],
                "config_deltas": [
                    {
                        "file_path": ".env.example",
                        "key": "JWT_SECRET_KEY",
                        "change_type": "ADDED",
                    }
                ],
            },
            "review_report": {
                "analysis_id": analysis_id,
                "summary": "AI Change Review identified breaking auth path and caller impacts.",
                "total_findings": 1,
                "confirmed_count": 1,
                "supported_inference_count": 0,
                "rejected_count": 0,
                "overall_risk_level": "HIGH",
                "findings": [
                    {
                        "id": str(uuid4()),
                        "title": "Breaking Route Path Change for /api/v1/login/token",
                        "risk_type": "API_CONTRACT_BREAK",
                        "severity": "HIGH",
                        "reasoning_summary": "Path changed to /api/v1/auth/token causing external clients using old path to receive 404.",
                        "evidence_refs": ["route:app/api/auth.py:login_access_token"],
                        "affected_files": ["app/api/auth.py", "frontend/src/lib/api.ts"],
                        "affected_symbols": ["login_access_token"],
                        "confidence": 0.95,
                        "assumptions": ["External clients rely on old endpoint path"],
                        "verdict": "CONFIRMED",
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    }
                ],
                "model_metadata": {
                    "prompt_tokens": 1200,
                    "completion_tokens": 300,
                    "total_tokens": 1500,
                },
            },
        },
    )
    db_session.add(analysis)

    impact = ChangeImpactModel(
        id=str(uuid4()),
        analysis_id=analysis_id,
        impact_type="API_CONTRACT_CHANGE",
        severity="HIGH",
        title="Route path modified: /api/v1/login/token",
        description="External consumers and frontend API clients will fail with 404.",
        source_file="app/api/auth.py",
        affected_file="frontend/src/lib/api.ts",
        evidence_payload={"route": "/api/v1/login/token"},
        confidence=1.0,
        verification_status="FACT",
    )

    db_session.add(impact)
    db_session.commit()
    db_session.refresh(analysis)
    return analysis


def test_generate_change_analysis_report_structure(sample_completed_analysis):
    """Verify generate_change_analysis_report produces accurate contracts and Markdown."""
    report = generate_change_analysis_report(sample_completed_analysis)

    assert report.analysis_id == UUID(sample_completed_analysis.id)
    assert report.repository_url == "https://github.com/fastapi/fastapi"
    assert report.base_commit_sha == "1111111111111111111111111111111111111111"
    assert report.head_commit_sha == "2222222222222222222222222222222222222222"
    assert report.pr_number == 456
    assert report.pr_title == "Overhaul OAuth2 and JWT authentication"
    assert report.risk_level == ChangeRiskLevel.HIGH
    assert "HIGH risk assessed" in report.risk_explanation

    # Deltas
    assert len(report.route_deltas) == 1
    assert report.route_deltas[0].route_name == "login_access_token"
    assert len(report.schema_deltas) == 1
    assert len(report.dependency_deltas) == 1
    assert len(report.config_deltas) == 1

    # Findings
    assert len(report.review_findings) == 1
    assert report.review_findings[0].title == "Breaking Route Path Change for /api/v1/login/token"

    # Epistemic limitation check: Never claim tests were executed!
    assert report.tool_availability["runtime_sandbox"] is False
    assert any("NOT executed" in lim or "not executed" in lim for lim in report.limitations)
    assert "NOT executed" in report.markdown_report or "not executed" in report.markdown_report.lower()

    # Markdown content verification
    assert "# 🔍 RepoLens Change Intelligence Report" in report.markdown_report
    assert "1111111111111111111111111111111111111111" in report.markdown_report
    assert "2222222222222222222222222222222222222222" in report.markdown_report


def test_generate_change_analysis_telemetry(sample_completed_analysis):
    """Verify telemetry aggregates authoritative model data without leaking secrets."""
    telemetry = generate_change_analysis_telemetry(sample_completed_analysis)

    assert telemetry.analysis_id == sample_completed_analysis.id
    assert telemetry.files_changed == 3
    assert telemetry.symbols_changed == 5
    assert telemetry.impacted_symbols == 8
    assert telemetry.contract_breaks == 1
    assert telemetry.confirmed_findings == 1
    assert telemetry.total_tokens == 1500


def test_api_get_change_analysis_report(client: TestClient, sample_completed_analysis):
    """Verify GET /api/v1/change-analyses/{id}/report returns structured JSON report."""
    response = client.get(f"/api/v1/change-analyses/{sample_completed_analysis.id}/report")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    assert data["analysis_id"] == sample_completed_analysis.id
    assert data["pr_number"] == 456
    assert len(data["route_deltas"]) == 1
    assert "markdown_report" in data


def test_api_download_markdown_report(client: TestClient, sample_completed_analysis):
    """Verify GET /api/v1/change-analyses/{id}/markdown returns raw text/markdown."""
    response = client.get(f"/api/v1/change-analyses/{sample_completed_analysis.id}/markdown")
    assert response.status_code == status.HTTP_200_OK
    assert "text/markdown" in response.headers["content-type"]
    assert "# 🔍 RepoLens Change Intelligence Report" in response.text


def test_api_get_telemetry(client: TestClient, sample_completed_analysis):
    """Verify GET /api/v1/change-analyses/{id}/telemetry returns operational telemetry."""
    response = client.get(f"/api/v1/change-analyses/{sample_completed_analysis.id}/telemetry")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    assert data["analysis_id"] == sample_completed_analysis.id
    assert data["contract_breaks"] == 1
    assert data["total_tokens"] == 1500


def test_api_get_diff(client: TestClient, sample_completed_analysis):
    """Verify GET /api/v1/change-analyses/{id}/diff returns structural diff result."""
    response = client.get(f"/api/v1/change-analyses/{sample_completed_analysis.id}/diff")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    assert "route_deltas" in data
    assert len(data["route_deltas"]) == 1


def test_missing_risk_is_not_misrepresented_as_low(sample_completed_analysis):
    sample_completed_analysis.risk_level = None
    report = generate_change_analysis_report(sample_completed_analysis)
    assert report.risk_level is None
    assert "Risk assessment not available" in report.risk_explanation
    assert "NOT_ASSESSED" in report.markdown_report
    assert "**Risk Assessment**: `LOW`" not in report.markdown_report


def test_none_risk_is_distinct_from_low_and_unassessed():
    from app.analysis.report_generator import _compute_risk_explanation

    result = _compute_risk_explanation(
        ChangeRiskLevel.NONE, contract_breaks=0, security_impacts=0,
        total_impacts=0, confirmed_findings=0,
    )
    assert "NONE risk assessed" in result
    assert "LOW risk assessed" not in result


def test_critical_risk_does_not_invent_direct_caller_blast_radius():
    from app.analysis.report_generator import _compute_risk_explanation

    result = _compute_risk_explanation(
        ChangeRiskLevel.CRITICAL, contract_breaks=0, security_impacts=0,
        total_impacts=0, confirmed_findings=0,
    )
    assert "CRITICAL risk assessed" in result
    assert "direct caller blast radius" not in result
    assert "0 contract/schema" in result


def test_pr_title_cannot_inject_markdown_report_table_rows(sample_completed_analysis):
    sample_completed_analysis.model_metadata["pr_title"] = (
        "Harmless] (https://attacker.example)\n| **Faked Metric** | 999 |"
    )
    report = generate_change_analysis_report(sample_completed_analysis)
    assert "[#456 Harmless\\]" in report.markdown_report
    assert "| **Faked Metric** | 999 |" not in report.markdown_report
    assert report.markdown_report.count("| **Pull Request** |") == 1


@pytest.mark.parametrize(
    "execution_status,is_fallback",
    [
        ("TIMEOUT", False),
        ("SKIPPED", False),
        ("SUCCESS", True),
        ("PROVIDER_COOLDOWN", False),
    ],
)
def test_unknown_or_fallback_review_status_never_crashes_report(
    sample_completed_analysis, execution_status, is_fallback,
):
    """Unrecognized AI outcomes remain visibly unverified, not fatal or successful."""
    review = sample_completed_analysis.model_metadata["review_report"]
    review["model_metadata"]["execution_status"] = execution_status
    review["model_metadata"]["is_fallback"] = is_fallback
    result = generate_change_analysis_report(sample_completed_analysis)
    assert "Result unavailable or unverified" in result.markdown_report
    assert "| **Change Review Agent** | ✅ Executed |" not in result.markdown_report


def test_report_does_not_allow_source_metadata_to_inject_markdown_rows(
    sample_completed_analysis,
):
    """Untrusted route details and impact titles cannot forge report rows."""
    meta = sample_completed_analysis.model_metadata["diff_result"]
    meta["route_deltas"][0]["details"] = "changed | next\n| **Forged Risk** | CRITICAL |"
    sample_completed_analysis.impacts[0].title = "Risk\n| **Forged Impact** | CRITICAL |"
    report = generate_change_analysis_report(sample_completed_analysis)
    assert "| **Forged Risk** | CRITICAL |" not in report.markdown_report
    assert "| **Forged Impact** | CRITICAL |" not in report.markdown_report
    assert "Forged Risk" in report.markdown_report
    assert "Forged Impact" in report.markdown_report


def test_report_escapes_untrusted_review_finding_title(sample_completed_analysis):
    review = sample_completed_analysis.model_metadata["review_report"]
    review["findings"][0]["title"] = "Safe title\n## Forged section | ALERT"
    report = generate_change_analysis_report(sample_completed_analysis)
    assert "## Forged section | ALERT" not in report.markdown_report
    assert "Safe title" in report.markdown_report


def test_malformed_review_evidence_is_disclosed_without_logging_private_text(
    sample_completed_analysis, monkeypatch,
):
    """An invalid finding cannot become a silently clean review or leak its data."""
    import app.analysis.report_generator as generator

    secret_marker = "private-model-finding-secret-canary"
    sample_completed_analysis.model_metadata["review_report"]["findings"].append(
        {"title": secret_marker, "evidence_refs": [secret_marker]}
    )
    logged = []
    monkeypatch.setattr(generator.logger, "warning", lambda *args: logged.append(args))
    report = generate_change_analysis_report(sample_completed_analysis)
    assert len(report.review_findings) == 1
    assert "Incomplete Review Evidence" in report.markdown_report
    assert any("malformed persisted AI review" in lim for lim in report.limitations)
    assert secret_marker not in str(logged)


def test_nonarray_review_findings_are_marked_incomplete(sample_completed_analysis):
    sample_completed_analysis.model_metadata["review_report"]["findings"] = {
        "invalid": "not a list"
    }
    report = generate_change_analysis_report(sample_completed_analysis)
    assert report.review_findings == []
    assert "Incomplete Review Evidence" in report.markdown_report
    assert "omitted" in report.markdown_report


def test_report_never_claims_graph_analysis_when_no_graph_artifact_exists(
    sample_completed_analysis,
):
    report = generate_change_analysis_report(sample_completed_analysis)
    assert report.tool_availability["tree_sitter_ast"] is True
    assert report.tool_availability["repository_graph"] is False
    assert "| **Repository Graph Traversal** | ⚠️ Execution Not Attested" in report.markdown_report
    assert "| **Tree-sitter AST Parser** | ✅ Evidence Recorded" in report.markdown_report


def test_report_degrades_safely_when_diff_metadata_is_malformed(
    sample_completed_analysis,
):
    sample_completed_analysis.model_metadata["diff_result"] = "invalid persisted diff"
    report = generate_change_analysis_report(sample_completed_analysis)
    assert report.tool_availability["tree_sitter_ast"] is False
    assert report.route_deltas == []
    assert "| **Tree-sitter AST Parser** | ⚠️ Execution Not Attested" in report.markdown_report
