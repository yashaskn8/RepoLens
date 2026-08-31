from uuid import UUID, uuid4
from datetime import datetime, timezone
import pytest

from app.schemas.change_analysis import ChangeReviewFinding, ChangeReviewReport, ChangeReviewVerdict
from app.schemas.enums import Severity
from app.delivery.diff_mapper import GitHubDiffFile
from app.delivery.review_renderer import ReviewPublicationRenderer
from app.models.change_analysis import ChangeAnalysisModel


def test_renderer_separates_confirmed_and_inferences_and_omits_rejected():
    """Verify renderer strictly separates CONFIRMED, SUPPORTED_INFERENCE, and omits REJECTED findings from findings list."""
    analysis = ChangeAnalysisModel(
        id=str(uuid4()),
        repository_url="https://github.com/octocat/Hello-World",
        repository_owner="octocat",
        repository_name="Hello-World",
        base_commit_sha="1111111111111111111111111111111111111111",
        head_commit_sha="2222222222222222222222222222222222222222",
        status="COMPLETED",
        risk_level="HIGH",
    )

    f_conf = ChangeReviewFinding(
        id=uuid4(),
        title="Breaking route change",
        risk_type="API_CONTRACT_BREAK",
        severity=Severity.HIGH,
        reasoning_summary="POST /api/users changed to PUT",
        evidence_refs=["line:api.py:10"],
        affected_files=["api.py"],
        verdict=ChangeReviewVerdict.CONFIRMED,
        created_at=datetime.now(timezone.utc),
    )

    f_inf = ChangeReviewFinding(
        id=uuid4(),
        title="Dependency upgrade incompatibility",
        risk_type="DEPENDENCY_INCOMPATIBILITY",
        severity=Severity.MEDIUM,
        reasoning_summary="React 19 bump may affect third-party components",
        evidence_refs=["line:package.json:5"],
        affected_files=["package.json"],
        assumptions=["Assumes downstream UI uses deprecated React 18 hooks"],
        verdict=ChangeReviewVerdict.SUPPORTED_INFERENCE,
        created_at=datetime.now(timezone.utc),
    )

    f_rej = ChangeReviewFinding(
        id=uuid4(),
        title="Hallucinated SQL Injection",
        risk_type="SECURITY_RISK",
        severity=Severity.CRITICAL,
        reasoning_summary="Raw SQL query without params",
        evidence_refs=["file:db.py"],
        affected_files=["db.py"],
        verdict=ChangeReviewVerdict.REJECTED,
        created_at=datetime.now(timezone.utc),
    )

    report = ChangeReviewReport(
        analysis_id=UUID(analysis.id),
        summary="Verified change intelligence review summary.",
        overall_risk=Severity.HIGH,
        findings=[f_conf, f_inf, f_rej],
        created_at=datetime.now(timezone.utc),
    )

    patch = "@@ -10,5 +10,5 @@\n+line 10\n"
    diff_files = [GitHubDiffFile(filename="api.py", patch=patch)]

    renderer = ReviewPublicationRenderer(max_body_chars=50000, max_inline_comments=20)
    pub = renderer.render_publication(
        analysis=analysis,
        pr_number=100,
        review_report=report,
        diff_files=diff_files,
    )

    # 1. Confirmed findings header and contents
    assert "## Confirmed Findings (1)" in pub.preview_body
    assert "Breaking route change" in pub.preview_body

    # 2. Supported inferences header and contents
    assert "## Supported Inferences (1)" in pub.preview_body
    assert "Dependency upgrade incompatibility" in pub.preview_body
    assert "Underlying Assumptions" in pub.preview_body

    # 3. Rejected findings: raw title must NOT be rendered as a finding
    assert "Hallucinated SQL Injection" not in pub.preview_body
    assert "1 candidate finding(s) were analyzed and rejected" in pub.preview_body

    # 4. Hidden marker presence and non-circular digest calculation
    expected_marker = f"<!-- repolens-review:{analysis.id}:{pub.preview_digest} -->"
    assert expected_marker in pub.preview_body

    # 5. Inline comments only for confirmed finding
    assert len(pub.inline_comments) == 1
    assert pub.inline_comments[0].path == "api.py"


def test_renderer_secret_redaction():
    """Verify secrets in findings or summary are redacted in rendered publication."""
    analysis = ChangeAnalysisModel(
        id=str(uuid4()),
        repository_url="https://github.com/octocat/Hello-World",
        repository_owner="octocat",
        repository_name="Hello-World",
        base_commit_sha="1111111111111111111111111111111111111111",
        head_commit_sha="2222222222222222222222222222222222222222",
        status="COMPLETED",
    )

    raw_secret = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    f_conf = ChangeReviewFinding(
        id=uuid4(),
        title=f"Secret exposed {raw_secret}",
        risk_type="SECURITY_RISK",
        severity=Severity.HIGH,
        reasoning_summary=f"Found key {raw_secret} in auth.py",
        evidence_refs=["line:auth.py:1"],
        affected_files=["auth.py"],
        verdict=ChangeReviewVerdict.CONFIRMED,
        created_at=datetime.now(timezone.utc),
    )
    report = ChangeReviewReport(
        analysis_id=UUID(analysis.id),
        summary=f"Review summary with secret token: {raw_secret}",
        overall_risk=Severity.HIGH,
        findings=[f_conf],
        created_at=datetime.now(timezone.utc),
    )

    renderer = ReviewPublicationRenderer()
    pub = renderer.render_publication(analysis=analysis, pr_number=1, review_report=report)

    assert raw_secret not in pub.preview_body


def test_renderer_truncation_bound():
    """Verify oversized markdown is safely truncated at finding boundaries."""
    analysis = ChangeAnalysisModel(
        id=str(uuid4()),
        repository_url="https://github.com/octocat/Hello-World",
        repository_owner="octocat",
        repository_name="Hello-World",
        base_commit_sha="1111111111111111111111111111111111111111",
        head_commit_sha="2222222222222222222222222222222222222222",
        status="COMPLETED",
    )

    findings = [
        ChangeReviewFinding(
            id=uuid4(),
            title=f"Large Finding {i}",
            risk_type="RISK",
            severity=Severity.LOW,
            reasoning_summary="A" * 500,
            evidence_refs=[],
            affected_files=[],
            verdict=ChangeReviewVerdict.CONFIRMED,
            created_at=datetime.now(timezone.utc),
        )
        for i in range(20)
    ]
    report = ChangeReviewReport(
        analysis_id=UUID(analysis.id),
        summary="Summary",
        overall_risk=Severity.LOW,
        findings=findings,
        created_at=datetime.now(timezone.utc),
    )

    # Set very small max_body_chars
    renderer = ReviewPublicationRenderer(max_body_chars=2000)
    pub = renderer.render_publication(analysis=analysis, pr_number=1, review_report=report)

    assert pub.is_truncated is True
    assert "exceeded maximum bound" in pub.truncation_reason.lower()
    assert len(pub.preview_body) <= 5000  # safety bound after truncation
