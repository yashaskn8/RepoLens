from uuid import uuid4
from datetime import datetime, timezone
import pytest

from app.schemas.change_analysis import ChangeReviewFinding, ChangeReviewVerdict
from app.schemas.enums import Severity
from app.delivery.diff_mapper import GitHubDiffFile, PullRequestDiffMapper


def test_diff_mapper_extract_head_lines_from_patch():
    """Verify hunk parsing correctly extracts valid head line numbers."""
    patch = (
        "@@ -10,4 +10,6 @@ def parse_config():\n"
        " context line\n"
        "-old_call()\n"
        "+new_call_line11()\n"
        "+new_call_line12()\n"
        " context line 13\n"
    )
    diff_file = GitHubDiffFile(filename="src/config.py", patch=patch)
    head_lines = diff_file.valid_head_lines

    assert 10 in head_lines  # context line (line 10)
    assert 11 in head_lines  # added line (line 11)
    assert 12 in head_lines  # added line (line 12)
    assert 13 in head_lines  # context line (line 13)
    assert 9 not in head_lines
    assert 14 not in head_lines


def test_diff_mapper_only_maps_confirmed_findings():
    """Verify SUPPORTED_INFERENCE and REJECTED findings are NEVER mapped inline."""
    mapper = PullRequestDiffMapper(max_inline_comments=5)
    patch = "@@ -1,3 +1,4 @@\n+x = 1\n+y = 2\n"
    diff_file = GitHubDiffFile(filename="app.py", patch=patch)

    confirmed_finding = ChangeReviewFinding(
        id=uuid4(),
        title="Breaking API change",
        risk_type="API_CONTRACT_BREAK",
        severity=Severity.HIGH,
        reasoning_summary="POST changed to PUT",
        evidence_refs=["line:app.py:1"],
        affected_files=["app.py"],
        verdict=ChangeReviewVerdict.CONFIRMED,
        created_at=datetime.now(timezone.utc),
    )

    inference_finding = ChangeReviewFinding(
        id=uuid4(),
        title="Possible race condition",
        risk_type="CONCURRENCY_RISK",
        severity=Severity.MEDIUM,
        reasoning_summary="Concurrent call might conflict",
        evidence_refs=["line:app.py:2"],
        affected_files=["app.py"],
        verdict=ChangeReviewVerdict.SUPPORTED_INFERENCE,
        created_at=datetime.now(timezone.utc),
    )

    comments, previews = mapper.map_findings_to_inline_comments(
        findings=[confirmed_finding, inference_finding],
        diff_files=[diff_file],
    )

    assert len(comments) == 1
    assert comments[0].path == "app.py"
    assert comments[0].line == 1
    assert comments[0].side == "RIGHT"
    assert "Breaking API change" in comments[0].body


def test_diff_mapper_skips_unchanged_or_deleted_lines():
    """Verify findings referencing deleted lines or lines outside diff are skipped."""
    mapper = PullRequestDiffMapper(max_inline_comments=5)
    patch = "@@ -10,3 +10,3 @@\n context 10\n-removed 11\n+added 11\n context 12\n"
    diff_file = GitHubDiffFile(filename="app.py", patch=patch)

    finding_out_of_diff = ChangeReviewFinding(
        id=uuid4(),
        title="Old bug",
        risk_type="BUG",
        severity=Severity.LOW,
        reasoning_summary="Bug on line 50",
        evidence_refs=["line:app.py:50"],
        affected_files=["app.py"],
        verdict=ChangeReviewVerdict.CONFIRMED,
        created_at=datetime.now(timezone.utc),
    )

    comments, _ = mapper.map_findings_to_inline_comments(
        findings=[finding_out_of_diff],
        diff_files=[diff_file],
    )
    assert len(comments) == 0


def test_diff_mapper_enforces_max_inline_bound():
    """Verify inline comments are capped at max_inline_comments."""
    mapper = PullRequestDiffMapper(max_inline_comments=2)
    patch = "@@ -1,5 +1,5 @@\n+line 1\n+line 2\n+line 3\n"
    diff_file = GitHubDiffFile(filename="app.py", patch=patch)

    findings = [
        ChangeReviewFinding(
            id=uuid4(),
            title=f"Finding {i}",
            risk_type="BUG",
            severity=Severity.LOW,
            reasoning_summary=f"Bug on line {i}",
            evidence_refs=[f"line:app.py:{i}"],
            affected_files=["app.py"],
            verdict=ChangeReviewVerdict.CONFIRMED,
            created_at=datetime.now(timezone.utc),
        )
        for i in (1, 2, 3)
    ]

    comments, _ = mapper.map_findings_to_inline_comments(
        findings=findings,
        diff_files=[diff_file],
    )
    assert len(comments) == 2
