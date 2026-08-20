"""Fixture findings with known root causes and expected remediation properties (Phase 3H).

Each fixture maps a ground-truth finding to:
- The expected files/symbols to change
- A known-good unified diff (for resolution checking)
- Expected remediation properties (scope, patch file set)

These are entirely synthetic and deterministic — no LLM calls during setup.
"""

from typing import Dict, List, Optional
from uuid import UUID, uuid4

from dataclasses import dataclass, field

from app.evaluation.schemas import GroundTruthIssue, IssueCategory
from app.planning.schemas import FixPlan, FixScope, OrderedChangeStep
from app.schemas.enums import Severity
from app.schemas.evidence import Evidence
from app.schemas.finding import Finding


@dataclass
class RemediationFixtureFinding:
    """A single fixture finding with known root cause and expected remediation properties."""

    finding: Finding
    expected_files_to_change: List[str]
    expected_scope: FixScope
    known_good_diff: str
    defect_snippet: str  # The exact snippet that should be removed/changed
    ground_truth: GroundTruthIssue


def build_remediation_fixtures() -> List[RemediationFixtureFinding]:
    """Build fixture findings with known root causes for remediation evaluation.

    Returns 4 findings covering:
    1. SQL Injection (security) — parameterized query fix
    2. Division by zero (correctness) — guard clause fix
    3. Route mismatch (architecture) — URL alignment fix
    4. HTTP method mismatch (architecture) — method alignment fix
    """
    scan_id = uuid4()

    fixtures: List[RemediationFixtureFinding] = []

    # =========================================================================
    # Fixture 1: SQL Injection — parameterized query
    # =========================================================================
    sqli_finding = Finding(
        id=uuid4(),
        scan_id=scan_id,
        title="SQL Injection in Database Query Utility",
        description="Formatted string in SQL execution allows direct SQL injection via user_id parameter.",
        severity=Severity.HIGH,
        category="security",
        evidences=[
            Evidence(
                file_path="app/db/query.py",
                start_line=8,
                end_line=9,
                code_snippet="query = f\"SELECT * FROM accounts WHERE user_id = '{user_id}'\"",
            )
        ],
    )

    sqli_diff = (
        "--- a/app/db/query.py\n"
        "+++ b/app/db/query.py\n"
        "@@ -7,3 +7,3 @@\n"
        "-    query = f\"SELECT * FROM accounts WHERE user_id = '{user_id}'\"\n"
        "-    cursor.execute(query)\n"
        "+    query = \"SELECT * FROM accounts WHERE user_id = ?\"\n"
        "+    cursor.execute(query, (user_id,))\n"
    )

    fixtures.append(RemediationFixtureFinding(
        finding=sqli_finding,
        expected_files_to_change=["app/db/query.py"],
        expected_scope=FixScope.LINE,
        known_good_diff=sqli_diff,
        defect_snippet="query = f\"SELECT * FROM accounts WHERE user_id = '{user_id}'\"",
        ground_truth=GroundTruthIssue(
            issue_id="REM-GT-001",
            category=IssueCategory.SECURITY,
            title="SQL Injection in Database Query Utility",
            description="Formatted string in SQL query permits SQL injection.",
            expected_file="app/db/query.py",
            expected_start_line=8,
            expected_end_line=9,
            query="SQL injection parameterized query fix",
        ),
    ))

    # =========================================================================
    # Fixture 2: Division by zero — guard clause
    # =========================================================================
    div_zero_finding = Finding(
        id=uuid4(),
        scan_id=scan_id,
        title="Unhandled ZeroDivisionError in Discount Calculation",
        description="Division by total_amount without checking for 0.0 causes unhandled crash.",
        severity=Severity.MEDIUM,
        category="correctness",
        evidences=[
            Evidence(
                file_path="app/core/calculator.py",
                start_line=3,
                end_line=4,
                code_snippet="return discount / total_amount",
            )
        ],
    )

    div_zero_diff = (
        "--- a/app/core/calculator.py\n"
        "+++ b/app/core/calculator.py\n"
        "@@ -3,1 +3,3 @@\n"
        "-    return discount / total_amount\n"
        "+    if total_amount == 0.0:\n"
        "+        return 0.0\n"
        "+    return discount / total_amount\n"
    )

    fixtures.append(RemediationFixtureFinding(
        finding=div_zero_finding,
        expected_files_to_change=["app/core/calculator.py"],
        expected_scope=FixScope.FUNCTION,
        known_good_diff=div_zero_diff,
        defect_snippet="return discount / total_amount",
        ground_truth=GroundTruthIssue(
            issue_id="REM-GT-002",
            category=IssueCategory.CORRECTNESS,
            title="Unhandled ZeroDivisionError in Discount Calculation",
            description="Division by total_amount without checking for 0.0.",
            expected_file="app/core/calculator.py",
            expected_start_line=3,
            expected_end_line=4,
            query="division by zero guard clause fix",
        ),
    ))

    # =========================================================================
    # Fixture 3: Route mismatch — URL alignment
    # =========================================================================
    route_finding = Finding(
        id=uuid4(),
        scan_id=scan_id,
        title="Unmatched Route: Frontend calls /submit instead of /checkout",
        description="Client invokes POST /api/v1/orders/submit which does not exist on backend.",
        severity=Severity.MEDIUM,
        category="route_mismatch",
        evidences=[
            Evidence(
                file_path="frontend/src/api/orders.ts",
                start_line=4,
                end_line=7,
                code_snippet="return await fetch('/api/v1/orders/submit', {",
            )
        ],
    )

    route_diff = (
        "--- a/frontend/src/api/orders.ts\n"
        "+++ b/frontend/src/api/orders.ts\n"
        "@@ -4,1 +4,1 @@\n"
        "-  return await fetch('/api/v1/orders/submit', {\n"
        "+  return await fetch('/api/v1/orders/checkout', {\n"
    )

    fixtures.append(RemediationFixtureFinding(
        finding=route_finding,
        expected_files_to_change=["frontend/src/api/orders.ts"],
        expected_scope=FixScope.LINE,
        known_good_diff=route_diff,
        defect_snippet="return await fetch('/api/v1/orders/submit', {",
        ground_truth=GroundTruthIssue(
            issue_id="REM-GT-003",
            category=IssueCategory.ROUTE_MISMATCH,
            title="Unmatched Route: Frontend calls /submit instead of /checkout",
            description="Client invokes POST /api/v1/orders/submit which does not exist.",
            expected_file="frontend/src/api/orders.ts",
            expected_start_line=4,
            expected_end_line=7,
            query="orders submit checkout route mismatch fix",
        ),
    ))

    # =========================================================================
    # Fixture 4: HTTP method mismatch — method alignment
    # =========================================================================
    method_finding = Finding(
        id=uuid4(),
        scan_id=scan_id,
        title="HTTP Method Mismatch on Users Endpoint",
        description="Client sends DELETE to /api/v1/users/{id} which only implements GET.",
        severity=Severity.MEDIUM,
        category="method_mismatch",
        evidences=[
            Evidence(
                file_path="frontend/src/api/users.ts",
                start_line=4,
                end_line=6,
                code_snippet="method: 'DELETE',",
            )
        ],
    )

    method_diff = (
        "--- a/frontend/src/api/users.ts\n"
        "+++ b/frontend/src/api/users.ts\n"
        "@@ -4,1 +4,1 @@\n"
        "-    method: 'DELETE',\n"
        "+    method: 'GET',\n"
    )

    fixtures.append(RemediationFixtureFinding(
        finding=method_finding,
        expected_files_to_change=["frontend/src/api/users.ts"],
        expected_scope=FixScope.LINE,
        known_good_diff=method_diff,
        defect_snippet="method: 'DELETE',",
        ground_truth=GroundTruthIssue(
            issue_id="REM-GT-004",
            category=IssueCategory.METHOD_MISMATCH,
            title="HTTP Method Mismatch on Users Endpoint",
            description="Client sends DELETE to GET-only endpoint.",
            expected_file="frontend/src/api/users.ts",
            expected_start_line=4,
            expected_end_line=6,
            query="users endpoint DELETE GET method mismatch fix",
        ),
    ))

    return fixtures
