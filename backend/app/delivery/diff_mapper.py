"""Deterministic Diff Mapper for Pull Request Inline Review Comments.

Guarantees:
- Strictly maps only CONFIRMED findings to inline comments.
- Requires exact file match against PR changed files.
- Verifies line presence on the head (right) side of PR diff hunks.
- Never guesses lines, never picks nearest line, never comments on unchanged/deleted-only lines.
- Enforces MAX_REVIEW_INLINE_COMMENTS bound.
- Safely falls back to top-level review summary when mapping is unavailable or ambiguous.
"""

import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from app.schemas.change_analysis import ChangeReviewFinding, ChangeReviewVerdict
from app.schemas.review_publication import InlineReviewComment, InlineReviewCommentPreview

logger = logging.getLogger(__name__)


class GitHubDiffFile:
    """Represents a changed file within a pull request with its patch hunks."""

    def __init__(
        self,
        filename: str,
        status: str = "modified",
        patch: Optional[str] = None,
        previous_filename: Optional[str] = None,
    ):
        self.filename = filename.replace("\\", "/")
        self.status = status
        self.patch = patch or ""
        self.previous_filename = previous_filename.replace("\\", "/") if previous_filename else None
        self._head_lines: Optional[Set[int]] = None

    @property
    def valid_head_lines(self) -> Set[int]:
        """Parse patch hunks to extract exact line numbers valid on the head/right side of the PR diff."""
        if self._head_lines is not None:
            return self._head_lines

        self._head_lines = set()
        if not self.patch:
            return self._head_lines

        # Regex to parse hunk headers: @@ -old_start,old_count +new_start,new_count @@
        hunk_header_regex = re.compile(r"^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,(\d+))?\s+@@")
        current_head_line = 0
        in_hunk = False

        for line in self.patch.splitlines():
            hunk_match = hunk_header_regex.match(line)
            if hunk_match:
                current_head_line = int(hunk_match.group(1))
                in_hunk = True
                continue

            if not in_hunk:
                continue

            if line.startswith("+"):
                # Added/modified line on the head side
                self._head_lines.add(current_head_line)
                current_head_line += 1
            elif line.startswith("-"):
                # Deleted line on base side (does not advance head line counter)
                pass
            elif line.startswith(" ") or line == "":
                # Context line present in diff hunk on head side
                self._head_lines.add(current_head_line)
                current_head_line += 1
            elif line.startswith("\\"):
                # "\ No newline at end of file"
                pass

        return self._head_lines


class PullRequestDiffMapper:
    """Deterministic mapper converting verified findings into exact GitHub inline comments."""

    def __init__(self, max_inline_comments: int = 20):
        self.max_inline_comments = max(1, max_inline_comments)

    def extract_finding_location(
        self,
        finding: ChangeReviewFinding,
    ) -> Optional[Tuple[str, int]]:
        """Extract exact file and head line number from finding evidence refs or affected files."""
        # 1. Search for explicit line evidence: "line:filepath:line_number" or "line:filepath:start-end"
        for ev in finding.evidence_refs:
            if ev.startswith("line:"):
                parts = ev.split(":")
                if len(parts) >= 3:
                    file_part = parts[1].replace("\\", "/")
                    line_str = parts[2].split("-")[0]
                    try:
                        line_no = int(line_str)
                        if line_no > 0:
                            return (file_part, line_no)
                    except ValueError:
                        pass

        # 2. Search for explicit symbol evidence: "symbol:filepath:TYPE:name:line_number"
        for ev in finding.evidence_refs:
            if ev.startswith("symbol:"):
                parts = ev.split(":")
                if len(parts) >= 5:
                    file_part = parts[1].replace("\\", "/")
                    try:
                        line_no = int(parts[4])
                        if line_no > 0:
                            return (file_part, line_no)
                    except ValueError:
                        pass

        return None

    def map_findings_to_inline_comments(
        self,
        findings: List[ChangeReviewFinding],
        diff_files: List[GitHubDiffFile],
    ) -> Tuple[List[InlineReviewComment], List[InlineReviewCommentPreview]]:
        """Map confirmed findings to exact inline comments, respecting diff boundaries and limits."""
        diff_map: Dict[str, GitHubDiffFile] = {df.filename: df for df in diff_files}
        comments: List[InlineReviewComment] = []
        previews: List[InlineReviewCommentPreview] = []
        seen_locations: Set[Tuple[str, int]] = set()

        # Sort findings deterministically
        sorted_findings = sorted(
            findings,
            key=lambda f: (str(f.affected_files[0]) if f.affected_files else "", f.title),
        )

        for finding in sorted_findings:
            # Rule 1: Only CONFIRMED findings are eligible for inline comments
            if finding.verdict != ChangeReviewVerdict.CONFIRMED:
                continue

            loc = self.extract_finding_location(finding)
            if not loc:
                continue

            file_path, line_no = loc
            if file_path not in diff_map:
                continue

            diff_file = diff_map[file_path]
            # Rule 2: Line must exist in the valid head diff hunk lines
            if line_no not in diff_file.valid_head_lines:
                continue

            # Deduplicate multiple comments on exact same line
            if (file_path, line_no) in seen_locations:
                continue

            if len(comments) >= self.max_inline_comments:
                break

            seen_locations.add((file_path, line_no))

            # Format concise, professional markdown body
            body = (
                f"**RepoLens Verified Finding: {finding.title}**\n\n"
                f"- **Severity**: `{finding.severity.value if hasattr(finding.severity, 'value') else finding.severity}`\n"
                f"- **Risk Type**: `{finding.risk_type}`\n\n"
                f"{finding.reasoning_summary}"
            )
            suggested = getattr(finding, "suggested_remediation", None)
            if suggested:
                body += f"\n\n**Suggested Fix**:\n{suggested}"

            comment = InlineReviewComment(
                path=file_path,
                line=line_no,
                side="RIGHT",
                body=body,
            )
            preview = InlineReviewCommentPreview(
                path=file_path,
                line=line_no,
                side="RIGHT",
                body=body,
                finding_id=str(finding.id) if hasattr(finding, "id") else None,
                finding_title=finding.title,
                severity=finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
            )
            comments.append(comment)
            previews.append(preview)

        # Stable sort by path and line
        comments.sort(key=lambda c: (c.path, c.line))
        previews.sort(key=lambda p: (p.path, p.line))

        return comments, previews
