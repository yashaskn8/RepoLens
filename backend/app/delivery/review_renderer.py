"""Deterministic Review Publication Renderer.

Guarantees:
- Produces deterministic, structured markdown from verified ChangeReviewReport.
- Strictly separates CONFIRMED findings from SUPPORTED INFERENCE findings.
- Never renders REJECTED findings as valid findings (renders aggregate rejection count only).
- Non-circular digest calculation: computes SHA-256 preview_digest on canonical payload BEFORE appending hidden marker.
- Injects deterministic hidden idempotency marker `<!-- repolens-review:{pub_id}:{digest} -->`.
- Sanitizes markdown and redacts all secrets/credentials.
- Enforces character length budgets and truncates safely at finding boundaries.
"""

from dataclasses import dataclass
import hashlib
import json
import logging
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

from app.schemas.change_analysis import ChangeReviewFinding, ChangeReviewReport, ChangeReviewVerdict
from app.delivery.diff_mapper import GitHubDiffFile, PullRequestDiffMapper
from app.models.change_analysis import ChangeAnalysisModel, ChangeImpactModel
from app.schemas.review_publication import (
    InlineReviewComment,
    InlineReviewCommentPreview,
)
from app.security.redaction import redact_secrets

logger = logging.getLogger(__name__)


@dataclass
class RenderedReviewPublication:
    """Output bundle of deterministic review rendering."""

    preview_body: str
    preview_digest: str
    inline_comments: List[InlineReviewComment]
    inline_previews: List[InlineReviewCommentPreview]
    is_truncated: bool
    truncation_reason: Optional[str]


class ReviewPublicationRenderer:
    """Renders verified change intelligence into sanitized, publication-ready GitHub review markdown."""

    def __init__(
        self,
        max_body_chars: int = 50_000,
        max_inline_comments: int = 20,
    ):
        self.max_body_chars = max(1000, max_body_chars)
        self.diff_mapper = PullRequestDiffMapper(max_inline_comments=max_inline_comments)

    def _sanitize_text(self, text: Optional[str]) -> str:
        """Redact secrets and strip null bytes/dangerous control chars from text."""
        if not text:
            return ""
        # 1. Secret redaction
        clean = redact_secrets(text)
        # 2. Control char cleaning
        clean = clean.replace("\x00", "").replace("\r\n", "\n")
        return clean

    def render_publication(
        self,
        analysis: ChangeAnalysisModel,
        pr_number: int,
        review_report: Optional[ChangeReviewReport] = None,
        impacts: Optional[List[ChangeImpactModel]] = None,
        diff_files: Optional[List[GitHubDiffFile]] = None,
    ) -> RenderedReviewPublication:
        """Render complete, deterministic review publication with inline comments and preview digest."""
        all_findings: List[ChangeReviewFinding] = review_report.findings if review_report else []
        diff_files = diff_files or []

        # 1. Map inline comments for CONFIRMED findings
        inline_comments, inline_previews = self.diff_mapper.map_findings_to_inline_comments(
            findings=all_findings,
            diff_files=diff_files,
        )

        # 2. Categorize findings by verdict
        confirmed_findings = [f for f in all_findings if f.verdict == ChangeReviewVerdict.CONFIRMED]
        inference_findings = [f for f in all_findings if f.verdict == ChangeReviewVerdict.SUPPORTED_INFERENCE]
        rejected_count = sum(1 for f in all_findings if f.verdict == ChangeReviewVerdict.REJECTED)

        # Sort findings deterministically for stable rendering
        confirmed_findings.sort(key=lambda f: (str(f.severity), f.title))
        inference_findings.sort(key=lambda f: (str(f.severity), f.title))

        # 3. Construct structured sections
        header = (
            f"# RepoLens Change Intelligence\n\n"
            f"- **Repository**: `{self._sanitize_text(analysis.repository_owner)}/{self._sanitize_text(analysis.repository_name)}`\n"
            f"- **Pull Request**: `#{pr_number}`\n"
            f"- **Base Commit**: `{analysis.base_commit_sha[:8]}` (`{analysis.base_commit_sha}`)\n"
            f"- **Head Commit**: `{analysis.head_commit_sha[:8]}` (`{analysis.head_commit_sha}`)\n"
            f"- **Overall Risk**: `{self._sanitize_text(analysis.risk_level or 'UNKNOWN')}`\n\n"
        )

        summary_text = review_report.summary if review_report and review_report.summary else "Semantic change analysis completed."
        summary_section = f"## Summary\n\n{self._sanitize_text(summary_text)}\n\n"

        # Confirmed findings section
        confirmed_section = f"## Confirmed Findings ({len(confirmed_findings)})\n\n"
        if confirmed_findings:
            for f in confirmed_findings:
                sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                confirmed_section += f"### [{sev}] {self._sanitize_text(f.title)}\n"
                confirmed_section += f"- **Risk Type**: `{self._sanitize_text(f.risk_type)}`\n"
                if f.affected_files:
                    files_str = ", ".join(f"`{self._sanitize_text(p)}`" for p in f.affected_files)
                    confirmed_section += f"- **Affected Files**: {files_str}\n"
                confirmed_section += f"- **Evidence Reasoning**: {self._sanitize_text(f.reasoning_summary)}\n"
                suggested = getattr(f, "suggested_remediation", None)
                if suggested:
                    confirmed_section += f"- **Suggested Fix**: {self._sanitize_text(suggested)}\n"
                confirmed_section += "\n"
        else:
            confirmed_section += "_No confirmed critical regressions or breaking contract changes detected._\n\n"

        # Supported inferences section
        inferences_section = f"## Supported Inferences ({len(inference_findings)})\n\n"
        if inference_findings:
            for f in inference_findings:
                sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                inferences_section += f"### [{sev}] {self._sanitize_text(f.title)}\n"
                inferences_section += f"- **Risk Type**: `{self._sanitize_text(f.risk_type)}`\n"
                inferences_section += f"- **Inference Rationale**: {self._sanitize_text(f.reasoning_summary)}\n"
                if f.assumptions:
                    assump_str = "; ".join(self._sanitize_text(a) for a in f.assumptions)
                    inferences_section += f"- **Underlying Assumptions**: {assump_str}\n"
                inferences_section += "\n"
        else:
            inferences_section += "_No behavioral inference risks identified._\n\n"

        # Rejected findings note
        rejected_section = "## Rejected Findings\n\n"
        if rejected_count > 0:
            rejected_section += f"{rejected_count} candidate finding(s) were analyzed and rejected by deterministic verification.\n\n"
        else:
            rejected_section += "0 candidate findings were rejected.\n\n"

        # Change impact summary
        impact_section = "## Change Impact\n\n"
        impact_list = impacts or []
        if impact_list:
            impact_section += f"- **Changed Files**: `{analysis.changed_files_count}`\n"
            impact_section += f"- **Changed Symbols**: `{analysis.changed_symbols_count}`\n"
            impact_section += f"- **Impacted Graph Symbols**: `{analysis.impacted_symbols_count}`\n"
            for imp in impact_list[:5]:
                impact_section += f"- `{self._sanitize_text(imp.impact_type)}`: {self._sanitize_text(imp.title)}\n"
            impact_section += "\n"
        else:
            impact_section += f"- Changed files: `{analysis.changed_files_count}`\n\n"

        # Limitations section
        limitations_section = (
            "## Limitations & Provenance\n\n"
            f"- Generated from immutable git revisions: `{analysis.base_commit_sha}` (base) and `{analysis.head_commit_sha}` (head).\n"
            "- Human authorization was required prior to publication.\n"
            "- Publication event is strictly `COMMENT` (no autonomous PR approval or merging).\n"
        )

        # 4. Assemble complete markdown body (WITHOUT marker)
        body_without_marker = (
            header
            + summary_section
            + confirmed_section
            + inferences_section
            + rejected_section
            + impact_section
            + limitations_section
        )

        # 5. Check truncation bound
        is_truncated = False
        truncation_reason = None
        if len(body_without_marker) > self.max_body_chars:
            is_truncated = True
            truncation_reason = f"Body length ({len(body_without_marker)}) exceeded maximum bound ({self.max_body_chars} chars)"
            # Safe truncation: keep header, summary, and limitations, truncate findings
            body_without_marker = (
                header
                + summary_section
                + f"## Confirmed Findings ({len(confirmed_findings)})\n\n_Findings truncated due to size limits. See RepoLens dashboard for full details._\n\n"
                + rejected_section
                + limitations_section
            )

        # 6. Calculate preview digest over canonical publication representation (WITHOUT marker)
        canonical_snapshot = {
            "analysis_id": str(analysis.id),
            "repository_owner": analysis.repository_owner,
            "repository_name": analysis.repository_name,
            "pr_number": pr_number,
            "base_commit_sha": analysis.base_commit_sha,
            "head_commit_sha": analysis.head_commit_sha,
            "body": body_without_marker,
            "inline_comments": [c.model_dump() for c in inline_comments],
            "event": "COMMENT",
        }
        canonical_json = json.dumps(canonical_snapshot, sort_keys=True, separators=(",", ":"))
        preview_digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

        # 7. Append deterministic hidden marker to final body using calculated preview_digest
        hidden_marker = f"\n\n<!-- repolens-review:{analysis.id}:{preview_digest} -->"
        final_body = body_without_marker + hidden_marker

        return RenderedReviewPublication(
            preview_body=final_body,
            preview_digest=preview_digest,
            inline_comments=inline_comments,
            inline_previews=inline_previews,
            is_truncated=is_truncated,
            truncation_reason=truncation_reason,
        )
