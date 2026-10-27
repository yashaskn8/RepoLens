"""Deterministic Report and Telemetry Generator for Change Intelligence Analysis.

Produces comprehensive, evidence-grounded Change Analysis Reports (Structured + Markdown)
and authoritative telemetry aggregations without leaking secrets or making false claims.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

from app.models.change_analysis import ChangeAnalysisModel, ChangeImpactModel
from app.schemas.change_analysis import (
    ChangeAnalysisReportResponse,
    ChangeAnalysisStatus,
    ChangeImpact,
    ChangeImpactEvidence,
    ChangeReviewFinding,
    ConfigDelta,
    DependencyDelta,
    RouteContractDelta,
    SchemaModelDelta,
    Severity,
)
from app.schemas.enums import ChangeImpactType, ChangeRiskLevel, ImpactVerificationStatus
from app.schemas.telemetry import ChangeAnalysisTelemetry
from app.security.redaction import redact_secrets

logger = logging.getLogger(__name__)


def _compute_risk_explanation(
    risk_level: Optional[ChangeRiskLevel],
    contract_breaks: int,
    security_impacts: int,
    total_impacts: int,
    confirmed_findings: int,
) -> str:
    """Explain stored risk without inventing impacts or treating missing data as LOW."""
    if risk_level is None:
        return (
            "Risk assessment not available. The recorded change analysis does not "
            "contain an authoritative risk rating; do not infer LOW risk."
        )
    if risk_level == ChangeRiskLevel.NONE:
        return (
            "NONE risk assessed by static analysis. This is not proof of safety "
            "and does not establish that tests or runtime checks succeeded."
        )
    if risk_level == ChangeRiskLevel.CRITICAL:
        return (
            f"CRITICAL risk assessed. Recorded impacts include {contract_breaks} "
            f"contract/schema change(s) and {security_impacts} security-sensitive "
            "change(s). Review source evidence; blast radius is not independently proven by the rating."
        )
    if risk_level == ChangeRiskLevel.HIGH:
        return (
            f"HIGH risk assessed. {total_impacts} impact record(s) and "
            f"{confirmed_findings} retained review finding(s) were recorded. "
            "Validate the relevant dependencies and contracts."
        )
    if risk_level == ChangeRiskLevel.MEDIUM:
        return (
            f"MEDIUM risk assessed. {total_impacts} impact record(s) were "
            "recorded. Their downstream effects require evidence-based verification."
        )
    return (
        "LOW risk assessed by static analysis. The rating does not prove "
        "the absence of breaking contracts, exploits, or runtime regressions."
    )


def _markdown_pr_label(raw: object) -> str:
    """Escape untrusted pull request titles inside a Markdown link/table cell."""
    if not isinstance(raw, str):
        return ""
    cleaned = " ".join(raw.split())[:180]
    for char, replacement in (
        ("\\", "\\\\"),
        ("|", "\\|"),
        ("[", "\\["),
        ("]", "\\]"),
        ("`", "&#96;"),
        ("<", "&lt;"),
        (">", "&gt;"),
    ):
        cleaned = cleaned.replace(char, replacement)
    return cleaned


def _render_markdown_report(
    analysis: ChangeAnalysisModel,
    route_deltas: List[RouteContractDelta],
    schema_deltas: List[SchemaModelDelta],
    dependency_deltas: List[DependencyDelta],
    config_deltas: List[ConfigDelta],
    impacts: List[ChangeImpact],
    review_findings: List[ChangeReviewFinding],
    risk_explanation: str,
    duration_seconds: Optional[float],
    llm_status: str = "AVAILABLE",
    is_llm_fallback: bool = False,
    has_review_data: bool = False,
    invalid_review_count: int = 0,
    ast_recorded: bool = False,
    graph_recorded: bool = False,
) -> str:
    """Render deterministic, rich GitHub Flavored Markdown Change Analysis Report."""
    meta = analysis.model_metadata or {}
    pr_num = meta.get("pr_number")
    pr_title = meta.get("pr_title")

    lines = []
    lines.append(f"# 🔍 RepoLens Change Intelligence Report")
    lines.append("")
    lines.append(f"> **Analysis ID**: `{analysis.id}`  ")
    lines.append(f"> **Generated**: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ")
    lines.append(f"> **Status**: `{analysis.status}` | **Risk Rating**: `{analysis.risk_level or 'NOT_ASSESSED'}`  ")
    lines.append("")

    # 1. Provenance
    lines.append("## 📌 Provenance & Revisions")
    lines.append("")
    lines.append("| Property | Value |")
    lines.append("| :--- | :--- |")
    lines.append(f"| **Repository** | [{analysis.repository_url}]({analysis.repository_url}) |")
    if isinstance(pr_num, int) and not isinstance(pr_num, bool) and pr_num > 0:
        lines.append(
            f"| **Pull Request** | [#{pr_num} {_markdown_pr_label(pr_title)}]"
            f"({analysis.repository_url}/pull/{pr_num}) |"
        )
    lines.append(f"| **Base Revision** | `{analysis.base_commit_sha}` ({_markdown_pr_label(analysis.base_ref or 'base')}) |")
    lines.append(f"| **Head Revision** | `{analysis.head_commit_sha}` ({_markdown_pr_label(analysis.head_ref or 'head')}) |")
    lines.append(f"| **Created At** | `{analysis.created_at.isoformat() if analysis.created_at else 'N/A'}` |")
    lines.append(f"| **Completed At** | `{analysis.completed_at.isoformat() if analysis.completed_at else 'N/A'}` |")
    if duration_seconds is not None:
        lines.append(f"| **Execution Duration** | `{duration_seconds:.2f}s` |")
    lines.append("")

    # 2. Executive Summary
    lines.append("## 📊 Change Metrics & Blast Radius Overview")
    lines.append("")
    lines.append(f"**Risk Assessment**: `{analysis.risk_level or 'NOT_ASSESSED'}`  ")
    lines.append(f"*{risk_explanation}*")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("| :--- | :--- |")
    lines.append(f"| 📁 **Files Changed** | `{analysis.changed_files_count}` |")
    lines.append(f"| 🧩 **Symbols Changed** | `{analysis.changed_symbols_count}` |")
    lines.append(f"| 💥 **Impacted Symbols / Callers** | `{analysis.impacted_symbols_count}` |")
    lines.append(f"| ⚡ **API Route Contract Deltas** | {f'`{len(route_deltas)}`' if ast_recorded else 'Unavailable'} |")
    lines.append(f"| 📐 **Schema & Model Deltas** | {f'`{len(schema_deltas)}`' if ast_recorded else 'Unavailable'} |")
    lines.append(f"| 📦 **Dependency Deltas** | {f'`{len(dependency_deltas)}`' if ast_recorded else 'Unavailable'} |")
    lines.append(f"| ⚙️ **Config Deltas** | {f'`{len(config_deltas)}`' if ast_recorded else 'Unavailable'} |")
    lines.append(f"| 🤖 **Verified Review Findings** | `{len(review_findings)}` |")
    lines.append("")

    # 3. Contract Changes
    if route_deltas or schema_deltas or dependency_deltas or config_deltas:
        lines.append("## ⚡ Semantic Contract Changes")
        lines.append("")

        if route_deltas:
            lines.append("### 🌐 API Route Deltas")
            lines.append("| File | Route | Method | Change Type | Details |")
            lines.append("| :--- | :--- | :--- | :--- | :--- |")
            for r in route_deltas:
                m = f"`{r.base_http_method or '-'}` → `{r.head_http_method or '-'}`"
                lines.append(f"| `{_markdown_pr_label(r.file_path)}` | `{_markdown_pr_label(r.route_name)}` | {m} | `{r.change_type}` | {_markdown_pr_label(r.details)} |")
            lines.append("")

        if schema_deltas:
            lines.append("### 📐 Data Schema & Model Deltas")
            lines.append("| File | Model | Field | Type Change | Details |")
            lines.append("| :--- | :--- | :--- | :--- | :--- |")
            for s in schema_deltas:
                t = f"`{s.base_type or '-'}` → `{s.head_type or '-'}`"
                lines.append(f"| `{_markdown_pr_label(s.file_path)}` | `{_markdown_pr_label(s.model_name)}` | `{_markdown_pr_label(s.field_name)}` | {t} | {_markdown_pr_label(s.details)} |")
            lines.append("")

        if dependency_deltas:
            lines.append("### 📦 Package Dependency Deltas")
            lines.append("| Manifest | Package | Base Version | Head Version | Change |")
            lines.append("| :--- | :--- | :--- | :--- | :--- |")
            for d in dependency_deltas:
                lines.append(f"| `{_markdown_pr_label(d.manifest_file)}` | **{_markdown_pr_label(d.package_name)}** | `{_markdown_pr_label(d.base_version or '-')}` | `{_markdown_pr_label(d.head_version or '-')}` | `{d.change_type}` |")
            lines.append("")

        if config_deltas:
            lines.append("### ⚙️ Configuration & Environment Deltas")
            lines.append("| Config File | Key | Change Type |")
            lines.append("| :--- | :--- | :--- |")
            for c in config_deltas:
                lines.append(f"| `{_markdown_pr_label(c.file_path)}` | `{_markdown_pr_label(c.key)}` | `{c.change_type}` |")
            lines.append("")

    # 4. Blast Radius Impacts
    if impacts:
        lines.append("## 💥 Impact Explorer & Blast Radius")
        lines.append("")
        lines.append("| Severity | Type | Source Symbol / File | Affected Symbol / File | Status | Description |")
        lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
        for imp in impacts:
            src = f"`{_markdown_pr_label(imp.source_file)}`" + (f" (`{_markdown_pr_label(imp.source_symbol)}`)" if imp.source_symbol else "")
            aff = f"`{_markdown_pr_label(imp.affected_file)}`" + (f" (`{_markdown_pr_label(imp.affected_symbol)}`)" if imp.affected_symbol else "")
            lines.append(
                f"| **{imp.severity.value}** | `{imp.impact_type.value}` | {src} | {aff} | `{imp.verification_status.value}` | {_markdown_pr_label(imp.title)} |"
            )
        lines.append("")

    # 5. Verified AI Review Findings
    if review_findings:
        lines.append("## 🤖 Grounded AI Change Review Findings")
        lines.append("")
        for f in review_findings:
            lines.append(f"### ⚠️ [{f.severity.value}] {_markdown_pr_label(f.title)}")
            lines.append(f"- **Risk Category**: `{_markdown_pr_label(f.risk_type)}`")
            lines.append(f"- **Verdict**: `{f.verdict.value}` (Confidence: `{f.confidence:.0%}`)")
            lines.append(f"- **Reasoning**: {_markdown_pr_label(f.reasoning_summary)}")
            if f.affected_files:
                lines.append(f"- **Affected Files**: {', '.join(f'`{_markdown_pr_label(p)}`' for p in f.affected_files)}")
            if f.evidence_refs:
                lines.append(f"- **Evidence References**: {', '.join(f'`{_markdown_pr_label(r)}`' for r in f.evidence_refs)}")
            if f.assumptions:
                lines.append(f"- **Disclosed Assumptions**: {'; '.join(_markdown_pr_label(a) for a in f.assumptions)}")
            lines.append("")

    # 6. Tool Availability & Epistemic Limitations
    lines.append("## 🛡️ Tool Availability & Analysis Constraints")
    lines.append("")
    lines.append("| Engine / Capability | Availability | Mode |")
    lines.append("| :--- | :--- | :--- |")
    lines.append(
        "| **Tree-sitter AST Parser** | "
        + ("✅ Evidence Recorded" if ast_recorded else "⚠️ Execution Not Attested")
        + " | Deterministic Structural Facts |"
    )
    lines.append(
        "| **Repository Graph Traversal** | "
        + ("✅ Evidence Recorded" if graph_recorded else "⚠️ Execution Not Attested")
        + " | Bounded Blast Radius Traversal |"
    )
    lines.append("| **Static Security Scanners** | ℹ️ Not Executed | Dedicated Scan Phase Only |")

    if not has_review_data:
        agent_row = "| **Change Review Agent** | ℹ️ Not Executed | Static Only |"
    elif not is_llm_fallback and llm_status == "SUCCESS":
        agent_row = "| **Change Review Agent** | ✅ Executed | Bounded Context Reasoning |"
    elif llm_status == "UNAVAILABLE":
        agent_row = "| **Change Review Agent** | ⚠️ Unavailable — deterministic-only result | Fallback Mode |"
    elif llm_status == "FAILED":
        agent_row = "| **Change Review Agent** | ❌ Failed — deterministic fallback | Fallback Mode |"
    else:
        # Unrecognized or skipped model execution statuses must not crash
        # report rendering or be reported as successful AI verification.
        agent_row = "| **Change Review Agent** | ⚠️ Result unavailable or unverified | Static Evidence Only |"
    lines.append(agent_row)
    lines.append("| **Runtime Sandbox / Dynamic Testing** | ❌ Not Executed | Static Evidence Only |")
    lines.append("")
    lines.append("### Limitations & Grounding Constraints")
    lines.append("- **Static Analysis Boundary**: Analysis operates purely on static source AST and repository dependency graphs. No repository code was executed in a sandbox.")
    lines.append("- **No Test Execution**: Repository test suites, integration tests, and CI/CD pipelines were **NOT executed**.")
    if invalid_review_count:
        lines.append(
            f"- **Incomplete Review Evidence**: {invalid_review_count} malformed AI review record(s) "
            "were omitted; this review result must not be treated as complete."
        )
    lines.append("- **Dynamic Dispatch**: Dynamic reflection, runtime monkeypatching, and duck-typed method invocation cannot be completely proven via static traversal.")
    lines.append("")

    # 7. Phase 7: GitHub Review Publication State
    pub = getattr(analysis, "review_publication", None)
    lines.append("## 🚀 GitHub Review Publication")
    lines.append("")
    if pub is None:
        lines.append("- **Status**: `NOT_REQUESTED`")
    elif pub.status == "PUBLISHED":
        lines.append("- **Status**: `PUBLISHED`")
        lines.append("- **Review Type**: `COMMENT`")
        lines.append(f"- **Repository**: `{pub.repository_owner}/{pub.repository_name}`")
        lines.append(f"- **Pull Request**: `#{pub.pr_number}`")
        lines.append(f"- **Base SHA**: `{pub.base_commit_sha}`")
        lines.append(f"- **Head SHA**: `{pub.head_commit_sha}`")
        if pub.github_review_id:
            lines.append(f"- **Review ID**: `{pub.github_review_id}`")
        if pub.github_review_url:
            lines.append(f"- **Review URL**: {pub.github_review_url}")
        if pub.published_at:
            lines.append(f"- **Published At**: {pub.published_at.isoformat()}")
        inline_count = len(pub.inline_comments_payload or [])
        lines.append(f"- **Inline Comments Count**: {inline_count}")
        lines.append(f"- **Reconciliation Occurred**: {'Yes' if pub.reconciliation_occurred else 'No'}")
    elif pub.status in ("BLOCKED", "FAILED"):
        lines.append(f"- **Status**: `{pub.status}`")
        if pub.failure_code:
            lines.append(f"- **Failure Code**: `{pub.failure_code}`")
        if pub.failure_message:
            safe_msg = redact_secrets(pub.failure_message)[:500]
            lines.append(f"- **Failure Message**: {safe_msg}")
    else:
        # PREVIEW_READY, APPROVED, PUBLISHING
        lines.append(f"- **Status**: `{pub.status}`")
        if pub.preview_digest:
            lines.append(f"- **Preview Digest**: `{pub.preview_digest}`")
        inline_count = len(pub.inline_comments_payload or [])
        lines.append(f"- **Inline Comments Count**: {inline_count}")
    lines.append("")

    return "\n".join(lines)


def generate_change_analysis_report(model: ChangeAnalysisModel) -> ChangeAnalysisReportResponse:
    """Generate authoritative structured and Markdown report from ChangeAnalysisModel."""
    meta = model.model_metadata or {}
    pr_num = meta.get("pr_number")
    pr_title = meta.get("pr_title")

    # Extract deltas from diff_result if available
    raw_diff = meta.get("diff_result")
    # A diff is authoritative only for the exact immutable revisions of this
    # analysis. Never attribute another pair's contract deltas to this report.
    ast_recorded = (
        isinstance(raw_diff, dict)
        and raw_diff.get("base_commit_sha") == model.base_commit_sha
        and raw_diff.get("head_commit_sha") == model.head_commit_sha
    )
    diff_data = raw_diff if ast_recorded else {}
    raw_blast = meta.get("blast_radius")
    graph_recorded = isinstance(raw_blast, dict) and bool(raw_blast)
    route_deltas = [RouteContractDelta(**r) for r in diff_data.get("route_deltas", [])]
    schema_deltas = [SchemaModelDelta(**s) for s in diff_data.get("schema_deltas", [])]
    dependency_deltas = [DependencyDelta(**d) for d in diff_data.get("dependency_deltas", [])]
    config_deltas = [ConfigDelta(**c) for c in diff_data.get("config_deltas", [])]

    # Map impacts
    impacts: List[ChangeImpact] = [
        ChangeImpact(
            id=UUID(imp.id),
            analysis_id=UUID(imp.analysis_id),
            impact_type=ChangeImpactType(imp.impact_type),
            severity=Severity(imp.severity),
            title=imp.title,
            description=imp.description,
            source_file=imp.source_file,
            source_symbol=imp.source_symbol,
            affected_file=imp.affected_file,
            affected_symbol=imp.affected_symbol,
            evidence_payload=imp.evidence_payload or {},
            confidence=imp.confidence,
            verification_status=ImpactVerificationStatus(imp.verification_status),
            created_at=imp.created_at or datetime.now(timezone.utc),
        )
        for imp in (model.impacts or [])
    ]

    # Map review findings and extract model metadata null-safely
    raw_review = meta.get("review_report")
    review_data = raw_review if isinstance(raw_review, dict) else {}
    raw_meta = review_data.get("model_metadata")
    if isinstance(raw_meta, dict):
        extra = raw_meta.get("extra_metadata") if isinstance(raw_meta.get("extra_metadata"), dict) else {}
        is_llm_fallback = bool(raw_meta.get("is_fallback") or extra.get("is_fallback", False))
        llm_status = str(raw_meta.get("execution_status") or extra.get("execution_status") or ("SUCCESS" if raw_review and not is_llm_fallback else "UNAVAILABLE")).upper()
    else:
        is_llm_fallback = False
        llm_status = "SUCCESS" if raw_review else "UNAVAILABLE"

    review_findings: List[ChangeReviewFinding] = []
    raw_findings = review_data.get("findings", [])
    invalid_review_count = 0
    if not isinstance(raw_findings, list):
        raw_findings = []
        invalid_review_count += 1
    for rf in raw_findings:
        try:
            if not isinstance(rf, dict):
                raise ValueError("Malformed review finding")
            parsed = ChangeReviewFinding(**rf)
            # Rejected candidates are diagnostics, never report findings.
            # Supported inferences remain explicitly labeled by their verdict.
            if parsed.verdict.value != "REJECTED":
                review_findings.append(parsed)
        except (TypeError, ValueError) as exc:
            invalid_review_count += 1
            # ValidationError includes untrusted source text. Log only type.
            logger.warning(
                "Failed to deserialize review finding (%s).", type(exc).__name__
            )

    # Count contract breaks and security impacts
    contract_breaks = sum(
        1 for imp in impacts if imp.impact_type in (ChangeImpactType.API_CONTRACT_CHANGE, ChangeImpactType.SCHEMA_CHANGE)
    )
    security_impacts = sum(
        1 for imp in impacts if imp.impact_type == ChangeImpactType.SECURITY_SENSITIVE_CHANGE
    )

    duration_sec: Optional[float] = None
    if model.created_at and model.completed_at:
        duration_sec = (model.completed_at - model.created_at).total_seconds()

    risk_enum = ChangeRiskLevel(model.risk_level) if model.risk_level else None
    risk_expl = _compute_risk_explanation(
        risk_level=risk_enum,
        contract_breaks=contract_breaks,
        security_impacts=security_impacts,
        total_impacts=len(impacts),
        confirmed_findings=len(review_findings),
    )

    markdown_content = _render_markdown_report(
        analysis=model,
        route_deltas=route_deltas,
        schema_deltas=schema_deltas,
        dependency_deltas=dependency_deltas,
        config_deltas=config_deltas,
        impacts=impacts,
        review_findings=review_findings,
        risk_explanation=risk_expl,
        duration_seconds=duration_sec,
        llm_status=llm_status,
        is_llm_fallback=is_llm_fallback,
        has_review_data=bool(raw_review),
        invalid_review_count=invalid_review_count,
        ast_recorded=ast_recorded,
        graph_recorded=graph_recorded,
    )

    tool_avail = {
        "tree_sitter_ast": ast_recorded,
        "repository_graph": graph_recorded,
        "semgrep_scanner": False,
        "osv_scanner": False,
        "llm_reviewer": bool(raw_review and not is_llm_fallback and llm_status == "SUCCESS"),
        "runtime_sandbox": False,
    }

    limitations = [
        "Static structural and graph-based change intelligence only; no repository code was executed in a sandbox.",
        "Repository test suites and CI pipelines were NOT executed.",
        "Dynamic reflection and runtime duck-typing cannot be fully determined through static analysis alone.",
    ]
    if not ast_recorded:
        limitations.append(
            "Structural diff evidence is missing or does not match the requested immutable revisions; contract delta counts are unavailable, not verified zero."
        )
    if invalid_review_count:
        limitations.append(
            f"{invalid_review_count} malformed persisted AI review record(s) were omitted; review coverage is incomplete."
        )

    return ChangeAnalysisReportResponse(
        analysis_id=UUID(model.id),
        repository_url=model.repository_url,
        repository_owner=model.repository_owner,
        repository_name=model.repository_name,
        base_commit_sha=model.base_commit_sha,
        head_commit_sha=model.head_commit_sha,
        base_ref=model.base_ref,
        head_ref=model.head_ref,
        pr_number=pr_num,
        pr_title=pr_title,
        status=ChangeAnalysisStatus(model.status),
        risk_level=risk_enum,
        risk_explanation=risk_expl,
        created_at=model.created_at or datetime.now(timezone.utc),
        completed_at=model.completed_at,
        duration_seconds=duration_sec,
        files_changed_count=model.changed_files_count or 0,
        symbols_changed_count=model.changed_symbols_count or 0,
        impacted_symbols_count=model.impacted_symbols_count or 0,

        contract_breaks_count=contract_breaks,
        security_impacts_count=security_impacts,
        route_deltas=route_deltas,
        schema_deltas=schema_deltas,
        dependency_deltas=dependency_deltas,
        config_deltas=config_deltas,
        impacts=impacts,
        review_findings=review_findings,
        tool_availability=tool_avail,
        limitations=limitations,
        markdown_report=markdown_content,
    )


def generate_change_analysis_telemetry(model: ChangeAnalysisModel) -> ChangeAnalysisTelemetry:
    """Aggregate authoritative operational telemetry for ChangeAnalysisModel without secrets."""
    meta = model.model_metadata or {}
    review_data = meta.get("review_report") or {}
    blast_data = meta.get("blast_radius") or {}
    model_meta = review_data.get("model_metadata") or {}

    duration_ms: Optional[int] = None
    if model.created_at and model.completed_at:
        duration_ms = int((model.completed_at - model.created_at).total_seconds() * 1000)

    impacts = model.impacts or []
    impacts_by_type: Dict[str, int] = {}
    impacts_by_severity: Dict[str, int] = {}
    impacts_by_verification_status: Dict[str, int] = {}

    direct_count = 0
    transitive_count = 0
    contract_breaks = 0
    security_impacts = 0

    for imp in impacts:
        t = imp.impact_type
        s = imp.severity
        v = imp.verification_status

        impacts_by_type[t] = impacts_by_type.get(t, 0) + 1
        impacts_by_severity[s] = impacts_by_severity.get(s, 0) + 1
        impacts_by_verification_status[v] = impacts_by_verification_status.get(v, 0) + 1

        if imp.impact_type in ("CALLER_IMPACT", "SYMBOL_CHANGE"):
            direct_count += 1
        else:
            transitive_count += 1

        if imp.impact_type in ("API_CONTRACT_CHANGE", "SCHEMA_CHANGE"):
            contract_breaks += 1
        if imp.impact_type == "SECURITY_SENSITIVE_CHANGE":
            security_impacts += 1


    return ChangeAnalysisTelemetry(
        analysis_id=model.id,
        repository_url=model.repository_url,
        base_commit_sha=model.base_commit_sha,
        head_commit_sha=model.head_commit_sha,
        status=model.status,
        risk_level=model.risk_level,
        duration_ms=duration_ms,
        files_changed=model.changed_files_count or 0,
        symbols_changed=model.changed_symbols_count or 0,
        impacted_symbols=model.impacted_symbols_count or 0,

        direct_impacts=direct_count,
        transitive_impacts=transitive_count,
        contract_breaks=contract_breaks,
        security_impacts=security_impacts,
        impacts_by_type=impacts_by_type,
        impacts_by_severity=impacts_by_severity,
        impacts_by_verification_status=impacts_by_verification_status,
        review_findings_count=review_data.get("total_findings", 0),
        confirmed_findings=review_data.get("confirmed_count", 0),
        supported_inferences=review_data.get("supported_inference_count", 0),
        rejected_findings=review_data.get("rejected_count", 0),
        prompt_tokens=model_meta.get("prompt_tokens"),
        completion_tokens=model_meta.get("completion_tokens"),
        total_tokens=model_meta.get("total_tokens"),
        is_truncated=bool(blast_data.get("is_truncated", False)),
        truncation_reason=blast_data.get("truncation_reason"),
        review_publication_status=model.review_publication.status if getattr(model, "review_publication", None) else "NOT_REQUESTED",
        review_publication_inline_comments_count=len(model.review_publication.inline_comments_payload or []) if getattr(model, "review_publication", None) and model.review_publication.inline_comments_payload else 0,
        review_publication_reconciliation_occurred=bool(model.review_publication.reconciliation_occurred) if getattr(model, "review_publication", None) else False,
        review_publication_published=(model.review_publication.status == "PUBLISHED") if getattr(model, "review_publication", None) else False,
        review_publication_block_reason=model.review_publication.failure_code if getattr(model, "review_publication", None) else None,
    )
