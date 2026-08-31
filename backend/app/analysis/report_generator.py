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

logger = logging.getLogger(__name__)


def _compute_risk_explanation(
    risk_level: Optional[ChangeRiskLevel],
    contract_breaks: int,
    security_impacts: int,
    total_impacts: int,
    confirmed_findings: int,
) -> str:
    """Generate deterministic explanation for the assigned risk level."""
    if risk_level == ChangeRiskLevel.CRITICAL:
        return (
            f"CRITICAL risk assessed: {contract_breaks} breaking contract change(s) or "
            f"{security_impacts} security-sensitive impact(s) identified with direct caller blast radius."
        )
    elif risk_level == ChangeRiskLevel.HIGH:
        return (
            f"HIGH risk assessed: {total_impacts} impacted symbol(s) detected across caller dependencies "
            f"or API contracts requiring immediate validation."
        )
    elif risk_level == ChangeRiskLevel.MEDIUM:
        return (
            f"MEDIUM risk assessed: {total_impacts} affected downstream caller(s) or signature changes "
            f"confined to internal repository symbols."
        )
    else:
        return (
            f"LOW risk assessed: Structural changes appear isolated with no breaking contract deltas "
            f"or high-severity blast radius."
        )


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
    lines.append(f"> **Status**: `{analysis.status}` | **Risk Rating**: `{analysis.risk_level or 'LOW'}`  ")
    lines.append("")

    # 1. Provenance
    lines.append("## 📌 Provenance & Revisions")
    lines.append("")
    lines.append("| Property | Value |")
    lines.append("| :--- | :--- |")
    lines.append(f"| **Repository** | [{analysis.repository_url}]({analysis.repository_url}) |")
    if pr_num:
        lines.append(f"| **Pull Request** | [#{pr_num} {pr_title or ''}]({analysis.repository_url}/pull/{pr_num}) |")
    lines.append(f"| **Base Revision** | `{analysis.base_commit_sha}` ({analysis.base_ref or 'base'}) |")
    lines.append(f"| **Head Revision** | `{analysis.head_commit_sha}` ({analysis.head_ref or 'head'}) |")
    lines.append(f"| **Created At** | `{analysis.created_at.isoformat() if analysis.created_at else 'N/A'}` |")
    lines.append(f"| **Completed At** | `{analysis.completed_at.isoformat() if analysis.completed_at else 'N/A'}` |")
    if duration_seconds is not None:
        lines.append(f"| **Execution Duration** | `{duration_seconds:.2f}s` |")
    lines.append("")

    # 2. Executive Summary
    lines.append("## 📊 Change Metrics & Blast Radius Overview")
    lines.append("")
    lines.append(f"**Risk Assessment**: `{analysis.risk_level or 'LOW'}`  ")
    lines.append(f"*{risk_explanation}*")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("| :--- | :--- |")
    lines.append(f"| 📁 **Files Changed** | `{analysis.changed_files_count}` |")
    lines.append(f"| 🧩 **Symbols Changed** | `{analysis.changed_symbols_count}` |")
    lines.append(f"| 💥 **Impacted Symbols / Callers** | `{analysis.impacted_symbols_count}` |")
    lines.append(f"| ⚡ **API Route Contract Deltas** | `{len(route_deltas)}` |")
    lines.append(f"| 📐 **Schema & Model Deltas** | `{len(schema_deltas)}` |")
    lines.append(f"| 📦 **Dependency Deltas** | `{len(dependency_deltas)}` |")
    lines.append(f"| ⚙️ **Config Deltas** | `{len(config_deltas)}` |")
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
                lines.append(f"| `{r.file_path}` | `{r.route_name}` | {m} | `{r.change_type}` | {r.details} |")
            lines.append("")

        if schema_deltas:
            lines.append("### 📐 Data Schema & Model Deltas")
            lines.append("| File | Model | Field | Type Change | Details |")
            lines.append("| :--- | :--- | :--- | :--- | :--- |")
            for s in schema_deltas:
                t = f"`{s.base_type or '-'}` → `{s.head_type or '-'}`"
                lines.append(f"| `{s.file_path}` | `{s.model_name}` | `{s.field_name}` | {t} | {s.details} |")
            lines.append("")

        if dependency_deltas:
            lines.append("### 📦 Package Dependency Deltas")
            lines.append("| Manifest | Package | Base Version | Head Version | Change |")
            lines.append("| :--- | :--- | :--- | :--- | :--- |")
            for d in dependency_deltas:
                lines.append(f"| `{d.manifest_file}` | **{d.package_name}** | `{d.base_version or '-'}` | `{d.head_version or '-'}` | `{d.change_type}` |")
            lines.append("")

        if config_deltas:
            lines.append("### ⚙️ Configuration & Environment Deltas")
            lines.append("| Config File | Key | Change Type |")
            lines.append("| :--- | :--- | :--- |")
            for c in config_deltas:
                lines.append(f"| `{c.file_path}` | `{c.key}` | `{c.change_type}` |")
            lines.append("")

    # 4. Blast Radius Impacts
    if impacts:
        lines.append("## 💥 Impact Explorer & Blast Radius")
        lines.append("")
        lines.append("| Severity | Type | Source Symbol / File | Affected Symbol / File | Status | Description |")
        lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
        for imp in impacts:
            src = f"`{imp.source_file}`" + (f" (`{imp.source_symbol}`)" if imp.source_symbol else "")
            aff = f"`{imp.affected_file}`" + (f" (`{imp.affected_symbol}`)" if imp.affected_symbol else "")
            lines.append(
                f"| **{imp.severity.value}** | `{imp.impact_type.value}` | {src} | {aff} | `{imp.verification_status.value}` | {imp.title} |"
            )
        lines.append("")

    # 5. Verified AI Review Findings
    if review_findings:
        lines.append("## 🤖 Grounded AI Change Review Findings")
        lines.append("")
        for f in review_findings:
            lines.append(f"### ⚠️ [{f.severity.value}] {f.title}")
            lines.append(f"- **Risk Category**: `{f.risk_type}`")
            lines.append(f"- **Verdict**: `{f.verdict.value}` (Confidence: `{f.confidence:.0%}`)")
            lines.append(f"- **Reasoning**: {f.reasoning_summary}")
            if f.affected_files:
                lines.append(f"- **Affected Files**: {', '.join(f'`{p}`' for p in f.affected_files)}")
            if f.evidence_refs:
                lines.append(f"- **Evidence References**: {', '.join(f'`{r}`' for r in f.evidence_refs)}")
            if f.assumptions:
                lines.append(f"- **Disclosed Assumptions**: {'; '.join(f.assumptions)}")
            lines.append("")

    # 6. Tool Availability & Epistemic Limitations
    lines.append("## 🛡️ Tool Availability & Analysis Constraints")
    lines.append("")
    lines.append("| Engine / Capability | Availability | Mode |")
    lines.append("| :--- | :--- | :--- |")
    lines.append("| **Tree-sitter AST Parser** | ✅ Available | Deterministic Structural Facts |")
    lines.append("| **Repository Graph Traversal** | ✅ Available | Bounded Blast Radius Traversal |")
    lines.append("| **Static Security Scanners** | ℹ️ Not Executed | Dedicated Scan Phase Only |")
    lines.append("| **Change Review Agent** | ✅ Available | Bounded Context Reasoning |")
    lines.append("| **Runtime Sandbox / Dynamic Testing** | ❌ Not Executed | Static Evidence Only |")
    lines.append("")
    lines.append("### Limitations & Grounding Constraints")
    lines.append("- **Static Analysis Boundary**: Analysis operates purely on static source AST and repository dependency graphs. No repository code was executed in a sandbox.")
    lines.append("- **No Test Execution**: Repository test suites, integration tests, and CI/CD pipelines were **NOT executed**.")
    lines.append("- **Dynamic Dispatch**: Dynamic reflection, runtime monkeypatching, and duck-typed method invocation cannot be completely proven via static traversal.")
    lines.append("")

    return "\n".join(lines)


def generate_change_analysis_report(model: ChangeAnalysisModel) -> ChangeAnalysisReportResponse:
    """Generate authoritative structured and Markdown report from ChangeAnalysisModel."""
    meta = model.model_metadata or {}
    pr_num = meta.get("pr_number")
    pr_title = meta.get("pr_title")

    # Extract deltas from diff_result if available
    diff_data = meta.get("diff_result") or {}
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

    # Map review findings
    review_data = meta.get("review_report") or {}
    review_findings: List[ChangeReviewFinding] = []
    for rf in review_data.get("findings", []):
        try:
            review_findings.append(ChangeReviewFinding(**rf))
        except Exception as exc:
            logger.warning(f"Failed to deserialize review finding in report: {str(exc)}")

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
    )

    is_llm_fallback = bool(meta.get("review_report", {}).get("model_metadata", {}).get("is_fallback", False))
    tool_avail = {
        "tree_sitter_ast": True,
        "repository_graph": True,
        "semgrep_scanner": False,
        "osv_scanner": False,
        "llm_reviewer": bool(meta.get("review_report") and not is_llm_fallback),
        "runtime_sandbox": False,
    }

    limitations = [
        "Static structural and graph-based change intelligence only; no repository code was executed in a sandbox.",
        "Repository test suites and CI pipelines were NOT executed.",
        "Dynamic reflection and runtime duck-typing cannot be fully determined through static analysis alone.",
    ]

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
    )
