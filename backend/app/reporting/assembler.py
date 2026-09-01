"""Tenant-scoped translation from canonical scan records to ReportDocument."""

from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from sqlalchemy import case, func
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.artifacts.service import get_artifact_store
from app.models.artifact import ArtifactModel, ArtifactTombstoneModel
from app.models.finding import EvidenceModel, FindingModel
from app.models.patch import PatchModel
from app.models.scan import ScanModel
from app.reporting.prioritizer import build_roadmap, prioritize
from app.reporting.schemas import (
    AnalyzerCoverage,
    REPORT_SCHEMA_VERSION,
    ReportAppendix,
    ReportArchitectureSection,
    ReportContractSection,
    ReportCoverage,
    ReportDocument,
    ReportEvidenceReference,
    ReportExecutiveSummary,
    ReportFinding,
    ReportFindingSection,
    ReportMetadata,
    ReportRemediationStep,
    ReportRiskSummary,
    ReportScope,
    ReportSecuritySection,
)
from app.reporting.versions import RENDERER_VERSION
from app.security.redaction import redact_secrets


_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
_CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_CWE_PATTERN = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)
_SECURITY_TERMS = {
    "security", "vulnerability", "dependency", "secret", "authentication",
    "authorization", "trust-boundary", "tenant-isolation", "injection",
}
_CONTRACT_TERMS = {"contract", "integration", "api-contract", "schema-mismatch"}
_ARCHITECTURE_TERMS = {"architecture", "code-quality", "correctness", "maintainability"}


class ReportAssemblyError(RuntimeError):
    pass


def _safe_text(value: Any, limit: int) -> str:
    text = redact_secrets(str(value or "")).replace("\x00", "[U+0000]")
    return text if len(text) <= limit else text[:limit] + "… [truncated]"


def _safe_string_list(value: Any, *, item_limit: int = 256, list_limit: int = 100) -> List[str]:
    if not isinstance(value, (list, tuple, set)):
        return []
    return [_safe_text(item, item_limit) for item in list(value)[:list_limit]]


def _safe_int(value: Any) -> Optional[int]:
    try:
        result = int(value)
    except (TypeError, ValueError):
        return None
    return max(0, result)


def _extract_reference(pattern: re.Pattern[str], values: Iterable[Optional[str]]) -> Optional[str]:
    for value in values:
        if value:
            match = pattern.search(str(value))
            if match:
                return match.group(0).upper()
    return None


def _category_tokens(finding: FindingModel) -> set[str]:
    values = [finding.category, finding.rule_id, finding.detector_kind, finding.source_tool, finding.title]
    joined = " ".join(str(value or "").lower() for value in values)
    return {term for term in (_SECURITY_TERMS | _CONTRACT_TERMS | _ARCHITECTURE_TERMS) if term in joined}


def _evidence_strength(evidence: List[ReportEvidenceReference], verdict: Optional[str], analyzer: Optional[str]) -> str:
    exact = sum(1 for item in evidence if item.start_line is not None and item.end_line is not None)
    if evidence and exact and analyzer and verdict == "CONFIRMED":
        return "STRONG"
    if evidence and (exact or any(item.excerpt for item in evidence)):
        return "MODERATE"
    if evidence:
        return "LIMITED"
    return "NONE"


def _coverage(meta: Dict[str, Any], scope: ReportScope) -> Tuple[ReportCoverage, List[str]]:
    raw = meta.get("scanner_coverage") or meta.get("scanners") or []
    analyzers: List[AnalyzerCoverage] = []
    limitations: List[str] = []
    if isinstance(raw, list):
        for item in raw[:100]:
            if not isinstance(item, dict):
                continue
            analyzer = _safe_text(item.get("tool") or item.get("scanner") or "unknown", 128)
            status = _safe_text(item.get("status") or "UNKNOWN", 32).upper()
            limitation_value = item.get("failure_reason") or item.get("error_category")
            limitation = _safe_text(limitation_value, 512) if limitation_value else None
            analyzers.append(
                AnalyzerCoverage(
                    analyzer=analyzer,
                    status=status,
                    findings_count=_safe_int(item.get("findings_count")) or 0,
                    execution_time_ms=_safe_int(item.get("execution_time_ms")),
                    limitation=limitation,
                )
            )
            if status not in {"COMPLETED", "AVAILABLE"}:
                limitations.append(f"{analyzer}: {status}" + (f" — {limitation}" if limitation else ""))

    if scope.truncated:
        status = "PARTIAL"
    elif analyzers and any(item.status not in {"COMPLETED", "AVAILABLE"} for item in analyzers):
        status = "DEGRADED"
    elif analyzers:
        status = "FULL"
    else:
        status = "UNKNOWN"
        limitations.append("Analyzer coverage metadata was not recorded.")

    distinction = {
        "FULL": "No findings means no findings were recorded within the fully recorded analyzer scope.",
        "PARTIAL": "No findings must not be interpreted as clean: the analysis scope was truncated.",
        "DEGRADED": "No findings must not be interpreted as clean: at least one analyzer was unavailable or degraded.",
        "UNKNOWN": "No findings must not be interpreted as clean: analyzer coverage was not recorded.",
    }[status]
    return ReportCoverage(status=status, analyzers=analyzers, distinction=distinction), limitations


def _canonical_coverage_payload(
    db: Session,
    *,
    tenant_id: str,
    artifact_id: str | None,
) -> dict[str, Any] | None:
    if not artifact_id:
        return None
    model = db.query(ArtifactModel).filter(
        ArtifactModel.id == artifact_id,
        ArtifactModel.tenant_id == tenant_id,
        ArtifactModel.artifact_type == "COVERAGE",
    ).first()
    if model is None:
        return None
    tombstoned = db.query(ArtifactTombstoneModel.id).filter(
        ArtifactTombstoneModel.artifact_id == model.id,
        ArtifactTombstoneModel.tenant_id == tenant_id,
    ).first()
    if tombstoned is not None:
        return None
    try:
        store = get_artifact_store()
        if not store.verify_digest(model.payload_locator, model.content_digest):
            return None
        with store.get(model.payload_locator) as stream:
            raw = stream.read(min(model.payload_size_bytes + 1, 1_048_577))
        if len(raw) > 1_048_576:
            return None
        payload = json.loads(raw.decode("utf-8"))
        return payload if isinstance(payload, dict) else None
    except Exception:
        return None


def _finding_provenance(metadata: dict[str, Any]) -> dict[str, Any]:
    direct = metadata.get("provenance")
    if isinstance(direct, dict):
        return direct
    extra = metadata.get("extra_metadata")
    if isinstance(extra, dict) and isinstance(extra.get("provenance"), dict):
        return extra["provenance"]
    return {}


class ReportAssembler:
    """Build a bounded immutable snapshot through an explicit tenant boundary."""

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()

    def assemble(
        self,
        db: Session,
        *,
        scan_id: str,
        tenant_id: str,
        report_id: str,
        generated_at: Optional[datetime] = None,
    ) -> ReportDocument:
        scan = (
            db.query(ScanModel)
            .filter(ScanModel.id == str(scan_id), ScanModel.owner_user_id == str(tenant_id))
            .first()
        )
        if scan is None:
            raise ReportAssemblyError("Owned scan was not found.")
        if scan.status != "COMPLETED":
            raise ReportAssemblyError("Reports can only be generated for completed scans.")

        maximum = self.settings.REPORT_MAX_FINDINGS
        total_finding_count = int(
            db.query(func.count(FindingModel.id)).filter(FindingModel.scan_id == scan.id).scalar() or 0
        )
        severity_order = case(
            (FindingModel.severity == "CRITICAL", 0),
            (FindingModel.severity == "HIGH", 1),
            (FindingModel.severity == "MEDIUM", 2),
            (FindingModel.severity == "LOW", 3),
            else_=4,
        )
        verdict_order = case(
            (FindingModel.verification_verdict == "CONFIRMED", 0),
            (FindingModel.verification_verdict == "POSSIBLE", 1),
            (FindingModel.verification_verdict.is_(None), 2),
            else_=3,
        )
        finding_rows = (
            db.query(FindingModel)
            .filter(FindingModel.scan_id == scan.id)
            .order_by(severity_order.asc(), verdict_order.asc(), FindingModel.id.asc())
            .limit(maximum)
            .all()
        )
        omitted_findings = max(0, total_finding_count - len(finding_rows))
        finding_ids = [str(row.id) for row in finding_rows]
        valid_finding_ids = set(finding_ids)

        evidence_cap = self.settings.REPORT_MAX_EVIDENCE_REFERENCES
        evidence_rows = []
        total_evidence_count = 0
        if finding_ids:
            total_evidence_count = int(
                db.query(func.count(EvidenceModel.id))
                .filter(EvidenceModel.finding_id.in_(finding_ids))
                .scalar()
                or 0
            )
            ranked_evidence = (
                db.query(
                    EvidenceModel.id.label("evidence_id"),
                    func.row_number().over(
                        partition_by=EvidenceModel.finding_id,
                        order_by=EvidenceModel.id.asc(),
                    ).label("evidence_rank"),
                )
                .filter(EvidenceModel.finding_id.in_(finding_ids))
                .subquery()
            )
            candidates = (
                db.query(EvidenceModel, ranked_evidence.c.evidence_rank)
                .join(ranked_evidence, EvidenceModel.id == ranked_evidence.c.evidence_id)
                .filter(ranked_evidence.c.evidence_rank <= self.settings.REPORT_MAX_EVIDENCE_PER_FINDING)
                .order_by(ranked_evidence.c.evidence_rank.asc(), EvidenceModel.finding_id.asc(), EvidenceModel.id.asc())
                .all()
            )
            candidates_by_finding: Dict[str, List[EvidenceModel]] = defaultdict(list)
            for evidence, _rank in candidates:
                candidates_by_finding[str(evidence.finding_id)].append(evidence)
            for rank in range(self.settings.REPORT_MAX_EVIDENCE_PER_FINDING):
                for finding_id in finding_ids:
                    bucket = candidates_by_finding.get(finding_id, [])
                    if rank < len(bucket):
                        evidence_rows.append(bucket[rank])
                        if len(evidence_rows) >= evidence_cap:
                            break
                if len(evidence_rows) >= evidence_cap:
                    break
        omitted_evidence = max(0, total_evidence_count - len(evidence_rows))
        evidence_by_finding: Dict[str, List[EvidenceModel]] = defaultdict(list)
        for row in evidence_rows:
            evidence_by_finding[str(row.finding_id)].append(row)

        patches_by_finding: Dict[str, List[PatchModel]] = defaultdict(list)
        if finding_ids:
            patch_rows = (
                db.query(PatchModel)
                .filter(PatchModel.finding_id.in_(finding_ids))
                .order_by(PatchModel.finding_id.asc(), PatchModel.revision_number.desc(), PatchModel.id.asc())
                .limit(maximum * 4)
                .all()
            )
            for row in patch_rows:
                if len(patches_by_finding[str(row.finding_id)]) < 4:
                    patches_by_finding[str(row.finding_id)].append(row)

        meta = dict(scan.model_metadata) if isinstance(scan.model_metadata, dict) else {}
        canonical_coverage = _canonical_coverage_payload(
            db,
            tenant_id=tenant_id,
            artifact_id=str(meta.get("coverage_artifact_id")) if meta.get("coverage_artifact_id") else None,
        )
        if canonical_coverage is not None and isinstance(canonical_coverage.get("scanners"), list):
            # Canonical immutable coverage supersedes compatibility metadata.
            meta["scanner_coverage"] = canonical_coverage["scanners"]
            meta["analysis_coverage"] = canonical_coverage.get("coverage")
        scope_meta = meta.get("analysis_scope") or meta.get("scope") or {}
        scope_meta = scope_meta if isinstance(scope_meta, dict) else {}
        unsupported = _safe_string_list(meta.get("unsupported_areas") or scope_meta.get("unsupported_areas"))
        limits = _safe_string_list(scope_meta.get("limits_encountered"))
        if scope_meta.get("reason"):
            limits.append(_safe_text(scope_meta.get("reason"), 512))
        languages_raw = meta.get("languages") if isinstance(meta.get("languages"), dict) else {}
        languages = {
            _safe_text(key, 64): _safe_int(value) or 0
            for key, value in list(languages_raw.items())[:100]
        }
        scope = ReportScope(
            files_discovered=_safe_int(scope_meta.get("total_observed_files")),
            files_analyzed=_safe_int(scope_meta.get("files_processed")),
            source_bytes_analyzed=_safe_int(scope_meta.get("source_bytes_processed")),
            source_bytes_discovered=_safe_int(scope_meta.get("total_observed_bytes")),
            languages=languages,
            unsupported_areas=unsupported,
            truncated=bool(scope_meta.get("truncated", False)),
            truncation_reason=_safe_text(scope_meta.get("reason"), 512) if scope_meta.get("reason") else None,
            limits_encountered=limits,
        )
        coverage, coverage_limitations = _coverage(meta, scope)

        appendix_evidence: List[ReportEvidenceReference] = []
        report_findings: List[ReportFinding] = []
        for row in finding_rows:
            row_meta = row.model_metadata if isinstance(row.model_metadata, dict) else {}
            provenance = _finding_provenance(row_meta)
            symbol_value = row_meta.get("symbol") or row_meta.get("symbol_name")
            symbol = _safe_text(symbol_value, 256) if symbol_value else None
            refs: List[ReportEvidenceReference] = []
            for evidence in evidence_by_finding.get(str(row.id), []):
                raw_excerpt = _safe_text(evidence.code_snippet, self.settings.REPORT_MAX_EXCERPT_CHARS) if evidence.code_snippet else None
                excerpt_truncated = bool(evidence.code_snippet and raw_excerpt and raw_excerpt.endswith("… [truncated]"))
                reference = ReportEvidenceReference(
                    evidence_id=str(evidence.id),
                    finding_id=str(row.id),
                    file_path=_safe_text(evidence.file_path, 512),
                    symbol=symbol,
                    start_line=evidence.start_line,
                    end_line=evidence.end_line,
                    excerpt=raw_excerpt,
                    context=_safe_text(evidence.context_notes, 2048) if evidence.context_notes else None,
                    analyzer=_safe_text(row.source_tool, 128) if row.source_tool else None,
                    artifact_id=(
                        _safe_text(
                            (provenance.get("evidence_artifact_by_id") or {}).get(str(evidence.id)),
                            128,
                        )
                        if isinstance(provenance.get("evidence_artifact_by_id"), dict)
                        and (provenance.get("evidence_artifact_by_id") or {}).get(str(evidence.id))
                        else None
                    ),
                    excerpt_truncated=excerpt_truncated,
                )
                refs.append(reference)
                appendix_evidence.append(reference)

            patches = patches_by_finding.get(str(row.id), [])
            verified_patches = [
                patch for patch in patches
                if patch.status in {"VERIFIED", "APPROVED"} or patch.machine_verdict == "PASSED"
            ]
            if verified_patches:
                availability = "VERIFIED_PATCH"
                preferred_patch = verified_patches[0]
            elif patches:
                availability = "CANDIDATE_PATCH"
                preferred_patch = patches[0]
            elif row.mitigation_guidance:
                availability = "GUIDANCE"
                preferred_patch = None
            else:
                availability = "NONE"
                preferred_patch = None

            recommendation_source = (
                preferred_patch.explanation if preferred_patch is not None
                else row.mitigation_guidance
            )
            recommendation = _safe_text(
                recommendation_source or "No remediation metadata was produced; review the cited evidence before changing code.",
                4096,
            )
            validation_steps: List[str] = []
            if preferred_patch is not None:
                validation_steps.extend(_safe_string_list(preferred_patch.generated_tests_or_test_plan, item_limit=512, list_limit=10))
            analyzer_label = _safe_text(row.source_tool or "originating analyzer", 128)
            rule_label = _safe_text(row.rule_id or row.detector_id or "recorded rule", 256)
            if not validation_steps:
                validation_steps = [
                    f"Re-run {analyzer_label} for {rule_label}.",
                    "Confirm the finding no longer appears at the cited source range and review affected behavior.",
                ]

            tokens = _category_tokens(row)
            security_impact = bool(tokens & _SECURITY_TERMS)
            affected_files = sorted({reference.file_path for reference in refs})
            blast_radius = len(affected_files)
            recorded_blast = _safe_int(row_meta.get("blast_radius"))
            if recorded_blast is not None:
                blast_radius = max(blast_radius, recorded_blast)
            dependencies = [
                dependency for dependency in _safe_string_list(row_meta.get("dependency_ids"), item_limit=36)
                if dependency in valid_finding_ids and dependency != str(row.id)
            ]
            impact_value = row_meta.get("potential_impact") or row_meta.get("impact")
            potential_impact = _safe_text(
                impact_value or "The analysis did not establish a separate impact statement.",
                4096,
            )
            structured_cve = row_meta.get("cve") or row_meta.get("advisory_id")
            structured_cwe = row_meta.get("cwe")
            cve = _extract_reference(_CVE_PATTERN, [row.rule_id, row.detector_id, structured_cve])
            cwe = _extract_reference(_CWE_PATTERN, [row.rule_id, row.detector_id, structured_cwe])
            report_findings.append(
                ReportFinding(
                    finding_id=str(row.id),
                    title=_safe_text(row.title, 512),
                    severity=_safe_text(row.severity, 32).upper(),
                    lifecycle_status=_safe_text(row.status, 32).upper(),
                    verification_verdict=_safe_text(row.verification_verdict, 32).upper() if row.verification_verdict else None,
                    category=_safe_text(row.category or "general", 128),
                    rule_id=_safe_text(row.rule_id, 256) if row.rule_id else None,
                    detector_id=_safe_text(row.detector_id, 512) if row.detector_id else None,
                    analyzer=_safe_text(row.source_tool, 128) if row.source_tool else None,
                    affected_files=affected_files,
                    symbol=symbol,
                    technical_explanation=_safe_text(row.description, 8192),
                    potential_impact=potential_impact,
                    evidence=refs,
                    evidence_strength=_evidence_strength(refs, row.verification_verdict, row.source_tool),
                    security_impact=security_impact,
                    blast_radius=blast_radius,
                    dependency_ids=sorted(set(dependencies)),
                    remediation=ReportRemediationStep(
                        recommendation=recommendation,
                        validation_steps=validation_steps,
                        availability=availability,
                        patch_ids=[str(patch.id) for patch in patches],
                    ),
                    cwe=cwe,
                    cve=cve,
                    package=_safe_text(row_meta.get("package"), 256) if row_meta.get("package") else None,
                    affected_version=_safe_text(row_meta.get("affected_version"), 128) if row_meta.get("affected_version") else None,
                )
            )

        priorities = prioritize(report_findings)
        priority_position = {item.finding_id: item.priority_rank for item in priorities}
        finding_row_by_id = {str(row.id): row for row in finding_rows}
        report_findings.sort(key=lambda finding: (priority_position.get(finding.finding_id, 10**9), finding.finding_id))
        detail_order = [item.finding_id for item in priorities]
        detail_order.extend(
            finding.finding_id for finding in report_findings if finding.finding_id not in priority_position
        )
        detailed_finding_ids = set(detail_order[: self.settings.REPORT_MAX_DETAILED_FINDINGS])
        omitted_finding_details = max(0, len(report_findings) - len(detailed_finding_ids))
        severity_counts = Counter(finding.severity for finding in report_findings)
        verdict_counts = Counter(finding.verification_verdict or "UNVERIFIED" for finding in report_findings)
        highest = next((severity for severity in _SEVERITIES if severity_counts.get(severity)), None)
        contract_ids = [
            finding.finding_id for finding in report_findings
            if _category_tokens(finding_row_by_id[finding.finding_id]) & _CONTRACT_TERMS
        ]
        architecture_ids = [
            finding.finding_id for finding in report_findings
            if _category_tokens(finding_row_by_id[finding.finding_id]) & _ARCHITECTURE_TERMS
        ]
        security_ids = [finding.finding_id for finding in report_findings if finding.security_impact]
        inconsistency_ids = [
            finding.finding_id for finding in report_findings
            if finding.security_impact and any(term in finding.category.lower() for term in ("auth", "config", "trust", "tenant", "secret"))
        ]

        limitations = list(dict.fromkeys(coverage_limitations + unsupported + limits))
        if omitted_findings:
            limitations.append(f"{omitted_findings} findings were omitted by the report budget of {maximum} findings.")
        if omitted_finding_details:
            limitations.append(
                f"{omitted_finding_details} selected findings are represented in summaries and priority tables "
                f"but omit full detail because the detail budget is {self.settings.REPORT_MAX_DETAILED_FINDINGS}."
            )
        if omitted_evidence:
            limitations.append(f"{omitted_evidence} evidence references were omitted by report evidence budgets.")
        possible_count = verdict_counts.get("POSSIBLE", 0) + verdict_counts.get("UNVERIFIED", 0)
        if possible_count:
            limitations.append(f"{possible_count} findings are possible or unverified and are not presented as confirmed truth.")
        if not limitations:
            limitations.append("No analysis limitations were recorded by the completed scan.")

        if report_findings:
            overall = f"{len(report_findings)} findings recorded; highest severity {highest or 'UNKNOWN'}."
        elif coverage.status == "FULL":
            overall = "No findings were recorded within the analyzed scope."
        else:
            overall = "No findings were recorded, but the analysis was not fully covered."

        generated = generated_at or datetime.now(timezone.utc)
        evidence_payload = [item.model_dump(mode="json") for item in appendix_evidence]
        evidence_digest = hashlib.sha256(
            json.dumps(evidence_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        policy_version = _safe_text(meta.get("analysis_policy_version") or meta.get("policy_version") or "unversioned", 128)
        tool_versions_raw = meta.get("tool_versions") if isinstance(meta.get("tool_versions"), dict) else {}
        tool_versions = {
            _safe_text(key, 128): _safe_text(value, 128)
            for key, value in list(tool_versions_raw.items())[:100]
        }
        lineage = _safe_string_list(meta.get("artifact_lineage"), item_limit=256, list_limit=500)
        for row in finding_rows:
            provenance = _finding_provenance(
                row.model_metadata if isinstance(row.model_metadata, dict) else {}
            )
            finding_artifact_id = provenance.get("finding_artifact_id")
            if finding_artifact_id:
                lineage.append(_safe_text(finding_artifact_id, 128))
        lineage = list(dict.fromkeys(lineage))[:500]
        coverage_artifact = meta.get("coverage_artifact_id")
        frameworks = _safe_string_list(meta.get("frameworks"), item_limit=128, list_limit=100)
        architecture_overview = meta.get("architecture_overview")
        document = ReportDocument(
            metadata=ReportMetadata(
                report_id=report_id,
                tenant_id=tenant_id,
                scan_id=str(scan.id),
                repository=_safe_text(scan.repository_url, 512),
                branch=_safe_text(meta.get("resolved_branch_or_ref") or scan.branch, 128) if (meta.get("resolved_branch_or_ref") or scan.branch) else None,
                commit_sha=_safe_text(scan.commit_hash, 64) if scan.commit_hash else None,
                analysis_timestamp=scan.completed_at,
                generated_at=generated,
                renderer_version=RENDERER_VERSION,
                analysis_policy_version=policy_version,
                application_version=self.settings.VERSION,
                coverage_artifact_id=_safe_text(coverage_artifact, 128) if coverage_artifact else None,
                finding_ids=[finding.finding_id for finding in report_findings],
                evidence_digest=evidence_digest,
                artifact_lineage=lineage,
                tool_versions=tool_versions,
            ),
            scope=scope,
            executive_summary=ReportExecutiveSummary(
                overall_result=overall,
                risk=ReportRiskSummary(
                    highest_severity=highest,
                    severity_counts={severity: severity_counts.get(severity, 0) for severity in _SEVERITIES},
                    verdict_counts=dict(sorted(verdict_counts.items())),
                    security_findings=len(security_ids),
                    contract_findings=len(contract_ids),
                ),
                major_risks=[item.title for item in priorities[:3]],
                important_limitations=limitations[:5],
            ),
            coverage=coverage,
            prioritized_fix_plan=priorities,
            finding_sections=[
                ReportFindingSection(
                    title=(severity if severity in {"CRITICAL", "HIGH"} else "MEDIUM / LOW") + " FINDINGS",
                    finding_ids=[finding.finding_id for finding in report_findings if (
                        finding.finding_id in detailed_finding_ids
                        and (
                            finding.severity == severity if severity in {"CRITICAL", "HIGH"}
                            else finding.severity in {"MEDIUM", "LOW", "INFO"}
                        )
                    )],
                )
                for severity in ("CRITICAL", "HIGH", "MEDIUM_LOW")
            ],
            findings=report_findings,
            security=ReportSecuritySection(
                vulnerability_finding_ids=security_ids,
                inconsistency_finding_ids=inconsistency_ids,
            ),
            contracts=ReportContractSection(finding_ids=contract_ids),
            architecture=ReportArchitectureSection(
                overview=_safe_text(architecture_overview, 4096) if architecture_overview else None,
                frameworks=frameworks,
                finding_ids=architecture_ids,
            ),
            remediation_roadmap=build_roadmap(priorities),
            appendix=ReportAppendix(
                evidence=appendix_evidence,
                omitted_finding_count=omitted_findings,
                omitted_evidence_count=omitted_evidence,
            ),
            limitations=limitations,
        )
        return document


def report_input_digest(document: ReportDocument) -> str:
    """Digest canonical report inputs while excluding output identity/time."""
    payload = document.model_dump(mode="json")
    payload["metadata"].pop("report_id", None)
    payload["metadata"].pop("tenant_id", None)
    payload["metadata"].pop("generated_at", None)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
