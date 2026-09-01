"""Canonical provenance projection for repository scans and verified findings."""

from __future__ import annotations

import hashlib
from typing import Any, Iterable

from sqlalchemy.orm import Session

from app.artifacts.registry import ArtifactProvenanceError
from app.artifacts.schemas import (
    ArtifactCoverage,
    ArtifactSensitivity,
    ArtifactType,
    CoverageStatus,
    LineageRelation,
    RetentionClass,
)
from app.artifacts.service import CanonicalArtifactService
from app.governance.policies import OperationalPolicyService
from app.models.execution import WorkItemModel
from app.models.scan import ScanModel


def repository_identity(repository_url: str) -> str:
    return hashlib.sha256(repository_url.encode("utf-8")).hexdigest()[:32]


def _tenant_id(scan: ScanModel) -> str:
    return str(scan.owner_user_id or "legacy-local")


def scan_policy_snapshot_id(db: Session, scan: ScanModel) -> str:
    work = db.query(WorkItemModel).filter(
        WorkItemModel.work_kind == "SCAN",
        WorkItemModel.resource_id == scan.id,
    ).order_by(WorkItemModel.created_at.desc()).first()
    if work is not None:
        return work.policy_snapshot_id
    policy = OperationalPolicyService.active(db, scan.owner_user_id)
    if policy is None:
        policy = OperationalPolicyService.ensure_active(db)
    return policy.id


def publish_repository_revision(
    db: Session,
    *,
    scan: ScanModel,
    commit_sha: str,
    resolved_branch: str | None,
    request_id: str | None = None,
) -> str:
    metadata = scan.model_metadata if isinstance(scan.model_metadata, dict) else {}
    existing = metadata.get("repository_revision_artifact_id")
    if existing:
        return str(existing)
    registration = CanonicalArtifactService(db).publish_json(
        tenant_id=_tenant_id(scan),
        repository_id=repository_identity(scan.repository_url),
        revision_id=commit_sha,
        artifact_type=ArtifactType.REPOSITORY_REVISION,
        payload={
            "repository_url_digest": hashlib.sha256(scan.repository_url.encode("utf-8")).hexdigest(),
            "commit_sha": commit_sha,
            "resolved_branch_or_ref": resolved_branch,
        },
        producer="repolens-snapshot-service",
        producer_version="1.0",
        policy_snapshot_id=scan_policy_snapshot_id(db, scan),
        coverage=ArtifactCoverage(
            status=CoverageStatus.SUCCESSFULLY_ANALYZED,
            discovered_count=1,
            analyzed_count=1,
        ),
        sensitivity=ArtifactSensitivity.INTERNAL,
        retention_class=RetentionClass.EPHEMERAL_REPOSITORY_SNAPSHOT,
        referrer=("SCAN", scan.id),
        actor_id=scan.owner_user_id,
        request_id=request_id,
    )
    return registration.artifact.artifact_id


def publish_analysis_artifacts(
    db: Session,
    *,
    scan: ScanModel,
    commit_sha: str,
    revision_artifact_id: str,
    scanner_summary: list[dict[str, Any]],
    manifest_summary: dict[str, Any],
    request_id: str | None = None,
) -> dict[str, Any]:
    authority = CanonicalArtifactService(db)
    policy_id = scan_policy_snapshot_id(db, scan)
    overall_coverage = _scanner_coverage(scanner_summary)
    analyzer = authority.publish_json(
        tenant_id=_tenant_id(scan),
        repository_id=repository_identity(scan.repository_url),
        revision_id=commit_sha,
        artifact_type=ArtifactType.ANALYZER_RUN,
        payload={"manifest": manifest_summary, "scanners": scanner_summary},
        producer="repolens-deterministic-analysis",
        producer_version="1.0",
        policy_snapshot_id=policy_id,
        lineage=[(LineageRelation.DERIVED_FROM, revision_artifact_id)],
        coverage=overall_coverage,
        sensitivity=ArtifactSensitivity.SOURCE_DERIVED,
        retention_class=RetentionClass.ANALYSIS_ARTIFACT,
        referrer=("SCAN", scan.id),
        actor_id=scan.owner_user_id,
        request_id=request_id,
    )
    scanner_artifacts: dict[str, str] = {}
    for scanner in scanner_summary:
        tool = str(scanner.get("tool") or "unknown")
        registration = authority.publish_json(
            tenant_id=_tenant_id(scan),
            repository_id=repository_identity(scan.repository_url),
            revision_id=commit_sha,
            artifact_type=ArtifactType.SCANNER,
            payload=scanner,
            producer=f"repolens-scanner:{tool}"[:128],
            producer_version="1.0",
            policy_snapshot_id=policy_id,
            lineage=[
                (LineageRelation.DERIVED_FROM, revision_artifact_id),
                (LineageRelation.PRODUCED_BY, analyzer.artifact.artifact_id),
            ],
            coverage=_single_scanner_coverage(scanner),
            sensitivity=ArtifactSensitivity.SECURITY_SENSITIVE,
            retention_class=RetentionClass.ANALYSIS_ARTIFACT,
            actor_id=scan.owner_user_id,
            request_id=request_id,
        )
        scanner_artifacts[tool] = registration.artifact.artifact_id

    coverage = authority.publish_json(
        tenant_id=_tenant_id(scan),
        repository_id=repository_identity(scan.repository_url),
        revision_id=commit_sha,
        artifact_type=ArtifactType.COVERAGE,
        payload={
            "schema_version": "1.0",
            "scanners": scanner_summary,
            "coverage": overall_coverage.model_dump(mode="json"),
        },
        producer="repolens-coverage-projector",
        producer_version="1.0",
        policy_snapshot_id=policy_id,
        lineage=[
            (LineageRelation.DERIVED_FROM, revision_artifact_id),
            (LineageRelation.PRODUCED_BY, analyzer.artifact.artifact_id),
        ],
        coverage=overall_coverage,
        sensitivity=ArtifactSensitivity.INTERNAL,
        retention_class=RetentionClass.ANALYSIS_ARTIFACT,
        referrer=("SCAN", scan.id),
        actor_id=scan.owner_user_id,
        request_id=request_id,
    )
    return {
        "repository_revision_artifact_id": revision_artifact_id,
        "analyzer_run_artifact_id": analyzer.artifact.artifact_id,
        "scanner_artifact_ids": scanner_artifacts,
        "coverage_artifact_id": coverage.artifact.artifact_id,
        "analysis_coverage": overall_coverage.model_dump(mode="json"),
    }


def publish_finding_provenance(
    db: Session,
    *,
    scan: ScanModel,
    commit_sha: str,
    revision_artifact_id: str,
    analyzer_artifact_id: str,
    finding: Any,
    request_id: str | None = None,
) -> dict[str, Any]:
    evidence_values = list(getattr(finding, "evidences", None) or [])
    if not evidence_values:
        raise ArtifactProvenanceError(
            "Verified findings without evidence cannot enter canonical finding authority."
        )
    authority = CanonicalArtifactService(db)
    policy_id = scan_policy_snapshot_id(db, scan)
    repository_id = repository_identity(scan.repository_url)
    evidence_ids: list[str] = []
    evidence_by_id: dict[str, str] = {}
    for evidence in evidence_values:
        value = evidence if isinstance(evidence, dict) else evidence.model_dump(mode="json")
        snippet = str(value.get("code_snippet") or "")
        payload = {
            "evidence_id": str(value.get("id") or ""),
            "file_path": value.get("file_path"),
            "start_line": value.get("start_line"),
            "end_line": value.get("end_line"),
            "snippet_digest": hashlib.sha256(snippet.encode("utf-8")).hexdigest() if snippet else None,
            "context_digest": hashlib.sha256(
                str(value.get("context_notes") or "").encode("utf-8")
            ).hexdigest(),
        }
        registered = authority.publish_json(
            tenant_id=_tenant_id(scan),
            repository_id=repository_id,
            revision_id=commit_sha,
            artifact_type=ArtifactType.EVIDENCE,
            payload=payload,
            producer="repolens-finding-verifier",
            producer_version="1.0",
            policy_snapshot_id=policy_id,
            lineage=[
                (LineageRelation.PRODUCED_BY, analyzer_artifact_id),
                (LineageRelation.DERIVED_FROM, revision_artifact_id),
            ],
            coverage=ArtifactCoverage(
                status=CoverageStatus.SUCCESSFULLY_ANALYZED,
                discovered_count=1,
                analyzed_count=1,
            ),
            sensitivity=ArtifactSensitivity.SECURITY_SENSITIVE,
            retention_class=RetentionClass.ANALYSIS_ARTIFACT,
            actor_id=scan.owner_user_id,
            request_id=request_id,
        )
        evidence_ids.append(registered.artifact.artifact_id)
        evidence_by_id[str(value.get("id") or "")] = registered.artifact.artifact_id

    finding_id = str(getattr(finding, "id", ""))
    claim = authority.publish_json(
        tenant_id=_tenant_id(scan),
        repository_id=repository_id,
        revision_id=commit_sha,
        artifact_type=ArtifactType.CLAIM,
        payload={
            "finding_id": finding_id,
            "title": str(getattr(finding, "title", ""))[:512],
            "verification_verdict": str(getattr(finding, "verification_verdict", "")),
            "verification_reason_digest": hashlib.sha256(
                str(getattr(finding, "verification_reason", "") or "").encode("utf-8")
            ).hexdigest(),
        },
        producer="repolens-finding-verifier",
        producer_version="1.0",
        policy_snapshot_id=policy_id,
        lineage=[(LineageRelation.DERIVED_FROM, evidence_id) for evidence_id in evidence_ids],
        coverage=ArtifactCoverage(
            status=CoverageStatus.SUCCESSFULLY_ANALYZED,
            discovered_count=len(evidence_ids),
            analyzed_count=len(evidence_ids),
        ),
        sensitivity=ArtifactSensitivity.SECURITY_SENSITIVE,
        retention_class=RetentionClass.ANALYSIS_ARTIFACT,
        actor_id=scan.owner_user_id,
        request_id=request_id,
    )
    finding_artifact = authority.publish_json(
        tenant_id=_tenant_id(scan),
        repository_id=repository_id,
        revision_id=commit_sha,
        artifact_type=ArtifactType.FINDING,
        payload={
            "finding_id": finding_id,
            "title": str(getattr(finding, "title", ""))[:512],
            "severity": str(getattr(finding, "severity", "")),
            "category": str(getattr(finding, "category", ""))[:128],
            "rule_id": str(getattr(finding, "rule_id", "") or "")[:128],
        },
        producer="repolens-analysis-workflow",
        producer_version="1.0",
        policy_snapshot_id=policy_id,
        lineage=[(LineageRelation.DERIVED_FROM, claim.artifact.artifact_id)],
        coverage=ArtifactCoverage(
            status=CoverageStatus.SUCCESSFULLY_ANALYZED,
            discovered_count=1,
            analyzed_count=1,
        ),
        sensitivity=ArtifactSensitivity.SECURITY_SENSITIVE,
        retention_class=RetentionClass.ANALYSIS_ARTIFACT,
        referrer=("FINDING", finding_id),
        actor_id=scan.owner_user_id,
        request_id=request_id,
    )
    authority.registry.assert_finding_traceable(
        tenant_id=_tenant_id(scan),
        artifact_id=finding_artifact.artifact.artifact_id,
    )
    return {
        "evidence_artifact_ids": evidence_ids,
        "evidence_artifact_by_id": evidence_by_id,
        "claim_artifact_id": claim.artifact.artifact_id,
        "finding_artifact_id": finding_artifact.artifact.artifact_id,
    }


def publish_graph_artifacts(
    db: Session,
    *,
    scan: ScanModel,
    commit_sha: str,
    revision_artifact_id: str,
    analyzer_artifact_id: str,
    graph_data: Any,
    request_id: str | None = None,
) -> dict[str, str]:
    """Publish deterministic symbol/relationship and cross-layer contract facts."""
    authority = CanonicalArtifactService(db)
    policy_id = scan_policy_snapshot_id(db, scan)
    repository_id = repository_identity(scan.repository_url)
    data = graph_data.model_dump(mode="json") if hasattr(graph_data, "model_dump") else dict(graph_data)
    nodes = list(data.get("nodes") or [])
    edges = list(data.get("edges") or [])
    contract_report = data.get("contract_report") or {}
    lineage = [
        (LineageRelation.DERIVED_FROM, revision_artifact_id),
        (LineageRelation.PRODUCED_BY, analyzer_artifact_id),
    ]
    symbol_index = authority.publish_json(
        tenant_id=_tenant_id(scan),
        repository_id=repository_id,
        revision_id=commit_sha,
        artifact_type=ArtifactType.SYMBOL_INDEX,
        payload={
            "schema_version": "1.0",
            "nodes": nodes,
            "edges": edges,
            "node_counts_by_kind": data.get("node_counts_by_kind") or {},
            "edge_counts_by_kind": data.get("edge_counts_by_kind") or {},
        },
        producer="repolens-tree-sitter-graph-builder",
        producer_version="1.0",
        policy_snapshot_id=policy_id,
        lineage=lineage,
        coverage=ArtifactCoverage(
            status=CoverageStatus.SUCCESSFULLY_ANALYZED,
            discovered_count=len(nodes),
            analyzed_count=len(nodes),
        ),
        sensitivity=ArtifactSensitivity.SOURCE_DERIVED,
        retention_class=RetentionClass.SOURCE_BEARING_ARTIFACT,
        referrer=("SCAN", scan.id),
        actor_id=scan.owner_user_id,
        request_id=request_id,
    )
    matches = list(contract_report.get("matches") or [])
    contract = authority.publish_json(
        tenant_id=_tenant_id(scan),
        repository_id=repository_id,
        revision_id=commit_sha,
        artifact_type=ArtifactType.CONTRACT,
        payload={"schema_version": "1.0", "contract_match_report": contract_report},
        producer="repolens-contract-matcher",
        producer_version="1.0",
        policy_snapshot_id=policy_id,
        lineage=[*lineage, (LineageRelation.DERIVED_FROM, symbol_index.artifact.artifact_id)],
        coverage=ArtifactCoverage(
            status=CoverageStatus.SUCCESSFULLY_ANALYZED,
            discovered_count=len(matches),
            analyzed_count=len(matches),
        ),
        sensitivity=ArtifactSensitivity.INTERNAL,
        retention_class=RetentionClass.ANALYSIS_ARTIFACT,
        referrer=("SCAN", scan.id),
        actor_id=scan.owner_user_id,
        request_id=request_id,
    )
    return {
        "symbol_index_artifact_id": symbol_index.artifact.artifact_id,
        "contract_artifact_id": contract.artifact.artifact_id,
    }


def _scanner_coverage(scanner_summary: Iterable[dict[str, Any]]) -> ArtifactCoverage:
    rows = list(scanner_summary)
    completed = sum(1 for row in rows if str(row.get("status", "")).upper() == "COMPLETED")
    unavailable = sum(1 for row in rows if str(row.get("status", "")).upper() == "UNAVAILABLE")
    failed = len(rows) - completed - unavailable
    if not rows or failed:
        status = CoverageStatus.FAILED
        explanation = "One or more configured analyzers failed or produced invalid output."
    elif unavailable:
        status = CoverageStatus.UNAVAILABLE
        explanation = "One or more configured analyzers were unavailable; zero findings is not inferred."
    else:
        status = CoverageStatus.SUCCESSFULLY_ANALYZED
        explanation = None
    return ArtifactCoverage(
        status=status,
        discovered_count=len(rows),
        analyzed_count=completed,
        failed_count=failed + unavailable,
        explanation=explanation,
    )


def _single_scanner_coverage(scanner: dict[str, Any]) -> ArtifactCoverage:
    status_value = str(scanner.get("status") or "FAILED").upper()
    mapping = {
        "COMPLETED": CoverageStatus.SUCCESSFULLY_ANALYZED,
        "UNAVAILABLE": CoverageStatus.UNAVAILABLE,
        "TIMEOUT": CoverageStatus.FAILED,
        "INVALID_OUTPUT": CoverageStatus.FAILED,
        "SKIPPED": CoverageStatus.SKIPPED,
    }
    status = mapping.get(status_value, CoverageStatus.FAILED)
    return ArtifactCoverage(
        status=status,
        discovered_count=1,
        analyzed_count=1 if status == CoverageStatus.SUCCESSFULLY_ANALYZED else 0,
        skipped_count=1 if status == CoverageStatus.SKIPPED else 0,
        failed_count=1 if status not in {CoverageStatus.SUCCESSFULLY_ANALYZED, CoverageStatus.SKIPPED} else 0,
        explanation=(
            None
            if status == CoverageStatus.SUCCESSFULLY_ANALYZED
            else str(scanner.get("failure_reason") or f"Analyzer status: {status_value}")[:2048]
        ),
    )


__all__ = [
    "publish_analysis_artifacts",
    "publish_finding_provenance",
    "publish_graph_artifacts",
    "publish_repository_revision",
    "repository_identity",
    "scan_policy_snapshot_id",
]
