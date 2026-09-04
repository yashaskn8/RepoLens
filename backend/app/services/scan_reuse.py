"""Durable exact-analysis reuse at the scan boundary.

Only completed scans with the same tenant, repository identity, immutable
commit, and authority fingerprint are eligible.  Findings are copied into the
new user-visible scan with explicit provenance; no LLM workflow is rerun.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Iterable
from uuid import uuid4

from sqlalchemy.orm import Session

from app.models.finding import EvidenceModel, FindingModel
from app.models.scan import ScanModel
from app.analysis.reuse import ReuseDecision, revalidate_finding
from app.services.finding_grounding import is_canonical_confirmed_finding


def find_exact_reusable_scan(
    db: Session,
    *,
    tenant_id: str,
    repository_url: str,
    commit_sha: str,
    authority_fingerprint: str | None,
    exclude_scan_id: str | None = None,
) -> ScanModel | None:
    if not authority_fingerprint:
        return None
    query = (
        db.query(ScanModel)
        .filter(
            ScanModel.owner_user_id == tenant_id,
            ScanModel.repository_url == repository_url,
            ScanModel.commit_hash == commit_sha,
            ScanModel.status == "COMPLETED",
        )
        .order_by(ScanModel.completed_at.desc(), ScanModel.id.desc())
    )
    for scan in query.all():
        if exclude_scan_id and str(scan.id) == str(exclude_scan_id):
            continue
        metadata = scan.model_metadata if isinstance(scan.model_metadata, dict) else {}
        if metadata.get("analysis_authority_fingerprint") == authority_fingerprint:
            return scan
    return None


def copy_exact_verified_findings(
    db: Session,
    *,
    source_scan: ScanModel,
    target_scan: ScanModel,
    authority_fingerprint: str,
) -> int:
    """Copy only canonical verified findings while preserving immutable origin."""
    copied = 0
    for finding in list(source_scan.findings or []):
        if not is_canonical_confirmed_finding(
            finding,
            expected_commit_sha=source_scan.commit_hash or "__missing_commit__",
        ):
            continue
        metadata = deepcopy(finding.model_metadata) if isinstance(finding.model_metadata, dict) else {}
        provenance = dict(metadata.get("provenance") or {})
        provenance.update({
            "reuse_type": "exact",
            "origin_scan_id": source_scan.id,
            "previous_commit_sha": source_scan.commit_hash,
            "new_commit_sha": target_scan.commit_hash,
            "reuse_reason": "same tenant, repository, immutable commit, and analysis authorities",
            "authority_fingerprint": authority_fingerprint,
        })
        metadata["provenance"] = provenance
        clone = FindingModel(
            id=str(uuid4()),
            scan_id=target_scan.id,
            title=finding.title,
            description=finding.description,
            severity=finding.severity,
            status=finding.status,
            rule_id=finding.rule_id,
            category=finding.category,
            mitigation_guidance=finding.mitigation_guidance,
            verification_verdict=finding.verification_verdict,
            verification_reason=finding.verification_reason,
            source_tool=finding.source_tool,
            detector_id=finding.detector_id,
            detector_kind=finding.detector_kind,
            model_metadata=metadata,
        )
        for evidence in list(finding.evidences or []):
            clone.evidences.append(
                EvidenceModel(
                    id=str(uuid4()),
                    finding_id=clone.id,
                    file_path=evidence.file_path,
                    start_line=evidence.start_line,
                    end_line=evidence.end_line,
                    code_snippet=evidence.code_snippet,
                    context_notes=evidence.context_notes,
                )
            )
        db.add(clone)
        copied += 1
    return copied


def find_incremental_reusable_scan(
    db: Session,
    *,
    tenant_id: str,
    repository_url: str,
    compatibility_fingerprint: str | None,
    exclude_scan_id: str | None = None,
) -> ScanModel | None:
    """Return the newest completed prior commit with compatible authorities.

    This lookup is bounded to the tenant/repository and never treats a
    semantically similar commit as exact reuse.  The caller must still run
    ``revalidate_finding`` for every finding before copying anything.
    """
    if not compatibility_fingerprint:
        return None
    query = (
        db.query(ScanModel)
        .filter(
            ScanModel.owner_user_id == tenant_id,
            ScanModel.repository_url == repository_url,
            ScanModel.status == "COMPLETED",
        )
        .order_by(ScanModel.completed_at.desc(), ScanModel.id.desc())
    )
    for scan in query.all():
        if exclude_scan_id and str(scan.id) == str(exclude_scan_id):
            continue
        metadata = scan.model_metadata if isinstance(scan.model_metadata, dict) else {}
        if metadata.get("analysis_compatibility_fingerprint") == compatibility_fingerprint:
            return scan
    return None


def _clone_incremental_finding(
    db: Session,
    *,
    source_finding: FindingModel,
    target_scan: ScanModel,
    decision: ReuseDecision,
) -> None:
    metadata = deepcopy(source_finding.model_metadata) if isinstance(source_finding.model_metadata, dict) else {}
    provenance = metadata.get("provenance") if isinstance(metadata.get("provenance"), dict) else {}
    provenance = dict(provenance)
    provenance.update(dict(decision.provenance or {}))
    metadata["provenance"] = provenance
    clone_id = str(uuid4())
    clone = FindingModel(
        id=clone_id,
        scan_id=target_scan.id,
        title=source_finding.title,
        description=source_finding.description,
        severity=source_finding.severity,
        status=source_finding.status,
        rule_id=source_finding.rule_id,
        category=source_finding.category,
        mitigation_guidance=source_finding.mitigation_guidance,
        verification_verdict=source_finding.verification_verdict,
        verification_reason=source_finding.verification_reason,
        source_tool=source_finding.source_tool,
        detector_id=source_finding.detector_id,
        detector_kind=source_finding.detector_kind,
        model_metadata=metadata,
    )
    for evidence in decision.evidence:
        clone.evidences.append(
            EvidenceModel(
                id=str(uuid4()),
                finding_id=clone_id,
                file_path=evidence.file_path,
                start_line=evidence.start_line,
                end_line=evidence.end_line,
                code_snippet=evidence.code_snippet,
                context_notes=evidence.context_notes,
            )
        )
    db.add(clone)


def copy_incremental_verified_findings(
    db: Session,
    *,
    source_scan: ScanModel,
    target_scan: ScanModel,
    repo_dir: str,
    changed_files: Iterable[str] = (),
    changed_symbols: Iterable[str] = (),
    changed_dependencies: Iterable[str] = (),
    previous_authority_fingerprint: str | None,
    current_authority_fingerprint: str | None,
    tenant_matches: bool = True,
) -> dict[str, Any]:
    """Copy only findings proven safe for a new commit.

    The returned counters are deterministic reporting facts.  A finding that
    fails any authority, dependency, symbol, or source-byte check is skipped
    and must be analyzed normally by the target workflow.
    """
    copied = 0
    rejected = 0
    decisions: list[dict[str, Any]] = []
    for finding in list(source_scan.findings or []):
        decision = revalidate_finding(
            finding,
            repo_dir=repo_dir,
            commit_sha=str(target_scan.commit_hash or ""),
            previous_commit_sha=str(source_scan.commit_hash or ""),
            changed_files=changed_files,
            changed_symbols=changed_symbols,
            changed_dependencies=changed_dependencies,
            previous_authority_fingerprint=previous_authority_fingerprint,
            current_authority_fingerprint=current_authority_fingerprint,
            tenant_matches=tenant_matches,
        )
        decisions.append({
            "finding_id": str(finding.id),
            "reusable": decision.reusable,
            "reason": decision.reason,
        })
        if not decision.reusable:
            rejected += 1
            continue
        _clone_incremental_finding(db, source_finding=finding, target_scan=target_scan, decision=decision)
        copied += 1
    return {"copied": copied, "rejected": rejected, "decisions": decisions}


__all__ = [
    "copy_exact_verified_findings",
    "copy_incremental_verified_findings",
    "find_exact_reusable_scan",
    "find_incremental_reusable_scan",
]
