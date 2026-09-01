"""Deterministic remediation sequencing. No model output influences ordering."""

from collections import defaultdict
from typing import Dict, Iterable, List, Set

from app.reporting.schemas import ReportFinding, ReportPriorityItem, ReportRoadmapStep


_SEVERITY_WEIGHT = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
_VERDICT_WEIGHT = {"CONFIRMED": 3, "POSSIBLE": 2, None: 1, "REJECTED": 0}
_EVIDENCE_WEIGHT = {"STRONG": 3, "MODERATE": 2, "LIMITED": 1, "NONE": 0}
_REMEDIATION_WEIGHT = {"VERIFIED_PATCH": 3, "CANDIDATE_PATCH": 2, "GUIDANCE": 1, "NONE": 0}


def _is_actionable(finding: ReportFinding) -> bool:
    return finding.verification_verdict != "REJECTED" and finding.lifecycle_status not in {
        "FALSE_POSITIVE",
        "SUPPRESSED",
    }


def _base_key(finding: ReportFinding) -> tuple:
    return (
        -_SEVERITY_WEIGHT.get(finding.severity.upper(), 0),
        -_VERDICT_WEIGHT.get(finding.verification_verdict, 1),
        -int(finding.security_impact),
        -finding.blast_radius,
        -_EVIDENCE_WEIGHT.get(finding.evidence_strength, 0),
        -_REMEDIATION_WEIGHT.get(finding.remediation.availability, 0),
        finding.finding_id,
    )


def _dependency_order(findings: Iterable[ReportFinding]) -> List[ReportFinding]:
    """Stable Kahn ordering with risk ordering as the ready-queue tie breaker.

    Unknown dependencies are ignored. Cycles are appended using the stable base
    key and remain visible in each item's dependency metadata.
    """
    items = {finding.finding_id: finding for finding in findings if _is_actionable(finding)}
    indegree: Dict[str, int] = {finding_id: 0 for finding_id in items}
    dependents: Dict[str, Set[str]] = defaultdict(set)
    for finding in items.values():
        for dependency_id in finding.dependency_ids:
            if dependency_id in items and dependency_id != finding.finding_id:
                indegree[finding.finding_id] += 1
                dependents[dependency_id].add(finding.finding_id)

    ready = sorted((items[fid] for fid, degree in indegree.items() if degree == 0), key=_base_key)
    ordered: List[ReportFinding] = []
    while ready:
        current = ready.pop(0)
        ordered.append(current)
        for dependent_id in sorted(dependents[current.finding_id]):
            indegree[dependent_id] -= 1
            if indegree[dependent_id] == 0:
                ready.append(items[dependent_id])
                ready.sort(key=_base_key)

    emitted = {finding.finding_id for finding in ordered}
    ordered.extend(sorted((finding for finding in items.values() if finding.finding_id not in emitted), key=_base_key))
    return ordered


def _band(finding: ReportFinding) -> str:
    severity = finding.severity.upper()
    if severity == "CRITICAL" or (
        severity == "HIGH" and finding.verification_verdict == "CONFIRMED" and finding.security_impact
    ):
        return "FIX FIRST"
    if severity == "HIGH" or finding.category.lower() in {"contract", "integration", "correctness"}:
        return "FIX NEXT"
    return "FIX LATER"


def prioritize(findings: Iterable[ReportFinding]) -> List[ReportPriorityItem]:
    ordered = _dependency_order(findings)
    results: List[ReportPriorityItem] = []
    for rank, finding in enumerate(ordered, start=1):
        reasons = [finding.severity.upper()]
        reasons.append(finding.verification_verdict or "UNVERIFIED")
        reasons.append(f"{finding.evidence_strength.lower()} evidence")
        if finding.security_impact:
            reasons.append("security impact")
        if finding.blast_radius > 1:
            reasons.append(f"{finding.blast_radius} affected components")
        if finding.dependency_ids:
            reasons.append("dependency constrained")
        if finding.remediation.availability != "NONE":
            reasons.append(finding.remediation.availability.lower().replace("_", " "))
        results.append(
            ReportPriorityItem(
                finding_id=finding.finding_id,
                title=finding.title,
                severity=finding.severity,
                priority_rank=rank,
                priority_band=_band(finding),
                priority_reason="; ".join(reasons),
                dependency_ids=finding.dependency_ids,
            )
        )
    return results


def build_roadmap(items: List[ReportPriorityItem]) -> List[ReportRoadmapStep]:
    groups = [
        ("Critical security and highest-risk fixes", "FIX FIRST"),
        ("Contract-breaking and high-risk correctness fixes", "FIX NEXT"),
        ("Medium, low-priority, and hardening fixes", "FIX LATER"),
    ]
    roadmap: List[ReportRoadmapStep] = []
    for title, band in groups:
        selected = [item for item in items if item.priority_band == band]
        if not selected:
            continue
        roadmap.append(
            ReportRoadmapStep(
                sequence=len(roadmap) + 1,
                title=title,
                finding_ids=[item.finding_id for item in selected],
                dependency_ids=sorted({dep for item in selected for dep in item.dependency_ids}),
            )
        )
    return roadmap

