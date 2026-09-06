"""Deterministic findings that must not depend on model availability."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any
from uuid import UUID

from app.graph.schemas import ContractMatchStatus, RouteContractMatch
from app.schemas.enums import FindingStatus, Severity
from app.schemas.evidence import Evidence
from app.schemas.finding import Finding
from app.schemas.static_finding import StaticFinding


def scanner_candidates(
    raw_findings: Iterable[StaticFinding | Mapping[str, Any]],
    *,
    scan_id: UUID,
) -> list[Finding]:
    """Project canonical scanner output without asking a model to restate it."""
    candidates: list[Finding] = []
    for raw in raw_findings:
        try:
            finding = raw if isinstance(raw, StaticFinding) else StaticFinding.model_validate(raw)
            evidence = finding.evidence.model_copy(deep=True)
            candidates.append(
                Finding(
                    scan_id=scan_id,
                    title=finding.title,
                    description=finding.description,
                    severity=finding.severity,
                    status=FindingStatus.OPEN,
                    rule_id=finding.rule_id,
                    category=finding.category,
                    evidences=[evidence],
                    mitigation_guidance=finding.mitigation,
                    source_tool=finding.source_tool or finding.tool,
                    detector_id=finding.detector_id or finding.rule_id or str(finding.id),
                    detector_kind=finding.detector_kind or "static_scanner",
                )
            )
        except (TypeError, ValueError):
            continue
    return candidates


_CONTRACT_PRESENTATION: dict[ContractMatchStatus, tuple[str, Severity, str]] = {
    ContractMatchStatus.UNMATCHED_FRONTEND_REQUEST: (
        "Frontend request has no backend route",
        Severity.MEDIUM,
        "Add a matching backend route or remove/update the frontend request.",
    ),
    ContractMatchStatus.METHOD_MISMATCH: (
        "Frontend and backend HTTP methods differ",
        Severity.MEDIUM,
        "Align the frontend HTTP method with the matched backend route contract.",
    ),
    ContractMatchStatus.PATH_MISMATCH: (
        "Frontend and backend route paths differ",
        Severity.MEDIUM,
        "Align the frontend URL with the canonical backend route path.",
    ),
    ContractMatchStatus.AMBIGUOUS_MATCH: (
        "Frontend request maps to multiple backend routes",
        Severity.LOW,
        "Remove route ambiguity so the request resolves to one explicit contract.",
    ),
    ContractMatchStatus.REQUEST_BODY_TYPE_MISMATCH: (
        "Frontend request body type does not match backend schema",
        Severity.MEDIUM,
        "Send the object or array shape required by the matched backend request schema.",
    ),
    ContractMatchStatus.REQUEST_BODY_MISSING_REQUIRED_FIELDS: (
        "Frontend request omits required backend fields",
        Severity.MEDIUM,
        "Include every required backend request field, including required nested item fields.",
    ),
}


def contract_candidates(
    matches: Iterable[RouteContractMatch | Mapping[str, Any]],
    *,
    scan_id: UUID,
) -> list[Finding]:
    """Project route mismatches directly from the deterministic contract graph."""
    candidates: list[Finding] = []
    for raw in matches:
        try:
            match = raw if isinstance(raw, RouteContractMatch) else RouteContractMatch.model_validate(raw)
        except (TypeError, ValueError):
            continue
        presentation = _CONTRACT_PRESENTATION.get(match.status)
        if presentation is None or not match.frontend_file or match.frontend_line is None:
            continue
        title, severity, mitigation = presentation
        evidence_ref = f"contract:{match.frontend_request_id}"
        evidences = [
            Evidence(
                file_path=match.frontend_file,
                start_line=match.frontend_line,
                end_line=match.frontend_line,
                context_notes=(
                    f"Deterministic route-contract status={match.status.value}; "
                    f"evidence_ref={evidence_ref}; frontend_method={match.frontend_method}; "
                    f"frontend_url={match.frontend_url}"
                ),
            )
        ]
        if match.backend_file and match.backend_line:
            evidences.append(
                Evidence(
                    file_path=match.backend_file,
                    start_line=match.backend_line,
                    end_line=match.backend_line,
                    context_notes=(
                        f"Matched backend route/schema evidence; schema={match.backend_request_schema or 'unknown'}; "
                        f"missing_fields={match.missing_required_fields}; "
                        f"missing_item_fields={match.missing_item_fields}"
                    ),
                )
            )
        candidates.append(
            Finding(
                scan_id=scan_id,
                title=title,
                description=match.details,
                severity=severity,
                status=FindingStatus.OPEN,
                rule_id=evidence_ref,
                category="integration",
                evidences=evidences,
                mitigation_guidance=mitigation,
                source_tool="route_contract",
                detector_id=evidence_ref,
                detector_kind="contract_matcher",
            )
        )
    return candidates


__all__ = ["contract_candidates", "scanner_candidates"]
