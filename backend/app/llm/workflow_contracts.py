"""Shared structured-output contracts and execution lineage for AI workflows."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from sqlalchemy import inspect

from app.core.database import SessionLocal
from app.llm.types import AIExecutionLineage
from app.models.execution import WorkAttemptModel, WorkItemModel


FINDINGS_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["findings"],
    "properties": {
        "findings": {
            "type": "array",
            "maxItems": 100,
            "items": {"type": "object"},
        }
    },
}

VERIFICATION_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["evaluations"],
    "properties": {
        "evaluations": {
            "type": "array",
            "maxItems": 200,
            "items": {
                "type": "object",
                "required": ["index", "verdict"],
                "properties": {
                    "index": {"type": "integer", "minimum": 0},
                    "verdict": {"type": "string", "enum": ["CONFIRMED", "POSSIBLE", "REJECTED"]},
                },
            },
        }
    },
}

OBJECT_OUTPUT_SCHEMA: dict[str, Any] = {"type": "object"}


def evidence_digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def lineage_for_resource(
    *,
    resource_type: str,
    resource_id: str,
    prompt_template_version: str,
    output_schema_version: str | None,
    evidence: Any,
) -> AIExecutionLineage:
    db = SessionLocal()
    try:
        if not inspect(db.get_bind()).has_table("execution_work_items"):
            return AIExecutionLineage(
                prompt_template_version=prompt_template_version,
                output_schema_version=output_schema_version,
                evidence_digest=evidence_digest(evidence),
            )
        work = db.query(WorkItemModel).filter(
            WorkItemModel.resource_type == resource_type,
            WorkItemModel.resource_id == str(resource_id),
        ).order_by(WorkItemModel.created_at.desc()).first()
        if work is None:
            return AIExecutionLineage(
                prompt_template_version=prompt_template_version,
                output_schema_version=output_schema_version,
                evidence_digest=evidence_digest(evidence),
            )
        attempt = db.query(WorkAttemptModel).filter(
            WorkAttemptModel.work_item_id == work.id,
        ).order_by(WorkAttemptModel.attempt_number.desc()).first()
        return AIExecutionLineage(
            tenant_id=work.tenant_id,
            request_id=work.request_id,
            work_item_id=work.id,
            attempt_id=attempt.id if attempt else None,
            prompt_template_version=prompt_template_version,
            output_schema_version=output_schema_version,
            evidence_digest=evidence_digest(evidence),
            policy_snapshot_id=work.policy_snapshot_id,
        )
    finally:
        db.close()


def lineage_for_scan(
    scan_id: str,
    *,
    prompt_template_version: str,
    output_schema_version: str | None,
    evidence: Any,
) -> AIExecutionLineage:
    return lineage_for_resource(
        resource_type="SCAN",
        resource_id=scan_id,
        prompt_template_version=prompt_template_version,
        output_schema_version=output_schema_version,
        evidence=evidence,
    )


def lineage_for_change_analysis(
    analysis_id: str,
    *,
    prompt_template_version: str,
    output_schema_version: str | None,
    evidence: Any,
) -> AIExecutionLineage:
    return lineage_for_resource(
        resource_type="CHANGE_ANALYSIS",
        resource_id=analysis_id,
        prompt_template_version=prompt_template_version,
        output_schema_version=output_schema_version,
        evidence=evidence,
    )


def lineage_for_finding(
    finding_id: str,
    *,
    prompt_template_version: str,
    output_schema_version: str | None,
    evidence: Any,
) -> AIExecutionLineage:
    from app.models.finding import FindingModel

    db = SessionLocal()
    try:
        finding = db.query(FindingModel).filter(FindingModel.id == str(finding_id)).first()
        scan_id = finding.scan_id if finding is not None else None
    finally:
        db.close()
    if scan_id:
        return lineage_for_scan(
            str(scan_id),
            prompt_template_version=prompt_template_version,
            output_schema_version=output_schema_version,
            evidence=evidence,
        )
    return AIExecutionLineage(
        prompt_template_version=prompt_template_version,
        output_schema_version=output_schema_version,
        evidence_digest=evidence_digest(evidence),
    )


__all__ = [
    "FINDINGS_OUTPUT_SCHEMA",
    "OBJECT_OUTPUT_SCHEMA",
    "VERIFICATION_OUTPUT_SCHEMA",
    "evidence_digest",
    "lineage_for_change_analysis",
    "lineage_for_finding",
    "lineage_for_resource",
    "lineage_for_scan",
]
