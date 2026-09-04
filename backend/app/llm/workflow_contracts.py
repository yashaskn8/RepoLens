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
    "required": ["confidence", "findings"],
    "properties": {
        "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "findings": {
            "type": "array",
            "maxItems": 100,
            "items": {
                "type": "object",
                "required": [
                    "title",
                    "description",
                    "severity",
                    "category",
                    "evidence_refs",
                ],
                "properties": {
                    "candidate_id": {"type": "string", "minLength": 1, "maxLength": 256},
                    "title": {"type": "string", "minLength": 1, "maxLength": 300},
                    "description": {"type": "string", "minLength": 1, "maxLength": 8_000},
                    "severity": {
                        "type": "string",
                        "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                    },
                    "category": {"type": "string", "minLength": 1, "maxLength": 128},
                    "rule_id": {"type": ["string", "null"], "maxLength": 256},
                    "evidence_refs": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 16,
                        "items": {"type": "string", "minLength": 1, "maxLength": 1_024},
                    },
                    "mitigation_guidance": {"type": ["string", "null"], "maxLength": 8_000},
                    "source_behavior": {"type": "string", "maxLength": 4_000},
                    "trigger_condition": {"type": "string", "maxLength": 4_000},
                    "failure_mechanism": {"type": "string", "maxLength": 4_000},
                    "impact_claim": {"type": "string", "maxLength": 4_000},
                    "counter_evidence_considered": {
                        "type": "array",
                        "maxItems": 16,
                        "items": {"type": "string", "maxLength": 1_000},
                    },
                },
            },
        }
    },
}

_CANDIDATE_FINDING_ITEM_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": [
        "candidate_id",
        "title",
        "description",
        "severity",
        "category",
        "evidence_refs",
        "source_behavior",
        "trigger_condition",
        "failure_mechanism",
        "impact_claim",
        "counter_evidence_considered",
    ],
    "properties": FINDINGS_OUTPUT_SCHEMA["properties"]["findings"]["items"]["properties"],
}

CANDIDATE_FINDINGS_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["confidence", "findings"],
    "properties": {
        "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "findings": {
            "type": "array",
            "maxItems": 12,
            "items": _CANDIDATE_FINDING_ITEM_SCHEMA,
        },
    },
}

REVISION_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": [
        "finding_id",
        "removed_claims",
        "modified_claims",
        "new_claims",
        "revised_title",
        "revised_description",
        "revised_mitigation",
    ],
    "properties": {
        "finding_id": {"type": "string", "minLength": 1, "maxLength": 128},
        "removed_claims": {
            "type": "array",
            "maxItems": 8,
            "items": {"type": "string", "minLength": 1, "maxLength": 128},
        },
        "modified_claims": {
            "type": "array",
            "maxItems": 8,
            "items": {
                "type": "object",
                "required": ["claim_id", "revised_text"],
                "properties": {
                    "claim_id": {"type": "string", "minLength": 1, "maxLength": 128},
                    "revised_text": {"type": "string", "minLength": 1, "maxLength": 4_000},
                },
            },
        },
        "new_claims": {"type": "array", "maxItems": 0},
        "revised_title": {"type": "string", "minLength": 1, "maxLength": 300},
        "revised_description": {"type": "string", "minLength": 1, "maxLength": 8_000},
        "revised_mitigation": {"type": ["string", "null"], "maxLength": 8_000},
    },
}

VERIFICATION_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["confidence", "evaluations"],
    "properties": {
        "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "evaluations": {
            "type": "array",
            "maxItems": 200,
            "items": {
                "type": "object",
                "required": ["index", "verdict"],
                "properties": {
                    "index": {"type": "integer", "minimum": 0},
                    "verdict": {"type": "string", "enum": ["CONFIRMED", "POSSIBLE", "REJECTED"]},
                    "claims": {
                        "type": "array",
                        "maxItems": 8,
                        "items": {
                            "type": "object",
                            "required": ["claim_type", "state"],
                            "properties": {
                                "claim_type": {
                                    "type": "string",
                                    "enum": ["SOURCE_BEHAVIOR", "TRIGGER", "MECHANISM", "IMPACT", "SEVERITY", "MITIGATION"],
                                },
                                "state": {
                                    "type": "string",
                                    "enum": ["SUPPORTED", "CONTRADICTED", "INSUFFICIENT"],
                                },
                                "reason": {"type": "string", "maxLength": 2_000},
                            },
                        },
                    },
                },
            },
        }
    },
}

OBJECT_OUTPUT_SCHEMA: dict[str, Any] = {"type": "object"}

CHANGE_REVIEW_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["confidence", "summary", "findings"],
    "properties": {
        "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "summary": {"type": "string", "maxLength": 8_000},
        "findings": {"type": "array", "maxItems": 100, "items": {"type": "object"}},
    },
}


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
    "CANDIDATE_FINDINGS_OUTPUT_SCHEMA",
    "CHANGE_REVIEW_OUTPUT_SCHEMA",
    "FINDINGS_OUTPUT_SCHEMA",
    "OBJECT_OUTPUT_SCHEMA",
    "REVISION_OUTPUT_SCHEMA",
    "VERIFICATION_OUTPUT_SCHEMA",
    "evidence_digest",
    "lineage_for_change_analysis",
    "lineage_for_finding",
    "lineage_for_resource",
    "lineage_for_scan",
]
