"""Helper utilities for parsing LLM structured output into canonical Finding domain models."""

import json
import math
import re
from typing import Any, List, Mapping, Set
import uuid
from uuid import UUID

from app.schemas.enums import FindingStatus, Severity
from app.schemas.evidence import Evidence
from app.schemas.finding import Finding
from app.schemas.metadata import ModelExecutionMetadata
from app.agents.grounding import EvidenceIndex, ground_model_findings
from app.atomic_claims import claims_from_model_item, has_complete_atomic_contract
from app.finding_identity import canonical_issue_fingerprint


def safe_to_uuid(val: Any) -> UUID:
    """Safely convert any UUID or string identifier to a valid UUID object."""
    if isinstance(val, UUID):
        return val
    try:
        return UUID(str(val))
    except Exception:
        return uuid.uuid5(uuid.NAMESPACE_DNS, str(val))


def extract_json_block(text: str) -> str:
    """Extract JSON content from markdown code blocks or raw string."""
    cleaned = text.strip()
    match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", cleaned)
    if match:
        return match.group(1).strip()
    return cleaned


def validated_candidate_findings_payload(raw_content: str) -> dict[str, Any] | None:
    """Return a schema-shaped candidate response or None without guessing.

    `parse_llm_findings` intentionally drops malformed/un-grounded items for
    production safety. Failure attribution must distinguish that case from a
    valid, explicit empty answer, so it uses this stricter preflight as well.
    Limits mirror CANDIDATE_FINDINGS_OUTPUT_SCHEMA.
    """
    try:
        payload = json.loads(extract_json_block(raw_content))
    except (TypeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    confidence = payload.get("confidence")
    findings = payload.get("findings")
    if (
        isinstance(confidence, bool)
        or not isinstance(confidence, (int, float))
        or not isinstance(findings, list)
        or len(findings) > 12
    ):
        return None
    try:
        normalized_confidence = float(confidence)
    except (OverflowError, TypeError, ValueError):
        return None
    if not math.isfinite(normalized_confidence) or not 0.0 <= normalized_confidence <= 1.0:
        return None
    required_strings = {
        "candidate_id": 256,
        "title": 300,
        "description": 8_000,
        "category": 128,
        "source_behavior": 4_000,
        "trigger_condition": 4_000,
        "failure_mechanism": 4_000,
        "impact_claim": 4_000,
    }
    for item in findings:
        if not isinstance(item, dict):
            return None
        if any(
            not isinstance(item.get(name), str)
            or not item[name]
            or len(item[name]) > maximum
            for name, maximum in required_strings.items()
        ):
            return None
        severity = item.get("severity")
        if not isinstance(severity, str) or severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            return None
        evidence_refs = item.get("evidence_refs")
        if (
            not isinstance(evidence_refs, list)
            or not 1 <= len(evidence_refs) <= 16
            or any(not isinstance(value, str) or not value or len(value) > 1_024 for value in evidence_refs)
        ):
            return None
        counter_evidence = item.get("counter_evidence_considered")
        if (
            not isinstance(counter_evidence, list)
            or len(counter_evidence) > 16
            or any(not isinstance(value, str) or len(value) > 1_000 for value in counter_evidence)
        ):
            return None
        if item.get("rule_id") is not None and (
            not isinstance(item.get("rule_id"), str) or len(item["rule_id"]) > 256
        ):
            return None
        if item.get("mitigation_guidance") is not None and (
            not isinstance(item.get("mitigation_guidance"), str)
            or len(item["mitigation_guidance"]) > 8_000
        ):
            return None
    return payload


def parse_llm_findings(
    raw_content: str,
    scan_id: Any,
    default_category: str,
    model_metadata: ModelExecutionMetadata,
    evidence_index: EvidenceIndex,
    candidate_evidence: Mapping[str, Set[str]] | None = None,
) -> List[Finding]:
    """Parse only exactly cited, deterministically grounded model findings."""
    findings: List[Finding] = []
    clean_scan_id = safe_to_uuid(scan_id)
    json_str = extract_json_block(raw_content)

    try:
        data = json.loads(json_str)
    except Exception:
        return findings

    raw_items = data.get("findings", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
    if not isinstance(raw_items, list):
        return findings
    if candidate_evidence is not None:
        candidate_bound_items = []
        for item in raw_items:
            if not isinstance(item, dict):
                continue
            candidate_id = item.get("candidate_id")
            references = item.get("evidence_refs")
            allowed = candidate_evidence.get(candidate_id) if isinstance(candidate_id, str) else None
            mandatory_atomic_fields = (
                "source_behavior",
                "trigger_condition",
                "failure_mechanism",
                "impact_claim",
            )
            if (
                not allowed
                or not isinstance(references, list)
                or not references
                or any(not isinstance(ref, str) or ref not in allowed for ref in references)
                or any(
                    not isinstance(item.get(field), str) or not item[field].strip()
                    for field in mandatory_atomic_fields
                )
                or not isinstance(item.get("counter_evidence_considered"), list)
            ):
                continue
            candidate_bound_items.append(item)
        raw_items = candidate_bound_items
    grounded_items = ground_model_findings(raw_items, evidence_index)

    for item in grounded_items:
        if not isinstance(item, dict):
            continue

        try:
            title = item.get("title", "Untitled Issue")
            description = item.get("description", "")
            raw_sev = str(item.get("severity", "MEDIUM")).upper()
            severity = Severity[raw_sev] if raw_sev in Severity.__members__ else Severity.MEDIUM
            category = item.get("category", default_category)
            rule_id = item.get("rule_id")
            mitigation = item.get("mitigation_guidance") or item.get("mitigation")

            file_path = item.get("file_path", "unknown")
            start_line = item.get("start_line")
            end_line = item.get("end_line")
            snippet = item.get("code_snippet")

            provider_str = model_metadata.provider.value if hasattr(model_metadata.provider, "value") else str(model_metadata.provider or "AI")
            grounding_note = item.get("context_notes") or "Deterministic evidence reference validated"
            evidence = Evidence(
                file_path=file_path,
                start_line=int(start_line) if start_line and str(start_line).isdigit() else None,
                end_line=int(end_line) if end_line and str(end_line).isdigit() else None,
                code_snippet=snippet,
                context_notes=(
                    f"{grounding_note}; reasoning_provider={provider_str}; "
                    f"reasoning_model={model_metadata.model_name}"
                ),
            )

            execution_metadata = model_metadata.model_copy(deep=True)
            atomic_claims = claims_from_model_item(item)
            if candidate_evidence is not None and not has_complete_atomic_contract(atomic_claims):
                continue
            if atomic_claims:
                candidate_id = str(item.get("candidate_id") or "")
                execution_metadata.extra_metadata = {
                    **execution_metadata.extra_metadata,
                    "atomic_claims": [claim.model_dump(mode="json") for claim in atomic_claims],
                    "atomic_contract_required": candidate_evidence is not None,
                    "candidate_id": candidate_id or None,
                    "issue_fingerprint": canonical_issue_fingerprint(
                        category=str(category or default_category),
                        detector_identity=candidate_id,
                        file_path=file_path,
                        start_line=evidence.start_line,
                        end_line=evidence.end_line,
                    ),
                }

            finding = Finding(
                scan_id=clean_scan_id,
                title=title,
                description=description,
                severity=severity,
                status=FindingStatus.OPEN,
                rule_id=rule_id,
                category=category,
                evidences=[evidence],
                mitigation_guidance=mitigation,
                source_tool=item.get("source_tool"),
                detector_id=item.get("detector_id") or item.get("candidate_id"),
                detector_kind=item.get("detector_kind") or (
                    "semantic_candidate" if candidate_evidence is not None else None
                ),
                model_metadata=execution_metadata,
            )
            findings.append(finding)
        except Exception:
            continue

    return findings
