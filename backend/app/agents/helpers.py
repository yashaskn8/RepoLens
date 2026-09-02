"""Helper utilities for parsing LLM structured output into canonical Finding domain models."""

import json
import re
from typing import Any, List
import uuid
from uuid import UUID

from app.schemas.enums import FindingStatus, Severity
from app.schemas.evidence import Evidence
from app.schemas.finding import Finding
from app.schemas.metadata import ModelExecutionMetadata
from app.agents.grounding import EvidenceIndex, ground_model_findings


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


def parse_llm_findings(
    raw_content: str,
    scan_id: Any,
    default_category: str,
    model_metadata: ModelExecutionMetadata,
    evidence_index: EvidenceIndex,
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
                detector_id=item.get("detector_id"),
                detector_kind=item.get("detector_kind"),
                model_metadata=model_metadata,
            )
            findings.append(finding)
        except Exception:
            continue

    return findings
