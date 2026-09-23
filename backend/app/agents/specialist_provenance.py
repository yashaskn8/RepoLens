"""Bounded, content-free provenance for specialist evidence opportunities."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.context.slices import SpecialistContextPack
from app.security.redaction import redact_secrets
from app.specialist_candidates import AnalysisCandidate


SpecialistNode = Literal["architecture", "security", "bug"]
SpecialistCompletionReason = Literal[
    "NO_DETERMINISTIC_CANDIDATES",
    "ADMISSION_BLOCKED",
    "NO_CONTEXT_OR_CANDIDATES",
    "NO_PACKED_HYPOTHESES",
    "NO_LOCATABLE_PACKED_EVIDENCE",
    "MODEL_COMPLETED",
    "MODEL_INVALID_OUTPUT",
    "MODEL_FAILURE",
]


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _safe_text(value: Any, limit: int) -> str:
    text = redact_secrets(str(value or ""))
    text = re.sub(r"[\x00-\x1f\x7f]", " ", text)
    return text[:limit]


def _safe_repo_path(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    normalized = value.replace("\\", "/")
    parts = normalized.split("/")
    if (
        normalized.startswith("/")
        or normalized.startswith("//")
        or re.match(r"^[A-Za-z]:", normalized)
        or any(part in {"", ".", ".."} for part in parts)
        or "\x00" in normalized
    ):
        return None
    return _safe_text(normalized, 512)


class SpecialistEvidenceLocation(BaseModel):
    """Source locator for an evidence ID actually included in packed context."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_id: str = Field(min_length=1, max_length=256)
    file_path: str = Field(min_length=1, max_length=512)
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    symbol: str | None = Field(default=None, max_length=256)


class SpecialistCandidateProvenance(BaseModel):
    """Structural projection of one mapper hypothesis; never contains source text."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate_id: str = Field(min_length=1, max_length=128)
    candidate_kind: str = Field(min_length=1, max_length=96)
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=16)
    related_symbol: str | None = Field(default=None, max_length=256)
    candidate_file_path: str | None = Field(default=None, max_length=512)
    candidate_line: int | None = Field(default=None, ge=1)
    packed: bool = False
    packed_evidence_refs: tuple[str, ...] = Field(default=(), max_length=64)
    packed_locations: tuple[SpecialistEvidenceLocation, ...] = Field(default=(), max_length=32)
    evidence_truncated: bool = False


class SpecialistOpportunityRecord(BaseModel):
    """Checkpoint-safe proof of a specialist's bounded deterministic input."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["specialist-opportunity/1.0"] = "specialist-opportunity/1.0"
    node: SpecialistNode
    scan_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_id: str = Field(min_length=1, max_length=128)
    candidate_source: Literal["MAPPER", "LOCAL_BUILDER", "NONE"]
    candidate_count: int = Field(ge=0, le=100_000)
    candidate_inventory_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_inventory_truncated: bool = False
    candidates: tuple[SpecialistCandidateProvenance, ...] = Field(default=(), max_length=64)
    packed_candidate_ids: tuple[str, ...] = Field(default=(), max_length=3)
    context_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    model_attempted: bool = False
    model_succeeded: bool = False
    model_execution_count: int = Field(default=0, ge=0, le=16)
    model_output_candidate_ids: tuple[str, ...] = Field(default=(), max_length=64)
    completion_reason: SpecialistCompletionReason
    record_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_record_digest(self) -> "SpecialistOpportunityRecord":
        expected = _digest(self.model_dump(mode="json", exclude={"record_digest"}))
        if self.record_digest != expected:
            raise ValueError("specialist opportunity digest does not match its content")
        if self.model_succeeded and (not self.model_attempted or self.model_execution_count < 1):
            raise ValueError("successful specialist execution requires a recorded model attempt")
        if self.completion_reason == "MODEL_COMPLETED" and not self.model_succeeded:
            raise ValueError("MODEL_COMPLETED requires a successful model response")
        return self


def _anchor_value(anchor: Any, key: str, default: Any = None) -> Any:
    if isinstance(anchor, dict):
        return anchor.get(key, default)
    return getattr(anchor, key, default)


def build_specialist_opportunity(
    *,
    node: SpecialistNode,
    state: dict[str, Any],
    candidates: list[AnalysisCandidate],
    candidate_source: Literal["MAPPER", "LOCAL_BUILDER", "NONE"],
    completion_reason: SpecialistCompletionReason,
    model_attempted: bool = False,
    model_succeeded: bool = False,
    model_execution_count: int = 0,
    model_output_findings: list[Any] | None = None,
    context: SpecialistContextPack | None = None,
) -> dict[str, Any]:
    """Project only bounded IDs and locators into a deterministic, digest-bound record."""

    slices = {item.candidate_id: item for item in context.slices} if context is not None else {}
    evidence_index = context.evidence_index if context is not None else {}
    rows: list[SpecialistCandidateProvenance] = []
    candidate_projection: list[dict[str, Any]] = []
    for candidate in candidates[:64]:
        candidate_id = _safe_text(candidate.candidate_id, 128)
        candidate_kind = _safe_text(candidate.candidate_kind, 96)
        refs = tuple(dict.fromkeys(_safe_text(item, 256) for item in candidate.evidence_refs[:16] if item))
        evidence_slice = slices.get(candidate.candidate_id)
        packed_refs: list[str] = []
        if evidence_slice is not None:
            for field in (
                "primary_evidence_refs", "supporting_evidence_refs", "counter_evidence_refs",
                "graph_evidence_refs", "contract_evidence_refs", "scanner_evidence_refs",
                "flow_evidence_refs", "caller_evidence_refs", "callee_evidence_refs",
                "guard_evidence_refs", "test_evidence_refs", "config_evidence_refs",
            ):
                packed_refs.extend(getattr(evidence_slice, field, ()) or ())
        packed_refs = list(dict.fromkeys(_safe_text(item, 256) for item in packed_refs if item))[:64]
        locations: list[SpecialistEvidenceLocation] = []
        for evidence_id in packed_refs:
            anchor = evidence_index.get(evidence_id)
            if anchor is None:
                continue
            path = _safe_repo_path(_anchor_value(anchor, "file_path"))
            if path is None:
                continue
            raw_symbol = _anchor_value(anchor, "symbol")
            symbol = _safe_text(raw_symbol, 256) if raw_symbol else None
            start = _anchor_value(anchor, "start_line")
            end = _anchor_value(anchor, "end_line")
            if isinstance(start, bool) or not isinstance(start, int) or start < 1:
                start = None
            if isinstance(end, bool) or not isinstance(end, int) or end < 1:
                end = None
            locations.append(SpecialistEvidenceLocation(
                evidence_id=evidence_id,
                file_path=path,
                start_line=start,
                end_line=end,
                symbol=symbol,
            ))
            if len(locations) >= 32:
                break

        metadata = candidate.metadata if isinstance(candidate.metadata, dict) else {}
        candidate_path = _safe_repo_path(metadata.get("file_path"))
        raw_line = metadata.get("source_line", metadata.get("start_line"))
        candidate_line = raw_line if isinstance(raw_line, int) and not isinstance(raw_line, bool) and raw_line >= 1 else None
        raw_symbol = candidate.related_symbol
        symbol = _safe_text(raw_symbol, 256) if raw_symbol else None
        record = SpecialistCandidateProvenance(
            candidate_id=candidate_id,
            candidate_kind=candidate_kind,
            evidence_refs=refs,
            related_symbol=symbol,
            candidate_file_path=candidate_path,
            candidate_line=candidate_line,
            packed=evidence_slice is not None,
            packed_evidence_refs=tuple(packed_refs),
            packed_locations=tuple(locations),
            evidence_truncated=bool(
                context is not None and candidate_id in context.truncated_candidate_ids
            ),
        )
        rows.append(record)
        candidate_projection.append(record.model_dump(mode="json"))

    model_output_ids: list[str] = []
    for finding in (model_output_findings or [])[:64]:
        raw_id = getattr(finding, "id", None)
        if raw_id is None and isinstance(finding, dict):
            raw_id = finding.get("finding_id") or finding.get("id")
        if raw_id is not None:
            model_output_ids.append(_safe_text(raw_id, 128))

    payload: dict[str, Any] = {
        "schema_version": "specialist-opportunity/1.0",
        "node": node,
        "scan_digest": hashlib.sha256(_safe_text(state.get("scan_id"), 256).encode("utf-8")).hexdigest(),
        "snapshot_id": _safe_text(state.get("commit_hash") or "unknown-snapshot", 128),
        "candidate_source": candidate_source,
        "candidate_count": len(candidates),
        "candidate_inventory_digest": _digest({
            "count": len(candidates),
            "candidates": candidate_projection,
            "truncated": len(candidates) > 64,
        }),
        "candidate_inventory_truncated": len(candidates) > 64,
        "candidates": [item.model_dump(mode="json") for item in rows],
        "packed_candidate_ids": [
            _safe_text(item.candidate_id, 128) for item in (context.slices if context else ())
        ][:3],
        "context_digest": context.digest if context is not None else None,
        "model_attempted": model_attempted,
        "model_succeeded": model_succeeded,
        "model_execution_count": max(0, min(model_execution_count, 16)),
        "model_output_candidate_ids": list(dict.fromkeys(model_output_ids)),
        "completion_reason": completion_reason,
    }
    payload["record_digest"] = _digest(payload)
    return SpecialistOpportunityRecord.model_validate(payload).model_dump(mode="json")


__all__ = [
    "SpecialistCandidateProvenance",
    "SpecialistCompletionReason",
    "SpecialistEvidenceLocation",
    "SpecialistNode",
    "SpecialistOpportunityRecord",
    "build_specialist_opportunity",
]
