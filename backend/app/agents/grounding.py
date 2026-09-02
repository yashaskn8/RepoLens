"""Fail-closed grounding for specialist model findings.

Models may choose which deterministic facts support a claim, but they are not
authoritative for repository locations or detector provenance.  This module
binds exact model citations back to the immutable evidence index produced by
the context packer before a finding reaches the canonical parser.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from app.context.prompt import PackedRepositoryContext


class EvidenceGroundingError(ValueError):
    """Raised when a trusted evidence index is ambiguous or malformed."""


@dataclass(frozen=True, slots=True)
class EvidenceAnchor:
    """Immutable, authoritative source location and detector provenance."""

    evidence_id: str
    kind: str
    file_path: str | None
    start_line: int | None
    end_line: int | None
    code_snippet: str | None
    source_tool: str
    detector_id: str
    detector_kind: str
    content_hash: str | None = None
    commit_sha: str | None = None
    title: str | None = None
    description: str | None = None
    severity: str | None = None
    rule_id: str | None = None
    category: str | None = None
    mitigation: str | None = None

    @property
    def is_locatable(self) -> bool:
        """Whether this fact can safely back a canonical Finding evidence."""
        return isinstance(self.file_path, str) and bool(self.file_path)


EvidenceIndex = Mapping[str, EvidenceAnchor]
EvidenceIndexValue = EvidenceAnchor | Mapping[str, Any]


def _optional_line(value: Any, *, field_name: str, evidence_id: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise EvidenceGroundingError(
            f"Evidence {evidence_id!r} has invalid {field_name}; expected a positive integer or null"
        )
    return value


def _optional_string(value: Any, *, field_name: str, evidence_id: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise EvidenceGroundingError(
            f"Evidence {evidence_id!r} has invalid {field_name}; expected a string or null"
        )
    return value


def _fallback_provenance(kind: str, evidence_id: str, payload: Mapping[str, Any]) -> tuple[str, str, str]:
    source_tool = payload.get("source_tool")
    detector_id = payload.get("detector_id")
    detector_kind = payload.get("detector_kind")

    if kind == "static_finding":
        source_tool = source_tool or payload.get("tool") or "static_scanner"
        detector_id = detector_id or payload.get("rule_id") or evidence_id
        detector_kind = detector_kind or "static_scanner"
    elif kind == "contract":
        source_tool = source_tool or "route_contract"
        detector_id = detector_id or evidence_id
        detector_kind = detector_kind or "contract_matcher"
    elif kind == "chunk":
        source_tool = source_tool or "repository_context"
        detector_id = detector_id or evidence_id
        detector_kind = detector_kind or "retrieved_code"
    elif kind == "graph_edge":
        source_tool = source_tool or "repository_graph"
        detector_id = detector_id or evidence_id
        detector_kind = detector_kind or "graph_relationship"
    else:
        source_tool = source_tool or "deterministic_evidence"
        detector_id = detector_id or evidence_id
        detector_kind = detector_kind or kind or "deterministic_fact"

    values = (source_tool, detector_id, detector_kind)
    if not all(isinstance(value, str) and value for value in values):
        raise EvidenceGroundingError(f"Evidence {evidence_id!r} has invalid detector provenance")
    return values


def _anchor_from_mapping(evidence_id: str, payload: Mapping[str, Any]) -> EvidenceAnchor:
    embedded_id = payload.get("evidence_id")
    if embedded_id is not None and embedded_id != evidence_id:
        raise EvidenceGroundingError(
            f"Evidence index key {evidence_id!r} conflicts with embedded ID {embedded_id!r}"
        )

    kind = payload.get("kind", "deterministic_fact")
    if not isinstance(kind, str) or not kind:
        raise EvidenceGroundingError(f"Evidence {evidence_id!r} has invalid kind")

    file_path = _optional_string(payload.get("file_path"), field_name="file_path", evidence_id=evidence_id)
    start_line = _optional_line(payload.get("start_line"), field_name="start_line", evidence_id=evidence_id)
    end_line = _optional_line(payload.get("end_line"), field_name="end_line", evidence_id=evidence_id)
    if start_line is not None and end_line is not None and end_line < start_line:
        raise EvidenceGroundingError(f"Evidence {evidence_id!r} ends before it starts")
    code_snippet = _optional_string(
        payload.get("code_snippet"),
        field_name="code_snippet",
        evidence_id=evidence_id,
    )
    source_tool, detector_id, detector_kind = _fallback_provenance(kind, evidence_id, payload)
    return EvidenceAnchor(
        evidence_id=evidence_id,
        kind=kind,
        file_path=file_path,
        start_line=start_line,
        end_line=end_line,
        code_snippet=code_snippet,
        source_tool=source_tool,
        detector_id=detector_id,
        detector_kind=detector_kind,
        content_hash=_optional_string(
            payload.get("content_hash"), field_name="content_hash", evidence_id=evidence_id
        ),
        commit_sha=_optional_string(
            payload.get("commit_sha"), field_name="commit_sha", evidence_id=evidence_id
        ),
        title=_optional_string(payload.get("title"), field_name="title", evidence_id=evidence_id),
        description=_optional_string(
            payload.get("description"),
            field_name="description",
            evidence_id=evidence_id,
        ),
        severity=_optional_string(payload.get("severity"), field_name="severity", evidence_id=evidence_id),
        rule_id=_optional_string(payload.get("rule_id"), field_name="rule_id", evidence_id=evidence_id),
        category=_optional_string(payload.get("category"), field_name="category", evidence_id=evidence_id),
        mitigation=_optional_string(
            payload.get("mitigation"), field_name="mitigation", evidence_id=evidence_id
        ),
    )


def build_evidence_index(
    source: PackedRepositoryContext | Mapping[str, EvidenceIndexValue],
) -> EvidenceIndex:
    """Copy and freeze a packed or explicit evidence index.

    Conflicting embedded IDs and malformed locations fail closed.  The returned
    mapping and its values cannot be mutated after construction, and no object
    from the caller's mutable mapping is retained.
    """
    raw_index: Mapping[str, EvidenceIndexValue]
    if isinstance(source, PackedRepositoryContext):
        raw_index = source.evidence_index
    elif isinstance(source, Mapping):
        raw_index = source
    else:
        raise TypeError("source must be PackedRepositoryContext or an evidence mapping")

    anchors: dict[str, EvidenceAnchor] = {}
    for evidence_id, value in raw_index.items():
        if not isinstance(evidence_id, str) or not evidence_id:
            raise EvidenceGroundingError("Evidence index IDs must be non-empty strings")
        if isinstance(value, EvidenceAnchor):
            if value.evidence_id != evidence_id:
                raise EvidenceGroundingError(
                    f"Evidence index key {evidence_id!r} conflicts with anchor ID {value.evidence_id!r}"
                )
            anchor = _anchor_from_mapping(
                evidence_id,
                {
                    "evidence_id": value.evidence_id,
                    "kind": value.kind,
                    "file_path": value.file_path,
                    "start_line": value.start_line,
                    "end_line": value.end_line,
                    "code_snippet": value.code_snippet,
                    "source_tool": value.source_tool,
                    "detector_id": value.detector_id,
                    "detector_kind": value.detector_kind,
                    "content_hash": value.content_hash,
                    "commit_sha": value.commit_sha,
                    "title": value.title,
                    "description": value.description,
                    "severity": value.severity,
                    "rule_id": value.rule_id,
                    "category": value.category,
                    "mitigation": value.mitigation,
                },
            )
        elif isinstance(value, Mapping):
            anchor = _anchor_from_mapping(evidence_id, value)
        else:
            raise EvidenceGroundingError(f"Evidence {evidence_id!r} must be a mapping or EvidenceAnchor")
        anchors[evidence_id] = anchor
    return MappingProxyType(anchors)


def _safe_reference_note(anchor: EvidenceAnchor) -> str:
    evidence_id = anchor.evidence_id
    printable = "".join(character if character.isprintable() else "?" for character in evidence_id)
    parts = [f"evidence_ref={printable[:256]}"]
    if anchor.commit_sha:
        parts.append(f"commit={anchor.commit_sha[:64]}")
    if anchor.content_hash:
        parts.append(f"sha256={anchor.content_hash[:64]}")
    return "Deterministically grounded: " + "; ".join(parts)


def _valid_references(item: Mapping[str, Any], evidence_index: EvidenceIndex) -> list[str]:
    raw_refs = item.get("evidence_refs")
    if not isinstance(raw_refs, list):
        return []

    valid: list[str] = []
    seen: set[str] = set()
    for reference in raw_refs:
        # Deliberately do not strip, case-fold, normalize, or accept aliases.
        if isinstance(reference, str) and reference in evidence_index and reference not in seen:
            valid.append(reference)
            seen.add(reference)
    return valid


def _primary_anchor(references: list[str], evidence_index: EvidenceIndex) -> EvidenceAnchor | None:
    locatable = [evidence_index[reference] for reference in references if evidence_index[reference].is_locatable]
    if not locatable:
        return None
    # Scanner coordinates and rule provenance are stronger than a retrieved
    # excerpt when a model cites both for the same claim.
    return next((anchor for anchor in locatable if anchor.kind == "static_finding"), locatable[0])


def ground_model_findings(
    raw_findings: Iterable[Mapping[str, Any]],
    evidence_index: EvidenceIndex | Mapping[str, EvidenceIndexValue],
) -> list[dict[str, Any]]:
    """Return only exactly cited, locatable findings with authoritative evidence.

    Unknown references are removed.  A finding with no exact known reference,
    or with only non-locatable facts such as graph edges, is rejected.  Model
    supplied file paths, line numbers, snippets, and detector metadata are
    always overwritten by the selected deterministic evidence anchor.
    """
    frozen_index = (
        evidence_index
        if isinstance(evidence_index, MappingProxyType)
        and all(isinstance(value, EvidenceAnchor) for value in evidence_index.values())
        else build_evidence_index(evidence_index)
    )

    grounded: list[dict[str, Any]] = []
    for raw_item in raw_findings:
        if not isinstance(raw_item, Mapping):
            continue
        references = _valid_references(raw_item, frozen_index)
        primary = _primary_anchor(references, frozen_index)
        if primary is None:
            continue

        item = dict(raw_item)
        item.update(
            {
                "evidence_refs": references,
                "primary_evidence_ref": primary.evidence_id,
                "file_path": primary.file_path,
                "start_line": primary.start_line,
                "end_line": primary.end_line,
                "code_snippet": primary.code_snippet,
                "source_tool": primary.source_tool,
                "detector_id": primary.detector_id,
                "detector_kind": primary.detector_kind,
                "context_notes": _safe_reference_note(primary),
            }
        )
        if primary.kind == "static_finding":
            # Scanner facts outrank model prose and classification whenever the
            # packed index carries those canonical fields.
            if primary.title is not None:
                item["title"] = primary.title
            if primary.description is not None:
                item["description"] = primary.description
            if primary.severity is not None:
                item["severity"] = primary.severity
            if primary.rule_id is not None:
                item["rule_id"] = primary.rule_id
            if primary.category is not None:
                item["category"] = primary.category
            if primary.mitigation is not None:
                item["mitigation_guidance"] = primary.mitigation
            item["tool"] = primary.source_tool
        grounded.append(item)
    return grounded


__all__ = [
    "EvidenceAnchor",
    "EvidenceGroundingError",
    "EvidenceIndex",
    "build_evidence_index",
    "ground_model_findings",
]
