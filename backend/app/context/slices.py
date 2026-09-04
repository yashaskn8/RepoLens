"""Canonical construction of bounded evidence slices for specialist hypotheses."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import TYPE_CHECKING, Iterable

from app.specialist_candidates import AnalysisCandidate
from app.context.prompt import PackedRepositoryContext, pack_repository_context
from app.context.schemas import EvidenceSlice

if TYPE_CHECKING:
    from app.context.engine import ContextEngine


@dataclass(frozen=True, slots=True)
class SpecialistContextPack:
    """Bounded prompt material shared by candidate-first specialists."""

    text: str
    digest: str
    evidence_index: dict[str, dict]
    slices: tuple[EvidenceSlice, ...]
    estimated_tokens: int
    packed_bytes: int


def candidate_evidence_authority(
    slices: Iterable[EvidenceSlice],
) -> dict[str, set[str]]:
    """Return the exact evidence namespace authorized for each hypothesis."""
    authority: dict[str, set[str]] = {}
    for item in slices:
        authority[item.candidate_id] = set(
            item.primary_evidence_refs
            + item.supporting_evidence_refs
            + item.counter_evidence_refs
            + item.graph_evidence_refs
            + item.contract_evidence_refs
            + item.scanner_evidence_refs
        )
    return authority


def build_evidence_slice(
    *,
    scan_id: str,
    commit_sha: str,
    candidate: AnalysisCandidate,
    packed: PackedRepositoryContext,
) -> EvidenceSlice | None:
    """Bind a deterministic candidate to packed canonical facts, failing closed."""
    evidence_index = packed.evidence_index
    primary = [
        evidence_ref
        for evidence_ref in candidate.evidence_refs
        if evidence_ref in evidence_index
        and bool(evidence_index[evidence_ref].get("file_path"))
        and (
            not evidence_index[evidence_ref].get("commit_sha")
            or evidence_index[evidence_ref].get("commit_sha") == commit_sha
        )
    ][:6]
    if not primary:
        return None

    locatable = [
        evidence_id
        for evidence_id, anchor in evidence_index.items()
        if anchor.get("file_path") and evidence_id not in primary
    ]
    supporting = locatable[:6]
    counter_terms = [value.lower() for value in candidate.counter_evidence if value]
    counter = [
        evidence_id
        for evidence_id, anchor in evidence_index.items()
        if anchor.get("file_path")
        and any(term in str(anchor.get("code_snippet") or "").lower() for term in counter_terms)
    ][:4]
    graph_refs = [
        evidence_id for evidence_id, anchor in evidence_index.items() if anchor.get("kind") == "graph_edge"
    ][:20]
    contract_refs = [
        evidence_id for evidence_id, anchor in evidence_index.items() if anchor.get("kind") == "contract"
    ][:8]
    scanner_refs = [
        evidence_id for evidence_id, anchor in evidence_index.items() if anchor.get("kind") == "static_finding"
    ][:10]
    return EvidenceSlice(
        scan_id=scan_id,
        commit_sha=commit_sha,
        candidate_id=candidate.candidate_id,
        candidate_kind=candidate.candidate_kind,
        deterministic_reason=candidate.deterministic_reason,
        strength=candidate.strength.value,
        primary_evidence_refs=primary,
        supporting_evidence_refs=supporting,
        counter_evidence_refs=counter,
        graph_evidence_refs=graph_refs,
        contract_evidence_refs=contract_refs,
        scanner_evidence_refs=scanner_refs,
        candidate_metadata=dict(candidate.metadata),
        bounds={
            "primary": 6,
            "supporting": 6,
            "counter": 4,
            "graph_edges": 20,
            "contracts": 8,
            "scanner_findings": 10,
        },
    )


async def build_specialist_context(
    *,
    context_engine: "ContextEngine",
    scan_id: str,
    commit_sha: str,
    analysis_intent: str,
    candidates: list[AnalysisCandidate],
    token_budget: int,
    max_candidates: int = 3,
) -> SpecialistContextPack:
    """Retrieve and pack one small compatible candidate batch without losing anchors."""
    selected = candidates[:max_candidates]
    if not selected:
        return SpecialistContextPack("", hashlib.sha256(b"").hexdigest(), {}, (), 0, 0)
    per_candidate_budget = max(256, (token_budget // len(selected)) - 384)
    slices: list[EvidenceSlice] = []
    contexts: list[dict] = []
    evidence_index: dict[str, dict] = {}
    conflicted_evidence_ids: set[str] = set()

    for candidate in selected:
        bundle = await context_engine.build_context_bundle(
            scan_id=scan_id,
            query=(
                f"{candidate.candidate_kind} {candidate.related_symbol or ''} "
                f"{candidate.deterministic_reason[:160]}"
            ),
            analysis_intent=analysis_intent,
            context_budget=per_candidate_budget,
            max_chunks=6,
            required_chunk_ids=candidate.evidence_refs,
        )
        packed = pack_repository_context(bundle, token_budget=per_candidate_budget)
        evidence_slice = build_evidence_slice(
            scan_id=scan_id,
            commit_sha=commit_sha,
            candidate=candidate,
            packed=packed,
        )
        if evidence_slice is None:
            continue
        slices.append(evidence_slice)
        contexts.append(json.loads(packed.text))
        for evidence_id, fact in packed.evidence_index.items():
            if evidence_id in conflicted_evidence_ids:
                continue
            existing = evidence_index.get(evidence_id)
            if existing is None:
                evidence_index[evidence_id] = dict(fact)
            elif existing != fact:
                # Ambiguous IDs are excluded from the shared authority map.
                evidence_index.pop(evidence_id, None)
                conflicted_evidence_ids.add(evidence_id)

    payload = {
        "schema": "specialist-hypotheses/1.0",
        "hypotheses": [item.model_dump(mode="json") for item in slices],
        "contexts": contexts,
    }
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    packed_bytes = len(text.encode("utf-8"))
    return SpecialistContextPack(
        text=text,
        digest=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        evidence_index=evidence_index,
        slices=tuple(slices),
        estimated_tokens=max(1, (packed_bytes + 3) // 4),
        packed_bytes=packed_bytes,
    )


__all__ = [
    "SpecialistContextPack",
    "build_evidence_slice",
    "build_specialist_context",
    "candidate_evidence_authority",
]
