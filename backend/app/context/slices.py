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
            + item.flow_evidence_refs
            + item.caller_evidence_refs
            + item.callee_evidence_refs
            + item.guard_evidence_refs
            + item.test_evidence_refs
            + item.config_evidence_refs
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
    required = list(dict.fromkeys(candidate.evidence_refs))
    primary = [
        evidence_ref
        for evidence_ref in required
        if evidence_ref in evidence_index
        and bool(evidence_index[evidence_ref].get("file_path"))
        and (
            evidence_index[evidence_ref].get("commit_sha") == commit_sha
        )
    ][:6]
    if not primary or len(primary) != len(required):
        return None

    def linked_refs(key: str, maximum: int, *, expected_kind: str | None = None) -> list[str]:
        raw = candidate.metadata.get(key, [])
        if not isinstance(raw, list):
            return []
        selected: list[str] = []
        for evidence_id in raw:
            if not isinstance(evidence_id, str) or evidence_id in selected:
                continue
            anchor = evidence_index.get(evidence_id)
            if anchor is None or (expected_kind and anchor.get("kind") != expected_kind):
                continue
            if anchor.get("commit_sha") and anchor.get("commit_sha") != commit_sha:
                continue
            selected.append(evidence_id)
            if len(selected) >= maximum:
                break
        return selected

    supporting = linked_refs("supporting_evidence_refs", 6)
    counter = linked_refs("counter_evidence_refs", 4)
    if not counter and candidate.counter_evidence:
        # Textual counter-evidence labels may bind only to the candidate's own
        # anchors, never to an arbitrary repository chunk.
        terms = [value.lower() for value in candidate.counter_evidence if value]
        counter = [
            evidence_id
            for evidence_id in primary
            if any(
                term in str(evidence_index[evidence_id].get("code_snippet") or "").lower()
                for term in terms
            )
        ][:4]
    graph_refs = linked_refs("graph_evidence_refs", 20, expected_kind="graph_edge")
    contract_refs = linked_refs("contract_evidence_refs", 8, expected_kind="contract")
    scanner_refs = linked_refs("scanner_evidence_refs", 10, expected_kind="static_finding")
    flow_refs = linked_refs("flow_evidence_refs", 16)
    caller_refs = linked_refs("caller_evidence_refs", 8)
    callee_refs = linked_refs("callee_evidence_refs", 8)
    guard_refs = linked_refs("guard_evidence_refs", 8)
    test_refs = linked_refs("test_evidence_refs", 8)
    config_refs = linked_refs("config_evidence_refs", 8)
    role_groups = {
        "primary": primary,
        "supporting": supporting,
        "counter": counter,
        "graph": graph_refs,
        "contract": contract_refs,
        "scanner": scanner_refs,
        "flow": flow_refs,
        "caller": caller_refs,
        "callee": callee_refs,
        "guard": guard_refs,
        "test": test_refs,
        "config": config_refs,
    }
    evidence_roles: dict[str, list[str]] = {}
    for role, references in role_groups.items():
        for evidence_id in references:
            evidence_roles.setdefault(evidence_id, []).append(role)
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
        flow_evidence_refs=flow_refs,
        caller_evidence_refs=caller_refs,
        callee_evidence_refs=callee_refs,
        guard_evidence_refs=guard_refs,
        test_evidence_refs=test_refs,
        config_evidence_refs=config_refs,
        evidence_roles=evidence_roles,
        candidate_metadata=dict(candidate.metadata),
        bounds={
            "primary": 6,
            "supporting": 6,
            "counter": 4,
            "graph_edges": 20,
            "contracts": 8,
            "scanner_findings": 10,
            "flow": 16,
            "callers": 8,
            "callees": 8,
            "guards": 8,
            "tests": 8,
            "config": 8,
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
    if token_budget <= 0 or max_candidates <= 0:
        return SpecialistContextPack("", hashlib.sha256(b"").hexdigest(), {}, (), 0, 0)
    selected = []
    seen_issues: set[str] = set()
    for candidate in candidates:
        issue = str(candidate.metadata.get("issue_fingerprint") or candidate.candidate_id)
        if issue in seen_issues or not candidate.evidence_refs:
            continue
        seen_issues.add(issue)
        selected.append(candidate)
        if len(selected) >= max_candidates:
            break
    if not selected:
        return SpecialistContextPack("", hashlib.sha256(b"").hexdigest(), {}, (), 0, 0)
    per_candidate_budget = max(256, (token_budget // len(selected)) - 384)
    slices: list[EvidenceSlice] = []
    contexts: list[dict] = []
    evidence_index: dict[str, dict] = {}
    conflicted_evidence_ids: set[str] = set()

    for candidate in selected:
        declared_refs = list(candidate.evidence_refs)
        for role in ("supporting", "counter", "graph", "contract", "scanner", "flow",
                     "caller", "callee", "guard", "test", "config"):
            values = candidate.metadata.get(f"{role}_evidence_refs", [])
            if isinstance(values, list):
                declared_refs.extend(value for value in values[:20] if isinstance(value, str))
        declared_refs = list(dict.fromkeys(declared_refs))[:16]
        # Non-chunk graph/scanner contracts retain canonical context assembly.
        # Chunk-only candidates need no repository-wide search at all.
        anchor_only = all(ref.startswith("chunk:") for ref in declared_refs)
        bundle = await context_engine.build_context_bundle(
            scan_id=scan_id,
            query=(
                f"{candidate.candidate_kind} {candidate.related_symbol or ''} "
                f"{candidate.deterministic_reason[:160]}"
            ),
            analysis_intent=analysis_intent,
            context_budget=per_candidate_budget,
            max_chunks=max(6, len(declared_refs)),
            required_chunk_ids=declared_refs,
            anchor_only=anchor_only,
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
        allowed = candidate_evidence_authority([evidence_slice])[candidate.candidate_id]
        context = json.loads(packed.text)
        context["facts"] = {
            kind: [fact for fact in facts if fact.get("evidence_id") in allowed]
            for kind, facts in context.get("facts", {}).items()
            if isinstance(facts, list)
        }
        contexts.append({"facts": context["facts"]})
        for evidence_id, fact in packed.evidence_index.items():
            if evidence_id not in allowed:
                continue
            if evidence_id in conflicted_evidence_ids:
                continue
            existing = evidence_index.get(evidence_id)
            if existing is None:
                evidence_index[evidence_id] = dict(fact)
            elif existing != fact:
                # Ambiguous IDs are excluded from the shared authority map.
                evidence_index.pop(evidence_id, None)
                conflicted_evidence_ids.add(evidence_id)

    # Conflicting evidence IDs are never shared across hypotheses. One exact
    # fact appears once in the prompt, while candidate namespaces stay explicit.
    slices = [item for item in slices if not candidate_evidence_authority([item])[item.candidate_id].intersection(conflicted_evidence_ids)]
    while True:
        authority = candidate_evidence_authority(slices)
        retained_ids = set().union(*authority.values()) if authority else set()
        facts_by_kind: dict[str, dict[str, dict]] = {}
        for context in contexts:
            for kind, facts in context["facts"].items():
                for fact in facts:
                    eid = fact.get("evidence_id")
                    if eid in retained_ids and eid not in conflicted_evidence_ids:
                        facts_by_kind.setdefault(kind, {})[eid] = fact
        payload = {
            "schema": "specialist-hypotheses/2.0",
            "hypotheses": [item.model_dump(mode="json") for item in slices],
            "contexts": [{"facts": {kind: list(facts.values()) for kind, facts in facts_by_kind.items()}}],
        }
        text = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        if len(text.encode("utf-8")) <= token_budget * 4 or not slices:
            break
        # Never clip evidence halfway through a claim. Defer a whole candidate.
        slices.pop()
    evidence_index = {eid: fact for eid, fact in evidence_index.items() if eid in retained_ids}
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
