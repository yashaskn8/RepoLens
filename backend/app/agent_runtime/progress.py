"""Deterministic knowledge-state progress accounting for investigator tools."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Iterable

from app.agent_runtime.schemas import (
    EvidenceLedgerEntry,
    INVESTIGATOR_NO_PROGRESS_WINDOW,
    InvestigatorObservation,
    InvestigatorProgressCertificate,
    InvestigatorProgressClass,
    InvestigatorTargetState,
)


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _path(value: str | None) -> str | None:
    return value.replace("\\", "/").strip("/").casefold() if value else None


def _paths(values: Iterable[str | None]) -> set[str]:
    output: set[str] = set()
    for value in values:
        normalized = _path(value)
        if normalized:
            output.add(normalized)
    return output


def make_knowledge_key(
    *,
    snapshot: str,
    evidence_type: str,
    evidence_id: str | None,
    file_path: str | None,
    symbol_id: str | None,
    start_line: int | None,
    end_line: int | None,
    relationship: str | None,
    source_identity: str | None,
    target_identity: str | None,
) -> str:
    """Create a semantic identity; exclude tool name, result digest and prose."""
    path = _path(file_path)
    if relationship and source_identity and target_identity:
        identity = ["relationship", snapshot, relationship, source_identity, target_identity]
    elif evidence_type in {"AST_FACT"} and symbol_id:
        identity = ["symbol", snapshot, symbol_id]
    elif evidence_type == "SOURCE_LOCATION" and path:
        # A different range in an already-known file is not progress by itself.
        identity = ["file", snapshot, path]
    elif evidence_type == "SOURCE_SLICE" and path:
        # The exact bounded slice is useful evidence; its digest is deliberately
        # excluded so a changed digest becomes a contradiction, not novelty.
        identity = ["source-slice", snapshot, path, start_line, end_line]
    elif evidence_type in {"SCANNER_FINDING", "DATAFLOW_PATH", "CHANGE_FACT"}:
        identity = ["evidence", snapshot, evidence_type, evidence_id]
    elif symbol_id:
        identity = ["symbol", snapshot, symbol_id]
    elif path:
        identity = ["file", snapshot, path]
    else:
        identity = ["evidence", snapshot, evidence_type, evidence_id]
    return _digest(identity)


def knowledge_state_digest(
    target: InvestigatorTargetState,
    entries: Iterable[EvidenceLedgerEntry] | None = None,
) -> str:
    ledger = list(entries if entries is not None else target.evidence_ledger)
    fact_types = {"SOURCE_SLICE", "SCANNER_FINDING", "DATAFLOW_PATH", "CHANGE_FACT"}
    facts = sorted({
        item.knowledge_key for item in ledger
        if item.knowledge_key and item.evidence_type in fact_types
    })
    # Retain changed content as a distinct state only for the same semantic
    # source identity. Tool names, timestamps, model text, and result envelopes
    # never participate in this state digest.
    digests_by_fact: dict[str, set[str]] = {}
    for item in ledger:
        if item.knowledge_key and item.content_digest:
            digests_by_fact.setdefault(item.knowledge_key, set()).add(item.content_digest)
    content_states = sorted(
        (key, tuple(sorted(values)))
        for key, values in digests_by_fact.items()
        if len(values) > 1
    )
    files = _paths((
        target.finding.primary_file,
        *target.working_memory.important_files,
        *(item.file_path for item in ledger),
    ))
    symbols = {
        symbol for symbol in (
            *target.working_memory.discovered_symbols,
            *(item.symbol_id for item in ledger),
        ) if symbol
    }
    negatives = sorted({
        item.knowledge_key for item in ledger
        if item.status == "NOT_FOUND" and item.coverage_complete is True and item.knowledge_key
    })
    relationships = sorted({
        _digest([item.relationship, item.source_identity, item.target_identity])
        for item in ledger
        if item.relationship and item.source_identity and item.target_identity
    })
    coverage_facts = sorted({
        item.knowledge_key for item in ledger
        if item.evidence_type == "COVERAGE_LIMITATION" and item.knowledge_key
    })
    return _digest({
        "snapshot": target.finding.repository_snapshot,
        "files": sorted(files),
        "symbols": sorted(symbols),
        "facts": facts,
        "content_states": content_states,
        "negative_facts": negatives,
        "relationships": relationships,
        "coverage_facts": coverage_facts,
    })


@dataclass(frozen=True, slots=True)
class ProgressAssessment:
    certificate: InvestigatorProgressCertificate
    accepted: bool
    meaningful: bool
    knowledge_state_after: str
    knowledge_state_history: tuple[str, ...]
    consecutive_no_progress: int


def assess_progress(
    target: InvestigatorTargetState,
    observation: InvestigatorObservation,
    incoming: list[EvidenceLedgerEntry],
    *,
    argument_digest: str | None,
) -> ProgressAssessment:
    """Compare deterministic facts only and detect repeated unchanged states."""
    before = knowledge_state_digest(target)
    expected_snapshot = target.finding.repository_snapshot
    snapshot_valid = observation.repository_snapshot == expected_snapshot
    accepted = snapshot_valid
    accepted_entries = incoming if accepted else []
    existing = target.evidence_ledger

    old_files = _paths((
        target.finding.primary_file,
        *target.working_memory.important_files,
        *(item.file_path for item in existing),
    ))
    old_symbols = set(target.working_memory.discovered_symbols) | {
        item.symbol_id for item in existing if item.symbol_id
    }
    old_relations = {
        _digest([item.relationship, item.source_identity, item.target_identity])
        for item in existing if item.relationship and item.source_identity and item.target_identity
    }
    old_keys = {item.knowledge_key for item in existing if item.knowledge_key}
    old_negative_keys = {
        item.knowledge_key for item in existing
        if item.status == "NOT_FOUND" and item.coverage_complete is True and item.knowledge_key
    }

    new_files = {
        _path(item.file_path) for item in accepted_entries
        if item.file_path and _path(item.file_path) not in old_files
    }
    new_symbols = {
        item.symbol_id for item in accepted_entries
        if item.symbol_id and item.symbol_id not in old_symbols
    }
    new_relations = {
        _digest([item.relationship, item.source_identity, item.target_identity])
        for item in accepted_entries
        if item.relationship and item.source_identity and item.target_identity
    } - old_relations
    new_keys = {
        item.knowledge_key for item in accepted_entries
        if item.knowledge_key and item.knowledge_key not in old_keys
    }
    new_negative_keys = {
        item.knowledge_key for item in accepted_entries
        if item.status == "NOT_FOUND" and item.coverage_complete is True and item.knowledge_key
    } - old_negative_keys

    existing_by_key: dict[str, list[EvidenceLedgerEntry]] = {}
    existing_by_id: dict[str, list[EvidenceLedgerEntry]] = {}
    for item in existing:
        if item.knowledge_key:
            existing_by_key.setdefault(item.knowledge_key, []).append(item)
        if item.evidence_id:
            existing_by_id.setdefault(item.evidence_id, []).append(item)
    contradictions = 0
    contradiction_refs: list[str] = []
    for item in accepted_entries:
        prior_items = existing_by_key.get(item.knowledge_key or "", [])
        if not prior_items and item.evidence_id:
            prior_items = existing_by_id.get(item.evidence_id, [])
        if item.content_digest and any(
            prior.content_digest and prior.content_digest != item.content_digest
            for prior in prior_items
        ):
            contradictions += 1
            if item.evidence_id:
                contradiction_refs.append(item.evidence_id)

    novel_evidence_keys = {
        item.knowledge_key for item in accepted_entries
        if item.knowledge_key in new_keys
        and item.evidence_type in {"SOURCE_SLICE", "SCANNER_FINDING", "DATAFLOW_PATH", "CHANGE_FACT"}
    }
    meaningful = bool(
        new_files or new_symbols or new_relations or novel_evidence_keys
        or new_negative_keys or contradictions
    )
    indeterminate = (
        not accepted
        or observation.status in {"INTERNAL_ERROR", "RESOURCE_LIMIT", "INSUFFICIENT_EVIDENCE"}
        or bool(observation.errors)
        or any(item.evidence_type == "COVERAGE_LIMITATION" for item in accepted_entries)
        or (observation.truncated and not meaningful)
    )
    if indeterminate and not meaningful:
        progress_class = InvestigatorProgressClass.INDETERMINATE
    elif contradictions:
        progress_class = InvestigatorProgressClass.CONTRADICTION_PROGRESS
    elif new_negative_keys and not (new_files or new_symbols or new_relations or novel_evidence_keys):
        progress_class = InvestigatorProgressClass.NEGATIVE_PROGRESS
    elif meaningful:
        progress_class = InvestigatorProgressClass.PROGRESS
    elif observation.status == "NOT_FOUND" and any(
        item.status == "NOT_FOUND" and item.coverage_complete is False
        for item in accepted_entries
    ):
        progress_class = InvestigatorProgressClass.INDETERMINATE
    else:
        progress_class = InvestigatorProgressClass.NO_PROGRESS

    next_entries = [*existing, *accepted_entries]
    after = knowledge_state_digest(target, next_entries) if accepted else before
    if progress_class == InvestigatorProgressClass.NO_PROGRESS:
        streak = min(target.consecutive_no_progress + 1, target.budget.max_tool_calls)
        history = list(target.knowledge_state_history) or [before]
        prior_occurrences = history.count(after)
        cycle = streak >= INVESTIGATOR_NO_PROGRESS_WINDOW and prior_occurrences >= 2
        history = [*history, after][- (target.budget.max_tool_calls + 1):]
    else:
        streak = 0
        cycle = False
        history = list(target.knowledge_state_history) or [before]
        if after != history[-1]:
            history = [*history, after][- (target.budget.max_tool_calls + 1):]

    certificate = InvestigatorProgressCertificate(
        step_number=max(1, min(target.budget.step_number, target.budget.max_steps)),
        progress_class=progress_class,
        knowledge_state_before=before,
        knowledge_state_after=after,
        result_digest=observation.result_digest,
        argument_digest=argument_digest,
        new_file_count=len(new_files),
        new_symbol_count=len(new_symbols),
        new_relationship_count=len(new_relations),
        new_evidence_count=len(novel_evidence_keys),
        new_negative_count=len(new_negative_keys),
        contradiction_count=contradictions,
        evidence_refs=list(dict.fromkeys([
            *[item.evidence_id for item in accepted_entries if item.evidence_id],
            *contradiction_refs,
        ]))[:32],
        consecutive_no_progress=streak,
        knowledge_state_cycle=cycle,
    )
    return ProgressAssessment(
        certificate,
        accepted,
        meaningful,
        after,
        tuple(history),
        streak,
    )


__all__ = ["ProgressAssessment", "assess_progress", "knowledge_state_digest", "make_knowledge_key"]
