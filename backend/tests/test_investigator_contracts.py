"""Closed-schema tests for the bounded Evidence Investigator runtime."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.agent_runtime.schemas import (
    InvestigatorAction,
    InvestigatorDecision,
    InvestigatorStopReason,
    InvestigatorTargetState,
    MemoryEntry,
    MemoryKind,
    VerifierGap,
    InvestigatorFindingContext,
)


def test_investigator_decision_enforces_one_action_and_closed_fields():
    call = InvestigatorDecision(
        action=InvestigatorAction.TOOL_CALL,
        tool_name="search_symbol",
        arguments={"query": "parse_token"},
        reason="Need a stable symbol identity before inspecting callers.",
    )
    assert call.action == InvestigatorAction.TOOL_CALL

    for invalid in (
        {"action": "TOOL_CALL", "arguments": {}, "reason": "missing tool"},
        {"action": "FINISH", "tool_name": "search_symbol", "arguments": {}, "reason": "bad"},
        {"action": "ABSTAIN", "arguments": {"x": 1}, "reason": "bad"},
        {"action": "FINISH", "arguments": {}, "reason": "done", "extra": True},
    ):
        with pytest.raises(ValidationError):
            InvestigatorDecision.model_validate(invalid)


def test_investigator_state_json_round_trip_preserves_fact_kinds():
    state = InvestigatorTargetState(
        finding=InvestigatorFindingContext(
            finding_id="finding-1",
            title="Possible unsafe token use",
            category="security",
            description="Verifier could not prove caller validation.",
            repository_snapshot="a" * 40,
        ),
        verifier_gap=VerifierGap(
            finding_id="finding-1",
            reason="Caller validation is unresolved.",
            unresolved_claims=["all callers validate the token"],
        ),
    )
    state.working_memory.entries.extend([
        MemoryEntry(
            kind=MemoryKind.DETERMINISTIC_FACT,
            text="parse_token is defined in auth.py.",
            evidence_refs=["symbol:abc"],
        ),
        MemoryEntry(
            kind=MemoryKind.OPEN_QUESTION,
            text="Do all callers verify the signature?",
        ),
    ])
    restored = InvestigatorTargetState.model_validate_json(state.model_dump_json())
    assert restored.working_memory.entries[0].kind == MemoryKind.DETERMINISTIC_FACT
    assert restored.stop_reason is None
    restored.stop_reason = InvestigatorStopReason.INSUFFICIENT_EVIDENCE
    assert restored.model_dump(mode="json")["stop_reason"] == "INSUFFICIENT_EVIDENCE"
