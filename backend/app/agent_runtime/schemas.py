"""Closed, checkpoint-safe contracts for the RepoLens Evidence Investigator."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.agent_runtime.prompts import INVESTIGATOR_PROMPT_VERSION

INVESTIGATOR_DECISION_SCHEMA_VERSION = "investigator-decision/1.0"
INVESTIGATOR_STATE_VERSION = "investigator-state/1.0"
MAX_INVESTIGATOR_TARGETS = 4
MAX_INVESTIGATOR_STEPS = 6
MAX_INVESTIGATOR_TOOL_CALLS = 5


class InvestigatorModel(BaseModel):
    """Closed JSON-compatible base for durable investigator state."""

    model_config = ConfigDict(extra="forbid")


class InvestigatorAction(str, Enum):
    TOOL_CALL = "TOOL_CALL"
    FINISH = "FINISH"
    ABSTAIN = "ABSTAIN"


class InvestigatorStopReason(str, Enum):
    EVIDENCE_GATHERED = "EVIDENCE_GATHERED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    MAX_STEPS = "MAX_STEPS"
    MAX_TOOL_CALLS = "MAX_TOOL_CALLS"
    STUCK = "STUCK"
    TOOL_FAILURE = "TOOL_FAILURE"
    INVALID_MODEL_OUTPUT = "INVALID_MODEL_OUTPUT"
    CONTEXT_BUDGET_EXCEEDED = "CONTEXT_BUDGET_EXCEEDED"
    POLICY_BLOCKED = "POLICY_BLOCKED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    INFRASTRUCTURE_FAILURE = "INFRASTRUCTURE_FAILURE"


class InvestigatorDecision(InvestigatorModel):
    """One model-selected next action; never an authorization grant."""

    action: InvestigatorAction
    tool_name: str | None = Field(default=None, min_length=1, max_length=128)
    arguments: dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(min_length=1, max_length=600)

    @model_validator(mode="after")
    def validate_action_shape(self) -> "InvestigatorDecision":
        if self.action == InvestigatorAction.TOOL_CALL:
            if self.tool_name is None:
                raise ValueError("TOOL_CALL requires tool_name")
        elif self.tool_name is not None or self.arguments:
            raise ValueError("FINISH and ABSTAIN cannot contain a tool request")
        return self


class MemoryKind(str, Enum):
    DETERMINISTIC_FACT = "DETERMINISTIC_FACT"
    MODEL_HYPOTHESIS = "MODEL_HYPOTHESIS"
    OPEN_QUESTION = "OPEN_QUESTION"
    NEGATIVE_RESULT = "NEGATIVE_RESULT"
    COVERAGE_LIMITATION = "COVERAGE_LIMITATION"
    CONTRADICTION = "CONTRADICTION"


class MemoryEntry(InvestigatorModel):
    kind: MemoryKind
    text: str = Field(min_length=1, max_length=800)
    evidence_refs: list[str] = Field(default_factory=list, max_length=16)


class InvestigatorWorkingMemory(InvestigatorModel):
    """Small scan-local memory with explicit fact/hypothesis separation."""

    discovered_symbols: list[str] = Field(default_factory=list, max_length=32)
    important_files: list[str] = Field(default_factory=list, max_length=32)
    entries: list[MemoryEntry] = Field(default_factory=list, max_length=48)
    failed_approaches: list[str] = Field(default_factory=list, max_length=16)


class EvidenceLedgerEntry(InvestigatorModel):
    evidence_id: str | None = Field(default=None, max_length=128)
    source: str = Field(min_length=1, max_length=128)
    tool: str = Field(min_length=1, max_length=128)
    status: str = Field(min_length=1, max_length=64)
    repository_snapshot: str = Field(min_length=1, max_length=128)
    tool_contract_version: str = Field(min_length=1, max_length=32)
    file_path: str | None = Field(default=None, max_length=1024)
    symbol_id: str | None = Field(default=None, max_length=2048)
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    fact_summary: str = Field(min_length=1, max_length=1_200)
    content_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    supports: list[str] = Field(default_factory=list, max_length=12)
    contradicts: list[str] = Field(default_factory=list, max_length=12)
    warnings: list[str] = Field(default_factory=list, max_length=12)


class InvestigatorObservation(InvestigatorModel):
    step_id: str = Field(min_length=1, max_length=128)
    tool_name: str = Field(min_length=1, max_length=128)
    status: str = Field(min_length=1, max_length=64)
    useful_result: dict[str, Any] = Field(default_factory=dict)
    evidence_refs: list[str] = Field(default_factory=list, max_length=32)
    warnings: list[str] = Field(default_factory=list, max_length=16)
    errors: list[str] = Field(default_factory=list, max_length=16)
    result_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    repository_snapshot: str | None = Field(default=None, max_length=128)
    truncated: bool = False
    produced_new_evidence: bool = False
    ledger_entries: list[EvidenceLedgerEntry] = Field(default_factory=list, max_length=32)


class InvestigatorEvidenceArtifact(InvestigatorModel):
    tool_name: str = Field(min_length=1, max_length=128)
    status: str = Field(min_length=1, max_length=64)
    repository_snapshot: str | None = Field(default=None, max_length=128)
    evidence_refs: list[str] = Field(default_factory=list, max_length=32)
    result_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    fact_summary: str = Field(min_length=1, max_length=1_200)
    useful_result: dict[str, Any] = Field(default_factory=dict)


class InvestigatorFindingContext(InvestigatorModel):
    finding_id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=300)
    category: str = Field(default="bug", min_length=1, max_length=128)
    description: str = Field(min_length=1, max_length=2_000)
    severity: str | None = Field(default=None, max_length=32)
    primary_file: str | None = Field(default=None, max_length=1024)
    primary_start_line: int | None = Field(default=None, ge=1)
    primary_end_line: int | None = Field(default=None, ge=1)
    known_evidence_ids: list[str] = Field(default_factory=list, max_length=32)
    atomic_claim_summary: list[str] = Field(default_factory=list, max_length=12)
    repository_snapshot: str = Field(min_length=1, max_length=128)


class VerifierGap(InvestigatorModel):
    finding_id: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=2_000)
    unresolved_claims: list[str] = Field(default_factory=list, max_length=12)


class CompactToolDefinition(InvestigatorModel):
    name: str = Field(min_length=1, max_length=128)
    purpose: str = Field(min_length=1, max_length=600)
    capability: str = Field(min_length=1, max_length=64)
    input_schema: dict[str, Any]


class InvestigatorBudget(InvestigatorModel):
    step_number: int = Field(default=0, ge=0, le=MAX_INVESTIGATOR_STEPS)
    max_steps: int = Field(default=MAX_INVESTIGATOR_STEPS, ge=1, le=MAX_INVESTIGATOR_STEPS)
    tool_calls: int = Field(default=0, ge=0, le=MAX_INVESTIGATOR_TOOL_CALLS)
    max_tool_calls: int = Field(
        default=MAX_INVESTIGATOR_TOOL_CALLS,
        ge=1,
        le=MAX_INVESTIGATOR_TOOL_CALLS,
    )


class InvestigatorContextPack(InvestigatorModel):
    finding: InvestigatorFindingContext
    verifier_gap: VerifierGap
    working_memory: InvestigatorWorkingMemory
    evidence_ledger: list[EvidenceLedgerEntry] = Field(default_factory=list, max_length=64)
    recent_observations: list[InvestigatorObservation] = Field(default_factory=list, max_length=2)
    permitted_tools: list[CompactToolDefinition] = Field(default_factory=list, max_length=10)
    remaining_budget: InvestigatorBudget


class InvestigatorTrajectoryStep(InvestigatorModel):
    step_number: int = Field(ge=1, le=MAX_INVESTIGATOR_STEPS)
    action: InvestigatorAction | None = None
    reason: str = Field(min_length=1, max_length=600)
    tool_name: str | None = Field(default=None, max_length=128)
    argument_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    result_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    evidence_refs: list[str] = Field(default_factory=list, max_length=32)
    provider: str | None = Field(default=None, max_length=64)
    model: str | None = Field(default=None, max_length=128)
    prompt_version: str = INVESTIGATOR_PROMPT_VERSION
    tool_contract_version: str | None = Field(default=None, max_length=32)
    duration_ms: float = Field(default=0.0, ge=0.0)
    status: str = Field(min_length=1, max_length=64)
    remaining_steps: int = Field(ge=0, le=MAX_INVESTIGATOR_STEPS)
    remaining_tool_calls: int = Field(ge=0, le=MAX_INVESTIGATOR_TOOL_CALLS)
    context_metrics: dict[str, Any] = Field(default_factory=dict)
    stop_reason: InvestigatorStopReason | None = None


class InvestigatorResult(InvestigatorModel):
    finding_id: str = Field(min_length=1, max_length=128)
    stop_reason: InvestigatorStopReason
    evidence_refs: list[str] = Field(default_factory=list, max_length=64)
    source_locations: list[str] = Field(default_factory=list, max_length=32)
    important_observations: list[str] = Field(default_factory=list, max_length=16)
    unresolved_uncertainty: list[str] = Field(default_factory=list, max_length=16)
    trajectory_summary: str = Field(min_length=1, max_length=2_000)


class InvestigatorTargetState(InvestigatorModel):
    finding: InvestigatorFindingContext
    verifier_gap: VerifierGap
    budget: InvestigatorBudget = Field(default_factory=InvestigatorBudget)
    pending_decision: InvestigatorDecision | None = None
    pending_observation: InvestigatorObservation | None = None
    pending_call_fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    trajectory: list[InvestigatorTrajectoryStep] = Field(default_factory=list, max_length=MAX_INVESTIGATOR_STEPS)
    evidence_ledger: list[EvidenceLedgerEntry] = Field(default_factory=list, max_length=64)
    working_memory: InvestigatorWorkingMemory = Field(default_factory=InvestigatorWorkingMemory)
    recent_observations: list[InvestigatorObservation] = Field(default_factory=list, max_length=2)
    evidence_artifacts: list[InvestigatorEvidenceArtifact] = Field(default_factory=list, max_length=5)
    call_fingerprints: list[str] = Field(default_factory=list, max_length=MAX_INVESTIGATOR_TOOL_CALLS)
    evidence_digests: list[str] = Field(default_factory=list, max_length=64)
    stop_reason: InvestigatorStopReason | None = None
    result: InvestigatorResult | None = None


class InvestigatorRunState(InvestigatorModel):
    version: str = INVESTIGATOR_STATE_VERSION
    targets: list[str] = Field(default_factory=list, max_length=MAX_INVESTIGATOR_TARGETS)
    target_index: int = Field(default=0, ge=0, le=MAX_INVESTIGATOR_TARGETS)
    active: InvestigatorTargetState | None = None
    results: dict[str, InvestigatorResult] = Field(default_factory=dict)


INVESTIGATOR_DECISION_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["action", "tool_name", "arguments", "reason"],
    "properties": {
        "action": {"type": "string", "enum": [item.value for item in InvestigatorAction]},
        "tool_name": {"type": ["string", "null"], "minLength": 1, "maxLength": 128},
        "arguments": {"type": "object"},
        "reason": {"type": "string", "minLength": 1, "maxLength": 600},
    },
}


__all__ = [name for name in globals() if name.startswith("Investigator") or name in {
    "CompactToolDefinition",
    "EvidenceLedgerEntry",
    "MemoryEntry",
    "MemoryKind",
    "VerifierGap",
    "INVESTIGATOR_DECISION_OUTPUT_SCHEMA",
    "INVESTIGATOR_DECISION_SCHEMA_VERSION",
    "INVESTIGATOR_PROMPT_VERSION",
}]
