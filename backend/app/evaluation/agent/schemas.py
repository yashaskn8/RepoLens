"""Closed contracts for the isolated Evidence Investigator evaluation harness.

These models deliberately keep evaluator annotations and scripted decisions
separate from the investigator context.  The loader is responsible for
anti-leakage checks; these schemas provide the first closed, deterministic
boundary and reject malformed cases before a fixture is constructed.
"""

from __future__ import annotations

from enum import Enum
from pathlib import PurePosixPath
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.agent_runtime.schemas import InvestigatorAction, InvestigatorDecision, InvestigatorStopReason
from app.agent_tools.schemas import EvidenceType


class AgentEvalModel(BaseModel):
    """Closed JSON-compatible base for evaluation-only data."""

    model_config = ConfigDict(extra="forbid")


class AgentEvalMode(str, Enum):
    SCRIPTED = "SCRIPTED"
    LIVE = "LIVE"


class AgentEvalSplit(str, Enum):
    REGRESSION = "REGRESSION"
    CAPABILITY = "CAPABILITY"


class AgentEvalDifficulty(str, Enum):
    EASY = "EASY"
    MEDIUM = "MEDIUM"
    HARD = "HARD"


def _validate_relative_fixture_path(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("fixture file paths must be non-empty strings")
    normalized = value.replace("\\", "/")
    if any(part == "" for part in normalized.split("/")):
        raise ValueError("fixture file paths cannot contain empty segments")
    path = PurePosixPath(normalized)
    if normalized.startswith("/") or ":" in normalized.split("/", 1)[0]:
        raise ValueError("fixture file paths must be repository-relative")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("fixture file paths cannot contain traversal or empty segments")
    if "\x00" in normalized:
        raise ValueError("fixture file paths cannot contain NUL bytes")
    return "/".join(path.parts)


class AgentEvalFixture(AgentEvalModel):
    """Repository input only; no expected outcomes or grader instructions."""

    repository_url: str = Field(min_length=1, max_length=512)
    files: dict[str, str] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def validate_fixture(self) -> "AgentEvalFixture":
        normalized: dict[str, str] = {}
        for path, content in self.files.items():
            canonical = _validate_relative_fixture_path(path)
            if canonical in normalized:
                raise ValueError(f"duplicate normalized fixture path: {canonical}")
            if not isinstance(content, str):
                raise ValueError("fixture source contents must be strings")
            normalized[canonical] = content
        self.files = normalized
        if not self.repository_url.startswith("https://"):
            raise ValueError("fixture repository_url must use HTTPS")
        return self


class AgentEvalInvestigatorInput(AgentEvalModel):
    """Only the bounded verifier uncertainty supplied to the real investigator."""

    title: str = Field(min_length=1, max_length=300)
    description: str = Field(min_length=1, max_length=2_000)
    category: str = Field(min_length=1, max_length=128)
    severity: str | None = Field(default=None, max_length=32)
    primary_file: str = Field(min_length=1, max_length=1_024)
    primary_start_line: int = Field(ge=1)
    primary_end_line: int = Field(ge=1)
    verifier_uncertainty_reason: str = Field(min_length=1, max_length=2_000)
    atomic_claim_summaries: list[str] = Field(default_factory=list, max_length=12)

    @model_validator(mode="after")
    def validate_line_range(self) -> "AgentEvalInvestigatorInput":
        self.primary_file = _validate_relative_fixture_path(self.primary_file)
        if self.primary_end_line < self.primary_start_line:
            raise ValueError("primary_end_line must be greater than or equal to primary_start_line")
        return self


class AgentEvalEvidenceSpec(AgentEvalModel):
    """A structural requirement matched against trusted tool evidence."""

    evidence_type: EvidenceType | None = None
    file_path: str | None = Field(default=None, max_length=1_024)
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    symbol: str | None = Field(default=None, max_length=1_024)
    relationship: str | None = Field(default=None, max_length=128)
    source_id: str | None = Field(default=None, max_length=2_048)
    target_id: str | None = Field(default=None, max_length=2_048)

    @model_validator(mode="after")
    def validate_selector(self) -> "AgentEvalEvidenceSpec":
        if self.file_path is not None:
            self.file_path = _validate_relative_fixture_path(self.file_path)
        if self.end_line is not None and self.start_line is None:
            raise ValueError("end_line requires start_line")
        if self.start_line is not None and self.end_line is not None and self.end_line < self.start_line:
            raise ValueError("end_line must be greater than or equal to start_line")
        if not any(
            value is not None
            for value in (
                self.evidence_type,
                self.file_path,
                self.start_line,
                self.symbol,
                self.relationship,
                self.source_id,
                self.target_id,
            )
        ):
            raise ValueError("evidence specification must contain at least one structural selector")
        return self


class AgentEvalAnnotation(AgentEvalModel):
    """Hidden grader expectations; never copied into model-facing state."""

    acceptable_stop_reasons: list[InvestigatorStopReason] = Field(min_length=1, max_length=8)
    required_tools_all: list[str] = Field(default_factory=list, max_length=10)
    required_tools_any: list[str] = Field(default_factory=list, max_length=10)
    forbidden_tool_requests: list[str] = Field(default_factory=list, max_length=16)
    required_evidence: list[AgentEvalEvidenceSpec] = Field(default_factory=list, max_length=16)
    expected_abstention: bool = False
    recovery_required: bool = False
    max_steps: int = Field(default=6, ge=1, le=6)
    max_tool_calls: int = Field(default=5, ge=1, le=5)
    injection_case: bool = False
    durability_case: bool = False
    stuck_case: bool = False
    hidden_canary: str = Field(min_length=16, max_length=256)


class ScriptedDecision(InvestigatorDecision):
    """Evaluator-controlled decision; structurally identical to production output."""

    model_config = ConfigDict(extra="forbid")


class AgentEvalCase(AgentEvalModel):
    """One isolated investigator evaluation case."""

    schema_version: str = Field(default="agent-eval-case/1.0", min_length=1, max_length=64)
    case_id: str = Field(min_length=1, max_length=128)
    case_family: str = Field(min_length=1, max_length=128)
    split: AgentEvalSplit
    category: str = Field(min_length=1, max_length=128)
    difficulty: AgentEvalDifficulty
    fixture: AgentEvalFixture
    investigator_input: AgentEvalInvestigatorInput
    annotation: AgentEvalAnnotation
    scripted_decisions: list[ScriptedDecision] = Field(default_factory=list, max_length=8)

    @model_validator(mode="after")
    def validate_case(self) -> "AgentEvalCase":
        if self.investigator_input.category.lower() != self.category.lower():
            raise ValueError("case category must match investigator_input.category")
        if self.investigator_input.primary_file not in self.fixture.files:
            raise ValueError("primary_file must exist in the fixture")
        line_count = max(1, len(self.fixture.files[self.investigator_input.primary_file].splitlines()))
        if self.investigator_input.primary_end_line > line_count:
            raise ValueError("primary line range exceeds fixture source")
        if self.split == AgentEvalSplit.REGRESSION and not self.scripted_decisions:
            raise ValueError("REGRESSION cases require scripted decisions")
        if self.annotation.expected_abstention and self.annotation.required_evidence:
            raise ValueError("expected abstention cases cannot require evidence")
        if self.annotation.durability_case and not self.scripted_decisions:
            raise ValueError("durability cases require scripted decisions")
        return self


class AgentEvalDatasetManifest(AgentEvalModel):
    """Versioned manifest describing the case inventory and optional hash."""

    schema_version: str = Field(default="agent-eval-manifest/1.0", min_length=1, max_length=64)
    dataset_version: str = Field(min_length=1, max_length=64)
    evaluation_contract_version: str = Field(min_length=1, max_length=64)
    case_files: list[str] = Field(min_length=1, max_length=128)
    dataset_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_case_files(self) -> "AgentEvalDatasetManifest":
        normalized: list[str] = []
        for value in self.case_files:
            if not value.endswith(".json") or "/" in value or "\\" in value or value in {"", ".", ".."}:
                raise ValueError("case_files must contain simple JSON filenames")
            if value in normalized:
                raise ValueError(f"duplicate case file: {value}")
            normalized.append(value)
        self.case_files = normalized
        return self


__all__ = [
    "AgentEvalAnnotation",
    "AgentEvalCase",
    "AgentEvalDifficulty",
    "AgentEvalEvidenceSpec",
    "AgentEvalFixture",
    "AgentEvalInvestigatorInput",
    "AgentEvalMode",
    "AgentEvalSplit",
    "AgentEvalDatasetManifest",
    "ScriptedDecision",
]
