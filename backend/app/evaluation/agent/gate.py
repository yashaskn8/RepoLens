"""Deterministic CI regression-gate validation for scripted reports."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from app.evaluation.agent.contract import (
    REGRESSION_GATE_EXPECTED_CASE_COUNT,
    REGRESSION_GATE_MAX_UNSUPPORTED_FINDING_COUNT,
    REGRESSION_GATE_MINIMUM_PASS_RATE,
    evaluation_contract_hash,
)
from app.evaluation.agent.report import AgentEvalReport


class AgentEvalGate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "agent-eval-gate/1.0"
    dataset_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    evaluation_contract_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    minimum_pass_rate: float = Field(ge=0.0, le=1.0)
    maximum_unsupported_finding_count: int = Field(ge=0)
    expected_case_count: int = Field(ge=1)


class AgentEvalGateError(ValueError):
    pass


def load_gate(path: str | Path) -> AgentEvalGate:
    try:
        return AgentEvalGate.model_validate_json(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise AgentEvalGateError(f"invalid evaluator gate: {exc}") from exc


def assert_report_passes_gate(report: AgentEvalReport, gate: AgentEvalGate) -> None:
    failures: list[str] = []
    current_contract_hash = evaluation_contract_hash()
    if gate.evaluation_contract_hash != current_contract_hash:
        failures.append("committed regression gate uses a stale evaluation contract hash")
    if gate.expected_case_count != REGRESSION_GATE_EXPECTED_CASE_COUNT:
        failures.append("committed regression gate case-count policy was changed")
    if gate.minimum_pass_rate != REGRESSION_GATE_MINIMUM_PASS_RATE:
        failures.append("committed regression gate pass-rate policy was changed")
    if gate.maximum_unsupported_finding_count != REGRESSION_GATE_MAX_UNSUPPORTED_FINDING_COUNT:
        failures.append("committed regression gate unsupported-finding policy was changed")
    if report.dataset_hash != gate.dataset_hash:
        failures.append("dataset hash differs from the committed regression gate")
    if report.evaluation_contract_hash != gate.evaluation_contract_hash:
        failures.append("evaluation contract hash differs from the committed regression gate")
    if report.metrics.case_count != gate.expected_case_count:
        failures.append("case count differs from the committed regression gate")
    if report.metrics.pass_rate < gate.minimum_pass_rate:
        failures.append("pass rate is below the committed regression gate")
    if report.metrics.unsupported_finding_count > gate.maximum_unsupported_finding_count:
        failures.append("unsupported finding count exceeds the committed regression gate")
    if not all(item.passed for item in report.grades):
        failures.append("one or more deterministic trajectory graders failed")
    if failures:
        raise AgentEvalGateError("; ".join(failures))


__all__ = ["AgentEvalGate", "AgentEvalGateError", "assert_report_passes_gate", "load_gate"]
