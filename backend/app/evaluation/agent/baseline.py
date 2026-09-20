"""Committed trajectory baseline validation."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from app.evaluation.agent.report import AgentEvalReport


class AgentEvalBaselineCase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(min_length=1, max_length=128)
    stop_reason: str = Field(min_length=1, max_length=64)
    tool_names: list[str] = Field(default_factory=list, max_length=8)


class AgentEvalBaseline(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "agent-eval-baseline/1.0"
    dataset_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    evaluation_contract_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    cases: list[AgentEvalBaselineCase] = Field(min_length=1, max_length=128)


class AgentEvalBaselineError(ValueError):
    pass


def load_baseline(path: str | Path) -> AgentEvalBaseline:
    try:
        baseline = AgentEvalBaseline.model_validate_json(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise AgentEvalBaselineError(f"invalid scripted baseline: {exc}") from exc
    ids = [item.case_id for item in baseline.cases]
    if len(ids) != len(set(ids)):
        raise AgentEvalBaselineError("scripted baseline contains duplicate case IDs")
    return baseline


def assert_report_matches_baseline(report: AgentEvalReport, baseline: AgentEvalBaseline) -> None:
    if report.dataset_hash != baseline.dataset_hash or report.evaluation_contract_hash != baseline.evaluation_contract_hash:
        raise AgentEvalBaselineError("report identity differs from committed scripted baseline")
    actual = {
        item.case_id: (item.stop_reason.value if item.stop_reason else None, item.tool_names)
        for item in report.grades
    }
    expected = {item.case_id: (item.stop_reason, item.tool_names) for item in baseline.cases}
    if actual != expected:
        raise AgentEvalBaselineError("scripted trajectory differs from committed baseline")


__all__ = ["AgentEvalBaseline", "AgentEvalBaselineCase", "AgentEvalBaselineError", "assert_report_matches_baseline", "load_baseline"]
