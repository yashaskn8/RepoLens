"""Content-safe report contract for deterministic and optional live trials."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from app.evaluation.agent.contract import EVALUATION_CONTRACT_VERSION, evaluation_contract_hash
from app.evaluation.agent.grading import AgentEvalGrade, AgentEvalMetrics
from app.evaluation.agent.loader import AgentEvalDataset


class AgentEvalReportMode(str, Enum):
    SCRIPTED = "SCRIPTED"
    LIVE = "LIVE"


class AgentEvalReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "agent-eval-report/1.0"
    mode: AgentEvalReportMode
    dataset_version: str
    dataset_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    evaluation_contract_version: str = EVALUATION_CONTRACT_VERSION
    evaluation_contract_hash: str = Field(default_factory=evaluation_contract_hash, pattern=r"^[0-9a-f]{64}$")
    grades: list[AgentEvalGrade] = Field(default_factory=list)
    metrics: AgentEvalMetrics
    model_capability_measured: bool = False
    model_capability_status: str = "MODEL CAPABILITY NOT MEASURED"
    live_status: str = "NOT_EXECUTED"


def report_for_dataset(
    dataset: AgentEvalDataset,
    *,
    mode: AgentEvalReportMode,
    grades: list[AgentEvalGrade],
    metrics: AgentEvalMetrics,
    live_status: str = "NOT_EXECUTED",
    model_capability_measured: bool = False,
) -> AgentEvalReport:
    return AgentEvalReport(
        mode=mode,
        dataset_version=dataset.manifest.dataset_version,
        dataset_hash=dataset.dataset_hash,
        grades=grades,
        metrics=metrics,
        model_capability_measured=model_capability_measured,
        model_capability_status=("MEASURED" if model_capability_measured else "MODEL CAPABILITY NOT MEASURED"),
        live_status=live_status,
    )


__all__ = ["AgentEvalReport", "AgentEvalReportMode", "report_for_dataset"]
