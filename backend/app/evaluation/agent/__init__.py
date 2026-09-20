"""Isolated evaluation contracts and runtime for the production Evidence Investigator."""

from app.evaluation.agent.schemas import (
    AgentEvalAnnotation,
    AgentEvalCase,
    AgentEvalDifficulty,
    AgentEvalDatasetManifest,
    AgentEvalEvidenceSpec,
    AgentEvalFixture,
    AgentEvalInvestigatorInput,
    AgentEvalMode,
    AgentEvalSplit,
    ScriptedDecision,
)
from app.evaluation.agent.loader import AgentEvalDataset, AgentEvalDatasetError, load_agent_dataset
from app.evaluation.agent.fixtures import AgentEvalFixtureRuntime, build_fixture_runtime, fixture_snapshot_id
from app.evaluation.agent.recorder import (
    RecordedToolEvent,
    RecordingAgentToolRegistry,
    ScriptedEvaluationRouter,
    ScriptedRequestRecord,
    ScriptedRouterExhaustedError,
)
from app.evaluation.agent.runner import LiveTrialResult, ScriptedTrialResult, build_investigator_eval_graph, run_live_trial, run_scripted_trial
from app.evaluation.agent.grading import AgentEvalGrade, AgentEvalMetrics, compute_metrics, grade_trial
from app.evaluation.agent.contract import EVALUATION_CONTRACT_VERSION, evaluation_contract_hash, evaluation_contract_payload
from app.evaluation.agent.report import AgentEvalReport, AgentEvalReportMode, report_for_dataset
from app.evaluation.agent.gate import AgentEvalGate, AgentEvalGateError, assert_report_passes_gate, load_gate
from app.evaluation.agent.baseline import (
    AgentEvalBaseline,
    AgentEvalBaselineCase,
    AgentEvalBaselineError,
    assert_report_matches_baseline,
    load_baseline,
)

__all__ = [
    "AgentEvalAnnotation",
    "AgentEvalCase",
    "AgentEvalDifficulty",
    "AgentEvalDatasetManifest",
    "AgentEvalEvidenceSpec",
    "AgentEvalFixture",
    "AgentEvalInvestigatorInput",
    "AgentEvalMode",
    "AgentEvalSplit",
    "ScriptedDecision",
    "AgentEvalDataset",
    "AgentEvalDatasetError",
    "load_agent_dataset",
    "AgentEvalFixtureRuntime",
    "build_fixture_runtime",
    "fixture_snapshot_id",
    "RecordedToolEvent",
    "RecordingAgentToolRegistry",
    "ScriptedEvaluationRouter",
    "ScriptedRequestRecord",
    "ScriptedRouterExhaustedError",
    "ScriptedTrialResult",
    "LiveTrialResult",
    "build_investigator_eval_graph",
    "run_live_trial",
    "run_scripted_trial",
    "AgentEvalGrade",
    "AgentEvalMetrics",
    "compute_metrics",
    "grade_trial",
    "EVALUATION_CONTRACT_VERSION",
    "evaluation_contract_hash",
    "evaluation_contract_payload",
    "AgentEvalReport",
    "AgentEvalReportMode",
    "report_for_dataset",
    "AgentEvalGate",
    "AgentEvalGateError",
    "assert_report_passes_gate",
    "load_gate",
    "AgentEvalBaseline",
    "AgentEvalBaselineCase",
    "AgentEvalBaselineError",
    "assert_report_matches_baseline",
    "load_baseline",
]
