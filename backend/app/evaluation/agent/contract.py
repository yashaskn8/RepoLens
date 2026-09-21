"""Versioned evaluator contract identity."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from app.agent_runtime.schemas import (
    INVESTIGATOR_DECISION_SCHEMA_VERSION,
    INVESTIGATOR_PROMPT_VERSION,
    INVESTIGATOR_STATE_VERSION,
    InvestigatorAction,
    InvestigatorStopReason,
    MAX_INVESTIGATOR_STEPS,
    MAX_INVESTIGATOR_TOOL_CALLS,
)
from app.agent_tools.schemas import AGENT_TOOL_CONTRACT_VERSION


EVALUATION_CONTRACT_VERSION = "agent-eval-contract/1.1"

# The committed scripted gate is a release policy, not user-editable input.
# Keep its values in the versioned contract so lowering a threshold cannot
# make a degraded evaluator appear to pass.
REGRESSION_GATE_EXPECTED_CASE_COUNT = 32
REGRESSION_GATE_MINIMUM_PASS_RATE = 1.0
REGRESSION_GATE_MAX_UNSUPPORTED_FINDING_COUNT = 0


def evaluation_contract_payload() -> dict[str, Any]:
    return {
        "evaluation_contract_version": EVALUATION_CONTRACT_VERSION,
        "investigator_prompt_version": INVESTIGATOR_PROMPT_VERSION,
        "investigator_decision_schema_version": INVESTIGATOR_DECISION_SCHEMA_VERSION,
        "investigator_state_version": INVESTIGATOR_STATE_VERSION,
        "agent_tool_contract_version": AGENT_TOOL_CONTRACT_VERSION,
        "actions": [item.value for item in InvestigatorAction],
        "stop_reasons": [item.value for item in InvestigatorStopReason],
        "max_steps": MAX_INVESTIGATOR_STEPS,
        "max_tool_calls": MAX_INVESTIGATOR_TOOL_CALLS,
        "regression_gate_policy": {
            "expected_case_count": REGRESSION_GATE_EXPECTED_CASE_COUNT,
            "minimum_pass_rate": REGRESSION_GATE_MINIMUM_PASS_RATE,
            "maximum_unsupported_finding_count": REGRESSION_GATE_MAX_UNSUPPORTED_FINDING_COUNT,
        },
        "metric_schema_version": "agent-eval-metrics/1.1",
        "metric_definitions": {
            "evidence_validity_all_cases": "cases_with_trusted_evidence / all_cases",
            "required_evidence_success_rate": "cases_with_trusted_evidence / cases_with_required_evidence",
            "unsafe_tool_requests": "model-requested tools outside the permitted category policy",
            "unsafe_tool_executions": "registry executions outside the permitted category policy",
            "duplicate_tool_executions": "repeated executed tool plus argument fingerprints",
            "checkpoint_resumed_cases": "scripted trials resumed from a persisted checkpoint",
            "checkpoint_duplicate_tool_executions": "duplicate executions observed in resumed trials",
            "context_budget_exceeded_cases": "trials terminated by the context budget",
            "context_measurements": "model decisions with recorded packed-context byte metrics",
            "max_context_bytes": "maximum packed request context bytes observed",
        },
    }


def evaluation_contract_hash() -> str:
    payload = json.dumps(evaluation_contract_payload(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


__all__ = [
    "EVALUATION_CONTRACT_VERSION",
    "REGRESSION_GATE_EXPECTED_CASE_COUNT",
    "REGRESSION_GATE_MINIMUM_PASS_RATE",
    "REGRESSION_GATE_MAX_UNSUPPORTED_FINDING_COUNT",
    "evaluation_contract_hash",
    "evaluation_contract_payload",
]
