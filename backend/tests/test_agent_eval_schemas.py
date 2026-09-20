"""Phase-1 contract tests for isolated Evidence Investigator evaluations."""

import json

import pytest
from pydantic import ValidationError

from app.agent_runtime.schemas import InvestigatorAction, InvestigatorStopReason
from app.agent_tools.schemas import EvidenceType
from app.evaluation.agent.schemas import (
    AgentEvalAnnotation,
    AgentEvalCase,
    AgentEvalDifficulty,
    AgentEvalEvidenceSpec,
    AgentEvalFixture,
    AgentEvalInvestigatorInput,
    AgentEvalSplit,
    ScriptedDecision,
)


def _case(**overrides):
    payload = {
        "case_id": "tool-selection-001",
        "case_family": "TOOL_SELECTION",
        "split": "REGRESSION",
        "category": "bug",
        "difficulty": "EASY",
        "fixture": {
            "repository_url": "https://github.com/fixture/repo",
            "files": {"app.py": "def read_file(value):\n    return value\n"},
        },
        "investigator_input": {
            "title": "Possible unsafe file read",
            "description": "A caller-controlled value may reach the reader.",
            "category": "bug",
            "severity": "HIGH",
            "primary_file": "app.py",
            "primary_start_line": 1,
            "primary_end_line": 2,
            "verifier_uncertainty_reason": "The caller validation path is unresolved.",
        },
        "annotation": {
            "acceptable_stop_reasons": [InvestigatorStopReason.EVIDENCE_GATHERED],
            "required_tools_all": ["read_source_slice"],
            "required_evidence": [{
                "evidence_type": EvidenceType.SOURCE_SLICE,
                "file_path": "app.py",
                "start_line": 1,
                "end_line": 2,
            }],
            "hidden_canary": "CANARY_DO_NOT_LEAK_1234",
        },
        "scripted_decisions": [{
            "action": InvestigatorAction.TOOL_CALL,
            "tool_name": "read_source_slice",
            "arguments": {"file_path": "app.py", "start_line": 1, "end_line": 2},
            "reason": "Read the bounded source slice.",
        }, {
            "action": InvestigatorAction.FINISH,
            "tool_name": None,
            "arguments": {},
            "reason": "The evidence is sufficient for reevaluation.",
        }],
    }
    payload.update(overrides)
    return payload


def test_case_round_trips_with_closed_json_contract():
    case = AgentEvalCase.model_validate(_case())
    restored = AgentEvalCase.model_validate_json(case.model_dump_json())
    assert restored == case
    assert restored.model_dump(mode="json")["annotation"]["hidden_canary"] == "CANARY_DO_NOT_LEAK_1234"


def test_unknown_fields_are_rejected_at_each_boundary():
    payload = _case()
    payload["unexpected"] = True
    with pytest.raises(ValidationError):
        AgentEvalCase.model_validate(payload)

    fixture = payload["fixture"]
    fixture["unexpected"] = True
    with pytest.raises(ValidationError):
        AgentEvalFixture.model_validate(fixture)


@pytest.mark.parametrize("path", ["../secret.py", "/absolute.py", "C:/secret.py", "a//b.py", "a/../b.py"])
def test_fixture_paths_are_repository_relative(path):
    with pytest.raises(ValidationError):
        AgentEvalFixture.model_validate({
            "repository_url": "https://github.com/fixture/repo",
            "files": {path: "x\n"},
        })


def test_primary_file_and_line_range_must_be_valid():
    payload = _case()
    payload["investigator_input"]["primary_file"] = "missing.py"
    with pytest.raises(ValidationError):
        AgentEvalCase.model_validate(payload)

    payload = _case()
    payload["investigator_input"]["primary_end_line"] = 99
    with pytest.raises(ValidationError):
        AgentEvalCase.model_validate(payload)


def test_evidence_specs_use_current_tool_evidence_fields():
    with pytest.raises(ValidationError):
        AgentEvalEvidenceSpec.model_validate({})
    spec = AgentEvalEvidenceSpec.model_validate({
        "evidence_type": "CALL_RELATIONSHIP",
        "source_id": "symbol:source",
        "target_id": "symbol:target",
    })
    assert spec.evidence_type == EvidenceType.CALL_RELATIONSHIP


def test_regression_and_abstention_constraints_are_explicit():
    payload = _case(scripted_decisions=[])
    with pytest.raises(ValidationError):
        AgentEvalCase.model_validate(payload)

    payload = _case()
    payload["annotation"]["expected_abstention"] = True
    with pytest.raises(ValidationError):
        AgentEvalCase.model_validate(payload)


def test_schema_serialization_is_deterministic_for_same_input():
    first = AgentEvalCase.model_validate(_case())
    second = AgentEvalCase.model_validate(json.loads(first.model_dump_json()))
    assert first.model_dump_json() == second.model_dump_json()
