"""Phase-3 real fixture and registry construction tests."""

from pathlib import Path

from app.agent_tools.schemas import ToolResultStatus
from app.evaluation.agent.fixtures import build_fixture_runtime, fixture_snapshot_id
from app.evaluation.agent.schemas import AgentEvalCase


def _case(source: str) -> AgentEvalCase:
    return AgentEvalCase.model_validate({
        "case_id": "fixture-001",
        "case_family": "EVIDENCE_GROUNDING",
        "split": "REGRESSION",
        "category": "bug",
        "difficulty": "EASY",
        "fixture": {
            "repository_url": "https://github.com/fixture/repo",
            "files": {"app.py": source},
        },
        "investigator_input": {
            "title": "Possible unsafe read",
            "description": "A value may reach the file reader.",
            "category": "bug",
            "primary_file": "app.py",
            "primary_start_line": 1,
            "primary_end_line": 2,
            "verifier_uncertainty_reason": "Caller validation is unresolved.",
        },
        "annotation": {
            "acceptable_stop_reasons": ["EVIDENCE_GATHERED", "INSUFFICIENT_EVIDENCE"],
            "hidden_canary": "FIXTURE_CANARY_123456",
        },
        "scripted_decisions": [{
            "action": "ABSTAIN",
            "tool_name": None,
            "arguments": {},
            "reason": "Stop safely.",
        }],
    })


def test_fixture_runtime_builds_real_snapshot_and_registry_without_execution(tmp_path):
    # The source is intentionally hostile-looking; construction only parses and indexes it.
    case = _case("def read(value):\n    raise RuntimeError('must not execute')\n")
    with build_fixture_runtime(case) as runtime:
        assert runtime.snapshot.integrity_valid()
        assert runtime.snapshot.snapshot_id == fixture_snapshot_id(case)
        assert runtime.registry.get_tool("read_source_slice") is not None
        assert (runtime.repository_root / "app.py").read_text(encoding="utf-8").startswith("def read")
        assert runtime.initial_state["commit_hash"] == runtime.snapshot.snapshot_id

        result = runtime.registry.invoke("read_source_slice", {
            "snapshot_id": runtime.snapshot.snapshot_id,
            "file_path": "app.py",
            "start_line": 1,
            "end_line": 2,
        })
        assert result.status == ToolResultStatus.SUCCESS
        assert result.provenance is not None
        assert result.provenance.repository_snapshot == runtime.snapshot.snapshot_id


def test_fixture_snapshot_identity_is_content_deterministic():
    first = _case("def read(value):\n    return value\n")
    second = _case("def read(value):\n    return value\n")
    assert fixture_snapshot_id(first) == fixture_snapshot_id(second)


def test_fixture_registry_keeps_path_confinement():
    case = _case("def read(value):\n    return value\n")
    with build_fixture_runtime(case) as runtime:
        result = runtime.registry.invoke("read_source_slice", {
            "snapshot_id": runtime.snapshot.snapshot_id,
            "file_path": "../secret",
            "start_line": 1,
            "end_line": 1,
        })
        assert result.status in {ToolResultStatus.INVALID_INPUT, ToolResultStatus.INTERNAL_ERROR, ToolResultStatus.UNSUPPORTED}
        assert result.provenance is None or result.provenance.repository_snapshot == runtime.snapshot.snapshot_id
