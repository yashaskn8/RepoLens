"""Phase-2 loader, hashing, and anti-leakage tests."""

import json
from pathlib import Path

import pytest

from app.evaluation.agent.loader import (
    AgentEvalDatasetError,
    compute_dataset_hash,
    load_agent_dataset,
    public_case_payload,
)
from app.evaluation.agent.schemas import AgentEvalCase


def _case(case_id="case-001", source="def read(value):\n    return value\n"):
    return {
        "case_id": case_id,
        "case_family": "TOOL_SELECTION",
        "split": "REGRESSION",
        "category": "bug",
        "difficulty": "EASY",
        "fixture": {
            "repository_url": "https://github.com/fixture/repo",
            "files": {"app.py": source},
        },
        "investigator_input": {
            "title": "Possible issue",
            "description": "The verifier needs one more source fact.",
            "category": "bug",
            "primary_file": "app.py",
            "primary_start_line": 1,
            "primary_end_line": 2,
            "verifier_uncertainty_reason": "Caller validation is unresolved.",
        },
        "annotation": {
            "acceptable_stop_reasons": ["EVIDENCE_GATHERED"],
            "hidden_canary": "HIDDEN_CANARY_CASE_001",
        },
        "scripted_decisions": [{
            "action": "ABSTAIN",
            "tool_name": None,
            "arguments": {},
            "reason": "No safe additional evidence is required.",
        }],
    }


def _write_dataset(root: Path, payloads, *, declared_hash=None, order=None):
    cases_dir = root / "cases"
    cases_dir.mkdir(parents=True)
    filenames = order or [f"case-{index}.json" for index in range(len(payloads))]
    for filename, payload in zip(filenames, payloads):
        (cases_dir / filename).write_text(json.dumps(payload), encoding="utf-8")
    manifest = {
        "dataset_version": "v1",
        "evaluation_contract_version": "agent-eval-contract/1.0",
        "case_files": filenames,
    }
    if declared_hash is not None:
        manifest["dataset_hash"] = declared_hash
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def test_loader_accepts_valid_dataset_and_excludes_hidden_controls_from_public_payload(tmp_path):
    payload = _case()
    _write_dataset(tmp_path, [payload])
    dataset = load_agent_dataset(tmp_path)
    assert dataset.dataset_hash == compute_dataset_hash(dataset.cases)
    public = public_case_payload(dataset.cases[0])
    serialized = json.dumps(public)
    assert "annotation" not in serialized
    assert "scripted_decisions" not in serialized
    assert dataset.cases[0].case_id not in serialized


def test_dataset_hash_is_stable_across_manifest_file_order(tmp_path):
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    payloads = [_case("case-a"), _case("case-b", "def other(value):\n    return value\n")]
    _write_dataset(first_root, payloads, order=["a.json", "b.json"])
    _write_dataset(second_root, list(reversed(payloads)), order=["b.json", "a.json"])
    assert load_agent_dataset(first_root).dataset_hash == load_agent_dataset(second_root).dataset_hash


def test_dataset_mutation_changes_hash(tmp_path):
    _write_dataset(tmp_path, [_case()])
    initial = load_agent_dataset(tmp_path).dataset_hash
    path = tmp_path / "cases" / "case-0.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["fixture"]["files"]["app.py"] += "\n# changed\n"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert load_agent_dataset(tmp_path).dataset_hash != initial


def test_declared_hash_mismatch_fails_closed(tmp_path):
    _write_dataset(tmp_path, [_case()], declared_hash="0" * 64)
    with pytest.raises(AgentEvalDatasetError, match="hash mismatch"):
        load_agent_dataset(tmp_path)


def test_duplicate_case_ids_fail_closed(tmp_path):
    _write_dataset(tmp_path, [_case("same"), _case("same")])
    with pytest.raises(AgentEvalDatasetError, match="duplicate case_id"):
        load_agent_dataset(tmp_path)


@pytest.mark.parametrize("location", ["fixture", "investigator", "scripted"])
def test_hidden_canary_leakage_fails_closed(tmp_path, location):
    payload = _case()
    canary = payload["annotation"]["hidden_canary"]
    if location == "fixture":
        payload["fixture"]["files"]["app.py"] = f"# {canary}\nreturn_value = 1\n"
    elif location == "investigator":
        payload["investigator_input"]["description"] = canary
    else:
        payload["scripted_decisions"][0]["reason"] = canary
    _write_dataset(tmp_path, [payload])
    with pytest.raises(AgentEvalDatasetError, match="hidden canary leaked"):
        load_agent_dataset(tmp_path)


def test_loader_does_not_silently_accept_missing_case_file(tmp_path):
    root = tmp_path
    (root / "cases").mkdir()
    (root / "manifest.json").write_text(json.dumps({
        "dataset_version": "v1",
        "evaluation_contract_version": "agent-eval-contract/1.0",
        "case_files": ["missing.json"],
    }), encoding="utf-8")
    with pytest.raises(AgentEvalDatasetError, match="missing or unsafe"):
        load_agent_dataset(root)
