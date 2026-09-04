"""Focused acceptance tests for adaptive compute and evidence reuse."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from uuid import uuid4

import pytest

from app.analysis.reuse import changed_files_by_hash, exact_reuse_key, revalidate_finding
from app.analysis.authority import compatibility_digest
from app.llm.economy import WorkflowCloudBudget
from app.llm.types import LLMProvider
from app.agents.state import merge_cloud_budget
from app.schemas.enums import FindingStatus, Severity, VerificationVerdict
from app.schemas.evidence import Evidence
from app.schemas.finding import Finding
from app.services.finding_grounding import build_grounding_context_notes


def _authorities() -> dict[str, str]:
    return {
        "ingestion": "manifest-source",
        "parser": "parser-source",
        "scanner": "scanner-config",
        "analysis_policy": "policy-source",
        "graph": "graph-source",
        "verifier": "verifier-source",
        "detectors": "detectors-source",
        "prompt_schema": "prompt-schema",
        "runtime_policy": "policy-1",
    }


def test_exact_reuse_requires_all_authorities() -> None:
    assert exact_reuse_key(
        tenant_id="tenant-a",
        repository_id="repo-a",
        commit_sha="a" * 40,
        authorities={"parser": "only-one"},
    ) is None
    key = exact_reuse_key(
        tenant_id="tenant-a",
        repository_id="repo-a",
        commit_sha="a" * 40,
        authorities=_authorities(),
    )
    assert key and len(key) == 64


def test_compatibility_authority_excludes_only_commit() -> None:
    first = {**_authorities(), "repository": "repo", "tenant": "tenant", "commit": "a" * 40}
    second = {**first, "commit": "b" * 40}
    assert compatibility_digest(first) == compatibility_digest(second)
    assert compatibility_digest({**first, "verifier": "changed"}) != compatibility_digest(first)


def test_budget_snapshot_hydrates_monotonically() -> None:
    budget = WorkflowCloudBudget.from_snapshot(
        {"mode": "strict", "max_cloud_calls": 3, "max_cloud_tokens": 100, "used_cloud_calls": 2, "used_cloud_tokens": 40}
    )
    budget.hydrate({"used_cloud_calls": 1, "used_cloud_tokens": 10})
    assert budget.snapshot().used_cloud_calls == 2
    assert budget.snapshot().used_cloud_tokens == 40
    budget.hydrate({"used_cloud_calls": 3, "used_cloud_tokens": 90})
    assert budget.snapshot().exhausted is True


def test_budget_resume_retains_original_ceiling_and_value_order() -> None:
    budget = WorkflowCloudBudget(
        mode="strict",
        max_cloud_calls=5,
        max_cloud_tokens=500,
    )
    budget.set_schedule({"architecture": 40, "security_reasoning": 100, "verification": 95})
    budget.hydrate({"max_cloud_calls": 2, "max_cloud_tokens": 180, "used_cloud_calls": 1, "used_cloud_tokens": 60})
    assert budget.snapshot().max_cloud_calls == 2
    assert budget.snapshot().max_cloud_tokens == 180
    # Arrival order cannot let lower-value architecture consume the reserved
    # slots before security/verification are admitted.
    assert budget.reserve(LLMProvider.OPENROUTER, input_tokens=20, output_tokens=20, task_key="architecture") is False
    assert budget.reserve(LLMProvider.OPENROUTER, input_tokens=20, output_tokens=20, task_key="security_reasoning") is True
    assert budget.snapshot().used_cloud_calls == 2


def test_checkpoint_budget_reducer_is_monotonic_and_conservative() -> None:
    merged = merge_cloud_budget(
        {"max_cloud_calls": 4, "max_cloud_tokens": 400, "used_cloud_calls": 2, "used_cloud_tokens": 120},
        {"max_cloud_calls": 3, "max_cloud_tokens": 300, "used_cloud_calls": 1, "used_cloud_tokens": 160},
    )
    assert merged["max_cloud_calls"] == 3
    assert merged["max_cloud_tokens"] == 300
    assert merged["used_cloud_calls"] == 2
    assert merged["used_cloud_tokens"] == 160


def _finding(repo_dir: Path, commit: str) -> Finding:
    source = b"safe()\nproblem()\n"
    path = repo_dir / "app.py"
    path.write_bytes(source)
    snippet = "problem()"
    evidence = Evidence(
        file_path="app.py",
        start_line=2,
        end_line=2,
        code_snippet=snippet,
        context_notes=build_grounding_context_notes(
            commit_sha=commit,
            file_path="app.py",
            start_line=2,
            end_line=2,
            file_sha256=hashlib.sha256(source).hexdigest(),
            snippet_sha256=hashlib.sha256(snippet.encode()).hexdigest(),
        ),
    )
    return Finding(
        id=uuid4(),
        scan_id=uuid4(),
        title="Verified issue",
        description="A verified issue.",
        severity=Severity.HIGH,
        status=FindingStatus.OPEN,
        verification_verdict=VerificationVerdict.CONFIRMED,
        source_tool="semgrep",
        detector_kind="static_scanner",
        evidences=[evidence],
    )


def test_incremental_reuse_reattests_and_relocates_source(tmp_path: Path) -> None:
    old_commit = "a" * 40
    new_commit = "b" * 40
    finding = _finding(tmp_path, old_commit)
    (tmp_path / "app.py").write_text("header()\nsafe()\nproblem()\n", encoding="utf-8")
    decision = revalidate_finding(
        finding,
        repo_dir=str(tmp_path),
        commit_sha=new_commit,
        previous_commit_sha=old_commit,
        changed_files={"unrelated.py"},
        previous_authority_fingerprint="authority",
        current_authority_fingerprint="authority",
    )
    assert decision.reusable is True
    assert decision.evidence[0].start_line == 3
    assert json.loads(decision.evidence[0].context_notes)["commit_sha"] == new_commit


def test_incremental_reuse_rejects_authority_or_dependency_change(tmp_path: Path) -> None:
    finding = _finding(tmp_path, "a" * 40)
    decision = revalidate_finding(
        finding,
        repo_dir=str(tmp_path),
        commit_sha="b" * 40,
        previous_commit_sha="a" * 40,
        changed_dependencies={"dep:sqlalchemy"},
        previous_authority_fingerprint="old",
        current_authority_fingerprint="new",
    )
    assert decision.reusable is False


def test_changed_scope_uses_exact_file_hashes(tmp_path: Path) -> None:
    previous = tmp_path / "previous"
    current = tmp_path / "current"
    (previous / "src").mkdir(parents=True)
    (current / "src").mkdir(parents=True)
    (previous / "src" / "same.py").write_text("same()\n", encoding="utf-8")
    (current / "src" / "same.py").write_text("same()\n", encoding="utf-8")
    (previous / "src" / "changed.py").write_text("old()\n", encoding="utf-8")
    (current / "src" / "changed.py").write_text("new()\n", encoding="utf-8")
    (current / "src" / "added.py").write_text("added()\n", encoding="utf-8")
    assert changed_files_by_hash(str(previous), str(current)) == {
        "src/changed.py",
        "src/added.py",
    }
