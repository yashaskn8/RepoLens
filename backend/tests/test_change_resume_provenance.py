"""Exact-revision cache recovery must not reuse unrelated diff/impact evidence."""

from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.analysis import workflow_graph
from app.analysis.report_generator import generate_change_analysis_report
from app.models.change_analysis import ChangeAnalysisModel
from app.schemas.change_analysis import BlastRadiusReport, StructuralDiffResult


REPOSITORY = "https://github.com/example/repolens"
BASE = "a" * 40
HEAD = "b" * 40


def _diff(*, base=BASE, head=HEAD, repository=REPOSITORY):
    return StructuralDiffResult(
        base_commit_sha=base,
        head_commit_sha=head,
        repository_url=repository,
    )


def _state(diff, **overrides):
    state = {
        "analysis_id": str(uuid4()),
        "repository_url": REPOSITORY,
        "base_commit_sha": BASE,
        "head_commit_sha": HEAD,
        "base_workspace": "/test/base",
        "head_workspace": "/test/head",
        "diff_result": diff,
        "completed_nodes": [],
    }
    state.update(overrides)
    return state


@pytest.mark.parametrize(
    "candidate",
    [
        _diff(base="c" * 40),
        _diff(head="c" * 40),
        _diff(repository="https://github.com/other/repository"),
        None,
        {"base_commit_sha": BASE, "head_commit_sha": HEAD, "repository_url": REPOSITORY},
    ],
)
def test_diff_cache_requires_typed_exact_repository_and_revisions(candidate):
    assert not workflow_graph._matches_exact_diff(
        candidate,
        repository_url=REPOSITORY,
        base_commit_sha=BASE,
        head_commit_sha=HEAD,
    )
    assert workflow_graph._matches_exact_diff(
        _diff(),
        repository_url=REPOSITORY,
        base_commit_sha=BASE,
        head_commit_sha=HEAD,
    )


@pytest.mark.asyncio
async def test_mismatched_diff_recomputed_and_dependent_checkpoint_evidence_cleared(monkeypatch):
    calls = []
    fresh = _diff()

    def compute_structural_diff(**kwargs):
        calls.append(kwargs)
        return fresh

    monkeypatch.setattr(
        workflow_graph,
        "get_diff_engine",
        lambda: SimpleNamespace(compute_structural_diff=compute_structural_diff),
    )
    state = _state(
        _diff(head="c" * 40),
        blast_radius=BlastRadiusReport(analysis_id=uuid4()),
        review_report={"stale": True},
        impact_frontier={"queue": ["stale-node"]},
    )

    result = await workflow_graph.run_diff_node(state)

    assert len(calls) == 1
    assert calls[0]["base_commit_sha"] == BASE
    assert calls[0]["head_commit_sha"] == HEAD
    assert result["diff_result"] is fresh
    assert result["blast_radius"] is None
    assert result["review_report"] is None
    assert result["impact_frontier"] == {}


@pytest.mark.asyncio
async def test_exact_diff_reused_without_recomputation(monkeypatch):
    monkeypatch.setattr(
        workflow_graph,
        "get_diff_engine",
        lambda: pytest.fail("Exact-revision cached diff must not be recomputed"),
    )

    result = await workflow_graph.run_diff_node(_state(_diff()))

    assert result["status"] == "ANALYZING"
    assert "diff_result" not in result


@pytest.mark.asyncio
async def test_impact_rejects_wrong_revision_diff_before_graph_build(monkeypatch):
    monkeypatch.setattr(
        workflow_graph,
        "build_canonical_phase6_graph",
        lambda **kwargs: pytest.fail("Unrelated diff must be rejected before graph construction"),
    )
    with pytest.raises(RuntimeError, match="CHANGE_DIFF_PROVENANCE_MISMATCH"):
        await workflow_graph.run_impact_node(_state(_diff(base="c" * 40)))


def test_impact_cache_is_bound_to_analysis_repository_and_revisions():
    analysis_id = str(uuid4())
    valid = BlastRadiusReport(
        analysis_id=analysis_id,
        repository_url=REPOSITORY,
        base_commit_sha=BASE,
        head_commit_sha=HEAD,
    )
    expected = {
        "analysis_id": analysis_id,
        "repository_url": REPOSITORY,
        "base_commit_sha": BASE,
        "head_commit_sha": HEAD,
    }
    assert workflow_graph._matches_analysis_blast(valid, **expected)
    assert not workflow_graph._matches_analysis_blast(
        BlastRadiusReport(analysis_id=uuid4(), repository_url=REPOSITORY, base_commit_sha=BASE, head_commit_sha=HEAD),
        **expected,
    )
    assert not workflow_graph._matches_analysis_blast(
        BlastRadiusReport(analysis_id=analysis_id), **expected
    )
    assert not workflow_graph._matches_analysis_blast(
        valid.model_copy(update={"head_commit_sha": "c" * 40}), **expected
    )


@pytest.mark.asyncio
async def test_valid_impact_cache_skips_graph_build(monkeypatch):
    state = _state(_diff())
    state["blast_radius"] = BlastRadiusReport(
        analysis_id=state["analysis_id"],
        repository_url=REPOSITORY,
        base_commit_sha=BASE,
        head_commit_sha=HEAD,
    )
    monkeypatch.setattr(
        workflow_graph,
        "build_canonical_phase6_graph",
        lambda **kwargs: pytest.fail("Provenance-matched impact cache must be reused"),
    )
    result = await workflow_graph.run_impact_node(state)
    assert result["status"] == "ANALYZING"
    assert "blast_radius" not in result


def test_report_does_not_attest_unrelated_graph_or_repository(db_session):
    analysis_id = str(uuid4())
    analysis = ChangeAnalysisModel(
        id=analysis_id,
        repository_url=REPOSITORY,
        repository_owner="example",
        repository_name="repolens",
        base_commit_sha=BASE,
        head_commit_sha=HEAD,
        status="COMPLETED",
        model_metadata={
            "diff_result": _diff().model_dump(mode="json"),
            "blast_radius": BlastRadiusReport(analysis_id=uuid4()).model_dump(mode="json"),
        },
    )
    db_session.add(analysis)
    db_session.flush()

    report = generate_change_analysis_report(analysis)
    assert "| **Repository Graph Traversal** | ⚠️ Execution Not Attested" in report.markdown_report
    assert "| **Tree-sitter AST Parser** | ✅ Evidence Recorded" in report.markdown_report

    analysis.model_metadata = {
        "diff_result": _diff(repository="https://github.com/other/repository").model_dump(mode="json"),
        "blast_radius": BlastRadiusReport(analysis_id=analysis_id).model_dump(mode="json"),
    }
    report = generate_change_analysis_report(analysis)
    assert "| **Tree-sitter AST Parser** | ⚠️ Execution Not Attested" in report.markdown_report
    assert "| **Repository Graph Traversal** | ⚠️ Execution Not Attested" in report.markdown_report

    analysis.model_metadata = {
        "diff_result": _diff().model_dump(mode="json"),
        "blast_radius": BlastRadiusReport(
            analysis_id=analysis_id,
            repository_url=REPOSITORY,
            base_commit_sha=BASE,
            head_commit_sha=HEAD,
        ).model_dump(mode="json"),
    }
    report = generate_change_analysis_report(analysis)
    assert "| **Repository Graph Traversal** | ✅ Evidence Recorded" in report.markdown_report
