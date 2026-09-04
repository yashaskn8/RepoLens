"""Focused tests for deterministic V3 specialist hypotheses and evidence slices."""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest

from app.agents.bug import run_bug_agent
from app.agents.helpers import parse_llm_findings
from app.agents.revision import _contains_unsupported_new_claims
from app.agents.security import run_security_agent
from app.analysis.store import EvidenceStore
from app.specialist_candidates import (
    build_architecture_candidates,
    build_bug_candidates,
    build_security_flow_candidates,
)
from app.context.prompt import pack_repository_context
from app.context.engine import ContextEngine
from app.context.schemas import ContextBundle
from app.context.slices import build_evidence_slice
from app.graph.repository_graph import RepositoryGraph
from app.graph.schemas import EdgeKind, NodeKind
from app.indexing.schemas import ChunkSymbolKind, CodeChunk, INDEX_VERSION, content_hash
from app.ingestion.schemas import FileEntry, ParsedCall, ParsedSymbol, RepositoryManifest, SymbolKind
from app.retrieval.schemas import RetrievalChannel, RetrievalResult
from app.retrieval.service import RetrievalService
from app.llm.types import LLMProvider, LLMResponse
from app.schemas.metadata import ModelExecutionMetadata


def _chunk(
    chunk_id: str,
    content: str,
    *,
    file_path: str = "app.py",
    symbol: str = "handler",
    commit_sha: str = "a" * 40,
) -> CodeChunk:
    return CodeChunk(
        chunk_id=chunk_id,
        commit_sha=commit_sha,
        file_path=file_path,
        language="python",
        symbol=symbol,
        symbol_kind=ChunkSymbolKind.FUNCTION,
        start_line=1,
        end_line=max(1, len(content.splitlines())),
        content=content,
        content_hash=content_hash(content),
        index_version=INDEX_VERSION,
    )


def test_bug_candidates_detect_proven_swallow_but_not_guarded_handler():
    swallowed = _chunk(
        "chunk:swallow",
        "def load():\n    try:\n        work()\n    except Exception:\n        pass",
        symbol="load",
    )
    handled = _chunk(
        "chunk:handled",
        "def load():\n    try:\n        work()\n    except Exception:\n        raise",
        symbol="load_safe",
    )

    candidates = build_bug_candidates([swallowed, handled])

    assert [candidate.candidate_kind for candidate in candidates] == ["BROAD_EXCEPTION_SWALLOW"]
    assert candidates[0].evidence_refs == ["chunk:chunk:swallow"]


def test_bug_candidates_detect_blocking_call_only_inside_async_function():
    unsafe = _chunk(
        "chunk:async-blocking",
        "async def refresh():\n    time.sleep(2)",
        symbol="refresh",
    )
    safe = _chunk(
        "chunk:async-safe",
        "async def refresh_safe():\n    await asyncio.sleep(2)",
        symbol="refresh_safe",
    )

    candidates = build_bug_candidates([unsafe, safe])

    assert len(candidates) == 1
    assert candidates[0].candidate_kind == "ASYNC_BLOCKING_CALL"
    assert candidates[0].metadata["callee"] == "time.sleep"


def test_security_flow_candidate_carries_guard_counter_evidence():
    source = "def download(path):\n    safe = resolve_safe_path(root, path)\n    return open(safe)"
    chunk = _chunk("chunk:download", source, symbol="download")
    manifest = RepositoryManifest(
        repository_url="https://github.com/org/repo",
        commit_hash="a" * 40,
        files=[
            FileEntry(
                path="app.py",
                language="python",
                lines_count=3,
                symbols=[
                    ParsedSymbol(
                        name="GET /download",
                        kind=SymbolKind.FASTAPI_ROUTE,
                        start_line=1,
                        end_line=3,
                        details={"handler": "download", "http_method": "GET", "path": "/download"},
                    )
                ],
                calls=[
                    ParsedCall(
                        callee="resolve_safe_path",
                        callee_name="resolve_safe_path",
                        line_number=2,
                        caller_name="download",
                    ),
                    ParsedCall(
                        callee="open",
                        callee_name="open",
                        line_number=3,
                        caller_name="download",
                    ),
                ],
            )
        ],
    )

    candidates = build_security_flow_candidates(manifest, [chunk])

    assert len(candidates) == 1
    assert candidates[0].candidate_kind == "INPUT_TO_FILESYSTEM"
    assert candidates[0].metadata["flow_certainty"] == "POSSIBLE_EDGE"
    assert candidates[0].counter_evidence == ["resolve_safe_path"]


def test_security_source_candidates_detect_dynamic_sql_and_unsafe_cookie_only():
    chunks = [
        _chunk(
            "chunk:sql",
            "def lookup(user_id):\n    cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
            symbol="lookup",
        ),
        _chunk(
            "chunk:cookie",
            "def session(response, token):\n    response.set_cookie(key='sid', value=token)",
            symbol="session",
        ),
        _chunk(
            "chunk:safe-cookie",
            "def safe(response, token):\n    response.set_cookie(key='sid', value=token, secure=True, httponly=True, samesite='lax')",
            symbol="safe",
        ),
    ]
    manifest = RepositoryManifest(
        repository_url="https://github.com/org/repo",
        commit_hash="a" * 40,
        files=[],
    )

    candidates = build_security_flow_candidates(manifest, chunks)

    assert {candidate.candidate_kind for candidate in candidates} == {
        "DYNAMIC_SQL_CONSTRUCTION",
        "INSECURE_COOKIE_ATTRIBUTES",
    }
    assert all("chunk:safe-cookie" not in candidate.evidence_refs for candidate in candidates)


def test_architecture_cycle_is_candidate_but_acyclic_graph_is_not():
    chunks = [
        _chunk("chunk:a", "from b import value", file_path="a.py", symbol="a"),
        _chunk("chunk:b", "from a import value", file_path="b.py", symbol="b"),
    ]
    cyclic = RepositoryGraph()
    cyclic.add_node("file:a.py", NodeKind.FILE, "a.py", "a.py")
    cyclic.add_node("file:b.py", NodeKind.FILE, "b.py", "b.py")
    cyclic.add_edge("file:a.py", "file:b.py", EdgeKind.IMPORTS)
    cyclic.add_edge("file:b.py", "file:a.py", EdgeKind.IMPORTS)
    acyclic = RepositoryGraph()
    acyclic.add_node("file:a.py", NodeKind.FILE, "a.py", "a.py")
    acyclic.add_node("file:b.py", NodeKind.FILE, "b.py", "b.py")
    acyclic.add_edge("file:a.py", "file:b.py", EdgeKind.IMPORTS)

    cycle_candidates = build_architecture_candidates(cyclic, chunks)

    assert len(cycle_candidates) == 1
    assert cycle_candidates[0].candidate_kind == "DEPENDENCY_CYCLE"
    assert set(cycle_candidates[0].evidence_refs) == {"chunk:chunk:a", "chunk:chunk:b"}
    assert build_architecture_candidates(acyclic, chunks) == []


def test_evidence_slice_is_commit_bound_and_exposes_counter_evidence():
    chunk = _chunk(
        "chunk:download",
        "def download(path):\n    safe = resolve_safe_path(root, path)\n    return open(safe)",
        symbol="download",
    )
    candidate = build_bug_candidates([
        _chunk(
            "chunk:swallow",
            "def load():\n    try:\n        work()\n    except Exception:\n        pass",
            symbol="load",
        )
    ])[0]
    candidate.evidence_refs = [f"chunk:{chunk.chunk_id}"]
    candidate.counter_evidence = ["resolve_safe_path"]
    result = RetrievalResult(
        chunk_id=chunk.chunk_id,
        score=1.0,
        source_channels=[RetrievalChannel.EXACT],
        chunk=chunk,
    )
    packed = pack_repository_context(
        ContextBundle(
            scan_id="scan-1",
            query="download",
            analysis_intent="security",
            relevant_chunks=[result],
        ),
        token_budget=512,
    )

    evidence_slice = build_evidence_slice(
        scan_id="scan-1",
        commit_sha="a" * 40,
        candidate=candidate,
        packed=packed,
    )

    assert evidence_slice is not None
    assert evidence_slice.primary_evidence_refs == ["chunk:chunk:download"]
    assert evidence_slice.counter_evidence_refs == ["chunk:chunk:download"]
    assert build_evidence_slice(
        scan_id="scan-1",
        commit_sha="b" * 40,
        candidate=candidate,
        packed=packed,
    ) is None


def test_revision_rejects_any_unanchored_new_claims():
    assert _contains_unsupported_new_claims({"new_claims": []}) is False
    assert _contains_unsupported_new_claims({}) is False
    assert _contains_unsupported_new_claims({"new_claims": ["new assertion"]}) is True
    assert _contains_unsupported_new_claims({"new_claims": "new assertion"}) is True


def test_candidate_grounding_rejects_cross_hypothesis_evidence():
    metadata = ModelExecutionMetadata(model_name="test-model", provider="test")
    evidence_index = {
        "chunk:one": {
            "kind": "chunk",
            "file_path": "one.py",
            "start_line": 1,
            "end_line": 1,
            "code_snippet": "danger()",
        }
    }
    base = {
        "title": "Candidate",
        "description": "Candidate description",
        "severity": "MEDIUM",
        "category": "correctness",
        "candidate_id": "candidate:one",
        "evidence_refs": ["chunk:one"],
        "source_behavior": "danger is called",
        "trigger_condition": "the path executes",
        "failure_mechanism": "danger fails",
        "impact_claim": "the request fails",
    }

    rejected = parse_llm_findings(
        json.dumps({"findings": [base]}),
        uuid4(),
        "correctness",
        metadata,
        evidence_index,
        candidate_evidence={"candidate:one": {"chunk:two"}},
    )
    accepted = parse_llm_findings(
        json.dumps({"findings": [base]}),
        uuid4(),
        "correctness",
        metadata,
        evidence_index,
        candidate_evidence={"candidate:one": {"chunk:one"}},
    )

    assert rejected == []
    assert len(accepted) == 1
    assert len(accepted[0].model_metadata.extra_metadata["atomic_claims"]) == 5


@pytest.mark.asyncio
async def test_bug_agent_reasons_over_candidate_slice_not_generic_discovery():
    chunk = _chunk(
        "chunk:swallow",
        "def load():\n    try:\n        work()\n    except Exception:\n        pass",
        symbol="load",
    )
    candidate = build_bug_candidates([chunk])[0]
    manifest = RepositoryManifest(
        repository_url="https://github.com/org/repo",
        commit_hash="a" * 40,
        files=[FileEntry(path="app.py", language="python", lines_count=5)],
    )
    context_engine = ContextEngine(
        EvidenceStore(manifest=manifest),
        retrieval_service=RetrievalService(chunks=[chunk]),
    )
    runtime = SimpleNamespace(context=SimpleNamespace(context_engine=context_engine))
    router = AsyncMock()
    router.generate.return_value = LLMResponse(
        content=json.dumps({"confidence": 0.9, "findings": []}),
        model="laguna-test",
        provider=LLMProvider.HUGGINGFACE,
        metadata=ModelExecutionMetadata(model_name="laguna-test", provider="huggingface"),
    )
    state = {
        "scan_id": str(uuid4()),
        "commit_hash": "a" * 40,
        "manifest_summary": {"total_files": 1},
        "routes": [],
        "deterministic_correctness_candidates": [candidate.model_dump(mode="json")],
        "ai_admission": {
            "bug": {
                "decision": "CLOUD_REQUIRED",
                "reason": "candidate unresolved",
                "evidence_count": 1,
                "unresolved": True,
                "priority": 90,
                "max_output_tokens": 1024,
            }
        },
    }

    with patch("app.agents.bug.get_llm_router", return_value=router):
        result = await run_bug_agent(state, runtime)

    request = router.generate.await_args.args[0]
    user_prompt = request.messages[1].content
    assert candidate.candidate_id in user_prompt
    assert candidate.evidence_refs[0] in user_prompt
    assert "logic bug null exception async handling race condition" not in user_prompt
    assert result["candidate_findings"] == []


@pytest.mark.asyncio
async def test_security_agent_passes_possible_flow_and_guard_to_specialist():
    source = "def download(path):\n    safe = resolve_safe_path(root, path)\n    return open(safe)"
    chunk = _chunk("chunk:download", source, symbol="download")
    manifest = RepositoryManifest(
        repository_url="https://github.com/org/repo",
        commit_hash="a" * 40,
        files=[
            FileEntry(
                path="app.py",
                language="python",
                lines_count=3,
                symbols=[
                    ParsedSymbol(
                        name="GET /download",
                        kind=SymbolKind.FASTAPI_ROUTE,
                        start_line=1,
                        end_line=3,
                        details={"handler": "download"},
                    )
                ],
                calls=[
                    ParsedCall(callee="resolve_safe_path", callee_name="resolve_safe_path", line_number=2, caller_name="download"),
                    ParsedCall(callee="open", callee_name="open", line_number=3, caller_name="download"),
                ],
            )
        ],
    )
    candidate = build_security_flow_candidates(manifest, [chunk])[0]
    context_engine = ContextEngine(
        EvidenceStore(manifest=manifest),
        retrieval_service=RetrievalService(chunks=[chunk]),
    )
    runtime = SimpleNamespace(context=SimpleNamespace(context_engine=context_engine))
    router = AsyncMock()
    router.generate.return_value = LLMResponse(
        content=json.dumps({"confidence": 0.9, "findings": []}),
        model="security-test",
        provider=LLMProvider.GROQ,
        metadata=ModelExecutionMetadata(model_name="security-test", provider="groq"),
    )
    state = {
        "scan_id": str(uuid4()),
        "commit_hash": "a" * 40,
        "static_findings": [],
        "languages": {"python": 1},
        "frameworks": ["FastAPI"],
        "deterministic_security_flow_candidates": [candidate.model_dump(mode="json")],
        "ai_admission": {
            "security": {
                "decision": "CLOUD_REQUIRED",
                "reason": "flow unresolved",
                "evidence_count": 1,
                "unresolved": True,
                "priority": 100,
                "max_output_tokens": 1024,
            }
        },
    }

    with patch("app.agents.security.get_llm_router", return_value=router):
        await run_security_agent(state, runtime)

    user_prompt = router.generate.await_args.args[0].messages[1].content
    assert "POSSIBLE_EDGE" in user_prompt
    assert "resolve_safe_path" in user_prompt
    assert candidate.evidence_refs[0] in user_prompt
