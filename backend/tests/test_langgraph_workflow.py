"""Unit and integration tests for LangGraph multi-agent analysis workflow and evidence grounding."""

import json
import os
import tempfile
from unittest.mock import AsyncMock, patch
from uuid import uuid4
import pytest

from langgraph.checkpoint.memory import InMemorySaver
from app.agents.graph import build_analysis_graph, run_analysis_workflow
from app.analysis.store import EvidenceStore
from app.ingestion.schemas import FileEntry, ParsedSymbol, RepositoryManifest, SymbolKind
from app.llm.types import LLMProvider, LLMRequest, LLMResponse, ModelCapability, ModelExecutionMetadata, TaskPolicy
from app.schemas.enums import Severity
from app.schemas.finding import Finding


@pytest.fixture
def sample_analysis_environment():
    """Create a temporary workspace and pre-populated EvidenceStore for LangGraph execution."""
    with tempfile.TemporaryDirectory(prefix="workflow_test_") as tmp_dir:
        # Create real file in workspace
        app_file_path = os.path.join(tmp_dir, "server.py")
        with open(app_file_path, "w", encoding="utf-8") as f:
            f.write(
                "from fastapi import FastAPI\n"
                "app = FastAPI()\n\n"
                "@app.get('/items')\n"
                "def list_items():\n"
                "    return []\n"
            )

        manifest = RepositoryManifest(
            repository_url="https://github.com/org/repo-workflow-test.git",
            commit_hash="abcdef1234567890",
            total_files=1,
            total_size_bytes=100,
            languages={"python": 1},
            frameworks=[],
            files=[
                FileEntry(
                    path="server.py",
                    language="python",
                    size_bytes=100,
                    lines_count=6,
                    symbols=[
                        ParsedSymbol(
                            name="GET /items",
                            kind=SymbolKind.FASTAPI_ROUTE,
                            start_line=4,
                            end_line=6,
                            details={"http_method": "GET", "path": "/items"},
                        )
                    ],
                )
            ],
        )

        store = EvidenceStore(manifest=manifest)
        yield store, tmp_dir


def test_build_analysis_graph_compilation():
    """Verify that LangGraph StateGraph compiles and contains all 9 nodes including revision & lifecycle."""
    graph = build_analysis_graph()
    assert graph is not None
    node_keys = graph.nodes.keys()
    for expected_node in (
        "mapper",
        "architecture",
        "integration",
        "security",
        "bug",
        "verifier",
        "revise",
        "finalize",
        "finalize_uncertain",
    ):
        assert expected_node in node_keys


@pytest.mark.asyncio
async def test_langgraph_full_workflow_mocked_execution(sample_analysis_environment):
    """Verify that run_analysis_workflow executes all specialists and grounds candidate findings to verified."""
    store, repo_dir = sample_analysis_environment
    scan_id = str(uuid4())

    async def mock_generate_side_effect(request):
        policy = request.task_policy
        metadata = ModelExecutionMetadata(
            provider=LLMProvider.GEMINI,
            model_name="mock-model",
            prompt_tokens=10,
            completion_tokens=20,
            total_tokens=30,
            latency_ms=50.0,
        )

        if policy == TaskPolicy.ARCHITECTURE:
            payload = {
                "confidence": 0.9,
                "findings": [
                    {
                        "title": "Monolithic Route Coupling",
                        "description": "Routes defined in root without modular APIRouter.",
                        "severity": "LOW",
                        "category": "architecture",
                        "evidence_refs": ["chunk:abcdef123456:server.py:GET /items:4"],
                        "mitigation_guidance": "Extract into APIRouter module.",
                    }
                ],
            }
            return LLMResponse(
                content=json.dumps(payload),
                model="mock-model",
                provider=LLMProvider.GEMINI,
                metadata=metadata,
            )

        elif policy == TaskPolicy.SECURITY_REASONING:
            payload = {
                "confidence": 0.9,
                "findings": [
                    {
                        "title": "Missing Authentication on Route",
                        "description": "Endpoint /items lacks authentication dependency.",
                        "severity": "HIGH",
                        "category": "security",
                        "evidence_refs": ["chunk:abcdef123456:server.py:GET /items:4"],
                        "mitigation_guidance": "Add Depends(get_current_user).",
                    },
                    {
                        "title": "Hallucinated Hardcoded Secret",
                        "description": "In non-existent file",
                        "severity": "CRITICAL",
                        "category": "security",
                        "evidence_refs": ["chunk:invented:fake_auth.py:10"],
                    },
                ],
            }
            return LLMResponse(
                content=json.dumps(payload),
                model="mock-model",
                provider=LLMProvider.GROQ,
                metadata=metadata,
            )

        elif policy in (TaskPolicy.INTEGRATION_CODE, TaskPolicy.BUG_REASONING):
            return LLMResponse(
                content=json.dumps({"confidence": 0.9, "findings": []}),
                model="mock-model",
                provider=LLMProvider.HUGGINGFACE,
                metadata=metadata,
            )

        elif policy == TaskPolicy.VERIFICATION:
            payload = {
                "confidence": 0.9,
                "evaluations": [
                    {"index": 0, "verdict": "CONFIRMED", "justified_severity": "LOW", "reason": "Valid architectural observation."},
                    {"index": 1, "verdict": "CONFIRMED", "justified_severity": "HIGH", "reason": "Endpoint lacks authentication."},
                ],
            }
            return LLMResponse(
                content=json.dumps(payload),
                model="mock-model",
                provider=LLMProvider.NVIDIA,
                metadata=metadata,
            )

        return LLMResponse(content="{}", model="mock", provider=LLMProvider.GEMINI, metadata=metadata)

    mock_router = AsyncMock()
    mock_router.generate.side_effect = mock_generate_side_effect

    with patch("app.agents.architecture.get_llm_router", return_value=mock_router), \
         patch("app.agents.security.get_llm_router", return_value=mock_router), \
         patch("app.agents.bug.get_llm_router", return_value=mock_router), \
         patch("app.agents.verifier.get_llm_router", return_value=mock_router):

        final_state = await run_analysis_workflow(
            evidence_store=store,
            scan_id=scan_id,
            repo_dir=repo_dir,
        )

    # 1. State assertions
    assert final_state["scan_id"] == scan_id
    assert final_state["status"] == "COMPLETED"
    assert "FastAPI" in final_state["architecture_overview"]
    assert "finalize" in final_state["completed_nodes"]
    assert "revise" not in final_state["completed_nodes"]

    # 2. Candidate findings collected
    assert len(final_state["candidate_findings"]) == 2

    # 3. Grounding Verification assertions
    verified = final_state["verified_findings"]
    rejected = final_state["rejected_findings"]

    assert len(verified) >= 2
    for vf in verified:
        assert isinstance(vf, Finding)
        assert vf.evidences[0].file_path == "server.py"

    assert all(
        evidence.file_path != "fake_auth.py"
        for finding in final_state["candidate_findings"]
        for evidence in finding.evidences
    )
    assert all(rf.get("file_path") != "fake_auth.py" for rf in rejected)


@pytest.mark.asyncio
async def test_langgraph_revision_path_when_possible_verdict(sample_analysis_environment):
    """Verify that a revisable POSSIBLE finding triggers revise -> verifier -> finalize."""
    store, repo_dir = sample_analysis_environment
    scan_id = str(uuid4())

    verifier_call_count = 0
    bug_reasoning_call_count = 0

    async def mock_generate_side_effect(request: LLMRequest):
        nonlocal verifier_call_count, bug_reasoning_call_count
        policy = request.task_policy
        metadata = ModelExecutionMetadata(
            provider=LLMProvider.GEMINI,
            model_name="mock-model",
            prompt_tokens=10,
            completion_tokens=20,
            total_tokens=30,
            latency_ms=40.0,
        )

        if policy == TaskPolicy.SECURITY_REASONING:
            payload = {
                "confidence": 0.9,
                "findings": [
                    {
                        "title": "Missing Authorization Check",
                        "description": "Endpoint has no auth decorator.",
                        "severity": "HIGH",
                        "category": "security",
                        "evidence_refs": ["chunk:abcdef123456:server.py:GET /items:4"],
                        "mitigation_guidance": "Add security dependency.",
                    }
                ],
            }
            return LLMResponse(content=json.dumps(payload), model="m", provider=LLMProvider.GEMINI, metadata=metadata)

        elif policy in (TaskPolicy.ARCHITECTURE, TaskPolicy.INTEGRATION_CODE):
            return LLMResponse(content=json.dumps({"findings": []}), model="m", provider=LLMProvider.GEMINI, metadata=metadata)

        elif policy == TaskPolicy.BUG_REASONING:
            bug_reasoning_call_count += 1
            if bug_reasoning_call_count == 1:
                # Bug specialist: no findings
                return LLMResponse(content=json.dumps({"findings": []}), model="m", provider=LLMProvider.GEMINI, metadata=metadata)
            else:
                # Revision agent call
                payload = {
                    "findings": [
                        {
                            "title": "Refined Missing Auth Check",
                            "description": "Refined description: route GET /items lacks auth.",
                            "severity": "HIGH",
                            "category": "security",
                            "evidence_refs": ["chunk:abcdef123456:server.py:GET /items:4"],
                        }
                    ]
                }
                return LLMResponse(content=json.dumps(payload), model="m", provider=LLMProvider.GEMINI, metadata=metadata)

        elif policy == TaskPolicy.VERIFICATION:
            verifier_call_count += 1
            if verifier_call_count == 1:
                # First pass: returns POSSIBLE with correctable reason
                payload = {
                    "confidence": 0.6,
                    "evaluations": [
                        {"index": 0, "verdict": "POSSIBLE", "reason": "Semantic claim requires more specific rationale."}
                    ],
                }
            else:
                # Second pass: confirms revised finding
                payload = {
                    "confidence": 0.95,
                    "evaluations": [
                        {"index": 0, "verdict": "CONFIRMED", "justified_severity": "HIGH", "reason": "Revised rationale is clear."}
                    ],
                }
            return LLMResponse(content=json.dumps(payload), model="m", provider=LLMProvider.GEMINI, metadata=metadata)

        return LLMResponse(content="{}", model="m", provider=LLMProvider.GEMINI, metadata=metadata)

    mock_router = AsyncMock()
    mock_router.generate.side_effect = mock_generate_side_effect

    with patch("app.agents.architecture.get_llm_router", return_value=mock_router), \
         patch("app.agents.security.get_llm_router", return_value=mock_router), \
         patch("app.agents.bug.get_llm_router", return_value=mock_router), \
         patch("app.agents.revision.get_llm_router", return_value=mock_router), \
         patch("app.agents.verifier.get_llm_router", return_value=mock_router):

        final_state = await run_analysis_workflow(
            evidence_store=store,
            scan_id=scan_id,
            repo_dir=repo_dir,
        )

    assert final_state["status"] == "COMPLETED"
    assert final_state["revision_count"] == 1
    assert "revise" in final_state["completed_nodes"]
    assert "finalize" in final_state["completed_nodes"]
    assert len(final_state["verified_findings"]) == 1
    assert "Refined" in final_state["verified_findings"][0].title
    # candidate_findings remains the original 1; revision_candidates holds the refined finding
    assert len(final_state["candidate_findings"]) == 1
    assert len(final_state["revision_candidates"]) == 1


@pytest.mark.asyncio
async def test_langgraph_revision_exhaustion_routes_to_finalize_uncertain(sample_analysis_environment):
    """Verify that if finding remains unconfirmed on revision pass, workflow terminates in finalize_uncertain."""
    store, repo_dir = sample_analysis_environment
    scan_id = str(uuid4())

    bug_reasoning_call_count = 0

    async def mock_generate_side_effect(request: LLMRequest):
        nonlocal bug_reasoning_call_count
        policy = request.task_policy
        metadata = ModelExecutionMetadata(
            provider=LLMProvider.GEMINI,
            model_name="mock-model",
            prompt_tokens=10,
            completion_tokens=20,
            total_tokens=30,
            latency_ms=40.0,
        )

        if policy == TaskPolicy.SECURITY_REASONING:
            payload = {
                "confidence": 0.9,
                "findings": [
                    {
                        "title": "Ambiguous Auth Issue",
                        "description": "Auth may be missing.",
                        "severity": "MEDIUM",
                        "category": "security",
                        "evidence_refs": ["chunk:abcdef123456:server.py:GET /items:4"],
                    }
                ],
            }
            return LLMResponse(content=json.dumps(payload), model="m", provider=LLMProvider.GEMINI, metadata=metadata)

        elif policy in (TaskPolicy.ARCHITECTURE, TaskPolicy.INTEGRATION_CODE):
            return LLMResponse(content=json.dumps({"findings": []}), model="m", provider=LLMProvider.GEMINI, metadata=metadata)

        elif policy == TaskPolicy.BUG_REASONING:
            bug_reasoning_call_count += 1
            if bug_reasoning_call_count == 1:
                # Bug specialist: no findings
                return LLMResponse(content=json.dumps({"findings": []}), model="m", provider=LLMProvider.GEMINI, metadata=metadata)
            else:
                # Revision agent
                payload = {
                    "findings": [
                        {
                            "title": "Ambiguous Auth Issue v2",
                            "description": "Still somewhat ambiguous.",
                            "severity": "MEDIUM",
                            "category": "security",
                            "evidence_refs": ["chunk:abcdef123456:server.py:GET /items:4"],
                        }
                    ]
                }
                return LLMResponse(content=json.dumps(payload), model="m", provider=LLMProvider.GEMINI, metadata=metadata)

        elif policy == TaskPolicy.VERIFICATION:
            # Returns POSSIBLE on every pass
            payload = {
                "confidence": 0.5,
                "evaluations": [
                    {"index": 0, "verdict": "POSSIBLE", "reason": "Claim cannot be verified definitively."}
                ],
            }
            return LLMResponse(content=json.dumps(payload), model="m", provider=LLMProvider.GEMINI, metadata=metadata)

        return LLMResponse(content="{}", model="m", provider=LLMProvider.GEMINI, metadata=metadata)

    mock_router = AsyncMock()
    mock_router.generate.side_effect = mock_generate_side_effect

    with patch("app.agents.architecture.get_llm_router", return_value=mock_router), \
         patch("app.agents.security.get_llm_router", return_value=mock_router), \
         patch("app.agents.bug.get_llm_router", return_value=mock_router), \
         patch("app.agents.revision.get_llm_router", return_value=mock_router), \
         patch("app.agents.verifier.get_llm_router", return_value=mock_router):

        final_state = await run_analysis_workflow(
            evidence_store=store,
            scan_id=scan_id,
            repo_dir=repo_dir,
        )

    # Revision exhausted (revision_count == 1) routes to finalize_uncertain
    assert final_state["status"] == "COMPLETED_UNCERTAIN"
    assert final_state["revision_count"] == 1
    assert "finalize_uncertain" in final_state["completed_nodes"]
    assert "finalize" not in final_state["completed_nodes"]


@pytest.mark.asyncio
async def test_langgraph_verifier_failure_routes_to_uncertain_without_revision(sample_analysis_environment):
    """Verify that verifier infrastructure failure routes directly to finalize_uncertain and never tries revision."""
    store, repo_dir = sample_analysis_environment
    scan_id = str(uuid4())

    async def mock_generate_side_effect(request: LLMRequest):
        policy = request.task_policy
        metadata = ModelExecutionMetadata(provider=LLMProvider.GEMINI, model_name="m", prompt_tokens=5, completion_tokens=5, total_tokens=10, latency_ms=10.0)

        if policy == TaskPolicy.SECURITY_REASONING:
            payload = {
                "confidence": 0.9,
                "findings": [
                    {
                        "title": "Auth Issue",
                        "description": "Auth check.",
                        "severity": "HIGH",
                        "category": "security",
                        "evidence_refs": ["chunk:abcdef123456:server.py:GET /items:4"],
                    }
                ],
            }
            return LLMResponse(content=json.dumps(payload), model="m", provider=LLMProvider.GEMINI, metadata=metadata)

        elif policy in (TaskPolicy.ARCHITECTURE, TaskPolicy.INTEGRATION_CODE):
            return LLMResponse(content=json.dumps({"findings": []}), model="m", provider=LLMProvider.GEMINI, metadata=metadata)

        elif policy == TaskPolicy.VERIFICATION:
            # Simulate unexpected provider failure in verifier
            raise RuntimeError("Provider API rate limit exhaustion")

        return LLMResponse(content="{}", model="m", provider=LLMProvider.GEMINI, metadata=metadata)

    mock_router = AsyncMock()
    mock_router.generate.side_effect = mock_generate_side_effect

    with patch("app.agents.architecture.get_llm_router", return_value=mock_router), \
         patch("app.agents.security.get_llm_router", return_value=mock_router), \
         patch("app.agents.bug.get_llm_router", return_value=mock_router), \
         patch("app.agents.verifier.get_llm_router", return_value=mock_router):

        final_state = await run_analysis_workflow(
            evidence_store=store,
            scan_id=scan_id,
            repo_dir=repo_dir,
        )

    # Routes to finalize_uncertain without attempting revision
    assert final_state["status"] == "COMPLETED_UNCERTAIN"
    assert "finalize_uncertain" in final_state["completed_nodes"]
    assert "revise" not in final_state["completed_nodes"]
    assert final_state["revision_count"] == 0


@pytest.mark.asyncio
async def test_no_runtime_objects_in_checkpoint_state(sample_analysis_environment):
    """Verify that non-msgpack runtime objects (ContextEngine, RepositoryGraph) are never saved in checkpoints."""
    store, repo_dir = sample_analysis_environment
    scan_id = str(uuid4())

    checkpointer = InMemorySaver()

    mock_router = AsyncMock()
    dummy_meta = ModelExecutionMetadata(provider=LLMProvider.GEMINI, model_name="m", prompt_tokens=5, completion_tokens=5, total_tokens=10, latency_ms=10.0)
    mock_router.generate.return_value = LLMResponse(content=json.dumps({"findings": [], "evaluations": []}), model="m", provider=LLMProvider.GEMINI, metadata=dummy_meta)

    with patch("app.agents.architecture.get_llm_router", return_value=mock_router), \
         patch("app.agents.security.get_llm_router", return_value=mock_router), \
         patch("app.agents.bug.get_llm_router", return_value=mock_router), \
         patch("app.agents.verifier.get_llm_router", return_value=mock_router):

        final_state = await run_analysis_workflow(
            evidence_store=store,
            scan_id=scan_id,
            repo_dir=repo_dir,
            checkpointer=checkpointer,
        )

    assert final_state["status"] == "COMPLETED"

    # Inspect the saved checkpoint state
    app = build_analysis_graph(checkpointer=checkpointer)
    saved_state = await app.aget_state({"configurable": {"thread_id": scan_id}})
    assert saved_state is not None
    checkpoint_values = saved_state.values

    # Assert runtime service objects are completely absent from checkpointed state
    assert "context_engine" not in checkpoint_values
    assert "repository_graph" not in checkpoint_values
    assert "scan_runtime" not in checkpoint_values


@pytest.mark.asyncio
async def test_thread_isolation_in_checkpointer(sample_analysis_environment):
    """Verify that multiple scan_id threads execute independently without state contamination."""
    store, repo_dir = sample_analysis_environment
    scan_id_1 = f"thread-scan-{uuid4()}"
    scan_id_2 = f"thread-scan-{uuid4()}"

    checkpointer = InMemorySaver()
    mock_router = AsyncMock()
    dummy_meta = ModelExecutionMetadata(provider=LLMProvider.GEMINI, model_name="m", prompt_tokens=5, completion_tokens=5, total_tokens=10, latency_ms=10.0)
    mock_router.generate.return_value = LLMResponse(content=json.dumps({"findings": [], "evaluations": []}), model="m", provider=LLMProvider.GEMINI, metadata=dummy_meta)

    with patch("app.agents.architecture.get_llm_router", return_value=mock_router), \
         patch("app.agents.security.get_llm_router", return_value=mock_router), \
         patch("app.agents.bug.get_llm_router", return_value=mock_router), \
         patch("app.agents.verifier.get_llm_router", return_value=mock_router):

        await run_analysis_workflow(evidence_store=store, scan_id=scan_id_1, repo_dir=repo_dir, checkpointer=checkpointer)
        await run_analysis_workflow(evidence_store=store, scan_id=scan_id_2, repo_dir=repo_dir, checkpointer=checkpointer)

    app = build_analysis_graph(checkpointer=checkpointer)
    state_1 = await app.aget_state({"configurable": {"thread_id": scan_id_1}})
    state_2 = await app.aget_state({"configurable": {"thread_id": scan_id_2}})

    assert state_1.values["scan_id"] == scan_id_1
    assert state_2.values["scan_id"] == scan_id_2
    assert state_1.values["scan_id"] != state_2.values["scan_id"]


def test_no_direct_provider_selection_in_orchestration_and_revision():
    """Verify that graph.py and revision.py do not select concrete provider names directly."""
    import inspect
    from app.agents import graph, revision

    graph_source = inspect.getsource(graph).lower()
    revision_source = inspect.getsource(revision).lower()

    for forbidden in ("'cloudflare'", '"cloudflare"', "'openrouter'", '"openrouter"', "'mistral'", '"mistral"'):
        assert forbidden not in graph_source, f"Direct provider selection {forbidden} found in graph.py"
        assert forbidden not in revision_source, f"Direct provider selection {forbidden} found in revision.py"
