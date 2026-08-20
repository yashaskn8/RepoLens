"""Unit and integration tests for LangGraph multi-agent analysis workflow and evidence grounding."""

import json
import os
import tempfile
from unittest.mock import AsyncMock, patch
from uuid import uuid4
import pytest

from app.agents.graph import build_analysis_graph, run_analysis_workflow
from app.analysis.store import EvidenceStore
from app.ingestion.schemas import FileEntry, ParsedSymbol, RepositoryManifest, SymbolKind
from app.llm.types import LLMProvider, LLMResponse, ModelExecutionMetadata, TaskPolicy
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
    """Verify that LangGraph StateGraph compiles and contains all 6 specialist nodes."""
    graph = build_analysis_graph()
    assert graph is not None
    node_keys = graph.nodes.keys()
    for expected_node in ("mapper", "architecture", "integration", "security", "bug", "verifier"):
        assert expected_node in node_keys


@pytest.mark.asyncio
async def test_langgraph_full_workflow_mocked_execution(sample_analysis_environment):
    """Verify that run_analysis_workflow executes all specialists and grounds candidate findings."""
    store, repo_dir = sample_analysis_environment
    scan_id = str(uuid4())

    # Mock responses for each specialist
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

        if policy == TaskPolicy.LIGHTWEIGHT_CLASSIFICATION:
            return LLMResponse(
                content="REST API application using FastAPI.",
                model="mock-model",
                provider=LLMProvider.GROQ,
                metadata=metadata,
            )

        elif policy == TaskPolicy.ARCHITECTURE:
            payload = {
                "findings": [
                    {
                        "title": "Monolithic Route Coupling",
                        "description": "Routes defined in root without modular APIRouter.",
                        "severity": "LOW",
                        "category": "architecture",
                        "file_path": "server.py",
                        "start_line": 4,
                        "end_line": 6,
                        "code_snippet": "@app.get('/items')",
                        "mitigation_guidance": "Extract into APIRouter module.",
                    }
                ]
            }
            return LLMResponse(
                content=json.dumps(payload),
                model="mock-model",
                provider=LLMProvider.GEMINI,
                metadata=metadata,
            )

        elif policy == TaskPolicy.SECURITY_REASONING:
            # Emits one grounded finding (server.py) and one hallucinated file finding (fake_auth.py)
            payload = {
                "findings": [
                    {
                        "title": "Missing Authentication on Route",
                        "description": "Endpoint /items lacks authentication dependency.",
                        "severity": "HIGH",
                        "category": "security",
                        "file_path": "server.py",
                        "start_line": 4,
                        "end_line": 6,
                        "code_snippet": "def list_items():",
                        "mitigation_guidance": "Add Depends(get_current_user).",
                    },
                    {
                        "title": "Hallucinated Hardcoded Secret",
                        "description": "In non-existent file",
                        "severity": "CRITICAL",
                        "category": "security",
                        "file_path": "fake_auth.py",
                        "start_line": 10,
                        "end_line": 12,
                    },
                ]
            }
            return LLMResponse(
                content=json.dumps(payload),
                model="mock-model",
                provider=LLMProvider.GROQ,
                metadata=metadata,
            )

        elif policy in (TaskPolicy.INTEGRATION_CODE, TaskPolicy.BUG_REASONING):
            return LLMResponse(
                content=json.dumps({"findings": []}),
                model="mock-model",
                provider=LLMProvider.HUGGINGFACE,
                metadata=metadata,
            )

        elif policy == TaskPolicy.VERIFICATION:
            # Verifier confirms grounded findings
            payload = {
                "evaluations": [
                    {"index": 0, "verdict": "CONFIRMED", "justified_severity": "LOW", "reason": "Valid architectural observation."},
                    {"index": 1, "verdict": "CONFIRMED", "justified_severity": "HIGH", "reason": "Endpoint lacks authentication."},
                ]
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

    with patch("app.agents.mapper.get_llm_router", return_value=mock_router), \
         patch("app.agents.architecture.get_llm_router", return_value=mock_router), \
         patch("app.agents.integration.get_llm_router", return_value=mock_router), \
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

    # 2. Candidate findings collected
    assert len(final_state["candidate_findings"]) >= 3

    # 3. Grounding Verification assertions
    verified = final_state["verified_findings"]
    rejected = final_state["rejected_findings"]

    # Verified findings must all reference server.py (real file)
    assert len(verified) >= 2
    for vf in verified:
        assert isinstance(vf, Finding)
        assert vf.evidences[0].file_path == "server.py"

    # Hallucinated fake_auth.py must be in rejected findings
    rejected_files = [rf.get("file_path") for rf in rejected]
    assert "fake_auth.py" in rejected_files
    assert any("does not exist" in rf.get("reason", "") for rf in rejected if rf.get("file_path") == "fake_auth.py")
