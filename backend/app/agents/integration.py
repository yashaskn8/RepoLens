"""Integration Specialist Agent using Qwen3-Coder-Next."""

from uuid import UUID
from typing import Any, Dict
from app.agents.helpers import parse_llm_findings
from app.agents.state import AnalysisState
from app.llm.router import get_llm_router
from app.llm.types import LLMMessage, LLMRequest, TaskPolicy


async def run_integration_agent(state: AnalysisState) -> Dict[str, Any]:
    """Analyze API contracts, frontend-backend alignment, and route consistency."""
    scan_id = UUID(state["scan_id"])
    routes = state.get("routes", [])
    frontend_calls = state.get("frontend_calls", [])

    system_prompt = (
        "You are the Integration & Code Specialist AI Agent for RepoLens. "
        "Analyze frontend-backend API contracts, route consistency, and fetch/axios requests. "
        "Identify missing endpoints, parameter mismatches, or unhandled API errors.\n"
        "Return ONLY a JSON object with this exact structure:\n"
        "{\n"
        '  "findings": [\n'
        "    {\n"
        '      "title": "Short descriptive title",\n'
        '      "description": "Explanation of integration mismatch",\n'
        '      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",\n'
        '      "category": "integration",\n'
        '      "file_path": "relative/file/path.ext",\n'
        '      "start_line": 1,\n'
        '      "end_line": 10,\n'
        '      "code_snippet": "Relevant code snippet",\n'
        '      "mitigation_guidance": "Recommended integration fix"\n'
        "    }\n"
        "  ]\n"
        "}\n"
        "CRITICAL: Ground every finding in provided routes or HTTP calls. Do NOT invent files."
    )

    user_prompt = (
        f"Backend API Routes ({len(routes)}):\n{routes[:30]}\n\n"
        f"Frontend Client HTTP Calls ({len(frontend_calls)}):\n{frontend_calls[:30]}\n"
    )

    model_executions = []
    errors = []
    candidate_findings = []

    try:
        router = get_llm_router()
        request = LLMRequest(
            messages=[
                LLMMessage(role="system", content=system_prompt),
                LLMMessage(role="user", content=user_prompt),
            ],
            task_policy=TaskPolicy.INTEGRATION_CODE,
            temperature=0.1,
            max_tokens=2048,
        )
        response = await router.generate(request)
        model_executions.append(response.metadata)
        candidate_findings = parse_llm_findings(
            raw_content=response.content,
            scan_id=scan_id,
            default_category="integration",
            model_metadata=response.metadata,
        )
    except Exception as exc:
        errors.append(f"Integration Agent error: {str(exc)}")

    return {
        "candidate_findings": candidate_findings,
        "model_executions": model_executions,
        "errors": errors,
    }
