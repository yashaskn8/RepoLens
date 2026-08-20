"""Bug and Correctness Specialist Agent using NVIDIA Laguna XS 2.1."""

from uuid import UUID
from typing import Any, Dict
from app.agents.helpers import parse_llm_findings
from app.agents.state import AnalysisState
from app.llm.router import get_llm_router
from app.llm.types import LLMMessage, LLMRequest, TaskPolicy


async def run_bug_agent(state: AnalysisState) -> Dict[str, Any]:
    """Analyze code correctness, logic bugs, unhandled exceptions, and edge cases."""
    scan_id = UUID(state["scan_id"])
    manifest = state.get("manifest_summary", {})
    routes = state.get("routes", [])

    system_prompt = (
        "You are the Bug & Correctness Specialist AI Agent for RepoLens. "
        "Analyze code logic, exception handling, resource management, and asynchronous patterns. "
        "Identify logic bugs, null dereferences, race conditions, or unhandled failure states.\n"
        "Return ONLY a JSON object with this exact structure:\n"
        "{\n"
        '  "findings": [\n'
        "    {\n"
        '      "title": "Short descriptive bug title",\n'
        '      "description": "Mechanism and triggering conditions of the bug",\n'
        '      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",\n'
        '      "category": "correctness",\n'
        '      "file_path": "relative/file/path.ext",\n'
        '      "start_line": 1,\n'
        '      "end_line": 10,\n'
        '      "code_snippet": "Buggy code snippet",\n'
        '      "mitigation_guidance": "Corrected code snippet or implementation guidance"\n'
        "    }\n"
        "  ]\n"
        "}\n"
        "CRITICAL: Do NOT invent bugs or non-existent files."
    )

    user_prompt = (
        f"Repository Summary: {manifest}\n"
        f"Key Endpoints ({len(routes)}):\n{routes[:25]}\n"
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
            task_policy=TaskPolicy.BUG_REASONING,
            temperature=0.1,
            max_tokens=2048,
        )
        response = await router.generate(request)
        model_executions.append(response.metadata)
        candidate_findings = parse_llm_findings(
            raw_content=response.content,
            scan_id=scan_id,
            default_category="correctness",
            model_metadata=response.metadata,
        )
    except Exception as exc:
        errors.append(f"Bug Agent error: {str(exc)}")

    return {
        "candidate_findings": candidate_findings,
        "model_executions": model_executions,
        "errors": errors,
    }
