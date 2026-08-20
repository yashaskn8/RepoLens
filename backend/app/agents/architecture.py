"""Architecture Specialist Agent using Gemini 3.7 Flash and targeted ContextBundle."""

from uuid import UUID
from typing import Any, Dict
from app.agents.helpers import parse_llm_findings
from app.agents.state import AnalysisState
from app.llm.router import get_llm_router
from app.llm.types import LLMMessage, LLMRequest, TaskPolicy


async def run_architecture_agent(state: AnalysisState) -> Dict[str, Any]:
    """Analyze high-level architecture, module boundaries, and design patterns using targeted ContextBundle."""
    scan_id = UUID(state["scan_id"])
    manifest = state.get("manifest_summary", {})
    languages = state.get("languages", {})
    frameworks = state.get("frameworks", [])
    overview = state.get("architecture_overview", "")
    context_engine = state.get("context_engine")

    # Retrieve targeted context bundle
    targeted_code = ""
    graph_context = ""
    if context_engine:
        bundle = await context_engine.build_context_bundle(
            scan_id=str(scan_id),
            query=f"architecture layer module structure {overview[:80]}",
            analysis_intent="architecture",
            context_budget=3000,
            max_chunks=4,
        )
        targeted_code = "\n\n".join(
            f"--- {c.chunk.file_path} ({c.chunk.symbol}:{c.chunk.start_line}-{c.chunk.end_line}) ---\n{c.chunk.content}"
            for c in bundle.relevant_chunks
        )
        graph_context = "\n".join(
            f"{e.source} --[{e.kind.value}]--> {e.target}" for e in bundle.graph_relationships[:10]
        )

    system_prompt = (
        "You are the Architecture Specialist AI Agent for RepoLens. "
        "Analyze the repository's modularity, layer boundaries, and design patterns. "
        "Identify architectural anti-patterns, cyclic dependencies, or layer violations.\n"
        "Return ONLY a JSON object with this exact structure:\n"
        "{\n"
        '  "findings": [\n'
        "    {\n"
        '      "title": "Short descriptive title",\n'
        '      "description": "Clear explanation of architectural issue",\n'
        '      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",\n'
        '      "category": "architecture",\n'
        '      "file_path": "relative/file/path.ext",\n'
        '      "start_line": 1,\n'
        '      "end_line": 10,\n'
        '      "code_snippet": "Relevant code snippet if applicable",\n'
        '      "mitigation_guidance": "Recommended architectural refactoring"\n'
        "    }\n"
        "  ]\n"
        "}\n"
        "CRITICAL: Do NOT fabricate file paths or line numbers. If no issues exist, return an empty findings list."
    )

    user_prompt = (
        f"Repository: {state['repository_url']} ({state['commit_hash']})\n"
        f"Overview: {overview}\n"
        f"Languages: {languages}\n"
        f"Frameworks: {frameworks}\n"
        f"Total Files: {manifest.get('total_files', 0)}\n"
        f"Graph Relationships:\n{graph_context or 'None'}\n\n"
        f"Targeted Code Chunks:\n{targeted_code or 'No code chunks retrieved'}\n"
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
            task_policy=TaskPolicy.ARCHITECTURE,
            temperature=0.1,
            max_tokens=2048,
        )
        response = await router.generate(request)
        model_executions.append(response.metadata)
        candidate_findings = parse_llm_findings(
            raw_content=response.content,
            scan_id=scan_id,
            default_category="architecture",
            model_metadata=response.metadata,
        )
    except Exception as exc:
        errors.append(f"Architecture Agent error: {str(exc)}")

    return {
        "candidate_findings": candidate_findings,
        "model_executions": model_executions,
        "errors": errors,
    }
