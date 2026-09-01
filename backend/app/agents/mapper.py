"""Repository Mapper specialist node: deterministic structural mapping and light classification."""

import json
from typing import Any, Dict
from app.agents.state import AnalysisState
from app.llm.router import get_llm_router
from app.llm.types import LLMMessage, LLMRequest, ModelCapability, TaskPolicy
from app.llm.workflow_contracts import lineage_for_scan


async def run_repository_mapper(state: AnalysisState) -> Dict[str, Any]:
    """Execute Repository Mapper.
    
    Extracts structural facts from the repository manifest, routes, frameworks,
    and static findings, invoking Groq GPT-OSS 20B only for light architectural categorization.
    """
    manifest_summary = state.get("manifest_summary", {})
    languages = state.get("languages", {})
    frameworks = state.get("frameworks", [])

    # If architecture overview is not provided, invoke lightweight classification
    overview = f"Repository containing {manifest_summary.get('total_files', 0)} files across languages: {list(languages.keys())}."
    model_executions = []
    errors = []

    try:
        router = get_llm_router()
        prompt = (
            f"Given a repository with languages {languages} and frameworks {frameworks}, "
            f"provide a concise 1-sentence architectural summary and archetype category (e.g. Monorepo, REST API, Fullstack Web App)."
        )
        request = LLMRequest(
            messages=[
                LLMMessage(role="system", content="You are a repository mapping assistant. Respond concisely."),
                LLMMessage(role="user", content=prompt),
            ],
            task_policy=TaskPolicy.LIGHTWEIGHT_CLASSIFICATION,
            capability=ModelCapability.CLASSIFICATION,
            lineage=lineage_for_scan(
                str(state.get("scan_id", "")),
                prompt_template_version="repository-mapper/1.0",
                output_schema_version=None,
                evidence={"manifest": manifest_summary, "languages": languages, "frameworks": frameworks},
            ),
            temperature=0.0,
            max_tokens=150,
        )
        response = await router.generate(request)
        overview = response.content.strip()
        model_executions.append(response.metadata)
    except Exception as exc:
        errors.append(f"Repository Mapper LLM classification notice: {str(exc)}")

    return {
        "architecture_overview": overview,
        "completed_nodes": ["mapper"],
        "model_executions": model_executions,
        "errors": errors,
    }
