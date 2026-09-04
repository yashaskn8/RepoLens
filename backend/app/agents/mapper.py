"""Repository Mapper specialist node using deterministic structural facts only."""

from typing import Any, Dict
from app.agents.state import AnalysisState
from app.llm.admission import build_admission_map


def _repository_archetype(
    *,
    frameworks: list[str],
    routes: list[dict[str, Any]],
    frontend_calls: list[dict[str, Any]],
) -> str:
    normalized = " ".join(frameworks).lower()
    if routes and frontend_calls:
        return "full-stack web application"
    if routes:
        return "API or backend service"
    if frontend_calls or any(value in normalized for value in ("react", "next", "vue", "angular", "svelte")):
        return "frontend application"
    if any(value in normalized for value in ("django", "flask", "fastapi", "express", "spring")):
        return "web service"
    return "software repository"


def _deterministic_frameworks(
    configured: list[str],
    routes: list[dict[str, Any]],
) -> list[str]:
    """Augment manifest detection from canonical route symbol kinds."""
    detected = {str(name) for name in configured if str(name).strip()}
    for route in routes:
        kind = str(getattr(route.get("kind"), "value", route.get("kind", ""))).upper()
        if "FASTAPI" in kind:
            detected.add("FastAPI")
        elif "EXPRESS" in kind:
            detected.add("Express")
    return sorted(detected)


async def run_repository_mapper(state: AnalysisState) -> Dict[str, Any]:
    """Execute Repository Mapper.
    
    Extracts structural facts from the repository manifest, routes, and frameworks
    without spending a model call on a summary that deterministic metadata proves.
    """
    manifest_summary = state.get("manifest_summary", {})
    languages = state.get("languages", {})
    frameworks = state.get("frameworks", [])
    routes = state.get("routes", [])
    frontend_calls = state.get("frontend_calls", [])
    frameworks = _deterministic_frameworks(frameworks, routes)
    ordered_languages = sorted(languages, key=lambda key: (-int(languages.get(key, 0)), key))
    archetype = _repository_archetype(
        frameworks=frameworks,
        routes=routes,
        frontend_calls=frontend_calls,
    )
    overview = (
        f"{archetype.capitalize()} with {manifest_summary.get('total_files', 0)} files; "
        f"languages: {', '.join(ordered_languages) or 'unknown'}; "
        f"frameworks: {', '.join(sorted(frameworks)) or 'none detected'}; "
        f"routes: {len(routes)}; frontend requests: {len(frontend_calls)}."
    )

    return {
        "architecture_overview": overview,
        "ai_admission": build_admission_map({
            **state,
            "frameworks": frameworks,
            "architecture_overview": overview,
        }),
        "completed_nodes": ["mapper"],
        "model_executions": [],
        "errors": [],
    }
