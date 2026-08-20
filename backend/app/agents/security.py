"""Security Specialist Agent using Groq GPT-OSS 120B and targeted ContextBundle."""

from uuid import UUID
from typing import Any, Dict
from app.agents.helpers import parse_llm_findings
from app.agents.state import AnalysisState
from app.llm.router import get_llm_router
from app.llm.types import LLMMessage, LLMRequest, TaskPolicy


async def run_security_agent(state: AnalysisState) -> Dict[str, Any]:
    """Analyze security posture, vulnerability findings, and critical code risks using targeted ContextBundle."""
    scan_id = UUID(state["scan_id"])
    context_engine = state.get("context_engine")
    static_findings = state.get("static_findings", [])
    languages = state.get("languages", {})
    frameworks = state.get("frameworks", [])

    targeted_code = ""
    bundled_findings = ""
    if context_engine:
        bundle = await context_engine.build_context_bundle(
            scan_id=str(scan_id),
            query="security vulnerability injection secrets authentication sanitization",
            analysis_intent="security",
            context_budget=3000,
            max_chunks=4,
        )
        targeted_code = "\n\n".join(
            f"--- {c.chunk.file_path} ({c.chunk.symbol}:{c.chunk.start_line}-{c.chunk.end_line}) ---\n{c.chunk.content}"
            for c in bundle.relevant_chunks
        )
        bundled_findings = "\n".join(
            f"[{f.severity.value}] {f.tool}: {f.title} ({f.evidence.file_path}:{f.evidence.start_line})"
            for f in bundle.static_findings[:10]
        )

    system_prompt = (
        "You are the Security Specialist AI Agent for RepoLens. "
        "Analyze deterministic scanner findings (Semgrep, Trivy, OSV) and security-critical codebase patterns. "
        "Prioritize confirmed vulnerabilities, credential exposures, injection risks, and auth flaws.\n"
        "Return ONLY a JSON object with this exact structure:\n"
        "{\n"
        '  "findings": [\n'
        "    {\n"
        '      "title": "Short descriptive security title",\n'
        '      "description": "Vulnerability mechanism and impact",\n'
        '      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",\n'
        '      "category": "security",\n'
        '      "rule_id": "Optional CVE or rule identifier",\n'
        '      "file_path": "relative/file/path.ext",\n'
        '      "start_line": 1,\n'
        '      "end_line": 10,\n'
        '      "code_snippet": "Vulnerable code snippet",\n'
        '      "mitigation_guidance": "Exact remediation or upgrade command"\n'
        "    }\n"
        "  ]\n"
        "}\n"
        "CRITICAL: Never hallucinate CVEs or fabricate files."
    )

    user_prompt = (
        f"Languages: {languages}\n"
        f"Frameworks: {frameworks}\n"
        f"Deterministic Static Findings ({len(static_findings)}):\n{bundled_findings or static_findings[:20]}\n\n"
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
            task_policy=TaskPolicy.SECURITY_REASONING,
            temperature=0.0,
            max_tokens=2048,
        )
        response = await router.generate(request)
        model_executions.append(response.metadata)
        candidate_findings = parse_llm_findings(
            raw_content=response.content,
            scan_id=scan_id,
            default_category="security",
            model_metadata=response.metadata,
        )
    except Exception as exc:
        errors.append(f"Security Agent error: {str(exc)}")

    return {
        "candidate_findings": candidate_findings,
        "model_executions": model_executions,
        "errors": errors,
    }
