"""Evidence-grounded Verifier Agent validating candidate findings across all verification dimensions."""

import json
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from app.agents.helpers import extract_json_block
from app.agents.state import AnalysisState
from app.llm.router import get_llm_router
from app.llm.types import LLMMessage, LLMProvider, LLMRequest, TaskPolicy
from app.schemas.enums import FindingStatus, Severity, VerificationVerdict
from app.schemas.finding import Finding


def _normalize_title_key(title: str) -> str:
    """Normalize finding title for duplicate detection."""
    return re.sub(r"[^a-zA-Z0-9]", "", title.lower())


def _select_verifier_policy(creator_provider: Optional[str]) -> TaskPolicy:
    """Select an independent verification policy from a different provider than the creator."""
    if not creator_provider:
        return TaskPolicy.VERIFICATION

    prov = creator_provider.lower()
    if "nvidia" in prov:
        return TaskPolicy.SECURITY_REASONING  # Groq
    elif "gemini" in prov:
        return TaskPolicy.VERIFICATION       # NVIDIA
    elif "groq" in prov:
        return TaskPolicy.VERIFICATION       # NVIDIA
    elif "huggingface" in prov or "qwen" in prov:
        return TaskPolicy.VERIFICATION       # NVIDIA
    return TaskPolicy.VERIFICATION


def _read_real_file_lines(repo_dir: str, rel_path: str) -> Optional[List[str]]:
    """Safely read real source lines from repository workspace."""
    if not repo_dir or not rel_path:
        return None

    clean_path = rel_path.replace("\\", "/").lstrip("/")
    abs_path = os.path.abspath(os.path.join(repo_dir, clean_path))

    # Boundary confinement
    if not abs_path.startswith(os.path.abspath(repo_dir)):
        return None

    if not os.path.exists(abs_path) or not os.path.isfile(abs_path):
        return None

    try:
        with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.readlines()
    except Exception:
        return None


async def run_verifier_agent(state: AnalysisState) -> Dict[str, Any]:
    """Rigorously verify candidate findings against 7 independent criteria:
    
    1. File exists in workspace
    2. Symbol / line evidence exists within file bounds
    3. Evidence actually supports the claim (with independent ContextEngine retrieval)
    4. Contradictory evidence is absent
    5. Severity is justified
    6. Recommendation addresses root cause
    7. Deduplication against already accepted findings
    """
    candidate_findings: List[Finding] = state.get("candidate_findings", [])
    repo_dir = state.get("repo_dir", "")
    context_engine = state.get("context_engine")

    verified_findings: List[Finding] = []
    rejected_findings: List[Dict[str, Any]] = []
    model_executions = []
    errors = []

    if not candidate_findings:
        return {
            "verified_findings": [],
            "rejected_findings": [],
            "completed_nodes": ["verifier"],
            "status": "COMPLETED",
        }

    seen_signatures: Set[Tuple[str, Optional[str], Optional[int]]] = set()
    candidates_for_llm: List[Tuple[Finding, str, str, str]] = []  # (finding, real_code_slice, policy, independent_context)

    # =========================================================================
    # Phase 1: Deterministic Verification & Deduplication
    # =========================================================================
    for finding in candidate_findings:
        evidence = finding.evidences[0] if finding.evidences else None
        if not evidence or not evidence.file_path:
            rejected_findings.append({
                "finding_id": str(finding.id),
                "title": finding.title,
                "verdict": VerificationVerdict.REJECTED.value,
                "reason": "Missing required code evidence or file path.",
            })
            continue

        file_path = evidence.file_path.replace("\\", "/").lstrip("/")

        # 1. Deduplication check
        sig = (_normalize_title_key(finding.title), file_path, evidence.start_line)
        if sig in seen_signatures:
            rejected_findings.append({
                "finding_id": str(finding.id),
                "title": finding.title,
                "file_path": file_path,
                "verdict": VerificationVerdict.REJECTED.value,
                "reason": f"Duplicate finding: identical issue already reported for {file_path}:{evidence.start_line}.",
            })
            continue
        seen_signatures.add(sig)

        # 2. File existence check
        file_lines = _read_real_file_lines(repo_dir, file_path)
        if file_lines is None:
            rejected_findings.append({
                "finding_id": str(finding.id),
                "title": finding.title,
                "file_path": file_path,
                "verdict": VerificationVerdict.REJECTED.value,
                "reason": f"Fabricated file: '{file_path}' does not exist in repository workspace.",
            })
            continue

        total_lines = len(file_lines)

        # 3. Line bounds check
        if evidence.start_line is not None:
            if evidence.start_line < 1 or evidence.start_line > total_lines:
                rejected_findings.append({
                    "finding_id": str(finding.id),
                    "title": finding.title,
                    "file_path": file_path,
                    "verdict": VerificationVerdict.REJECTED.value,
                    "reason": f"Invalid line range: start_line {evidence.start_line} exceeds total file lines ({total_lines}).",
                })
                continue

            end_line = min(evidence.end_line or evidence.start_line, total_lines)
            if end_line < evidence.start_line:
                rejected_findings.append({
                    "finding_id": str(finding.id),
                    "title": finding.title,
                    "file_path": file_path,
                    "verdict": VerificationVerdict.REJECTED.value,
                    "reason": f"Invalid line range: end_line ({end_line}) < start_line ({evidence.start_line}).",
                })
                continue

            # Extract actual real code slice from file
            code_slice = "".join(file_lines[evidence.start_line - 1:end_line])
        else:
            # First 50 lines for broad file-level findings
            code_slice = "".join(file_lines[:50])

        # 4. Independent Supporting Evidence Retrieval
        independent_context = ""
        if context_engine:
            try:
                ind_bundle = await context_engine.build_context_bundle(
                    scan_id=state.get("scan_id", "verifier"),
                    query=f"{finding.title} {finding.description[:100]}",
                    analysis_intent="verification",
                    context_budget=1500,
                    max_chunks=2,
                )
                if ind_bundle.relevant_chunks:
                    independent_context = "\n".join(
                        f"Independent retrieved evidence ({c.chunk.file_path}:{c.chunk.start_line}):\n{c.chunk.content[:200]}"
                        for c in ind_bundle.relevant_chunks
                    )
            except Exception:
                pass

        # 5. Determine independent verifier provider policy
        creator_provider = finding.model_metadata.provider if finding.model_metadata else None
        verifier_policy = _select_verifier_policy(creator_provider)

        candidates_for_llm.append((finding, code_slice, verifier_policy, independent_context))

    # If all candidate findings failed deterministic checks, return early
    if not candidates_for_llm:
        return {
            "verified_findings": [],
            "rejected_findings": rejected_findings,
            "completed_nodes": ["verifier"],
            "status": "COMPLETED",
        }

    # =========================================================================
    # Phase 2: Independent LLM Verification Reasoning
    # =========================================================================
    system_prompt = (
        "You are the Independent Verifier AI Agent for RepoLens. "
        "Your task is to independently evaluate candidate code findings against the actual source code.\n\n"
        "For each finding, rigorously assess:\n"
        "1. Evidence Support: Does the actual code snippet prove the claimed defect?\n"
        "2. Contradictory Evidence: Is there counter-evidence (e.g. guard clauses, type checks, decorators) proving the claim false?\n"
        "3. Severity Justification: Is the stated severity accurate or exaggerated?\n"
        "4. Recommendation: Does the suggested fix address the actual root cause?\n\n"
        "Output ONLY a JSON object with this exact structure:\n"
        "{\n"
        '  "evaluations": [\n'
        "    {\n"
        '      "index": 0,\n'
        '      "verdict": "CONFIRMED" | "POSSIBLE" | "REJECTED",\n'
        '      "justified_severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",\n'
        '      "reason": "Clear explanation of verification decision"\n'
        "    }\n"
        "  ]\n"
        "}\n"
        "Rule: Output only CONFIRMED, POSSIBLE, or REJECTED. Reject any unsupported, hallucinated, or contradictory claims."
    )

    items_to_verify = []
    for idx, (f, code_slice, _, ind_ctx) in enumerate(candidates_for_llm):
        ev = f.evidences[0] if f.evidences else None
        items_to_verify.append({
            "index": idx,
            "title": f.title,
            "category": f.category,
            "claimed_severity": f.severity.value,
            "description": f.description,
            "file": ev.file_path if ev else "unknown",
            "lines": f"{ev.start_line}-{ev.end_line}" if ev and ev.start_line else "whole_file",
            "claimed_snippet": ev.code_snippet if ev else "",
            "actual_source_code": code_slice,
            "independent_context": ind_ctx or "None",
            "mitigation_guidance": f.mitigation_guidance or "",
        })

    user_prompt = f"Candidate Findings to Independently Verify:\n{json.dumps(items_to_verify, indent=2)}"

    # Primary policy from first candidate
    primary_policy = candidates_for_llm[0][2]

    try:
        router = get_llm_router()
        request = LLMRequest(
            messages=[
                LLMMessage(role="system", content=system_prompt),
                LLMMessage(role="user", content=user_prompt),
            ],
            task_policy=primary_policy,
            temperature=0.0,
            max_tokens=3000,
        )
        response = await router.generate(request)
        model_executions.append(response.metadata)

        ver_data = json.loads(extract_json_block(response.content))
        eval_map = {
            item["index"]: item
            for item in ver_data.get("evaluations", [])
            if "index" in item and "verdict" in item
        }

        for idx, (f, _, _, _) in enumerate(candidates_for_llm):
            evaluation = eval_map.get(idx)

            if not evaluation:
                # Default to POSSIBLE if grounded but missing model evaluation
                f.verification_verdict = VerificationVerdict.POSSIBLE
                f.verification_reason = "Grounded in source code; passed deterministic checks."
                verified_findings.append(f)
                continue

            raw_verdict = str(evaluation.get("verdict", "")).upper()
            reason = str(evaluation.get("reason", "No verification explanation provided."))

            if raw_verdict == "CONFIRMED":
                f.verification_verdict = VerificationVerdict.CONFIRMED
                f.verification_reason = reason
                justified_sev = evaluation.get("justified_severity")
                if justified_sev and justified_sev in Severity._value2member_map_:
                    f.severity = Severity(justified_sev)
                verified_findings.append(f)

            elif raw_verdict == "POSSIBLE":
                f.verification_verdict = VerificationVerdict.POSSIBLE
                f.verification_reason = reason
                justified_sev = evaluation.get("justified_severity")
                if justified_sev and justified_sev in Severity._value2member_map_:
                    f.severity = Severity(justified_sev)
                verified_findings.append(f)

            else:
                # REJECTED: isolate rejection reason for debugging, do not expose as verified issue
                rejected_findings.append({
                    "finding_id": str(finding.id),
                    "title": finding.title,
                    "file_path": finding.evidences[0].file_path if finding.evidences else "unknown",
                    "verdict": VerificationVerdict.REJECTED.value,
                    "reason": reason,
                })

    except Exception as exc:
        errors.append(f"Verifier Agent LLM reasoning failure: {str(exc)}")
        # Graceful fallback: If LLM call fails, mark deterministic-passed findings as POSSIBLE
        for f, _, _, _ in candidates_for_llm:
            f.verification_verdict = VerificationVerdict.POSSIBLE
            f.verification_reason = "Passed deterministic verification; verifier reasoning fallback."
            verified_findings.append(f)

    return {
        "verified_findings": verified_findings,
        "rejected_findings": rejected_findings,
        "completed_nodes": ["verifier"],
        "model_executions": model_executions,
        "errors": errors,
        "status": "COMPLETED",
    }
