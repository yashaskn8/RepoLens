"""Adversarial and rigorous unit tests for the enhanced Phase 1F Verifier Agent."""

import json
import os
import tempfile
from unittest.mock import AsyncMock, patch
from uuid import uuid4
import pytest

from app.agents.verifier import _select_verifier_policy, run_verifier_agent
from app.llm.types import LLMProvider, LLMResponse, ModelExecutionMetadata, TaskPolicy
from app.schemas.enums import Severity, VerificationVerdict
from app.schemas.evidence import Evidence
from app.schemas.finding import Finding


@pytest.fixture
def workspace_with_code():
    """Create a temporary repository workspace with sample Python code."""
    with tempfile.TemporaryDirectory(prefix="verifier_test_") as tmp_dir:
        # Create real auth.py with 10 lines
        auth_code = (
            "import jwt\n"
            "SECRET_KEY = 'supersecret'\n\n"
            "def verify_token(token: str):\n"
            "    return jwt.decode(token, key=SECRET_KEY, algorithms=['HS256'])\n\n"
            "def insecure_debug_endpoint():\n"
            "    pass\n"
        )
        with open(os.path.join(tmp_dir, "auth.py"), "w", encoding="utf-8") as f:
            f.write(auth_code)

        yield tmp_dir


def test_verifier_provider_diversity_selection():
    """Verify that verifier selects an independent provider different from the candidate creator."""
    assert _select_verifier_policy("gemini") == TaskPolicy.VERIFICATION       # NVIDIA
    assert _select_verifier_policy("nvidia") == TaskPolicy.SECURITY_REASONING  # Groq
    assert _select_verifier_policy("groq") == TaskPolicy.VERIFICATION         # NVIDIA
    assert _select_verifier_policy("huggingface") == TaskPolicy.VERIFICATION  # NVIDIA


@pytest.mark.asyncio
async def test_verifier_rejects_fabricated_files(workspace_with_code):
    """Adversarial Test: Verifier MUST reject findings pointing to non-existent files."""
    scan_id = str(uuid4())
    fake_finding = Finding(
        scan_id=scan_id,
        title="SQL Injection in Fake File",
        description="Exploitable SQL query in non-existent file",
        severity=Severity.CRITICAL,
        evidences=[
            Evidence(file_path="nonexistent_database.py", start_line=10, end_line=12)
        ],
        model_metadata=ModelExecutionMetadata(provider="gemini", model_name="gemini-3.7-flash"),
    )

    state = {
        "scan_id": scan_id,
        "repo_dir": workspace_with_code,
        "candidate_findings": [fake_finding],
    }

    result = await run_verifier_agent(state)

    # Must NOT be in verified_findings
    assert len(result["verified_findings"]) == 0

    # Must be recorded in rejected_findings with clear reason
    assert len(result["rejected_findings"]) == 1
    rejection = result["rejected_findings"][0]
    assert rejection["verdict"] == VerificationVerdict.REJECTED.value
    assert "Fabricated file" in rejection["reason"]
    assert "nonexistent_database.py" in rejection["file_path"]


@pytest.mark.asyncio
async def test_verifier_rejects_out_of_bounds_lines(workspace_with_code):
    """Adversarial Test: Verifier MUST reject findings referencing invalid line ranges."""
    scan_id = str(uuid4())
    invalid_line_finding = Finding(
        scan_id=scan_id,
        title="Buffer Overflow on Line 999",
        description="Claimed flaw beyond end of file",
        severity=Severity.HIGH,
        evidences=[
            Evidence(file_path="auth.py", start_line=999, end_line=1005)
        ],
        model_metadata=ModelExecutionMetadata(provider="groq", model_name="gpt-oss-120b"),
    )

    state = {
        "scan_id": scan_id,
        "repo_dir": workspace_with_code,
        "candidate_findings": [invalid_line_finding],
    }

    result = await run_verifier_agent(state)

    assert len(result["verified_findings"]) == 0
    assert len(result["rejected_findings"]) == 1
    rejection = result["rejected_findings"][0]
    assert rejection["verdict"] == VerificationVerdict.REJECTED.value
    assert "Invalid line range" in rejection["reason"]


@pytest.mark.asyncio
async def test_verifier_deduplicates_identical_findings(workspace_with_code):
    """Adversarial Test: Duplicate findings across agents must be deduplicated."""
    scan_id = str(uuid4())
    finding1 = Finding(
        scan_id=scan_id,
        title="Unprotected Endpoint",
        description="Missing auth check on insecure_debug_endpoint",
        severity=Severity.HIGH,
        evidences=[Evidence(file_path="auth.py", start_line=7, end_line=8)],
        model_metadata=ModelExecutionMetadata(provider="gemini", model_name="gemini-3.7-flash"),
    )
    finding2 = Finding(
        scan_id=scan_id,
        title="Unprotected Endpoint",
        description="Duplicate observation from another agent",
        severity=Severity.HIGH,
        evidences=[Evidence(file_path="auth.py", start_line=7, end_line=8)],
        model_metadata=ModelExecutionMetadata(provider="groq", model_name="gpt-oss-120b"),
    )

    state = {
        "scan_id": scan_id,
        "repo_dir": workspace_with_code,
        "candidate_findings": [finding1, finding2],
    }

    # Mock verifier model confirming the first finding
    mock_router = AsyncMock()
    mock_response = LLMResponse(
        content=json.dumps({
            "evaluations": [
                {"index": 0, "verdict": "CONFIRMED", "justified_severity": "HIGH", "reason": "Endpoint lacks auth."}
            ]
        }),
        model="nemotron",
        provider=LLMProvider.NVIDIA,
        metadata=ModelExecutionMetadata(provider=LLMProvider.NVIDIA, model_name="nemotron", prompt_tokens=10, completion_tokens=10, total_tokens=20, latency_ms=10.0),
    )
    mock_router.generate.return_value = mock_response

    with patch("app.agents.verifier.get_llm_router", return_value=mock_router):
        result = await run_verifier_agent(state)

    # Exactly 1 verified finding
    assert len(result["verified_findings"]) == 1
    assert result["verified_findings"][0].verification_verdict == VerificationVerdict.CONFIRMED

    # Exactly 1 rejected finding (the duplicate)
    assert len(result["rejected_findings"]) == 1
    assert "Duplicate finding" in result["rejected_findings"][0]["reason"]


@pytest.mark.asyncio
async def test_verifier_rejects_contradictory_claims(workspace_with_code):
    """Adversarial Test: When candidate claims a flaw that contradicts the real code, verifier rejects it."""
    scan_id = str(uuid4())
    contradictory_finding = Finding(
        scan_id=scan_id,
        title="Unverified JWT Decoding",
        description="Claiming jwt.decode is called with verify=False, but code has key=SECRET_KEY",
        severity=Severity.CRITICAL,
        evidences=[
            Evidence(file_path="auth.py", start_line=4, end_line=5, code_snippet="jwt.decode(token, verify=False)")
        ],
        model_metadata=ModelExecutionMetadata(provider="huggingface", model_name="qwen3"),
    )

    state = {
        "scan_id": scan_id,
        "repo_dir": workspace_with_code,
        "candidate_findings": [contradictory_finding],
    }

    # Mock verifier model detecting the contradiction
    mock_router = AsyncMock()
    mock_response = LLMResponse(
        content=json.dumps({
            "evaluations": [
                {
                    "index": 0,
                    "verdict": "REJECTED",
                    "reason": "Contradictory evidence: Line 5 explicitly uses key=SECRET_KEY and algorithm validation."
                }
            ]
        }),
        model="nemotron",
        provider=LLMProvider.NVIDIA,
        metadata=ModelExecutionMetadata(provider=LLMProvider.NVIDIA, model_name="nemotron", prompt_tokens=10, completion_tokens=10, total_tokens=20, latency_ms=10.0),
    )
    mock_router.generate.return_value = mock_response

    with patch("app.agents.verifier.get_llm_router", return_value=mock_router):
        result = await run_verifier_agent(state)

    assert len(result["verified_findings"]) == 0
    assert len(result["rejected_findings"]) == 1
    assert result["rejected_findings"][0]["verdict"] == VerificationVerdict.REJECTED.value
    assert "Contradictory evidence" in result["rejected_findings"][0]["reason"]


@pytest.mark.asyncio
async def test_verifier_adjusts_severity_and_confirms(workspace_with_code):
    """Verify that verifier can adjust exaggerated severity and confirm valid finding."""
    scan_id = str(uuid4())
    valid_finding = Finding(
        scan_id=scan_id,
        title="Empty Insecure Debug Function",
        description="Empty pass statement in debug endpoint",
        severity=Severity.CRITICAL,  # Exaggerated severity
        evidences=[
            Evidence(file_path="auth.py", start_line=7, end_line=8)
        ],
        model_metadata=ModelExecutionMetadata(provider="gemini", model_name="gemini-3.7-flash"),
    )

    state = {
        "scan_id": scan_id,
        "repo_dir": workspace_with_code,
        "candidate_findings": [valid_finding],
    }

    mock_router = AsyncMock()
    mock_response = LLMResponse(
        content=json.dumps({
            "evaluations": [
                {
                    "index": 0,
                    "verdict": "CONFIRMED",
                    "justified_severity": "LOW",
                    "reason": "Dead code function present, but not exploitable. Downgraded to LOW."
                }
            ]
        }),
        model="nemotron",
        provider=LLMProvider.NVIDIA,
        metadata=ModelExecutionMetadata(provider=LLMProvider.NVIDIA, model_name="nemotron", prompt_tokens=10, completion_tokens=10, total_tokens=20, latency_ms=10.0),
    )
    mock_router.generate.return_value = mock_response

    with patch("app.agents.verifier.get_llm_router", return_value=mock_router):
        result = await run_verifier_agent(state)

    assert len(result["verified_findings"]) == 1
    vf = result["verified_findings"][0]
    assert vf.verification_verdict == VerificationVerdict.CONFIRMED
    assert vf.severity == Severity.LOW  # Adjusted from CRITICAL
    assert "Downgraded to LOW" in vf.verification_reason


@pytest.mark.asyncio
async def test_verifier_no_variable_leakage_across_candidates_multiverdict(workspace_with_code):
    """Phase 3.5J Regression Test: Prove that across multiple candidate findings evaluated in the same batch
    (CONFIRMED, POSSIBLE, REJECTED), all resulting finding_ids, titles, file_paths, verdicts, and reasons
    map strictly to the exact input candidate without stale variable leakage.
    """
    scan_id = str(uuid4())

    c_confirmed = Finding(
        id=uuid4(),
        scan_id=scan_id,
        title="Confirmed Hardcoded JWT Secret",
        description="SECRET_KEY defined inline",
        severity=Severity.HIGH,
        evidences=[Evidence(file_path="auth.py", start_line=2, end_line=2, code_snippet="SECRET_KEY = 'supersecret'")],
        model_metadata=ModelExecutionMetadata(provider="gemini", model_name="gemini-3.7-flash"),
    )

    c_possible = Finding(
        id=uuid4(),
        scan_id=scan_id,
        title="Possible Insecure Token Verification",
        description="Token decode lacks audience check",
        severity=Severity.MEDIUM,
        evidences=[Evidence(file_path="auth.py", start_line=4, end_line=5, code_snippet="jwt.decode(...)")],
        model_metadata=ModelExecutionMetadata(provider="gemini", model_name="gemini-3.7-flash"),
    )

    c_rejected = Finding(
        id=uuid4(),
        scan_id=scan_id,
        title="Rejected False Positive SQLi",
        description="Claimed SQL injection on empty debug endpoint",
        severity=Severity.CRITICAL,
        evidences=[Evidence(file_path="auth.py", start_line=7, end_line=8, code_snippet="def insecure_debug_endpoint(): pass")],
        model_metadata=ModelExecutionMetadata(provider="gemini", model_name="gemini-3.7-flash"),
    )

    state = {
        "scan_id": scan_id,
        "repo_dir": workspace_with_code,
        "candidate_findings": [c_confirmed, c_possible, c_rejected],
    }

    mock_router = AsyncMock()
    mock_response = LLMResponse(
        content=json.dumps({
            "evaluations": [
                {
                    "index": 0,
                    "verdict": "CONFIRMED",
                    "justified_severity": "HIGH",
                    "reason": "Hardcoded secret verified on line 2."
                },
                {
                    "index": 1,
                    "verdict": "POSSIBLE",
                    "justified_severity": "MEDIUM",
                    "reason": "Token decode could be insecure depending on algorithm whitelist."
                },
                {
                    "index": 2,
                    "verdict": "REJECTED",
                    "justified_severity": "LOW",
                    "reason": "No SQL query in function; false positive."
                }
            ]
        }),
        model="nemotron",
        provider=LLMProvider.NVIDIA,
        metadata=ModelExecutionMetadata(
            provider=LLMProvider.NVIDIA,
            model_name="nemotron",
            prompt_tokens=50,
            completion_tokens=50,
            total_tokens=100,
            latency_ms=25.0,
        ),
    )
    mock_router.generate.return_value = mock_response

    with patch("app.agents.verifier.get_llm_router", return_value=mock_router):
        result = await run_verifier_agent(state)

    # 1. Verify finding counts
    assert len(result["verified_findings"]) == 2
    assert len(result["rejected_findings"]) == 1

    # 2. Verify CONFIRMED candidate mapping
    vf_conf = next(f for f in result["verified_findings"] if f.verification_verdict == VerificationVerdict.CONFIRMED)
    assert vf_conf.id == c_confirmed.id
    assert vf_conf.title == "Confirmed Hardcoded JWT Secret"
    assert vf_conf.verification_reason == "Hardcoded secret verified on line 2."
    assert vf_conf.evidences[0].file_path == "auth.py"

    # 3. Verify POSSIBLE candidate mapping
    vf_poss = next(f for f in result["verified_findings"] if f.verification_verdict == VerificationVerdict.POSSIBLE)
    assert vf_poss.id == c_possible.id
    assert vf_poss.title == "Possible Insecure Token Verification"
    assert vf_poss.verification_reason == "Token decode could be insecure depending on algorithm whitelist."
    assert vf_poss.evidences[0].file_path == "auth.py"

    # 4. Verify REJECTED candidate mapping (specifically ensuring NO variable leakage from other candidates)
    rf = result["rejected_findings"][0]
    assert rf["finding_id"] == str(c_rejected.id)
    assert rf["title"] == "Rejected False Positive SQLi"
    assert rf["file_path"] == "auth.py"
    assert rf["verdict"] == "REJECTED"
    assert rf["reason"] == "No SQL query in function; false positive."

