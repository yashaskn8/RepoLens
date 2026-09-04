"""Adversarial and rigorous unit tests for the enhanced Phase 1F Verifier Agent."""

import json
import hashlib
import os
import tempfile
from unittest.mock import AsyncMock, patch
from uuid import uuid4
import pytest

from app.agents.verifier import _apply_atomic_claim_constraints, _select_verifier_policy, run_verifier_agent
from app.atomic_claims import AtomicClaim, AtomicClaimType
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


def _finding_with_atomic_claims() -> Finding:
    evidence_ref = "chunk:repo:auth.py:verify:1"
    claims = [
        AtomicClaim(
            claim_id=f"claim:{claim_type.value.lower()}",
            claim_type=claim_type,
            claim_text=f"{claim_type.value} claim",
            evidence_refs=[evidence_ref],
        )
        for claim_type in (
            AtomicClaimType.SOURCE_BEHAVIOR,
            AtomicClaimType.TRIGGER,
            AtomicClaimType.MECHANISM,
            AtomicClaimType.IMPACT,
            AtomicClaimType.SEVERITY,
        )
    ]
    return Finding(
        scan_id=uuid4(),
        title="Atomic finding",
        description="A candidate with independently verifiable claims.",
        severity=Severity.CRITICAL,
        evidences=[Evidence(file_path="auth.py", start_line=1, end_line=2)],
        model_metadata=ModelExecutionMetadata(
            provider="gemini",
            model_name="candidate-model",
            extra_metadata={"atomic_claims": [claim.model_dump(mode="json") for claim in claims]},
        ),
    )


def test_atomic_verifier_blocks_confirmation_when_trigger_is_unsupported():
    finding = _finding_with_atomic_claims()
    claim_results = [
        {"claim_type": claim_type.value, "state": "SUPPORTED"}
        for claim_type in (
            AtomicClaimType.SOURCE_BEHAVIOR,
            AtomicClaimType.MECHANISM,
            AtomicClaimType.IMPACT,
            AtomicClaimType.SEVERITY,
        )
    ] + [{"claim_type": "TRIGGER", "state": "INSUFFICIENT"}]

    verdict, severity, _ = _apply_atomic_claim_constraints(
        finding,
        {"claims": claim_results},
        raw_verdict="CONFIRMED",
        justified_severity="HIGH",
        reason="Candidate appears plausible.",
    )

    assert verdict == "POSSIBLE"
    assert severity == "HIGH"


def test_atomic_verifier_caps_severity_when_impact_is_unsupported():
    finding = _finding_with_atomic_claims()
    claim_results = [
        {"claim_type": claim_type.value, "state": "SUPPORTED"}
        for claim_type in (
            AtomicClaimType.SOURCE_BEHAVIOR,
            AtomicClaimType.TRIGGER,
            AtomicClaimType.MECHANISM,
            AtomicClaimType.SEVERITY,
        )
    ] + [{"claim_type": "IMPACT", "state": "INSUFFICIENT"}]

    verdict, severity, reason = _apply_atomic_claim_constraints(
        finding,
        {"claims": claim_results},
        raw_verdict="CONFIRMED",
        justified_severity="CRITICAL",
        reason="Underlying mechanism is supported.",
    )

    assert verdict == "CONFIRMED"
    assert severity == "MEDIUM"
    assert "impact" in reason.lower()


def test_malformed_atomic_contract_cannot_confirm_or_retain_high_severity():
    finding = _finding_with_atomic_claims()
    finding.model_metadata.extra_metadata["atomic_claims"] = [{"claim_type": "TRIGGER"}]

    verdict, severity, reason = _apply_atomic_claim_constraints(
        finding,
        {"claims": []},
        raw_verdict="CONFIRMED",
        justified_severity="HIGH",
        reason="Verifier returned a broad approval.",
    )

    assert verdict == "POSSIBLE"
    assert severity == "MEDIUM"
    assert "malformed" in reason.lower()


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
            Evidence(
                file_path="auth.py",
                start_line=7,
                end_line=8,
                code_snippet="MODEL INVENTED THIS SNIPPET",
                context_notes="MODEL INVENTED THIS NOTE",
            )
        ],
        model_metadata=ModelExecutionMetadata(provider="gemini", model_name="gemini-3.7-flash"),
    )

    state = {
        "scan_id": scan_id,
        "commit_hash": "abc123",
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
    with open(os.path.join(workspace_with_code, "auth.py"), "rb") as source_file:
        expected_bytes = b"".join(source_file.read().splitlines(keepends=True)[6:8])
    expected_snippet = expected_bytes.decode("utf-8")
    assert vf.evidences[0].code_snippet == expected_snippet
    assert "MODEL INVENTED" not in (vf.evidences[0].context_notes or "")
    assert "commit_sha=abc123" in (vf.evidences[0].context_notes or "")
    assert "path=auth.py" in (vf.evidences[0].context_notes or "")
    assert "range=7-8" in (vf.evidences[0].context_notes or "")
    assert (
        f"content_sha256={hashlib.sha256(expected_bytes).hexdigest()}"
        in (vf.evidences[0].context_notes or "")
    )


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

    # 1. Only independently CONFIRMED findings cross the publication boundary.
    assert len(result["verified_findings"]) == 1
    assert len(result["rejected_findings"]) == 2

    # 2. Verify CONFIRMED candidate mapping
    vf_conf = result["verified_findings"][0]
    assert vf_conf.id == c_confirmed.id
    assert vf_conf.title == "Confirmed Hardcoded JWT Secret"
    assert vf_conf.verification_reason == "Hardcoded secret verified on line 2."
    assert vf_conf.evidences[0].file_path == "auth.py"

    # 3. POSSIBLE remains an honest diagnostic and is never published.
    possible = next(
        finding for finding in result["rejected_findings"]
        if finding["finding_id"] == str(c_possible.id)
    )
    assert possible["title"] == "Possible Insecure Token Verification"
    assert possible["file_path"] == "auth.py"
    assert possible["verdict"] == "POSSIBLE"
    assert possible["reason"] == "Token decode could be insecure depending on algorithm whitelist."

    # 4. Verify REJECTED candidate mapping (specifically ensuring NO variable leakage from other candidates)
    rf = next(
        finding for finding in result["rejected_findings"]
        if finding["finding_id"] == str(c_rejected.id)
    )
    assert rf["finding_id"] == str(c_rejected.id)
    assert rf["title"] == "Rejected False Positive SQLi"
    assert rf["file_path"] == "auth.py"
    assert rf["verdict"] == "REJECTED"
    assert rf["reason"] == "No SQL query in function; false positive."


@pytest.mark.asyncio
async def test_verifier_missing_evaluation_fails_closed(workspace_with_code):
    """A partial/empty verifier response must not publish a merely located claim."""
    scan_id = str(uuid4())
    candidate = Finding(
        scan_id=scan_id,
        title="Unconfirmed claim",
        description="A source locator alone does not prove this semantic claim.",
        severity=Severity.HIGH,
        evidences=[Evidence(file_path="auth.py", start_line=1, end_line=2)],
        model_metadata=ModelExecutionMetadata(provider="gemini", model_name="gemini-flash"),
    )
    mock_router = AsyncMock()
    mock_router.generate.return_value = LLMResponse(
        content=json.dumps({"confidence": 0.9, "evaluations": []}),
        model="nemotron",
        provider=LLMProvider.NVIDIA,
        metadata=ModelExecutionMetadata(provider=LLMProvider.NVIDIA, model_name="nemotron"),
    )

    with patch("app.agents.verifier.get_llm_router", return_value=mock_router):
        result = await run_verifier_agent({
            "scan_id": scan_id,
            "commit_hash": "deadbeef",
            "repo_dir": workspace_with_code,
            "candidate_findings": [candidate],
        })

    assert result["verified_findings"] == []
    assert len(result["rejected_findings"]) == 1
    diagnostic = result["rejected_findings"][0]
    assert diagnostic["finding_id"] == str(candidate.id)
    assert diagnostic["verdict"] == VerificationVerdict.POSSIBLE.value
    assert "semantic claim remains unconfirmed" in diagnostic["reason"]


@pytest.mark.asyncio
async def test_verifier_provider_failure_fails_closed(workspace_with_code):
    """Provider errors remain diagnostics rather than silently accepted findings."""
    scan_id = str(uuid4())
    candidate = Finding(
        scan_id=scan_id,
        title="Unconfirmed claim after provider failure",
        description="The verifier is unavailable.",
        severity=Severity.MEDIUM,
        evidences=[Evidence(file_path="auth.py", start_line=4, end_line=5)],
        model_metadata=ModelExecutionMetadata(provider="gemini", model_name="gemini-flash"),
    )
    mock_router = AsyncMock()
    mock_router.generate.side_effect = RuntimeError("quota exhausted")

    with patch("app.agents.verifier.get_llm_router", return_value=mock_router):
        result = await run_verifier_agent({
            "scan_id": scan_id,
            "repo_dir": workspace_with_code,
            "candidate_findings": [candidate],
        })

    assert result["verified_findings"] == []
    assert result["rejected_findings"][0]["verdict"] == VerificationVerdict.POSSIBLE.value
    assert result["errors"]
    assert "quota exhausted" in result["errors"][0]


@pytest.mark.asyncio
async def test_attested_deterministic_detectors_do_not_depend_on_an_llm(workspace_with_code):
    """Scanner/contract facts survive provider outages without inferring exploitability."""
    scan_id = str(uuid4())
    scanner_finding = Finding(
        scan_id=scan_id,
        title="Semgrep detector result",
        description="Canonical scanner-authored description.",
        severity=Severity.HIGH,
        evidences=[Evidence(
            file_path="auth.py",
            start_line=2,
            end_line=2,
            code_snippet="MODEL-SUPPLIED FALSE SNIPPET",
        )],
        source_tool="semgrep",
        detector_id="python.lang.security.hardcoded-secret",
        detector_kind="static_scanner",
    )
    contract_finding = Finding(
        scan_id=scan_id,
        title="Catastrophic remote compromise",
        description="Model-authored impact that is not a deterministic contract fact.",
        severity=Severity.CRITICAL,
        mitigation_guidance="Model-authored remediation.",
        evidences=[Evidence(file_path="auth.py", start_line=4, end_line=4)],
        source_tool="route_contract",
        detector_id="contract:frontend-login-request",
        detector_kind="contract_matcher",
    )

    mock_router = AsyncMock()
    mock_router.generate.side_effect = AssertionError("deterministic facts must not call an LLM")
    with patch("app.agents.verifier.get_llm_router", return_value=mock_router):
        result = await run_verifier_agent({
            "scan_id": scan_id,
            "commit_hash": "feedface",
            "repo_dir": workspace_with_code,
            "candidate_findings": [scanner_finding, contract_finding],
        })

    assert len(result["verified_findings"]) == 2
    assert result["rejected_findings"] == []
    mock_router.generate.assert_not_awaited()

    scanner = next(f for f in result["verified_findings"] if f.source_tool == "semgrep")
    assert scanner.verification_verdict == VerificationVerdict.CONFIRMED
    assert scanner.evidences[0].code_snippet != "MODEL-SUPPLIED FALSE SNIPPET"
    assert "exploitability was not inferred" in (scanner.verification_reason or "")

    contract = next(f for f in result["verified_findings"] if f.source_tool == "route_contract")
    assert contract.title == "Deterministic frontend/API contract mismatch"
    assert contract.severity == Severity.INFO
    assert contract.mitigation_guidance is None
    assert "Catastrophic remote compromise" not in contract.title
