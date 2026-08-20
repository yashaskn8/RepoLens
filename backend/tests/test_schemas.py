"""Tests for canonical domain schemas and enums."""

import uuid
import pytest
from pydantic import ValidationError

from app.schemas.enums import FindingStatus, ScanStatus, Severity
from app.schemas.evidence import Evidence, EvidenceCreate
from app.schemas.finding import Finding, FindingCreate
from app.schemas.metadata import ModelExecutionMetadata
from app.schemas.scan import Scan, ScanCreate


def test_severity_enum_values():
    """Verify Severity enum contains standard values."""
    assert Severity.CRITICAL == "CRITICAL"
    assert Severity.HIGH == "HIGH"
    assert Severity.MEDIUM == "MEDIUM"
    assert Severity.LOW == "LOW"
    assert Severity.INFO == "INFO"


def test_finding_status_enum_values():
    """Verify FindingStatus enum contains expected lifecycles."""
    assert FindingStatus.OPEN == "OPEN"
    assert FindingStatus.RESOLVED == "RESOLVED"
    assert FindingStatus.FALSE_POSITIVE == "FALSE_POSITIVE"
    assert FindingStatus.SUPPRESSED == "SUPPRESSED"


def test_scan_status_enum_values():
    """Verify ScanStatus enum values."""
    assert ScanStatus.PENDING == "PENDING"
    assert ScanStatus.RUNNING == "RUNNING"
    assert ScanStatus.COMPLETED == "COMPLETED"
    assert ScanStatus.FAILED == "FAILED"


def test_model_execution_metadata_schema():
    """Verify ModelExecutionMetadata validation and serialization."""
    meta = ModelExecutionMetadata(
        model_name="gemini-1.5-pro",
        provider="google",
        prompt_tokens=100,
        completion_tokens=50,
        total_tokens=150,
        execution_time_ms=350.2,
        temperature=0.0,
        extra_metadata={"cached": False},
    )
    assert meta.model_name == "gemini-1.5-pro"
    assert meta.provider == "google"
    assert meta.prompt_tokens == 100
    assert meta.completion_tokens == 50
    assert meta.total_tokens == 150
    assert meta.execution_time_ms == 350.2
    assert meta.temperature == 0.0
    assert meta.extra_metadata["cached"] is False


def test_evidence_schema_defaults_and_validation():
    """Verify Evidence schema validation."""
    evidence = Evidence(
        file_path="backend/app/main.py",
        start_line=10,
        end_line=15,
        code_snippet="app = FastAPI()",
        context_notes="App initialization",
    )
    assert isinstance(evidence.id, uuid.UUID)
    assert evidence.file_path == "backend/app/main.py"
    assert evidence.start_line == 10
    assert evidence.end_line == 15

    # Negative start_line should fail validation
    with pytest.raises(ValidationError):
        Evidence(file_path="main.py", start_line=0)


def test_finding_schema_with_evidence_and_metadata():
    """Verify Finding schema full lifecycle object."""
    scan_id = uuid.uuid4()
    finding_id = uuid.uuid4()

    evidence = Evidence(
        file_path="src/security/crypto.py",
        start_line=25,
        end_line=28,
        code_snippet="cipher = DES.new(key)",
        context_notes="Weak encryption algorithm",
    )

    metadata = ModelExecutionMetadata(
        model_name="gemini-1.5-flash",
        provider="google",
        prompt_tokens=200,
        completion_tokens=80,
    )

    finding = Finding(
        id=finding_id,
        scan_id=scan_id,
        title="Weak DES Encryption Used",
        description="DES encryption algorithm is vulnerable to brute-force attacks.",
        severity=Severity.HIGH,
        status=FindingStatus.OPEN,
        rule_id="CRYPTO-DES-001",
        category="security",
        evidences=[evidence],
        mitigation_guidance="Upgrade to AES-GCM 256-bit encryption.",
        model_metadata=metadata,
    )

    assert finding.id == finding_id
    assert finding.scan_id == scan_id
    assert finding.severity == Severity.HIGH
    assert finding.status == FindingStatus.OPEN
    assert len(finding.evidences) == 1
    assert finding.evidences[0].file_path == "src/security/crypto.py"
    assert finding.model_metadata.model_name == "gemini-1.5-flash"
    assert finding.created_at is not None
    assert finding.updated_at is not None


def test_scan_schema_creation_and_nesting():
    """Verify Scan schema nesting findings and metadata."""
    scan_id = uuid.uuid4()
    finding = Finding(
        scan_id=scan_id,
        title="Hardcoded API Key",
        description="Detected plaintext secret key.",
        severity=Severity.CRITICAL,
    )

    scan = Scan(
        id=scan_id,
        repository_url="https://github.com/example/repo",
        branch="main",
        commit_hash="c0ffee123456",
        status=ScanStatus.COMPLETED,
        findings_count=1,
        findings=[finding],
    )

    assert scan.id == scan_id
    assert scan.repository_url == "https://github.com/example/repo"
    assert scan.status == ScanStatus.COMPLETED
    assert scan.findings_count == 1
    assert len(scan.findings) == 1
    assert scan.findings[0].severity == Severity.CRITICAL
