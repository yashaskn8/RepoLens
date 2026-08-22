"""Tests for truthful deterministic tool workflow events and coverage mapping."""

from uuid import UUID, uuid4
import pytest
from sqlalchemy.orm import Session

from app.analysis.schemas import ScannerResult, ToolStatus
from app.analysis.store import EvidenceStore
from app.ingestion.schemas import AnalysisScope, RepositoryManifest
from app.models.scan import ScanModel
from app.models.workflow_event import WorkflowEventModel
from app.schemas.enums import ScanStatus, Severity
from app.schemas.evidence import Evidence
from app.schemas.static_finding import StaticFinding
from app.schemas.workflow_event import WorkflowEventCreate, WorkflowEventType
from app.services.report_service import ScanReportService
from app.services.workflow_event_service import WorkflowEventService


def test_tool_event_emission_and_coverage_mapping(db_session: Session):
    """Verify tool outcome events accurately reflect scanner status without fabricating starts or converting failures to success."""
    scan_id = uuid4()
    scan = ScanModel(
        id=str(scan_id),
        repository_url="https://github.com/org/test-tool-events",
        commit_hash="1122334455667788990011223344556677889900",
        status=ScanStatus.COMPLETED.value,
    )
    db_session.add(scan)
    db_session.commit()

    scanner_results = {
        "semgrep": ScannerResult(
            tool="semgrep",
            status=ToolStatus.COMPLETED,
            findings=[
                StaticFinding(
                    tool="semgrep",
                    rule_id="r1",
                    title="Insecure cookie",
                    description="Cookie without HttpOnly flag",
                    severity=Severity.HIGH,
                    evidence=Evidence(
                        file_path="app/auth.py",
                        start_line=12,
                        end_line=12,
                        code_snippet="res.set_cookie('token', val)",
                    ),
                )
            ],
        ),
        "trivy": ScannerResult(
            tool="trivy",
            status=ToolStatus.UNAVAILABLE,
            error_message="Executable trivy not found in PATH",
        ),
        "osv": ScannerResult(
            tool="osv",
            status=ToolStatus.FAILED,
            error_message="Non-zero exit code 1",
        ),
        "custom_tool": ScannerResult(
            tool="custom_tool",
            status=ToolStatus.TIMEOUT,
            error_message="Command timed out after 30 seconds",
        ),
        "parser_tool": ScannerResult(
            tool="parser_tool",
            status=ToolStatus.INVALID_OUTPUT,
            error_message="Failed to parse JSON output",
        ),
    }

    # Simulate emitting events as done in scans.py
    for tool_name, result in scanner_results.items():
        findings_count = len(result.findings) if result.findings else 0
        if result.status == ToolStatus.COMPLETED:
            evt_type = WorkflowEventType.TOOL_COMPLETED
            msg = f"Deterministic scanner {tool_name} completed with {findings_count} findings"
        elif result.status == ToolStatus.UNAVAILABLE:
            evt_type = WorkflowEventType.TOOL_UNAVAILABLE
            msg = f"Deterministic scanner {tool_name} is unavailable on host"
        elif result.status == ToolStatus.TIMEOUT:
            evt_type = WorkflowEventType.TOOL_FAILED
            msg = f"Deterministic scanner {tool_name} timed out"
        elif result.status == ToolStatus.INVALID_OUTPUT:
            evt_type = WorkflowEventType.TOOL_FAILED
            msg = f"Deterministic scanner {tool_name} produced invalid output"
        else:
            evt_type = WorkflowEventType.TOOL_FAILED
            msg = f"Deterministic scanner {tool_name} failed execution"

        WorkflowEventService.emit(
            db=db_session,
            event=WorkflowEventCreate(
                event_type=evt_type,
                scan_id=scan_id,
                stage="intelligence_analysis",
                tool_name=tool_name,
                message=msg,
                metadata_payload={"status": result.status.value, "findings_count": findings_count},
            ),
        )
    db_session.commit()

    # Query emitted events
    events = (
        db_session.query(WorkflowEventModel)
        .filter(WorkflowEventModel.scan_id == str(scan_id))
        .all()
    )
    assert len(events) == 5

    event_map = {e.tool_name: e for e in events}
    assert event_map["semgrep"].event_type == "TOOL_COMPLETED"
    assert event_map["trivy"].event_type == "TOOL_UNAVAILABLE"
    assert event_map["osv"].event_type == "TOOL_FAILED"
    assert event_map["custom_tool"].event_type == "TOOL_FAILED"
    assert event_map["custom_tool"].metadata_payload["status"] == "TIMEOUT"
    assert event_map["parser_tool"].event_type == "TOOL_FAILED"
    assert event_map["parser_tool"].metadata_payload["status"] == "INVALID_OUTPUT"

    # Verify build_scan_telemetry accurately tallies tool outcomes
    telemetry = ScanReportService.build_scan_telemetry(db=db_session, scan_id=str(scan_id))
    assert telemetry is not None
    assert telemetry.tools_completed == 1
    assert telemetry.tools_unavailable == 1
    assert telemetry.tools_failed == 3
