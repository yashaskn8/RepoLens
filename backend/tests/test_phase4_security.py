"""Security and isolation tests for Phase 4 Observability, Telemetry, and Events."""

import json
from uuid import uuid4
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.scan import ScanModel
from app.models.workflow_event import WorkflowEventModel
from app.schemas.enums import ScanStatus
from app.schemas.workflow_event import WorkflowEventCreate, WorkflowEventType
from app.security.redaction import (
    MAX_METADATA_DEPTH,
    MAX_METADATA_DICT_ENTRIES,
    MAX_METADATA_LIST_ITEMS,
    MAX_METADATA_STRING_LENGTH,
    redact_secrets,
    sanitize_metadata,
)
from app.services.workflow_event_service import WorkflowEventService, _sanitize_metadata


def test_cross_scan_event_isolation(client: TestClient, db_session: Session):
    """Verify workflow events emitted for Scan A are strictly isolated from Scan B."""
    scan_a_id = uuid4()
    scan_b_id = uuid4()

    scan_a = ScanModel(
        id=str(scan_a_id),
        repository_url="https://github.com/org/repo-a",
        commit_hash="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        status=ScanStatus.COMPLETED.value,
    )
    scan_b = ScanModel(
        id=str(scan_b_id),
        repository_url="https://github.com/org/repo-b",
        commit_hash="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        status=ScanStatus.COMPLETED.value,
    )
    db_session.add_all([scan_a, scan_b])

    # Emit events for Scan A
    WorkflowEventService.emit(
        db=db_session,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.SCAN_CREATED,
            scan_id=scan_a_id,
            message="Scan A created",
        ),
    )
    WorkflowEventService.emit(
        db=db_session,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.STAGE_STARTED,
            scan_id=scan_a_id,
            stage="intelligence_analysis",
            message="Scan A stage started",
        ),
    )

    # Emit events for Scan B
    WorkflowEventService.emit(
        db=db_session,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.SCAN_CREATED,
            scan_id=scan_b_id,
            message="Scan B created",
        ),
    )
    db_session.commit()

    # Query events for Scan A
    events_a = WorkflowEventService.list_for_scan(db=db_session, scan_id=str(scan_a_id))
    assert len(events_a) == 2
    for e in events_a:
        assert e.scan_id == str(scan_a_id)
        assert e.scan_id != str(scan_b_id)

    # Query events for Scan B
    events_b = WorkflowEventService.list_for_scan(db=db_session, scan_id=str(scan_b_id))
    assert len(events_b) == 1
    assert events_b[0].scan_id == str(scan_b_id)

    # Verify REST endpoint event list isolation via SSE stream
    resp_a = client.get(f"/api/v1/scans/{scan_a_id}/events")
    assert resp_a.status_code == 200
    assert "text/event-stream" in resp_a.headers["content-type"]
    assert str(scan_a_id) in resp_a.text
    assert str(scan_b_id) not in resp_a.text

    resp_b = client.get(f"/api/v1/scans/{scan_b_id}/events")
    assert resp_b.status_code == 200
    assert "text/event-stream" in resp_b.headers["content-type"]
    assert str(scan_b_id) in resp_b.text
    assert str(scan_a_id) not in resp_b.text


def test_recursive_metadata_secret_redaction_and_bounding():
    """Verify recursive stripping of secret fields and bounding of large values."""
    payload = {
        "safe_metric": "safe_value",
        "api_key": "sk-should-be-stripped",
        "jwt_token": "bearer-token-strip",
        "auth_header": "Basic admin:pass",
        "db_password": "supersecretpassword",
        "nested_data": {
            "oauth_token": "oauth123",
            "prompt_text": "Sensitive system prompt",
            "public_metric": 42,
        },
        "massive_log": "A" * 3000,
    }

    sanitized = sanitize_metadata(payload)

    assert "safe_metric" in sanitized
    assert sanitized["safe_metric"] == "safe_value"

    # Verify blacklisted keys are stripped
    assert "api_key" not in sanitized
    assert "jwt_token" not in sanitized
    assert "auth_header" not in sanitized
    assert "db_password" not in sanitized

    # Verify nested dictionary sanitization
    assert "nested_data" in sanitized
    assert "oauth_token" not in sanitized["nested_data"]
    assert "prompt_text" not in sanitized["nested_data"]
    assert sanitized["nested_data"]["public_metric"] == 42

    # Verify string bounding
    assert len(sanitized["massive_log"]) <= 2048 + len("... [truncated]")
    assert "... [truncated]" in sanitized["massive_log"]


def test_operational_telemetry_host_path_leak_prevention(client: TestClient):
    """Verify health and telemetry endpoints never leak local host filesystem structures."""
    resp = client.get("/health/detailed")
    assert resp.status_code == 200
    text = resp.text

    # Assert no Windows local paths
    assert "C:\\Users\\" not in text
    assert "c:\\users\\" not in text.lower()
    # Assert no Unix home paths
    assert "/home/" not in text
    # Assert no DB path filenames
    assert ".db" not in text or "repolens_checkpoints" not in text


# ──────────────────────────────────────────────────────────────────────────────
# FIX 4 — Complete Event Sanitization and Bounding Tests (13 Cases)
# ──────────────────────────────────────────────────────────────────────────────


def test_nested_dict_secret_stripping_and_value_redaction():
    """1. Nested dict secret key stripped, secret value redacted."""
    raw = {
        "level1": {
            "level2": {
                "secret_key": "topsecret",
                "safe_field": "sk-1234567890abcdef12345678",
            }
        }
    }
    sanitized = sanitize_metadata(raw)
    assert "secret_key" not in sanitized["level1"]["level2"]
    assert sanitized["level1"]["level2"]["safe_field"] == "sk-[REDACTED]"


def test_list_contained_secret_redaction():
    """2. Secrets contained inside lists are redacted."""
    raw = {
        "messages": [
            "Normal log entry",
            "Authorization: Bearer mysecrettoken1234567890",
            "sk-abcdefghijklmnopqrstuvwxyz123456",
        ]
    }
    sanitized = sanitize_metadata(raw)
    assert sanitized["messages"][0] == "Normal log entry"
    assert sanitized["messages"][1] == "Authorization: Bearer [REDACTED]"
    assert sanitized["messages"][2] == "sk-[REDACTED]"


def test_tuple_contained_secret_redaction():
    """3. Secrets contained inside tuples are converted and redacted."""
    raw = {
        "pair": ("ghp_123456789012345678901234567890123456", "safe_val")
    }
    sanitized = sanitize_metadata(raw)
    assert isinstance(sanitized["pair"], list)
    assert sanitized["pair"][0] == "[REDACTED_GITHUB_TOKEN]"
    assert sanitized["pair"][1] == "safe_val"


def test_deep_nesting_limit():
    """4. Deep nesting beyond MAX_METADATA_DEPTH is cleanly bounded."""
    deep = {}
    curr = deep
    for i in range(12):
        curr["next"] = {}
        curr = curr["next"]
    curr["leaf"] = "deep_value"

    sanitized = sanitize_metadata(deep)
    # Walk down to verify truncation at max depth
    node = sanitized
    depth = 0
    while isinstance(node, dict) and "next" in node:
        node = node["next"]
        depth += 1
    assert depth <= MAX_METADATA_DEPTH + 1


def test_huge_list_limit():
    """5. Huge list is truncated at MAX_METADATA_LIST_ITEMS."""
    raw = {"items": list(range(200))}
    sanitized = sanitize_metadata(raw)
    assert len(sanitized["items"]) <= MAX_METADATA_LIST_ITEMS + 1
    assert "[truncated: max items exceeded]" in sanitized["items"]


def test_huge_dictionary_limit():
    """6. Huge dictionary is bounded with truncation marker."""
    raw = {f"entry_{i}": f"val_{i}" for i in range(200)}
    sanitized = sanitize_metadata(raw)
    assert len(sanitized) <= MAX_METADATA_DICT_ENTRIES + 1
    assert sanitized.get("_truncated") is True


def test_huge_string_limit():
    """7. Huge string is truncated to MAX_METADATA_STRING_LENGTH."""
    raw = {"long_str": "X" * 10000}
    sanitized = sanitize_metadata(raw)
    assert len(sanitized["long_str"]) <= MAX_METADATA_STRING_LENGTH + len("... [truncated]")
    assert "... [truncated]" in sanitized["long_str"]


def test_total_metadata_serialized_size_limit():
    """8. Total metadata serialized payload size limit triggers safe fallback."""
    # Create metadata that exceeds 65536 serialized bytes
    raw = {f"entry_{i}": "A" * 1500 for i in range(45)}
    sanitized = sanitize_metadata(raw)
    assert sanitized.get("_truncated") is True
    assert "Total metadata serialized bytes exceeded limit" in sanitized.get("reason", "")


def test_safe_normal_metadata_preserved():
    """9. Normal safe metadata is preserved exactly."""
    raw = {
        "stage": "intelligence_analysis",
        "tool_name": "semgrep",
        "findings_count": 5,
        "duration_ms": 1234.5,
        "is_completed": True,
        "null_val": None,
    }
    sanitized = sanitize_metadata(raw)
    assert sanitized == raw


def test_secret_shaped_value_under_safe_key_is_redacted():
    """10. Secret-shaped values (sk-..., gsk_..., AIza..., JWT) under safe keys are redacted."""
    raw = {
        "output_summary": "Connected with gsk_abcdef1234567890abcdef and AIzaSyD12345678901234567890",
        "nv_endpoint_info": "nvapi-1234567890abcdef12345678",
    }
    sanitized = sanitize_metadata(raw)
    assert "gsk_[REDACTED]" in sanitized["output_summary"]
    assert "AIza[REDACTED]" in sanitized["output_summary"]
    assert "nvapi-[REDACTED]" in sanitized["nv_endpoint_info"]


def test_event_message_credential_redaction_and_bounding(db_session: Session):
    """11. event.message credential redaction and length bounding upon emission."""
    scan_id = uuid4()
    scan = ScanModel(
        id=str(scan_id),
        repository_url="https://github.com/org/msg-sec-test",
        status=ScanStatus.RUNNING.value,
    )
    db_session.add(scan)
    db_session.commit()

    long_secret_msg = (
        "Provider failed with Authorization: Bearer secret_token_1234567890_abc "
        + "sk-1234567890abcdef12345678 "
        + "C:\\Users\\admin\\secret\\data "
        + ("A" * 3000)
    )

    evt = WorkflowEventService.emit(
        db=db_session,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.STAGE_FAILED,
            scan_id=scan_id,
            message=long_secret_msg,
        ),
    )
    db_session.commit()

    assert evt is not None
    assert "secret_token" not in evt.message
    assert "Bearer [REDACTED]" in evt.message
    assert "sk-[REDACTED]" in evt.message
    assert "[HOST_USER_DIR]" in evt.message
    assert "C:\\Users\\admin" not in evt.message
    assert len(evt.message) <= 2048 + len("... [truncated]")


def test_scanner_failure_reason_redaction(db_session: Session):
    """12. Scanner failure reason with host paths and credentials is sanitized."""
    scan_id = uuid4()
    scan = ScanModel(
        id=str(scan_id),
        repository_url="https://github.com/org/scanner-sec-test",
        status=ScanStatus.RUNNING.value,
    )
    db_session.add(scan)
    db_session.commit()

    raw_reason = "Trivy failed on /home/developer/workspace/app with API_KEY='sk-123456789012345678'"

    evt = WorkflowEventService.emit(
        db=db_session,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.TOOL_FAILED,
            scan_id=scan_id,
            tool_name="trivy",
            message=raw_reason,
            metadata_payload={"reason": raw_reason},
        ),
    )
    db_session.commit()

    assert evt is not None
    assert "/home/developer" not in evt.message
    assert "/home/[HOST_USER]" in evt.message
    assert "sk-123456789012345678" not in evt.message
    assert "[REDACTED]" in evt.message
    assert "/home/developer" not in evt.metadata_payload["reason"]
    assert "sk-123456789012345678" not in evt.metadata_payload["reason"]


def test_sanitized_metadata_remains_json_serializable():
    """13. Sanitized metadata with arbitrary objects remains strictly JSON serializable."""
    class CustomObject:
        def __str__(self):
            return "CustomObj(sk-1234567890abcdef12345678)"

    raw = {
        "custom": CustomObject(),
        "numbers": [1, 2.5, True, None],
        "subdict": {"k": "v"},
    }

    sanitized = sanitize_metadata(raw)
    dumped = json.dumps(sanitized)
    loaded = json.loads(dumped)

    assert "sk-[REDACTED]" in loaded["custom"]
    assert loaded["numbers"] == [1, 2.5, True, None]
    assert loaded["subdict"] == {"k": "v"}
