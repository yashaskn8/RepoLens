"""ChainBrain explanation authorization, quotas and hallucination-boundary tests."""
import json
from types import SimpleNamespace
from uuid import uuid4
from unittest.mock import AsyncMock

import pytest

from app.analysis.chainbrain_explanations import deterministic_explanation, explain_with_ai


_SIGNAL = {
    "rule_id": "CB-NPM-001",
    "title": "Install hook contains download-and-execute behavior: example",
    "package": "example",
    "severity": "HIGH",
    "risk_score": 85,
    "description": "Installation script pipes a remote download into a shell.",
    "scope": "root",
    "ecosystem": "npm",
    "raw_script": "SECRET_DO_NOT_SEND_TO_PROVIDER",
}


@pytest.mark.asyncio
async def test_chainbrain_ai_narrative_never_changes_detector_verdict():
    fake = AsyncMock()
    fake.generate.return_value = SimpleNamespace(
        content=json.dumps({
            "explanation": "The declared postinstall step retrieves a remote script and executes it.",
            "review_step": "Inspect the script source and pin the approved artifact before using it.",
        }),
        provider=SimpleNamespace(value="gemini"),
    )
    source = dict(_SIGNAL)
    result = await explain_with_ai(
        source, tenant_id=str(uuid4()), request_id="unit-test", router=fake,
    )
    assert result["ai_status"] == "model_generated_unverified"
    assert result["verified_malware"] is False
    assert result["rule_id"] == "CB-NPM-001"
    assert result["severity"] == "HIGH"
    assert result["risk_score"] == 85
    assert source == _SIGNAL
    request = fake.generate.await_args.args[0]
    assert "SECRET_DO_NOT_SEND_TO_PROVIDER" not in str(request)
    assert request.budget.max_ai_calls == 1
    assert request.budget.max_output_tokens == 220
    assert request.allow_escalation is False
    assert request.lineage.tenant_id is not None


@pytest.mark.asyncio
@pytest.mark.parametrize("model_output", [
    "{}",
    '{"explanation":"okay","review_step":"fine"}',
    '{"explanation":"<script>alert(1)</script> invalid","review_step":"Do this one thing"}',
    "not-json",
])
async def test_chainbrain_ai_invalid_response_falls_back_without_false_claim(model_output):
    fake = AsyncMock()
    fake.generate.return_value = SimpleNamespace(
        content=model_output,
        provider=SimpleNamespace(value="gemini"),
    )
    result = await explain_with_ai(
        _SIGNAL, tenant_id=str(uuid4()), request_id="unit-test", router=fake,
    )
    assert result["ai_status"] == "unavailable"
    assert result["explanation"] == _SIGNAL["description"]
    assert "ai_explanation" not in result
    assert result["verified_malware"] is False


def test_chainbrain_default_explanation_is_offline_and_deterministic():
    result = deterministic_explanation(_SIGNAL)
    assert result["ai_status"] == "not_requested"
    assert result["risk_score_kind"] == "heuristic_not_probability"
    assert result["risk_score"] == 85
    assert "SECRET_DO_NOT_SEND_TO_PROVIDER" not in str(result)


def test_chainbrain_opt_in_flag_defaults_off():
    from app.core.config import Settings

    assert Settings(_env_file=None, CHAINBRAIN_AI_EXPLANATIONS_ENABLED=False).CHAINBRAIN_AI_EXPLANATIONS_ENABLED is False
    assert Settings(_env_file=None).CHAINBRAIN_AI_EXPLANATIONS_ENABLED is False


def test_chainbrain_ai_disabled_api_checks_ownership_and_does_not_charge(client, db_session, monkeypatch):
    from app.api.routes import scans
    from app.models.scan import ScanModel
    from app.models.user import UserModel
    from app.schemas.enums import ScanStatus
    from app.services import quota_service

    owner = db_session.query(UserModel).filter_by(email="default_test_user@example.com").one()
    scan = ScanModel(
        id=str(uuid4()), owner_user_id=owner.id,
        repository_url="https://github.com/owner/repo",
        commit_hash="a" * 40,
        status=ScanStatus.COMPLETED.value,
        model_metadata={"supply_chain": {"status": "COMPLETED", "signals": [dict(_SIGNAL)]}},
    )
    db_session.add(scan)
    db_session.commit()

    monkeypatch.setattr(
        scans, "get_settings",
        lambda: SimpleNamespace(CHAINBRAIN_AI_EXPLANATIONS_ENABLED=False),
    )
    called = AsyncMock()
    monkeypatch.setattr(scans, "explain_with_ai", called)
    from unittest.mock import patch
    with patch.object(quota_service, "check_and_increment_quota") as quota:
        result = client.post(f"/api/v1/scans/{scan.id}/supply-chain/signals/0/explain")
    assert result.status_code == 503
    assert result.json()["detail"]["error_code"] == "CHAINBRAIN_AI_DISABLED"
    called.assert_not_awaited()
    quota.assert_not_called()
