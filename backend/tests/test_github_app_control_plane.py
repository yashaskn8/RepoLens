"""Zero-network security tests for the optional GitHub App control plane."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
import re
import subprocess
from urllib.parse import parse_qs, urlparse
from unittest.mock import AsyncMock, Mock, patch
from uuid import uuid4

import httpx
import pytest
from pydantic import ValidationError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from app.core.config import Settings, get_settings
from app.github_app.auth import (
    GitHubAppError,
    GitHubAppTokenService,
    create_app_jwt,
    decrypt_oauth_verifier,
    encrypt_oauth_verifier,
)
from app.github_app.authorization import require_bound_repository, require_installation_permissions
from app.github_app.webhooks import (
    DeliveryCollisionError,
    accept_webhook_delivery,
    parse_signed_payload,
    verify_webhook_signature,
)
from app.models.change_analysis import ChangeAnalysisModel
from app.models.github_app import (
    GitHubAppInstallationModel,
    GitHubAppPullRequestHeadModel,
    GitHubAppRepositoryModel,
    GitHubAppWebhookDeliveryModel,
)
from app.models.user import UserModel
from app.security.redaction import redact_secrets


@pytest.fixture(scope="module")
def app_key_pem():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode("ascii")


def app_settings(app_key_pem: str) -> Settings:
    return Settings(
        _env_file=None,
        ENVIRONMENT="test",
        GITHUB_APP_ENABLED=True,
        GITHUB_APP_ID="123456",
        GITHUB_APP_CLIENT_ID="Iv1-test-client",
        GITHUB_APP_CLIENT_SECRET="test-client-secret",
        GITHUB_APP_PRIVATE_KEY_PEM=app_key_pem,
        GITHUB_APP_WEBHOOK_SECRET="webhook-test-secret-that-is-long-enough",
        GITHUB_APP_STATE_ENCRYPTION_KEY="ab" * 32,
        GITHUB_APP_CALLBACK_URL="https://repolens.test/api/v1/github-app/connect/callback",
    )


def _decode_b64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def test_app_jwt_is_short_lived_rs256(app_key_pem):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    cfg = app_settings(app_key_pem)
    now = 1_800_000_000
    token = create_app_jwt(cfg, now=now)
    header_segment, claims_segment, signature_segment = token.split(".")
    header = json.loads(_decode_b64url(header_segment))
    claims = json.loads(_decode_b64url(claims_segment))
    public_key = load_pem_private_key(app_key_pem.encode(), password=None).public_key()
    public_key.verify(
        _decode_b64url(signature_segment),
        f"{header_segment}.{claims_segment}".encode("ascii"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    assert header == {"alg": "RS256", "typ": "JWT"}
    assert claims == {"iat": now - 60, "exp": now + 540, "iss": "123456"}


def test_oauth_verifier_is_authenticated_encrypted_and_tamper_evident(app_key_pem):
    cfg = app_settings(app_key_pem)
    raw = "verifier-that-is-not-a-token-and-is-long-enough"
    encrypted = encrypt_oauth_verifier(raw, cfg)
    assert raw not in encrypted
    assert decrypt_oauth_verifier(encrypted, cfg) == raw
    damaged = encrypted[:-2] + ("AA" if encrypted[-2:] != "AA" else "BB")
    with pytest.raises(GitHubAppError):
        decrypt_oauth_verifier(damaged, cfg)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("GITHUB_APP_STATE_ENCRYPTION_KEY", "ab" * 31 + "  "),
        ("GITHUB_APP_CALLBACK_URL", "https:///api/v1/github-app/connect/callback"),
        ("GITHUB_APP_CALLBACK_URL", "https://user:pass@example.test/api/v1/github-app/connect/callback"),
        ("GITHUB_APP_CALLBACK_URL", "https://example.test:bad/api/v1/github-app/connect/callback"),
    ],
)
def test_enabled_app_config_rejects_malformed_encryption_key_and_callback(app_key_pem, field, value):
    settings = app_settings(app_key_pem).model_dump()
    settings[field] = value
    with pytest.raises(ValidationError):
        Settings(**settings)


@pytest.mark.asyncio
async def test_installation_token_is_repository_scoped_minimum_permission_and_cached(app_key_pem):
    cfg = app_settings(app_key_pem)
    calls = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        assert request.url == "https://api.github.com/app/installations/44/access_tokens"
        assert request.headers["authorization"].startswith("Bearer ")
        body = json.loads(request.content)
        assert body == {"repository_ids": [55], "permissions": {"contents": "read"}}
        return httpx.Response(201, json={
            "token": "ghs_fake-installation-token-123456789",
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            "permissions": {"contents": "read", "metadata": "read"},
            "repositories": [{"id": 55}],
        })

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    service = GitHubAppTokenService(cfg, client=client)
    first = await service.installation_token("44", "55", permission_profile="contents_read")
    second = await service.installation_token("44", "55", permission_profile="contents_read")
    assert first == second == "ghs_fake-installation-token-123456789"
    assert len(calls) == 1
    service.invalidate_installation("44")
    assert not service._cache
    await client.aclose()


@pytest.mark.asyncio
async def test_installation_token_rejects_escalated_permission_response(app_key_pem):
    cfg = app_settings(app_key_pem)

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, json={
            "token": "ghs_fake-installation-token-123456789",
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            "permissions": {"contents": "write", "metadata": "read"},
            "repositories": [{"id": 55}],
        })

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubAppError, match="permission profile"):
        await GitHubAppTokenService(cfg, client=client).installation_token("44", "55")
    await client.aclose()


@pytest.mark.parametrize(
    "repositories",
    [None, [], [{"id": 55}, {"id": 56}], [{"id": 56}], ["55"]],
)
@pytest.mark.asyncio
async def test_installation_token_requires_exact_repository_scope(app_key_pem, repositories):
    cfg = app_settings(app_key_pem)

    async def handler(request: httpx.Request) -> httpx.Response:
        payload = {
            "token": "ghs_fake-installation-token-123456789",
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            "permissions": {"contents": "read", "metadata": "read"},
        }
        if repositories is not None:
            payload["repositories"] = repositories
        return httpx.Response(201, json=payload)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubAppError, match="not scoped"):
        await GitHubAppTokenService(cfg, client=client).installation_token("44", "55")
    await client.aclose()


def test_webhook_signature_uses_exact_raw_bytes_and_parser_rejects_duplicate_keys():
    secret = "0123456789abcdef0123456789abcdef"
    raw = b'{"action":"created"}'
    signature = "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    assert verify_webhook_signature(raw, signature, secret)
    assert not verify_webhook_signature(raw + b" ", signature, secret)
    assert not verify_webhook_signature(raw, "sha256=" + "0" * 64, secret)
    with pytest.raises(ValueError, match="Duplicate"):
        parse_signed_payload(b'{"action":"opened","action":"closed"}')


def test_signed_webhook_route_is_idempotent_and_detects_delivery_collision(client, db_session, app_key_pem):
    from app.main import app

    cfg = app_settings(app_key_pem)
    app.dependency_overrides[get_settings] = lambda: cfg
    body = json.dumps({
        "action": "created",
        "installation": {
            "id": 44,
            "account": {"id": 99, "login": "sample-org", "type": "Organization"},
            "permissions": {"contents": "read", "pull_requests": "write"},
        },
        "repositories": [],
    }, separators=(",", ":")).encode()
    delivery_id = str(uuid4())
    signature = "sha256=" + hmac.new(cfg.GITHUB_APP_WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
    headers = {
        "x-hub-signature-256": signature,
        "x-github-delivery": delivery_id,
        "x-github-event": "installation",
        "content-type": "application/json",
    }
    try:
        accepted = client.post("/api/v1/github-app/webhook", content=body, headers=headers)
        assert accepted.status_code == 200
        assert accepted.json() == {"accepted": True, "duplicate": False, "queued": False}
        replay = client.post("/api/v1/github-app/webhook", content=body, headers=headers)
        assert replay.status_code == 200 and replay.json()["duplicate"] is True

        altered = body.replace(b"sample-org", b"other-org")
        altered_headers = dict(headers)
        altered_headers["x-hub-signature-256"] = "sha256=" + hmac.new(
            cfg.GITHUB_APP_WEBHOOK_SECRET.encode(), altered, hashlib.sha256
        ).hexdigest()
        collision = client.post("/api/v1/github-app/webhook", content=altered, headers=altered_headers)
        assert collision.status_code == 409

        invalid_headers = dict(headers)
        invalid_headers["x-github-delivery"] = str(uuid4())
        invalid_headers["x-hub-signature-256"] = "sha256=" + "0" * 64
        denied = client.post("/api/v1/github-app/webhook", content=body, headers=invalid_headers)
        assert denied.status_code == 401
    finally:
        app.dependency_overrides.pop(get_settings, None)
    stored = db_session.query(GitHubAppInstallationModel).filter_by(installation_id="44").one()
    assert stored.status == "UNBOUND"
    assert stored.permissions_json == '{"contents":"read","pull_requests":"write"}'
    assert stored.permissions_digest == hashlib.sha256(stored.permissions_json.encode()).hexdigest()


def test_oauth_routes_bind_only_verified_installation_and_consume_state_once(
    client, db_session, app_key_pem
):
    from app.api.routes import github_app as routes
    from app.main import app

    cfg = app_settings(app_key_pem)
    app.dependency_overrides[get_settings] = lambda: cfg
    db_session.add(GitHubAppInstallationModel(
        installation_id="44", account_id="99", account_login="sample-org",
        account_type="Organization", status="UNBOUND",
    ))
    db_session.add(GitHubAppRepositoryModel(
        repository_id="77", installation_id="44", owner_login="sample-org",
        repository_name="private-repo", is_private=True, active=True,
    ))
    db_session.flush()
    fake_tokens = AsyncMock()
    fake_tokens.exchange_oauth_code.return_value = "ghu_ephemeral-test-user-token"
    fake_tokens.list_user_installations.return_value = [
        {"id": 44, "account": {"id": 99, "login": "sample-org"}},
        {"id": 45, "account": {"id": 100, "login": "not-installed-here"}},
    ]
    with patch.object(routes, "get_github_app_token_service", return_value=fake_tokens):
        try:
            started = client.post("/api/v1/github-app/connect/start")
            assert started.status_code == 200
            query = parse_qs(urlparse(started.json()["authorization_url"]).query)
            assert query["code_challenge_method"] == ["S256"]
            state = query["state"][0]
            stored_state = db_session.query(routes.GitHubAppOAuthStateModel).one()
            verifier = decrypt_oauth_verifier(stored_state.verifier_ciphertext, cfg)
            assert base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode() == query["code_challenge"][0]

            callback = client.get(
                "/api/v1/github-app/connect/callback",
                params={"code": "temporary-code", "state": state},
            )
            assert callback.status_code == 200
            assert [item["installation_id"] for item in callback.json()["installations"]] == ["44"]
            fake_tokens.exchange_oauth_code.assert_awaited_once_with("temporary-code", verifier)
            fake_tokens.list_user_installations.assert_awaited_once_with("ghu_ephemeral-test-user-token")
            installed = db_session.query(GitHubAppInstallationModel).filter_by(installation_id="44").one()
            assert installed.status == "ACTIVE"
            assert installed.owner_user_id is not None

            replay = client.get(
                "/api/v1/github-app/connect/callback",
                params={"code": "temporary-code", "state": state},
            )
            assert replay.status_code == 400
        finally:
            app.dependency_overrides.pop(get_settings, None)


def test_multiple_accessible_installations_require_one_explicit_verified_selection(
    client, db_session, app_key_pem
):
    from app.api.routes import github_app as routes
    from app.main import app

    cfg = app_settings(app_key_pem)
    app.dependency_overrides[get_settings] = lambda: cfg
    for installation_id, account_id, account_login in (
        ("44", "99", "sample-org"),
        ("45", "100", "another-org"),
    ):
        db_session.add(GitHubAppInstallationModel(
            installation_id=installation_id,
            account_id=account_id,
            account_login=account_login,
            account_type="Organization",
            status="UNBOUND",
        ))
    db_session.flush()
    fake_tokens = AsyncMock()
    fake_tokens.exchange_oauth_code.return_value = "ghu_ephemeral-test-user-token"
    fake_tokens.list_user_installations.return_value = [
        {"id": 44, "account": {"id": 99, "login": "sample-org"}},
        {"id": 45, "account": {"id": 100, "login": "another-org"}},
    ]
    with patch.object(routes, "get_github_app_token_service", return_value=fake_tokens):
        try:
            started = client.post("/api/v1/github-app/connect/start")
            query = parse_qs(urlparse(started.json()["authorization_url"]).query)
            callback = client.get(
                "/api/v1/github-app/connect/callback",
                params={"code": "temporary-code", "state": query["state"][0]},
            )
            assert callback.status_code == 200
            response = callback.json()
            assert response["requires_installation_selection"] is True
            assert len(response["installations"]) == 2
            assert response["binding_grant"]
            assert db_session.query(GitHubAppInstallationModel).filter_by(status="ACTIVE").count() == 0

            forbidden_selection = client.post("/api/v1/github-app/connect/bind", json={
                "binding_grant": response["binding_grant"],
                "installation_id": "999",
            })
            assert forbidden_selection.status_code == 403

            selection = client.post("/api/v1/github-app/connect/bind", json={
                "binding_grant": response["binding_grant"],
                "installation_id": "45",
            })
            assert selection.status_code == 200
            assert [row["installation_id"] for row in selection.json()["installations"]] == ["45"]
            assert db_session.query(GitHubAppInstallationModel).filter_by(
                installation_id="45", status="ACTIVE"
            ).one().owner_user_id is not None
            assert db_session.query(GitHubAppInstallationModel).filter_by(
                installation_id="44", status="UNBOUND"
            ).one().owner_user_id is None

            replay = client.post("/api/v1/github-app/connect/bind", json={
                "binding_grant": response["binding_grant"],
                "installation_id": "44",
            })
            assert replay.status_code == 400
        finally:
            app.dependency_overrides.pop(get_settings, None)


def test_private_snapshot_uses_ephemeral_askpass_without_token_in_command_or_config(
    monkeypatch, app_key_pem
):
    from app.ingestion.snapshot import RepositorySnapshotService

    cfg = app_settings(app_key_pem)
    service = RepositorySnapshotService(settings=cfg)
    sha = "a" * 40
    token = "ghs_fake-installation-token-123456789"
    calls = []
    scripts = []

    def fake_run(command, *, cwd, env, shell, capture_output, text, timeout, check):
        calls.append((command, cwd, dict(env)))
        if "fetch" in command:
            match = re.search(r'"([^"]+askpass\.py)"', env["GIT_ASKPASS"])
            with open(match.group(1), encoding="utf-8") as handle:
                scripts.append(handle.read())
        output = sha if command[-2:] == ["rev-parse", "HEAD"] else ""
        return subprocess.CompletedProcess(command, 0, output, "")

    monkeypatch.setattr("app.ingestion.snapshot.subprocess.run", fake_run)
    workspace = service.materialize_snapshot_from_metadata(
        repository_url="https://github.com/sample-org/private-repo",
        commit_hash=sha,
        installation_token=token,
    )
    try:
        assert calls
        assert all(token not in " ".join(map(str, command)) for command, _, _ in calls)
        assert all(
            env.get("REPOLENS_GITHUB_APP_TOKEN") != token
            for command, _, env in calls
            if "fetch" not in command
        )
        fetches = [env for command, _, env in calls if "fetch" in command]
        assert len(fetches) == 1
        assert fetches[0]["REPOLENS_GITHUB_APP_TOKEN"] == token
        askpass_command = fetches[0]["GIT_ASKPASS"]
        assert token not in askpass_command
        match = re.search(r'"([^"]+askpass\.py)"', askpass_command)
        assert match
        askpass_path = match.group(1)
        assert not os.path.exists(askpass_path)
        assert len(scripts) == 1 and token not in scripts[0]
        remote_command = next(command for command, _, _ in calls if "remote" in command)
        assert remote_command[-1] == "https://github.com/sample-org/private-repo.git"
    finally:
        service.release_snapshot(workspace)


def test_app_snapshot_credentials_fail_closed_when_app_is_disabled():
    from app.ingestion.snapshot import RepositorySnapshotService, SnapshotMetadataError

    with pytest.raises(SnapshotMetadataError, match="not configured"):
        RepositorySnapshotService(settings=Settings(_env_file=None)).materialize_snapshot_from_metadata(
            repository_url="https://github.com/sample-org/private-repo",
            commit_hash="a" * 40,
            installation_token="ghs_fake-installation-token-123456789",
        )


def test_disabled_app_webhook_route_is_unavailable(client):
    from app.main import app

    app.dependency_overrides[get_settings] = lambda: Settings(_env_file=None, GITHUB_APP_ENABLED=False)
    try:
        response = client.post("/api/v1/github-app/webhook", content=b"{}")
        assert response.status_code == 404
    finally:
        app.dependency_overrides.pop(get_settings, None)


def test_webhook_rejects_non_json_before_parsing(client, app_key_pem):
    from app.main import app

    cfg = app_settings(app_key_pem)
    app.dependency_overrides[get_settings] = lambda: cfg
    body = b"not-json"
    signature = "sha256=" + hmac.new(cfg.GITHUB_APP_WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
    try:
        response = client.post(
            "/api/v1/github-app/webhook",
            content=body,
            headers={"content-type": "text/plain", "x-hub-signature-256": signature},
        )
        assert response.status_code == 415
    finally:
        app.dependency_overrides.pop(get_settings, None)


def test_installation_binding_cannot_be_used_by_another_repolens_user(client, db_session, app_key_pem):
    cfg = app_settings(app_key_pem)
    user = db_session.query(UserModel).filter_by(email="default_test_user@example.com").one()
    db_session.add(GitHubAppInstallationModel(
        installation_id="44", account_id="99", account_login="sample-org",
        account_type="Organization", owner_user_id=user.id, status="ACTIVE",
        permissions_json='{"contents":"read","pull_requests":"write"}',
        permissions_digest=hashlib.sha256(b'{"contents":"read","pull_requests":"write"}').hexdigest(),
    ))
    db_session.add(GitHubAppRepositoryModel(
        repository_id="77", installation_id="44", owner_login="sample-org",
        repository_name="private-repo", is_private=True, active=True,
    ))
    db_session.flush()

    with pytest.raises(GitHubAppError, match="not authorized"):
        require_bound_repository(
            db_session,
            installation_id="44",
            repository_id="77",
            owner_user_id=str(uuid4()),
            settings=cfg,
        )


def test_installation_operation_permissions_are_verified_from_signed_state():
    installation = GitHubAppInstallationModel(
        installation_id="44",
        account_id="99",
        account_login="sample-org",
        account_type="Organization",
        permissions_json='{"contents":"read","pull_requests":"read"}',
        permissions_digest=hashlib.sha256(b'{"contents":"read","pull_requests":"read"}').hexdigest(),
        status="ACTIVE",
    )
    require_installation_permissions(installation, "contents_read")
    require_installation_permissions(installation, "pull_requests_read")
    with pytest.raises(GitHubAppError, match="lacks the permission"):
        require_installation_permissions(installation, "pull_requests_write")

    installation.permissions_json = '{"contents":"write","pull_requests":"write"}'
    with pytest.raises(GitHubAppError, match="integrity"):
        require_installation_permissions(installation, "contents_read")


def test_user_can_disconnect_only_own_installation_and_invalidates_tokens(client, db_session, app_key_pem):
    from app.api.routes import github_app as routes
    from app.main import app

    cfg = app_settings(app_key_pem)
    app.dependency_overrides[get_settings] = lambda: cfg
    user = db_session.query(UserModel).filter_by(email="default_test_user@example.com").one()
    db_session.add(GitHubAppInstallationModel(
        installation_id="44", account_id="99", account_login="sample-org",
        account_type="Organization", owner_user_id=user.id, status="ACTIVE",
    ))
    db_session.flush()
    fake_tokens = Mock()
    with patch.object(routes, "get_github_app_token_service", return_value=fake_tokens):
        try:
            response = client.post("/api/v1/github-app/connect/installations/44/disconnect")
            assert response.status_code == 200 and response.json() == {"disconnected": True}
            stored = db_session.query(GitHubAppInstallationModel).filter_by(installation_id="44").one()
            assert stored.owner_user_id is None and stored.status == "UNBOUND"
            fake_tokens.invalidate_installation.assert_called_once_with("44")
        finally:
            app.dependency_overrides.pop(get_settings, None)


def test_webhook_delivery_pruning_keeps_recent_or_unprocessed_rows(db_session):
    from app.github_app.webhooks import prune_processed_deliveries

    now = datetime.now(timezone.utc)
    db_session.add_all([
        GitHubAppWebhookDeliveryModel(
            delivery_id="old-processed", body_sha256="a" * 64, event_name="pull_request",
            status="IGNORED", received_at=now - timedelta(days=181),
        ),
        GitHubAppWebhookDeliveryModel(
            delivery_id="recent-processed", body_sha256="b" * 64, event_name="pull_request",
            status="QUEUED", received_at=now - timedelta(days=10),
        ),
        GitHubAppWebhookDeliveryModel(
            delivery_id="old-received", body_sha256="c" * 64, event_name="pull_request",
            status="RECEIVED", received_at=now - timedelta(days=181),
        ),
    ])
    db_session.flush()

    assert prune_processed_deliveries(db_session, now=now) == 1
    assert db_session.query(GitHubAppWebhookDeliveryModel).filter_by(delivery_id="old-processed").first() is None
    assert db_session.query(GitHubAppWebhookDeliveryModel).filter_by(delivery_id="recent-processed").first() is not None
    assert db_session.query(GitHubAppWebhookDeliveryModel).filter_by(delivery_id="old-received").first() is not None


def _pr_payload(*, updated_at: str, head_sha: str, head_repo_id: int = 77):
    sha = "a" * 40
    return {
        "action": "synchronize",
        "installation": {"id": 44},
        "repository": {
            "id": 77,
            "name": "private-repo",
            "full_name": "sample-org/private-repo",
            "owner": {"login": "sample-org"},
            "private": True,
        },
        "pull_request": {
            "number": 9,
            "title": "change",
            "draft": False,
            "merged": False,
            "state": "open",
            "updated_at": updated_at,
            "base": {"ref": "main", "sha": sha, "repo": {"id": 77}},
            "head": {"ref": "feature", "sha": head_sha, "repo": {"id": head_repo_id}},
        },
    }


def test_webhook_enqueues_only_bound_same_repository_heads_and_rejects_stale_head(client, db_session):
    from app.services import quota_service
    from app.services.workflow_event_service import WorkflowEventService
    from app.github_app import webhooks

    user = db_session.query(UserModel).filter_by(email="default_test_user@example.com").one()
    db_session.add(GitHubAppInstallationModel(
        installation_id="44", account_id="99", account_login="sample-org",
        account_type="Organization", owner_user_id=user.id, status="ACTIVE",
        permissions_json='{"contents":"read","pull_requests":"write"}',
        permissions_digest=hashlib.sha256(b'{"contents":"read","pull_requests":"write"}').hexdigest(),
    ))
    db_session.add(GitHubAppRepositoryModel(
        repository_id="77", installation_id="44", owner_login="sample-org",
        repository_name="private-repo", is_private=True, active=True,
    ))
    db_session.flush()
    body = b"{}"
    t1 = "2026-09-25T10:00:00Z"
    head_a = "b" * 40
    with patch.object(quota_service, "check_and_increment_quota"), \
         patch.object(webhooks.WorkSubmissionService, "submit") as submit, \
         patch.object(WorkflowEventService, "emit_critical"):
        duplicate, analysis_id = webhooks.accept_webhook_delivery(
            db_session, raw_body=body, delivery_id=str(uuid4()), event_name="pull_request",
            payload=_pr_payload(updated_at=t1, head_sha=head_a),
        )
        assert (duplicate, analysis_id is not None) == (False, True)
        db_session.flush()
        analysis = db_session.query(ChangeAnalysisModel).filter_by(id=analysis_id).one()
        assert analysis.github_app_installation_id == "44"
        assert analysis.github_app_repository_id == "77"
        assert analysis.head_commit_sha == head_a
        submit.assert_called_once()

        # A second delivery for the exact same revision does not create work twice.
        duplicate, same_id = webhooks.accept_webhook_delivery(
            db_session, raw_body=body, delivery_id=str(uuid4()), event_name="pull_request",
            payload=_pr_payload(updated_at="2026-09-25T10:00:01Z", head_sha=head_a),
        )
        assert not duplicate and same_id == analysis_id
        submit.assert_called_once()

        # Late delivery for an older head cannot move the authoritative PR pointer backwards.
        stale_id = webhooks.accept_webhook_delivery(
            db_session, raw_body=body, delivery_id=str(uuid4()), event_name="pull_request",
            payload=_pr_payload(updated_at=t1, head_sha="c" * 40),
        )[1]
        assert stale_id == analysis_id
        submit.assert_called_once()

        current = db_session.query(GitHubAppPullRequestHeadModel).one()
        assert current.current_analysis_id == analysis_id and current.head_sha == head_a


def test_fork_pull_request_is_not_enqueued(client, db_session):
    from app.github_app import webhooks
    from app.services import quota_service
    from app.services.workflow_event_service import WorkflowEventService

    user = db_session.query(UserModel).filter_by(email="default_test_user@example.com").one()
    db_session.add(GitHubAppInstallationModel(
        installation_id="44", account_id="99", account_login="sample-org",
        account_type="Organization", owner_user_id=user.id, status="ACTIVE",
    ))
    db_session.add(GitHubAppRepositoryModel(
        repository_id="77", installation_id="44", owner_login="sample-org",
        repository_name="private-repo", is_private=True, active=True,
    ))
    db_session.flush()
    payload = _pr_payload(updated_at="2026-09-25T10:00:00Z", head_sha="b" * 40, head_repo_id=88)
    with patch.object(quota_service, "check_and_increment_quota"), \
         patch.object(webhooks.WorkSubmissionService, "submit") as submit, \
         patch.object(WorkflowEventService, "emit_critical"):
        _, analysis_id = webhooks.accept_webhook_delivery(
            db_session, raw_body=b"{}", delivery_id=str(uuid4()), event_name="pull_request", payload=payload
        )
    assert analysis_id is None
    submit.assert_not_called()


def test_app_token_redaction_covers_new_github_token_prefixes():
    token = "ghs_APPID_JWT_fake_installation_token_1234567890"
    assert token not in redact_secrets(f"Authorization: Bearer {token}")
