"""Optional GitHub App OAuth binding and signed webhook ingress."""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import secrets
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user, verify_csrf
from app.core.config import Settings, get_settings
from app.core.database import get_db
from app.execution.dispatcher import DurableWorkDispatcher
from app.governance.events import AuditLedger
from app.github_app.auth import (
    GitHubAppError,
    decrypt_oauth_verifier,
    encrypt_oauth_verifier,
    get_github_app_token_service,
)
from app.github_app.webhooks import (
    DeliveryCollisionError,
    WebhookValidationError,
    accept_webhook_delivery,
    parse_signed_payload,
    validate_delivery_identity,
    verify_webhook_signature,
)
from app.models.github_app import (
    GitHubAppBindingGrantModel,
    GitHubAppInstallationModel,
    GitHubAppOAuthStateModel,
    GitHubAppRepositoryModel,
    GitHubAppWebhookDeliveryModel,
)
from app.schemas.auth import CurrentUser

router = APIRouter(prefix="/github-app", tags=["GitHub App"])


class OAuthStartResponse(BaseModel):
    authorization_url: str
    expires_in_seconds: int = 600


class ConnectedInstallation(BaseModel):
    installation_id: str
    account_login: str
    account_type: str
    repositories: list[str]


class ConnectedInstallationsResponse(BaseModel):
    installations: list[ConnectedInstallation]
    requires_installation_selection: bool = False
    binding_grant: str | None = None


class BindInstallationRequest(BaseModel):
    binding_grant: str = Field(min_length=32, max_length=128)
    installation_id: str = Field(pattern=r"^[1-9][0-9]{0,18}$", max_length=19)


class DisconnectResponse(BaseModel):
    disconnected: bool = True


class WebhookAccepted(BaseModel):
    accepted: bool = True
    duplicate: bool = False
    queued: bool = False


def _require_enabled(settings: Settings) -> None:
    if not settings.GITHUB_APP_ENABLED:
        raise HTTPException(status_code=404, detail="GitHub App integration is not enabled.")


@router.post("/connect/start", response_model=OAuthStartResponse)
def begin_github_app_connection(
    current_user: CurrentUser = Depends(get_current_user),
    _csrf: None = Depends(verify_csrf),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> OAuthStartResponse:
    """Start a short-lived PKCE transaction for the authenticated RepoLens user."""
    _require_enabled(settings)
    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(48)
    # PKCE S256 challenge is unpadded base64url(SHA-256(verifier)); token_urlsafe
    # does not itself compute the challenge.
    import base64

    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    now = datetime.now(timezone.utc)
    # One live transaction per user keeps storage bounded and makes the flow
    # simple to reason about across browser tabs.
    db.query(GitHubAppOAuthStateModel).filter(
        GitHubAppOAuthStateModel.user_id == current_user.id,
    ).delete(synchronize_session=False)
    db.query(GitHubAppBindingGrantModel).filter(
        GitHubAppBindingGrantModel.user_id == current_user.id,
    ).delete(synchronize_session=False)
    row = GitHubAppOAuthStateModel(
        state_digest=hashlib.sha256(state.encode("ascii")).hexdigest(),
        user_id=current_user.id,
        verifier_ciphertext=encrypt_oauth_verifier(verifier, settings),
        expires_at=now + timedelta(minutes=10),
    )
    db.add(row)
    db.commit()
    query = urlencode({
        "client_id": settings.GITHUB_APP_CLIENT_ID,
        "redirect_uri": settings.GITHUB_APP_CALLBACK_URL,
        "scope": "read:user",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    return OAuthStartResponse(authorization_url=f"https://github.com/login/oauth/authorize?{query}")


@router.get("/connect/callback", response_model=ConnectedInstallationsResponse)
async def complete_github_app_connection(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ConnectedInstallationsResponse:
    """Consume a user-bound PKCE state and bind only installations GitHub says this user can access."""
    _require_enabled(settings)
    if error or not code or not state or len(state) > 128 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in state):
        raise HTTPException(status_code=400, detail="GitHub App authorization could not be completed.")
    state_digest = hashlib.sha256(state.encode("ascii")).hexdigest()
    now = datetime.now(timezone.utc)
    transaction = db.query(GitHubAppOAuthStateModel).filter(
        GitHubAppOAuthStateModel.state_digest == state_digest,
        GitHubAppOAuthStateModel.user_id == current_user.id,
        GitHubAppOAuthStateModel.consumed_at.is_(None),
        GitHubAppOAuthStateModel.expires_at > now,
    ).with_for_update().first()
    if transaction is None:
        raise HTTPException(status_code=400, detail="GitHub App authorization state is invalid or already used.")
    verifier_ciphertext = transaction.verifier_ciphertext
    consumed = db.execute(
        update(GitHubAppOAuthStateModel)
        .where(
            GitHubAppOAuthStateModel.state_digest == state_digest,
            GitHubAppOAuthStateModel.user_id == current_user.id,
            GitHubAppOAuthStateModel.consumed_at.is_(None),
            GitHubAppOAuthStateModel.expires_at > now,
        )
        .values(consumed_at=now, verifier_ciphertext="[CONSUMED]")
        .execution_options(synchronize_session=False)
    ).rowcount
    if consumed != 1:
        db.rollback()
        raise HTTPException(status_code=400, detail="GitHub App authorization state is invalid or already used.")
    db.commit()  # one use even if the remote exchange fails
    try:
        verifier = decrypt_oauth_verifier(verifier_ciphertext, settings)
        service = get_github_app_token_service()
        user_token = await service.exchange_oauth_code(code, verifier)
        accessible = await service.list_user_installations(user_token)
    except GitHubAppError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    finally:
        verifier = ""
        user_token = ""

    available: list[tuple[GitHubAppInstallationModel, ConnectedInstallation]] = []
    for item in accessible:
        installation_id = item.get("id")
        if (
            not isinstance(installation_id, (int, str))
            or isinstance(installation_id, bool)
            or not str(installation_id).isdigit()
            or not 1 <= int(installation_id) <= 9_223_372_036_854_775_807
        ):
            continue
        row = db.query(GitHubAppInstallationModel).filter_by(installation_id=str(installation_id)).with_for_update().first()
        account = item.get("account") if isinstance(item.get("account"), dict) else {}
        if row is None or row.status in {"DELETED", "SUSPENDED"}:
            continue
        account_id = account.get("id")
        if (
            not isinstance(account_id, (int, str))
            or isinstance(account_id, bool)
            or str(account_id) != row.account_id
        ):
            continue
        if row.owner_user_id not in (None, current_user.id):
            continue
        repos = db.query(GitHubAppRepositoryModel).filter_by(
            installation_id=row.installation_id, active=True
        ).order_by(GitHubAppRepositoryModel.repository_id.asc()).limit(500).all()
        available.append((row, ConnectedInstallation(
            installation_id=row.installation_id,
            account_login=row.account_login,
            account_type=row.account_type,
            repositories=[f"{repo.owner_login}/{repo.repository_name}" for repo in repos],
        )))
    if not available:
        db.rollback()
        raise HTTPException(
            status_code=403,
            detail="No active RepoLens GitHub App installation was verified for this GitHub user.",
        )
    if len(available) == 1:
        row, connected = available[0]
        row.owner_user_id = current_user.id
        row.status = "ACTIVE"
        db.commit()
        return ConnectedInstallationsResponse(installations=[connected])
    if len(available) > 100:
        db.rollback()
        raise HTTPException(status_code=413, detail="Too many installations are available for one binding transaction.")

    # Do not silently bind every installation reachable by a GitHub account.
    # Return a short-lived, user-bound capability for an explicit selection.
    binding_grant = secrets.token_urlsafe(32)
    db.query(GitHubAppBindingGrantModel).filter(
        GitHubAppBindingGrantModel.user_id == current_user.id,
    ).delete(synchronize_session=False)
    db.add(GitHubAppBindingGrantModel(
        grant_digest=hashlib.sha256(binding_grant.encode("ascii")).hexdigest(),
        user_id=current_user.id,
        installation_ids_json=json.dumps(
            sorted(row.installation_id for row, _ in available), separators=(",", ":")
        ),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    ))
    db.commit()
    return ConnectedInstallationsResponse(
        installations=[connected for _, connected in available],
        requires_installation_selection=True,
        binding_grant=binding_grant,
    )


@router.post("/connect/bind", response_model=ConnectedInstallationsResponse)
def bind_verified_installation(
    payload: BindInstallationRequest,
    current_user: CurrentUser = Depends(get_current_user),
    _csrf: None = Depends(verify_csrf),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ConnectedInstallationsResponse:
    """Bind exactly one installation selected from a recent GitHub-verified grant."""
    _require_enabled(settings)
    grant_digest = hashlib.sha256(payload.binding_grant.encode("ascii")).hexdigest()
    now = datetime.now(timezone.utc)
    grant = db.query(GitHubAppBindingGrantModel).filter(
        GitHubAppBindingGrantModel.grant_digest == grant_digest,
        GitHubAppBindingGrantModel.user_id == current_user.id,
        GitHubAppBindingGrantModel.consumed_at.is_(None),
        GitHubAppBindingGrantModel.expires_at > now,
    ).with_for_update().first()
    if grant is None:
        raise HTTPException(status_code=400, detail="Installation selection grant is invalid or expired.")
    try:
        allowed_ids = json.loads(grant.installation_ids_json)
    except (TypeError, json.JSONDecodeError) as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail="Installation selection grant is invalid.") from exc
    if (
        not isinstance(allowed_ids, list)
        or len(allowed_ids) > 100
        or any(not isinstance(value, str) or not value.isdigit() for value in allowed_ids)
        or payload.installation_id not in allowed_ids
    ):
        raise HTTPException(status_code=403, detail="Installation was not authorized by this selection grant.")

    installation = db.query(GitHubAppInstallationModel).filter_by(
        installation_id=payload.installation_id,
    ).with_for_update().first()
    if installation is None or installation.status in {"DELETED", "SUSPENDED"}:
        raise HTTPException(status_code=409, detail="Installation is no longer active.")
    if installation.owner_user_id not in (None, current_user.id):
        raise HTTPException(status_code=409, detail="Installation is already bound to another RepoLens user.")
    consumed = db.execute(
        update(GitHubAppBindingGrantModel)
        .where(
            GitHubAppBindingGrantModel.grant_digest == grant_digest,
            GitHubAppBindingGrantModel.user_id == current_user.id,
            GitHubAppBindingGrantModel.consumed_at.is_(None),
            GitHubAppBindingGrantModel.expires_at > now,
        )
        .values(consumed_at=now)
        .execution_options(synchronize_session=False)
    ).rowcount
    if consumed != 1:
        db.rollback()
        raise HTTPException(status_code=409, detail="Installation selection grant was already used.")
    installation.owner_user_id = current_user.id
    installation.status = "ACTIVE"
    db.commit()
    repositories = db.query(GitHubAppRepositoryModel).filter_by(
        installation_id=installation.installation_id, active=True
    ).order_by(GitHubAppRepositoryModel.repository_id.asc()).limit(500).all()
    return ConnectedInstallationsResponse(installations=[ConnectedInstallation(
        installation_id=installation.installation_id,
        account_login=installation.account_login,
        account_type=installation.account_type,
        repositories=[f"{repo.owner_login}/{repo.repository_name}" for repo in repositories],
    )])


@router.post("/connect/installations/{installation_id}/disconnect", response_model=DisconnectResponse)
def disconnect_installation(
    installation_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    _csrf: None = Depends(verify_csrf),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> DisconnectResponse:
    """Remove this RepoLens user binding without uninstalling the GitHub App."""
    _require_enabled(settings)
    if len(installation_id) > 19 or not installation_id.isdigit() or int(installation_id) <= 0:
        raise HTTPException(status_code=404, detail="Installation not found.")
    installation = db.query(GitHubAppInstallationModel).filter_by(
        installation_id=installation_id,
        owner_user_id=current_user.id,
    ).with_for_update().first()
    if installation is None:
        raise HTTPException(status_code=404, detail="Installation not found.")
    installation.owner_user_id = None
    if installation.status == "ACTIVE":
        installation.status = "UNBOUND"
    db.commit()
    get_github_app_token_service().invalidate_installation(installation_id)
    return DisconnectResponse()


@router.get("/connect/installations", response_model=ConnectedInstallationsResponse)
def list_bound_installations(
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ConnectedInstallationsResponse:
    _require_enabled(settings)
    rows = db.query(GitHubAppInstallationModel).filter_by(
        owner_user_id=current_user.id, status="ACTIVE"
    ).order_by(GitHubAppInstallationModel.installation_id.asc()).limit(100).all()
    return ConnectedInstallationsResponse(installations=[
        ConnectedInstallation(
            installation_id=row.installation_id,
            account_login=row.account_login,
            account_type=row.account_type,
            repositories=[
                f"{repo.owner_login}/{repo.repository_name}"
                for repo in db.query(GitHubAppRepositoryModel).filter_by(
                    installation_id=row.installation_id, active=True
                ).order_by(GitHubAppRepositoryModel.repository_id.asc()).limit(500).all()
            ],
        )
        for row in rows
    ])


async def _read_bounded_body(request: Request, limit: int) -> bytes:
    length = request.headers.get("content-length")
    if length is not None:
        try:
            if int(length) < 1 or int(length) > limit:
                raise HTTPException(status_code=413, detail="Webhook payload size is outside the allowed bound.")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Webhook content length is invalid.") from exc
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > limit:
            raise HTTPException(status_code=413, detail="Webhook payload size is outside the allowed bound.")
    if not body:
        raise HTTPException(status_code=400, detail="Webhook payload is empty.")
    return bytes(body)


@router.post("/webhook", response_model=WebhookAccepted)
async def github_app_webhook(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> WebhookAccepted:
    """Authenticate exact raw bytes before parsing, then commit delivery and any work atomically."""
    _require_enabled(settings)
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        raise HTTPException(status_code=415, detail="GitHub webhook content type must be application/json.")
    raw_body = await _read_bounded_body(request, settings.GITHUB_APP_MAX_WEBHOOK_BYTES)
    signature = request.headers.get("x-hub-signature-256")
    if not verify_webhook_signature(raw_body, signature, settings.GITHUB_APP_WEBHOOK_SECRET):
        raise HTTPException(status_code=401, detail="Invalid webhook signature.")
    delivery_id = request.headers.get("x-github-delivery", "")
    event_name = request.headers.get("x-github-event", "")
    try:
        validate_delivery_identity(delivery_id, event_name)
        payload = parse_signed_payload(raw_body)
        duplicate, analysis_id = accept_webhook_delivery(
            db,
            raw_body=raw_body,
            delivery_id=delivery_id,
            event_name=event_name,
            payload=payload,
        )
        db.commit()
    except DeliveryCollisionError as exc:
        db.rollback()
        AuditLedger.append(
            db,
            tenant_id="GITHUB_APP_SECURITY",
            event_type="GITHUB_WEBHOOK_DELIVERY_COLLISION",
            resource_type="GITHUB_APP_DELIVERY",
            resource_id=hashlib.sha256(delivery_id.encode("utf-8")).hexdigest(),
            payload={
                "event": event_name,
                "delivery_id": delivery_id,
                "incoming_body_sha256": hashlib.sha256(raw_body).hexdigest(),
            },
        )
        db.commit()
        raise HTTPException(status_code=409, detail="GitHub webhook delivery identity collision.") from exc
    except WebhookValidationError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except IntegrityError:
        db.rollback()
        row = db.query(GitHubAppWebhookDeliveryModel).filter_by(delivery_id=delivery_id).first()
        if row is None or row.body_sha256 != hashlib.sha256(raw_body).hexdigest():
            raise HTTPException(status_code=409, detail="GitHub webhook delivery identity collision.")
        duplicate, analysis_id = True, None
    except Exception:
        db.rollback()
        raise
    if analysis_id:
        DurableWorkDispatcher.nudge()
    return WebhookAccepted(duplicate=duplicate, queued=bool(analysis_id))
