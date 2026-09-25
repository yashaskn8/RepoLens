"""Signed GitHub App webhook validation and transactional event handling."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from app.execution.application import WorkSubmissionService, deterministic_resource_id
from app.execution.types import ResourceProfile, WorkKind
from app.governance.events import AuditLedger
from app.models.change_analysis import ChangeAnalysisModel
from app.models.github_app import (
    GitHubAppInstallationModel,
    GitHubAppPullRequestHeadModel,
    GitHubAppRepositoryModel,
    GitHubAppWebhookDeliveryModel,
)
from app.schemas.enums import ChangeAnalysisStatus, UsageOperation
from app.schemas.workflow_event import WorkflowEventCreate, WorkflowEventType
from app.services.quota_service import check_and_increment_quota
from app.services.workflow_event_service import WorkflowEventService

_SIGNATURE = re.compile(r"^sha256=[0-9a-f]{64}$")
_DELIVERY = re.compile(r"^[A-Za-z0-9-]{1,128}$")
_DECIMAL_ID = re.compile(r"^[1-9][0-9]{0,18}$")
_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
_SLUG = re.compile(r"^[A-Za-z0-9_.-]{1,256}$")
_PR_ACTIONS = frozenset({"opened", "reopened", "synchronize", "ready_for_review"})
_PERMISSION_LEVELS = frozenset({"read", "write", "admin"})
WEBHOOK_DELIVERY_RETENTION_DAYS = 180
WEBHOOK_DELIVERY_PRUNE_BATCH = 500


class WebhookValidationError(ValueError):
    """Webhook request failed an authenticated input contract."""


class DeliveryCollisionError(WebhookValidationError):
    """A delivery ID was reused with different authenticated bytes."""


def verify_webhook_signature(raw_body: bytes, signature: str | None, secret: str) -> bool:
    if not raw_body or not secret or not isinstance(signature, str) or not _SIGNATURE.fullmatch(signature):
        return False
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def parse_signed_payload(raw_body: bytes) -> dict[str, Any]:
    """Parse bounded signed JSON while rejecting duplicate object keys."""
    def no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise WebhookValidationError("Duplicate JSON property in webhook payload.")
            value[key] = item
        return value

    try:
        payload = json.loads(raw_body, object_pairs_hook=no_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise WebhookValidationError("Webhook payload is not valid bounded JSON.") from exc
    if not isinstance(payload, dict):
        raise WebhookValidationError("Webhook payload must be a JSON object.")
    return payload


def validate_delivery_identity(delivery_id: str, event_name: str) -> None:
    if not _DELIVERY.fullmatch(delivery_id):
        raise WebhookValidationError("GitHub delivery ID is invalid.")
    if not re.fullmatch(r"[a-z_]{1,64}", event_name):
        raise WebhookValidationError("GitHub event name is invalid.")


def prune_processed_deliveries(db: Session, *, now: datetime | None = None) -> int:
    """Delete at most one batch of old processed delivery digests per accepted event."""
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=WEBHOOK_DELIVERY_RETENTION_DAYS)
    ids = [row[0] for row in db.query(GitHubAppWebhookDeliveryModel.delivery_id).filter(
        GitHubAppWebhookDeliveryModel.status.in_(("QUEUED", "IGNORED")),
        GitHubAppWebhookDeliveryModel.received_at < cutoff,
    ).order_by(GitHubAppWebhookDeliveryModel.received_at.asc()).limit(WEBHOOK_DELIVERY_PRUNE_BATCH).all()]
    if not ids:
        return 0
    return db.query(GitHubAppWebhookDeliveryModel).filter(
        GitHubAppWebhookDeliveryModel.delivery_id.in_(ids)
    ).delete(synchronize_session=False)


def _as_id(value: Any) -> str | None:
    normalized = str(value) if isinstance(value, (str, int)) and not isinstance(value, bool) else ""
    return normalized if (
        _DECIMAL_ID.fullmatch(normalized)
        and int(normalized) <= 9_223_372_036_854_775_807
    ) else None


def _pull_request_updated_at(pr: dict[str, Any]) -> datetime | None:
    value = pr.get("updated_at")
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def _repo_data(value: Any, installation_id: str, db: Session, *, active: bool) -> None:
    if not isinstance(value, dict):
        return
    repository_id = _as_id(value.get("id"))
    full_name = value.get("full_name")
    owner = value.get("owner")
    owner_login = owner.get("login") if isinstance(owner, dict) else None
    name = value.get("name")
    if not repository_id or not isinstance(owner_login, str) or not owner_login or not isinstance(name, str) or not name:
        return
    # Do not allow webhook display fields and independent IDs to disagree.
    if not _SLUG.fullmatch(owner_login) or not _SLUG.fullmatch(name) or full_name != f"{owner_login}/{name}":
        return
    row = db.query(GitHubAppRepositoryModel).filter_by(repository_id=repository_id).with_for_update().first()
    if row is not None and row.installation_id != installation_id:
        return
    if row is None:
        row = GitHubAppRepositoryModel(
            repository_id=repository_id,
            installation_id=installation_id,
            owner_login=owner_login,
            repository_name=name,
            is_private=bool(value.get("private", False)),
            active=active,
        )
        db.add(row)
    else:
        row.owner_login = owner_login
        row.repository_name = name
        row.is_private = bool(value.get("private", row.is_private))
        row.active = active


def _refresh_installation_permissions(
    row: GitHubAppInstallationModel,
    installation: dict[str, Any],
) -> bool:
    """Persist a compact permission snapshot supplied by a signed GitHub event."""
    if "permissions" not in installation:
        return False
    raw_permissions = installation.get("permissions")
    if not isinstance(raw_permissions, dict) or len(raw_permissions) > 100:
        raise WebhookValidationError("Installation permission metadata is invalid.")
    normalized: dict[str, str] = {}
    for name in ("contents", "pull_requests"):
        level = raw_permissions.get(name)
        if level is None:
            continue
        if not isinstance(level, str) or level not in _PERMISSION_LEVELS:
            raise WebhookValidationError("Installation permission level is invalid.")
        normalized[name] = level
    canonical = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    changed = row.permissions_digest != digest
    row.permissions_json = canonical
    row.permissions_digest = digest
    if changed:
        from app.github_app.auth import get_github_app_token_service

        get_github_app_token_service().invalidate_installation(row.installation_id)
    return changed


def _apply_installation_event(db: Session, payload: dict[str, Any], action: str) -> str | None:
    installation = payload.get("installation")
    if not isinstance(installation, dict):
        raise WebhookValidationError("Installation event is missing installation identity.")
    installation_id = _as_id(installation.get("id"))
    account = installation.get("account")
    if installation_id is None or not isinstance(account, dict):
        raise WebhookValidationError("Installation event identity is invalid.")
    account_id = _as_id(account.get("id"))
    login = account.get("login")
    account_type = account.get("type")
    if account_id is None or not isinstance(login, str) or not login or account_type not in {"User", "Organization", "Enterprise"}:
        raise WebhookValidationError("Installation account identity is invalid.")

    row = db.query(GitHubAppInstallationModel).filter_by(installation_id=installation_id).with_for_update().first()
    if row is None:
        row = GitHubAppInstallationModel(
            installation_id=installation_id,
            account_id=account_id,
            account_login=login,
            account_type=account_type,
            status="UNBOUND",
        )
        db.add(row)
    else:
        if row.account_id != account_id:
            raise WebhookValidationError("Installation account does not match its stored identity.")
        row.account_login = login
        row.account_type = account_type
    _refresh_installation_permissions(row, installation)

    if action == "created":
        # Installation creation is not a user-to-installation authorization proof.
        row.owner_user_id = None
        row.status = "UNBOUND"
        row.suspended_at = None
        repositories = payload.get("repositories", [])
        if not isinstance(repositories, list) or len(repositories) > 500:
            raise WebhookValidationError("Installation repository inventory exceeds its bound.")
        for repository in repositories:
            _repo_data(repository, installation_id, db, active=True)
    elif action == "deleted":
        row.status = "DELETED"
        row.owner_user_id = None
        row.suspended_at = None
        db.query(GitHubAppRepositoryModel).filter_by(installation_id=installation_id).update({"active": False})
        from app.github_app.auth import get_github_app_token_service
        get_github_app_token_service().invalidate_installation(installation_id)
    elif action == "suspend":
        row.status = "SUSPENDED"
        row.suspended_at = datetime.now(timezone.utc)
        from app.github_app.auth import get_github_app_token_service
        get_github_app_token_service().invalidate_installation(installation_id)
    elif action == "unsuspend":
        row.status = "ACTIVE" if row.owner_user_id else "UNBOUND"
        row.suspended_at = None
    elif action == "new_permissions_accepted":
        if "permissions" not in installation:
            raise WebhookValidationError("Permission update is missing the new permission grant.")
    return installation_id


def _apply_installation_repositories_event(db: Session, payload: dict[str, Any], action: str) -> str | None:
    installation = payload.get("installation")
    installation_id = _as_id(installation.get("id")) if isinstance(installation, dict) else None
    if installation_id is None:
        raise WebhookValidationError("Repository access event is missing installation identity.")
    row = db.query(GitHubAppInstallationModel).filter_by(installation_id=installation_id).with_for_update().first()
    if row is None or row.status == "DELETED":
        return installation_id
    if isinstance(installation, dict):
        _refresh_installation_permissions(row, installation)
    added = payload.get("repositories_added", [])
    removed = payload.get("repositories_removed", [])
    if not isinstance(added, list) or not isinstance(removed, list) or len(added) + len(removed) > 500:
        raise WebhookValidationError("Installation repository delta exceeds its bound.")
    if action in {"added", "removed"}:
        if payload.get("repository_selection") == "selected" and not removed:
            # GitHub can report all→selected with an empty removal list. Old
            # records must not imply continuing repository authority.
            db.query(GitHubAppRepositoryModel).filter_by(
                installation_id=installation_id
            ).update({"active": False})
            from app.github_app.auth import get_github_app_token_service
            get_github_app_token_service().invalidate_installation(installation_id)
        for repo in added:
            _repo_data(repo, installation_id, db, active=True)
        for repo in removed:
            repository_id = _as_id(repo.get("id")) if isinstance(repo, dict) else None
            if repository_id:
                db.query(GitHubAppRepositoryModel).filter_by(
                    repository_id=repository_id, installation_id=installation_id
                ).update({"active": False})
                from app.github_app.auth import get_github_app_token_service
                get_github_app_token_service().invalidate_repository(installation_id, repository_id)
    return installation_id


def _enqueue_pull_request(db: Session, payload: dict[str, Any], action: str) -> tuple[str | None, str | None]:
    installation = payload.get("installation")
    installation_id = _as_id(installation.get("id")) if isinstance(installation, dict) else None
    repository = payload.get("repository")
    repository_id = _as_id(repository.get("id")) if isinstance(repository, dict) else None
    if installation_id is None or repository_id is None:
        return installation_id, None
    installation_row = db.query(GitHubAppInstallationModel).filter_by(
        installation_id=installation_id, status="ACTIVE"
    ).with_for_update().first()
    repository_row = db.query(GitHubAppRepositoryModel).filter_by(
        installation_id=installation_id, repository_id=repository_id, active=True
    ).with_for_update().first()
    # Unbound installations and repositories outside the current installation grant no authority.
    if installation_row is None or not installation_row.owner_user_id or repository_row is None:
        return installation_id, None
    from app.github_app.auth import GitHubAppError
    from app.github_app.authorization import require_installation_permissions

    try:
        require_installation_permissions(installation_row, "contents_read")
    except GitHubAppError:
        return installation_id, None

    pr = payload.get("pull_request")
    if not isinstance(pr, dict) or action not in _PR_ACTIONS:
        return installation_id, None
    if pr.get("draft") is True or pr.get("merged") is True or pr.get("state") != "open":
        return installation_id, None
    base = pr.get("base")
    head = pr.get("head")
    base_repo = base.get("repo") if isinstance(base, dict) else None
    head_repo = head.get("repo") if isinstance(head, dict) else None
    # V1 does not clone or analyze fork heads.
    if not isinstance(base_repo, dict) or not isinstance(head_repo, dict):
        return installation_id, None
    if _as_id(base_repo.get("id")) != repository_id or _as_id(head_repo.get("id")) != repository_id:
        return installation_id, None
    base_sha = base.get("sha") if isinstance(base, dict) else None
    head_sha = head.get("sha") if isinstance(head, dict) else None
    if not isinstance(base_sha, str) or not _SHA.fullmatch(base_sha) or not isinstance(head_sha, str) or not _SHA.fullmatch(head_sha):
        return installation_id, None
    number = pr.get("number") or payload.get("number")
    if not isinstance(number, int) or isinstance(number, bool) or not 1 <= number <= 2_147_483_647:
        return installation_id, None
    updated_at = _pull_request_updated_at(pr)
    if updated_at is None:
        return installation_id, None

    current = db.query(GitHubAppPullRequestHeadModel).filter_by(
        installation_id=installation_id, repository_id=repository_id, pull_number=number
    ).with_for_update().first()
    if current is not None:
        current_time = current.head_updated_at
        if current_time.tzinfo is None:
            current_time = current_time.replace(tzinfo=timezone.utc)
        if updated_at <= current_time:
            return installation_id, current.current_analysis_id
        if current.base_sha == base_sha.lower() and current.head_sha == head_sha.lower():
            current.head_updated_at = updated_at
            return installation_id, current.current_analysis_id

    owner_id = installation_row.owner_user_id
    check_and_increment_quota(db, owner_id, UsageOperation.CHANGE_ANALYSIS_CREATE.value)
    analysis_id = deterministic_resource_id(
        owner_id,
        "github-app-pr-analysis",
        f"{installation_id}:{repository_id}:{number}:{base_sha.lower()}:{head_sha.lower()}",
    )
    owner = repository_row.owner_login
    name = repository_row.repository_name
    repository_url = f"https://github.com/{owner}/{name}"
    analysis = db.query(ChangeAnalysisModel).filter_by(id=analysis_id).first()
    if analysis is None:
        analysis = ChangeAnalysisModel(
            id=analysis_id,
            owner_user_id=owner_id,
            repository_url=repository_url,
            repository_owner=owner,
            repository_name=name,
            base_ref=(base.get("ref") if isinstance(base, dict) and isinstance(base.get("ref"), str) else None),
            base_commit_sha=base_sha.lower(),
            head_ref=(head.get("ref") if isinstance(head, dict) and isinstance(head.get("ref"), str) else None),
            head_commit_sha=head_sha.lower(),
            github_app_installation_id=installation_id,
            github_app_repository_id=repository_id,
            github_app_pull_number=number,
            status=ChangeAnalysisStatus.PENDING.value,
            model_metadata={
                "source": "github_app_webhook",
                "pr_number": number,
                "pr_title": (pr.get("title") or "")[:512],
                "pr_url": f"https://github.com/{owner}/{name}/pull/{number}",
                "is_fork": False,
                "pr_state": "open",
                "head_repo_url": repository_url,
            },
        )
        db.add(analysis)
        semantic_key = "ghapp:" + hashlib.sha256(
            f"{installation_id}:{repository_id}:{number}:{base_sha.lower()}:{head_sha.lower()}".encode("ascii")
        ).hexdigest()
        request_payload = {
            "source": "github_app_webhook",
            "installation_id": installation_id,
            "repository_id": repository_id,
            "pull_number": number,
            "base_sha": base_sha.lower(),
            "head_sha": head_sha.lower(),
        }
        from app.api.routes.change_analysis import _change_request_budget

        WorkSubmissionService().submit(
            db,
            tenant_id=owner_id,
            actor_id=owner_id,
            request_id=str(uuid4()),
            work_kind=WorkKind.CHANGE_ANALYSIS,
            resource_type="CHANGE_ANALYSIS",
            resource_id=analysis_id,
            request_payload=request_payload,
            idempotency_key=semantic_key,
            external_idempotency_key=semantic_key,
            resource_profile=ResourceProfile.CHANGE_ANALYSIS,
            budget=_change_request_budget(),
        )
        WorkflowEventService.emit_critical(
            db=db,
            event=WorkflowEventCreate(
                event_type=WorkflowEventType.CHANGE_ANALYSIS_REQUESTED,
                change_analysis_id=UUID(analysis_id),
                actor_user_id=owner_id,
                message=f"GitHub App PR analysis queued for {owner}/{name}#{number} ({base_sha[:8]} -> {head_sha[:8]})",
                metadata_payload={
                    "source": "github_app_webhook",
                    "installation_id": installation_id,
                    "repository_id": repository_id,
                    "pull_number": number,
                    "base_sha": base_sha.lower(),
                    "head_sha": head_sha.lower(),
                },
            ),
        )
    else:
        # A retry for the same semantic identity must not enqueue a second analysis.
        if current is not None:
            current.base_sha = base_sha.lower()
            current.head_sha = head_sha.lower()
            current.head_updated_at = updated_at
            current.current_analysis_id = analysis_id
            return installation_id, analysis_id

    if current is None:
        current = GitHubAppPullRequestHeadModel(
            id=str(uuid4()), installation_id=installation_id, repository_id=repository_id,
            pull_number=number, base_sha=base_sha.lower(), head_sha=head_sha.lower(),
            head_updated_at=updated_at, current_analysis_id=analysis_id,
        )
        db.add(current)
    else:
        current.base_sha = base_sha.lower()
        current.head_sha = head_sha.lower()
        current.head_updated_at = updated_at
        current.current_analysis_id = analysis_id
    return installation_id, analysis_id


def accept_webhook_delivery(
    db: Session,
    *,
    raw_body: bytes,
    delivery_id: str,
    event_name: str,
    payload: dict[str, Any],
) -> tuple[bool, str | None]:
    """Apply one signed delivery in the same transaction as durable work creation."""
    validate_delivery_identity(delivery_id, event_name)
    digest = hashlib.sha256(raw_body).hexdigest()
    existing = db.query(GitHubAppWebhookDeliveryModel).filter_by(delivery_id=delivery_id).with_for_update().first()
    if existing is not None:
        if not hmac.compare_digest(existing.body_sha256, digest):
            raise DeliveryCollisionError("GitHub delivery ID was reused with different signed content.")
        return True, None

    action_value = payload.get("action")
    action = action_value if isinstance(action_value, str) and len(action_value) <= 64 else None
    installation = payload.get("installation")
    installation_id = _as_id(installation.get("id")) if isinstance(installation, dict) else None
    delivery = GitHubAppWebhookDeliveryModel(
        delivery_id=delivery_id,
        body_sha256=digest,
        event_name=event_name,
        action=action,
        installation_id=installation_id,
        status="RECEIVED",
    )
    db.add(delivery)
    db.flush()

    analysis_id: str | None = None
    if event_name == "installation":
        installation_id = _apply_installation_event(db, payload, action or "")
    elif event_name == "installation_repositories":
        installation_id = _apply_installation_repositories_event(db, payload, action or "")
    elif event_name == "pull_request":
        installation_id, analysis_id = _enqueue_pull_request(db, payload, action or "")
    elif event_name == "github_app_authorization" and action == "revoked":
        # User authorization is short-lived and not persisted; no install binding is
        # inferred from this event because the installation remains app-authorized.
        pass

    delivery.installation_id = installation_id
    delivery.status = "QUEUED" if analysis_id else "IGNORED"
    delivery.processed_at = datetime.now(timezone.utc)
    AuditLedger.append(
        db,
        tenant_id=(
            db.query(GitHubAppInstallationModel.owner_user_id)
            .filter_by(installation_id=installation_id)
            .scalar() or "GITHUB_APP_UNBOUND"
        ),
        event_type="GITHUB_APP_WEBHOOK_ACCEPTED",
        resource_type="GITHUB_APP_DELIVERY",
        resource_id=delivery_id,
        payload={
            "event": event_name,
            "action": action,
            "installation_id": installation_id,
            "body_sha256": digest,
            "analysis_id": analysis_id,
            "status": delivery.status,
        },
    )
    prune_processed_deliveries(db)
    return False, analysis_id
