"""Database-backed tenant and repository binding for GitHub App operations."""

import hashlib
import json

from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.github_app.auth import (
    GitHubAppError,
    GitHubAppTokenService,
    get_github_app_token_service,
    permission_requirements,
)
from app.models.change_analysis import ChangeAnalysisModel
from app.models.github_app import GitHubAppInstallationModel, GitHubAppRepositoryModel


_PERMISSION_LEVEL = {"read": 1, "write": 2, "admin": 3}


def require_installation_permissions(
    installation: GitHubAppInstallationModel,
    permission_profile: str,
) -> None:
    """Fail closed unless the latest signed installation grant covers an operation."""
    required = permission_requirements(permission_profile)
    try:
        granted = json.loads(installation.permissions_json)
        canonical = json.dumps(granted, sort_keys=True, separators=(",", ":"))
    except (TypeError, json.JSONDecodeError) as exc:
        raise GitHubAppError("GitHub App installation permissions are invalid.") from exc
    if (
        not isinstance(granted, dict)
        or any(
            name not in {"contents", "pull_requests"}
            or not isinstance(level, str)
            or level not in _PERMISSION_LEVEL
            for name, level in granted.items()
        )
        or hashlib.sha256(canonical.encode("utf-8")).hexdigest() != installation.permissions_digest
    ):
        raise GitHubAppError("GitHub App installation permissions failed integrity validation.")
    for name, required_level in required.items():
        granted_level = granted.get(name)
        if _PERMISSION_LEVEL.get(granted_level, 0) < _PERMISSION_LEVEL[required_level]:
            raise GitHubAppError("GitHub App installation lacks the permission required for this operation.")


def require_bound_repository(
    db: Session,
    *,
    installation_id: str,
    repository_id: str,
    owner_user_id: str,
    settings: Settings | None = None,
) -> tuple[GitHubAppInstallationModel, GitHubAppRepositoryModel]:
    cfg = settings or get_settings()
    if not cfg.GITHUB_APP_ENABLED:
        raise GitHubAppError("GitHub App integration is disabled.")
    installation = db.query(GitHubAppInstallationModel).filter_by(
        installation_id=str(installation_id),
        owner_user_id=owner_user_id,
        status="ACTIVE",
    ).first()
    repository = db.query(GitHubAppRepositoryModel).filter_by(
        installation_id=str(installation_id),
        repository_id=str(repository_id),
        active=True,
    ).first()
    if installation is None or repository is None:
        raise GitHubAppError("GitHub App installation or repository is not authorized for this RepoLens user.")
    return installation, repository


async def token_for_analysis(
    db: Session,
    analysis: ChangeAnalysisModel,
    *,
    permission_profile: str,
    settings: Settings | None = None,
    token_service: GitHubAppTokenService | None = None,
) -> str:
    if not analysis.github_app_installation_id or not analysis.github_app_repository_id:
        raise GitHubAppError("Analysis has no GitHub App repository authority.")
    installation, repository = require_bound_repository(
        db,
        installation_id=analysis.github_app_installation_id,
        repository_id=analysis.github_app_repository_id,
        owner_user_id=analysis.owner_user_id or "",
        settings=settings,
    )
    if repository.owner_login.casefold() != analysis.repository_owner.casefold() or (
        repository.repository_name.casefold() != analysis.repository_name.casefold()
    ):
        raise GitHubAppError("Analysis repository identity no longer matches its authorized App repository.")
    require_installation_permissions(installation, permission_profile)
    service = token_service or get_github_app_token_service()
    return await service.installation_token(
        analysis.github_app_installation_id,
        analysis.github_app_repository_id,
        permission_profile=permission_profile,
    )


async def token_for_user_repository(
    db: Session,
    *,
    installation_id: str,
    repository_id: str,
    owner_user_id: str,
    permission_profile: str = "contents_read",
    settings: Settings | None = None,
    token_service: GitHubAppTokenService | None = None,
) -> str:
    installation, _ = require_bound_repository(
        db,
        installation_id=installation_id,
        repository_id=repository_id,
        owner_user_id=owner_user_id,
        settings=settings,
    )
    require_installation_permissions(installation, permission_profile)
    service = token_service or get_github_app_token_service()
    return await service.installation_token(
        installation_id,
        repository_id,
        permission_profile=permission_profile,
    )
