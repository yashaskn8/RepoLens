"""Versioned operational policy snapshots used by every durable job."""

import hashlib
import json
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.models.platform import OperationalPolicyModel


class OperationalPolicy(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = "1.0"
    pause_new_jobs: bool = False
    disabled_providers: list[str] = Field(default_factory=list, max_length=100)
    disabled_models: list[str] = Field(default_factory=list, max_length=100)
    disabled_analyzers: list[str] = Field(default_factory=list, max_length=100)
    github_writes_enabled: bool = False
    max_repository_files: int = Field(default=5000, ge=1)
    max_repository_bytes: int = Field(default=52_428_800, ge=1)
    max_concurrent_scans: int = Field(default=2, ge=1)
    max_ai_concurrency: int = Field(default=4, ge=1)
    max_renderer_concurrency: int = Field(default=2, ge=1)
    max_large_repository_jobs: int = Field(default=1, ge=1)
    max_active_jobs_per_user: int = Field(default=3, ge=1)
    max_model_cost_tier: Literal["FREE", "CHEAP", "STANDARD", "PREMIUM"] = "STANDARD"
    default_retention_days: int = Field(default=90, ge=1, le=3650)

    def canonical_digest(self) -> str:
        payload = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @classmethod
    def from_settings(cls, settings: Settings | None = None) -> "OperationalPolicy":
        configured = settings or get_settings()
        return cls(
            github_writes_enabled=bool(
                configured.GITHUB_DELIVERY_ENABLED or configured.GITHUB_PR_REVIEW_WRITE_ENABLED
            ),
            max_repository_files=configured.MAX_REPO_FILES,
            max_repository_bytes=configured.MAX_TOTAL_SOURCE_BYTES,
            max_concurrent_scans=configured.MAX_CONCURRENT_SCANS,
            max_ai_concurrency=configured.MAX_AI_CONCURRENCY,
            max_renderer_concurrency=configured.REPORT_MAX_CONCURRENT_JOBS,
            max_large_repository_jobs=configured.MAX_LARGE_REPOSITORY_JOBS,
            max_active_jobs_per_user=configured.MAX_ACTIVE_JOBS_PER_USER,
            default_retention_days=configured.ARTIFACT_RETENTION_DEFAULT_DAYS,
        )


class OperationalPolicyService:
    @staticmethod
    def ensure_active(db: Session, tenant_id: str | None = None) -> OperationalPolicyModel:
        existing = OperationalPolicyService.active(db, tenant_id)
        if existing is not None:
            return existing
        return OperationalPolicyService.snapshot(db, OperationalPolicy.from_settings(), tenant_id=tenant_id)

    @staticmethod
    def snapshot(
        db: Session,
        policy: OperationalPolicy,
        *,
        tenant_id: str | None = None,
        actor_id: str | None = None,
    ) -> OperationalPolicyModel:
        scope = tenant_id or "GLOBAL"
        digest = policy.canonical_digest()
        existing = db.query(OperationalPolicyModel).filter(
            OperationalPolicyModel.tenant_scope == scope,
            OperationalPolicyModel.content_digest == digest,
        ).first()
        if existing is not None:
            return existing
        now = datetime.now(timezone.utc)
        db.query(OperationalPolicyModel).filter(
            OperationalPolicyModel.tenant_scope == scope,
            OperationalPolicyModel.active.is_(True),
        ).update(
            {OperationalPolicyModel.active: False, OperationalPolicyModel.superseded_at: now},
            synchronize_session=False,
        )
        version = int(db.query(func.max(OperationalPolicyModel.version)).filter(
            OperationalPolicyModel.tenant_scope == scope,
        ).scalar() or 0) + 1
        model = OperationalPolicyModel(
            tenant_scope=scope,
            version=version,
            content_digest=digest,
            policy_payload=policy.model_dump(mode="json"),
            active=True,
            created_by=actor_id,
            created_at=now,
        )
        db.add(model)
        db.flush()
        return model

    @staticmethod
    def active(db: Session, tenant_id: str | None = None) -> OperationalPolicyModel | None:
        scopes = [tenant_id, "GLOBAL"] if tenant_id else ["GLOBAL"]
        for scope in scopes:
            if not scope:
                continue
            model = db.query(OperationalPolicyModel).filter(
                OperationalPolicyModel.tenant_scope == scope,
                OperationalPolicyModel.active.is_(True),
            ).order_by(OperationalPolicyModel.version.desc()).first()
            if model is not None:
                return model
        return None
