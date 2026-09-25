"""GitHub App installation, OAuth-state, webhook and PR-head records."""

from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from app.models.base import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class GitHubAppInstallationModel(Base):
    __tablename__ = "github_app_installations"

    installation_id = Column(String(32), primary_key=True)
    account_id = Column(String(32), nullable=False, index=True)
    account_login = Column(String(256), nullable=False)
    account_type = Column(String(32), nullable=False)
    permissions_json = Column(Text, nullable=False, default="{}")
    permissions_digest = Column(String(64), nullable=False, default="44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a")
    owner_user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    status = Column(String(24), nullable=False, default="UNBOUND", index=True)
    suspended_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now)

    repositories = relationship("GitHubAppRepositoryModel", back_populates="installation", cascade="all, delete-orphan")


class GitHubAppRepositoryModel(Base):
    __tablename__ = "github_app_repositories"

    repository_id = Column(String(32), primary_key=True)
    installation_id = Column(
        String(32), ForeignKey("github_app_installations.installation_id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    owner_login = Column(String(256), nullable=False)
    repository_name = Column(String(256), nullable=False)
    is_private = Column(Boolean, nullable=False, default=False)
    active = Column(Boolean, nullable=False, default=True, index=True)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now)

    installation = relationship("GitHubAppInstallationModel", back_populates="repositories")


class GitHubAppOAuthStateModel(Base):
    __tablename__ = "github_app_oauth_states"
    __table_args__ = (UniqueConstraint("user_id", name="uq_github_app_oauth_user"),)

    state_digest = Column(String(64), primary_key=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    verifier_ciphertext = Column(Text, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)


class GitHubAppBindingGrantModel(Base):
    """Short-lived user-bound proof that GitHub returned accessible installations."""

    __tablename__ = "github_app_binding_grants"
    __table_args__ = (UniqueConstraint("user_id", name="uq_github_app_binding_grant_user"),)

    grant_digest = Column(String(64), primary_key=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    installation_ids_json = Column(Text, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)


class GitHubAppWebhookDeliveryModel(Base):
    __tablename__ = "github_app_webhook_deliveries"

    delivery_id = Column(String(128), primary_key=True)
    body_sha256 = Column(String(64), nullable=False)
    event_name = Column(String(64), nullable=False)
    action = Column(String(64), nullable=True)
    installation_id = Column(String(32), nullable=True, index=True)
    status = Column(String(24), nullable=False, default="RECEIVED", index=True)
    received_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, index=True)
    processed_at = Column(DateTime(timezone=True), nullable=True)


class GitHubAppPullRequestHeadModel(Base):
    """Current semantic PR head; delivery IDs do not define analysis identity."""

    __tablename__ = "github_app_pull_request_heads"
    __table_args__ = (
        UniqueConstraint("installation_id", "repository_id", "pull_number", name="uq_github_app_pr_identity"),
    )

    id = Column(String(36), primary_key=True)
    installation_id = Column(
        String(32), ForeignKey("github_app_installations.installation_id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    repository_id = Column(
        String(32), ForeignKey("github_app_repositories.repository_id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    pull_number = Column(Integer, nullable=False)
    base_sha = Column(String(40), nullable=False)
    head_sha = Column(String(40), nullable=False)
    head_updated_at = Column(DateTime(timezone=True), nullable=False)
    current_analysis_id = Column(String(36), ForeignKey("change_analyses.id", ondelete="SET NULL"), nullable=True)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now)
