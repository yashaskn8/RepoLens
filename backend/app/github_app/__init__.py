"""Optional, tightly-scoped GitHub App integration."""

from app.github_app.auth import GitHubAppError, GitHubAppTokenService

__all__ = ["GitHubAppError", "GitHubAppTokenService"]
