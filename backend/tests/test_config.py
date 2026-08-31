"""Tests for application settings and configuration."""

import os
from app.core.config import Settings, get_settings


def test_settings_defaults():
    """Verify default configuration values."""
    settings = Settings()
    assert settings.PROJECT_NAME == "RepoLens"
    assert settings.VERSION == "1.0.0"
    assert settings.API_V1_STR == "/api/v1"
    assert settings.DATABASE_URL == "sqlite:///./repolens.db"
    assert settings.is_sqlite is True
    assert "http://localhost:3000" in settings.CORS_ORIGINS


def test_settings_cors_string_parsing():
    """Verify that comma-separated CORS strings are properly converted to lists."""
    settings = Settings(CORS_ORIGINS="http://localhost:3000,http://app.repolens.io")
    assert isinstance(settings.CORS_ORIGINS, list)
    assert len(settings.CORS_ORIGINS) == 2
    assert "http://localhost:3000" in settings.CORS_ORIGINS
    assert "http://app.repolens.io" in settings.CORS_ORIGINS


def test_settings_postgres_url():
    """Verify that PostgreSQL URL is recognized properly and is_sqlite is False."""
    pg_url = "postgresql://user:pass@localhost:5432/repolens"
    settings = Settings(DATABASE_URL=pg_url)
    assert settings.DATABASE_URL == pg_url
    assert settings.is_sqlite is False


def test_cached_get_settings():
    """Verify that get_settings returns a valid singleton."""
    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2
