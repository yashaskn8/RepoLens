"""Application settings and configuration using Pydantic Settings."""

from functools import lru_cache
from typing import List, Union
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings class supporting .env loading and environment overrides."""

    PROJECT_NAME: str = "RepoLens"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "development"

    # Database connection string (defaults to SQLite, portable to PostgreSQL)
    DATABASE_URL: str = "sqlite:///./repolens.db"

    # Server configuration
    BACKEND_HOST: str = "0.0.0.0"
    BACKEND_PORT: int = 8000

    # CORS Configuration
    CORS_ORIGINS: Union[List[str], str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    # LLM Provider API Keys
    GEMINI_API_KEY: str = ""
    GROQ_API_KEY: str = ""
    NVIDIA_API_KEY: str = ""
    HUGGINGFACE_API_KEY: str = ""

    # LLM Provider Base URLs
    GEMINI_BASE_URL: str = "https://generativelanguage.googleapis.com/v1beta"
    GROQ_BASE_URL: str = "https://api.groq.com/openai/v1"
    NVIDIA_BASE_URL: str = "https://integrate.api.nvidia.com/v1"
    HUGGINGFACE_BASE_URL: str = "https://router.huggingface.co/v1"

    # Canonical Policy Model IDs
    MODEL_ARCHITECTURE: str = "gemini-3.7-flash"
    MODEL_INTEGRATION_CODE: str = "Qwen/Qwen3-Coder-Next"
    MODEL_BUG_REASONING: str = "poolside/laguna-xs-2.1"
    MODEL_SECURITY_REASONING: str = "openai/gpt-oss-120b"
    MODEL_LIGHTWEIGHT_CLASSIFICATION: str = "openai/gpt-oss-20b"
    MODEL_VERIFICATION: str = "nvidia/nemotron-3-ultra-550b-a55b"

    # LLM Gateway Execution Settings
    LLM_DEFAULT_TIMEOUT: float = 30.0
    LLM_MAX_RETRIES: int = 2

    # Repository Ingestion Limits
    CLONE_TIMEOUT_SECONDS: int = 120
    MAX_REPO_FILES: int = 5000
    MAX_FILE_SIZE_BYTES: int = 1_048_576  # 1 MB
    MAX_TOTAL_SOURCE_BYTES: int = 52_428_800  # 50 MB global source budget
    MAX_SCAN_DURATION_SECONDS: int = 300  # 5 minutes maximum scan lifecycle timeout
    ALLOWED_EXTENSIONS: str = ".py,.js,.ts,.tsx,.jsx,.json,.yaml,.yml,.toml,.md,.txt,.cfg,.ini,.html,.css,.sql,.sh,.dockerfile,.env.example"

    # Deterministic Scanner Settings
    SEMGREP_PATH: str = "semgrep"
    TRIVY_PATH: str = "trivy"
    OSV_SCANNER_PATH: str = "osv-scanner"
    SCANNER_TIMEOUT_SECONDS: int = 60
    SEMGREP_ENABLED: bool = True
    TRIVY_ENABLED: bool = True
    OSV_SCANNER_ENABLED: bool = True

    # Embedding Model Settings
    EMBEDDING_MODEL_PRIMARY: str = "nvidia/nv-embedcode-7b-v1"
    EMBEDDING_MODEL_FALLBACK: str = "Qwen/Qwen3-Embedding-0.6B"
    EMBEDDING_DIMENSIONS_PRIMARY: int = 4096
    EMBEDDING_DIMENSIONS_FALLBACK: int = 1024

    # LangGraph Checkpoint Settings
    CHECKPOINT_DB_FILE: str = "checkpoints.db"

    # PostgreSQL pgvector Settings
    ENABLE_PGVECTOR: bool = False

    # Safe GitHub Delivery Settings (Phase 5)
    GITHUB_TOKEN: str = ""
    GITHUB_DELIVERY_ENABLED: bool = False

    # Safe GitHub PR Review Publication Settings (Phase 7)
    GITHUB_PR_REVIEW_WRITE_ENABLED: bool = False
    MAX_REVIEW_INLINE_COMMENTS: int = 20
    MAX_REVIEW_BODY_CHARS: int = 50_000


    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        """Parse comma-separated string into a list of origins if provided as string."""
        if isinstance(v, str):
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, list):
            return v
        return []

    @property
    def is_sqlite(self) -> bool:
        """Helper to determine if the configured database is SQLite."""
        return self.DATABASE_URL.startswith("sqlite")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings singleton instance."""
    return Settings()
