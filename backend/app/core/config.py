"""Application settings and configuration using Pydantic Settings."""

from functools import lru_cache
from typing import List, Literal, Optional, Union
from urllib.parse import urlparse
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings class supporting .env loading and environment overrides."""

    PROJECT_NAME: str = "RepoLens"
    VERSION: str = "1.0.1"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "development"

    # Database connection string (defaults to SQLite, portable to PostgreSQL)
    DATABASE_URL: str = "sqlite:///./repolens.db"
    DATABASE_POOL_SIZE: int = Field(default=10, ge=1, le=100)
    DATABASE_MAX_OVERFLOW: int = Field(default=20, ge=0, le=200)
    DATABASE_POOL_TIMEOUT_SECONDS: float = Field(default=5.0, gt=0, le=60)
    DATABASE_STATEMENT_TIMEOUT_MS: int = Field(default=15_000, ge=100, le=300_000)
    DATABASE_LOCK_TIMEOUT_MS: int = Field(default=2_000, ge=100, le=60_000)

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
    CLOUDFLARE_API_TOKEN: str = ""
    CLOUDFLARE_ACCOUNT_ID: str = ""
    MISTRAL_API_KEY: str = ""
    COHERE_API_KEY: str = ""
    OPENROUTER_API_KEY: str = ""

    # LLM Provider Base URLs
    GEMINI_BASE_URL: str = "https://generativelanguage.googleapis.com/v1beta"
    GROQ_BASE_URL: str = "https://api.groq.com/openai/v1"
    NVIDIA_BASE_URL: str = "https://integrate.api.nvidia.com/v1"
    HUGGINGFACE_BASE_URL: str = "https://router.huggingface.co/v1"
    CLOUDFLARE_BASE_URL: str = "https://api.cloudflare.com/client/v4"
    MISTRAL_BASE_URL: str = "https://api.mistral.ai/v1"
    COHERE_BASE_URL: str = "https://api.cohere.com/v1"
    OPENROUTER_BASE_URL: str = "https://openrouter.ai/api/v1"

    # Optional operator-managed, loopback-only local generation
    LOCAL_LLM_ENABLED: bool = False
    OLLAMA_BASE_URL: str = "http://127.0.0.1:11434"
    OLLAMA_MODEL: str = "qwen2.5:3b"
    OLLAMA_TIMEOUT: float = 10.0
    OLLAMA_FAILURE_COOLDOWN_SECONDS: float = 30.0
    OLLAMA_CONTEXT_WINDOW_TOKENS: int = 8192
    OLLAMA_MAX_OUTPUT_TOKENS: int = 2048

    # Canonical Policy Model IDs
    MODEL_ARCHITECTURE: str = "gemini-3.7-flash"
    MODEL_INTEGRATION_CODE: str = "Qwen/Qwen3-Coder-Next"
    MODEL_BUG_REASONING: str = "poolside/laguna-xs-2.1"
    MODEL_SECURITY_REASONING: str = "openai/gpt-oss-120b"
    MODEL_LIGHTWEIGHT_CLASSIFICATION: str = "openai/gpt-oss-20b"
    MODEL_VERIFICATION: str = "nvidia/nemotron-3-ultra-550b-a55b"

    # Task-Aware Multi-Provider Model Defaults
    CLOUDFLARE_DEFAULT_MODEL: str = "@cf/meta/llama-3.1-8b-instruct"
    MISTRAL_DEFAULT_MODEL: str = "mistral-small-latest"
    COHERE_EMBEDDING_MODEL: str = "embed-english-v3.0"
    COHERE_RERANK_MODEL: str = "rerank-v3.5"
    OPENROUTER_DEFAULT_MODEL: str = "meta-llama/llama-3.2-3b-instruct:free"

    # Routing & Reranking Optimization Thresholds
    ROUTER_RERANK_MIN_CANDIDATES: int = 3
    ROUTER_COMPLEXITY_CONTEXT_THRESHOLD: int = 2000

    # LLM Gateway Execution Settings
    LLM_DEFAULT_TIMEOUT: float = 30.0
    LLM_MAX_RETRIES: int = 2

    # Shared workflow cloud-use governor.  Local Ollama, cache hits, and
    # deterministic work never consume these limits.
    AI_ECONOMY_MODE: Literal["auto", "strict", "quality"] = "auto"
    AI_ECONOMY_STRICT_MAX_CLOUD_CALLS: int = 3
    AI_ECONOMY_STRICT_MAX_CLOUD_TOKENS: int = 12_000
    AI_ECONOMY_AUTO_MAX_CLOUD_CALLS: int = 8
    AI_ECONOMY_AUTO_MAX_CLOUD_TOKENS: int = 40_000
    AI_ECONOMY_QUALITY_MAX_CLOUD_CALLS: int = 16
    AI_ECONOMY_QUALITY_MAX_CLOUD_TOKENS: int = 100_000

    # Repository Ingestion Limits
    CLONE_TIMEOUT_SECONDS: int = 120
    MAX_REPO_FILES: int = 5000
    MAX_FILE_SIZE_BYTES: int = 1_048_576  # 1 MB
    MAX_TOTAL_SOURCE_BYTES: int = 52_428_800  # 50 MB global source budget
    MAX_SCAN_DURATION_SECONDS: int = 300  # 5 minutes maximum scan lifecycle timeout
    INDEX_MAX_DATABASE_BYTES: int = Field(default=2_147_483_648, ge=16_777_216)
    INDEX_RETENTION_SECONDS: int = Field(default=604_800, ge=86_400)
    INDEX_GC_ROWS: int = Field(default=256, ge=1, le=1024)
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

    # Local Embedding Settings (Sentence Transformers)
    LOCAL_EMBEDDING_ENABLED: bool = True
    LOCAL_EMBEDDING_MODEL: str = "sentence-transformers/all-MiniLM-L6-v2"
    LOCAL_EMBEDDING_DEVICE: str = "cpu"
    LOCAL_EMBEDDING_ALLOW_DOWNLOAD: bool = False

    # LangGraph Checkpoint Settings
    CHECKPOINT_DB_FILE: str = "checkpoints.db"

    # Redis Runtime Infrastructure (Phase 1)
    REDIS_URL: Optional[str] = None
    REDIS_MAX_CONNECTIONS: int = 10
    REDIS_TIMEOUT_SECONDS: float = 2.0
    REDIS_DEFAULT_CACHE_TTL_SECONDS: int = 3600
    REDIS_ENABLED: bool = True

    # Evidence-scoped AI response reuse and bounded in-process coalescing
    AI_EXACT_CACHE_TTL_SECONDS: int = 1800
    AI_SEMANTIC_CACHE_ENABLED: bool = True
    AI_SEMANTIC_CACHE_TTL_SECONDS: int = 900
    AI_SEMANTIC_CACHE_SIMILARITY_THRESHOLD: float = 0.985
    AI_SEMANTIC_CACHE_MAX_ENTRIES: int = 32
    AI_SINGLEFLIGHT_MAX_ENTRIES: int = 256

    # PostgreSQL pgvector Settings
    ENABLE_PGVECTOR: bool = False

    # Safe GitHub Delivery Settings (Phase 5)
    GITHUB_TOKEN: str = ""
    GITHUB_DELIVERY_ENABLED: bool = False

    # Safe GitHub PR Review Publication Settings (Phase 7)
    GITHUB_PR_REVIEW_WRITE_ENABLED: bool = False
    MAX_REVIEW_INLINE_COMMENTS: int = 20
    MAX_REVIEW_BODY_CHARS: int = 50_000

    # Authentication & Session Settings (Phase 8)
    AUTH_SESSION_TTL_SECONDS: int = 86400  # 24 hours
    AUTH_MAX_FAILED_LOGIN_ATTEMPTS: int = 5
    AUTH_LOCKOUT_SECONDS: int = 900  # 15 minutes
    AUTH_COOKIE_NAME: str = "repolens_session"
    AUTH_COOKIE_SECURE: bool = False
    AUTH_COOKIE_SAMESITE: Literal["lax", "strict", "none"] = "lax"
    AUTH_COOKIE_DOMAIN: Optional[str] = None

    # CSRF Protection Settings (Phase 8)
    CSRF_COOKIE_NAME: str = "repolens_csrf"
    CSRF_HEADER_NAME: str = "X-CSRF-Token"

    # Daily Quota Limits Per User (Phase 8)
    MAX_DAILY_SCANS_PER_USER: int = 20
    MAX_DAILY_CHANGE_ANALYSES_PER_USER: int = 50
    MAX_DAILY_PATCH_GENERATIONS_PER_USER: int = 50

    # Immutable PDF report artifacts and bounded local report execution
    REPORT_ARTIFACT_DIR: str = "./artifacts/reports"
    REPORT_MAX_FINDINGS: int = 500
    REPORT_MAX_DETAILED_FINDINGS: int = 50
    REPORT_MAX_EVIDENCE_REFERENCES: int = 1000
    REPORT_MAX_EVIDENCE_PER_FINDING: int = 5
    REPORT_MAX_EXCERPT_CHARS: int = 4096
    REPORT_MAX_EXCERPT_LINES: int = 40
    REPORT_MAX_PDF_PAGES: int = 250
    REPORT_MAX_PDF_BYTES: int = 26_214_400  # 25 MiB
    REPORT_MAX_CONCURRENT_JOBS: int = 2
    REPORT_MAX_ATTEMPTS: int = 3
    REPORT_LEASE_SECONDS: int = 300
    REPORT_RECOVERY_INTERVAL_SECONDS: int = 30

    # Shared execution authority and resource governance
    EXECUTION_LEASE_SECONDS: int = 300
    EXECUTION_RECOVERY_INTERVAL_SECONDS: int = 30
    EXECUTION_MAX_ATTEMPTS: int = 3
    MAX_CONCURRENT_SCANS: int = 2
    MAX_AI_CONCURRENCY: int = 4
    MAX_LARGE_REPOSITORY_JOBS: int = 1
    MAX_ACTIVE_JOBS_PER_USER: int = 3
    MAX_OUTBOX_ATTEMPTS: int = 10

    # Canonical artifact authority and lifecycle defaults
    ARTIFACT_STORAGE_BACKEND: Literal["local", "blob"] = "local"
    ARTIFACT_ROOT_DIR: str = "./artifacts/canonical"
    ARTIFACT_BLOB_NAMESPACE: str = "repolens"
    ARTIFACT_BLOB_CONTAINER: str = ""
    ARTIFACT_RETENTION_DEFAULT_DAYS: int = 90
    ARTIFACT_GC_BATCH_SIZE: int = 100
    ARTIFACT_RECONCILIATION_INTERVAL_SECONDS: int = 60

    # API compatibility and idempotency contract
    API_CURRENT_VERSION: str = "1"
    API_MINIMUM_SUPPORTED_VERSION: str = "1"
    API_DEPRECATION_WINDOW_DAYS: int = 180
    IDEMPOTENCY_KEY_MAX_LENGTH: int = 128

    # Production Hardening & Network Controls (Phase 8)
    TRUSTED_HOSTS: Union[List[str], str] = ["localhost", "127.0.0.1", "testserver"]
    ENABLE_API_DOCS: Optional[bool] = None

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        """Parse comma-separated string into a list of origins if provided as string."""
        if isinstance(v, str):
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, list):
            return v
        return []

    @field_validator("TRUSTED_HOSTS", mode="before")
    @classmethod
    def assemble_trusted_hosts(cls, v: Union[str, List[str]]) -> List[str]:
        """Parse comma-separated string into a list of trusted hosts if provided as string."""
        if isinstance(v, str):
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, list):
            return v
        return ["localhost", "127.0.0.1", "testserver"]

    @model_validator(mode="after")
    def validate_production_and_cookie_invariants(self) -> "Settings":
        """Enforce strict fail-closed production security and cookie invariants."""
        if not 0.0 <= self.AI_SEMANTIC_CACHE_SIMILARITY_THRESHOLD <= 1.0:
            raise ValueError(
                "AI_SEMANTIC_CACHE_SIMILARITY_THRESHOLD must be between 0 and 1"
            )
        if min(
            self.AI_EXACT_CACHE_TTL_SECONDS,
            self.AI_SEMANTIC_CACHE_TTL_SECONDS,
            self.AI_SEMANTIC_CACHE_MAX_ENTRIES,
            self.AI_SINGLEFLIGHT_MAX_ENTRIES,
        ) < 1:
            raise ValueError("AI cache TTL, bucket, and single-flight limits must be positive")
        if min(
            self.OLLAMA_TIMEOUT,
            self.OLLAMA_CONTEXT_WINDOW_TOKENS,
            self.OLLAMA_MAX_OUTPUT_TOKENS,
        ) <= 0 or self.OLLAMA_FAILURE_COOLDOWN_SECONDS < 0:
            raise ValueError("Ollama timeouts and token limits must be positive")
        if min(
            self.AI_ECONOMY_STRICT_MAX_CLOUD_CALLS,
            self.AI_ECONOMY_STRICT_MAX_CLOUD_TOKENS,
            self.AI_ECONOMY_AUTO_MAX_CLOUD_CALLS,
            self.AI_ECONOMY_AUTO_MAX_CLOUD_TOKENS,
            self.AI_ECONOMY_QUALITY_MAX_CLOUD_CALLS,
            self.AI_ECONOMY_QUALITY_MAX_CLOUD_TOKENS,
        ) < 1:
            raise ValueError("AI economy cloud ceilings must be positive")
        if self.ENABLE_API_DOCS is None:
            self.ENABLE_API_DOCS = not self.is_production

        if self.AUTH_COOKIE_SAMESITE not in ("lax", "strict", "none"):
            raise ValueError(f"AUTH_COOKIE_SAMESITE must be one of 'lax', 'strict', 'none', got '{self.AUTH_COOKIE_SAMESITE}'")

        if self.AUTH_COOKIE_SAMESITE == "none" and not self.AUTH_COOKIE_SECURE:
            raise ValueError("When AUTH_COOKIE_SAMESITE is 'none', AUTH_COOKIE_SECURE must be True.")

        if self.is_production:
            if not self.AUTH_COOKIE_SECURE:
                raise ValueError("CRITICAL CONFIGURATION ERROR: In production environment, AUTH_COOKIE_SECURE must be True.")

            # CORS validation in production
            cors = self.CORS_ORIGINS if isinstance(self.CORS_ORIGINS, list) else [self.CORS_ORIGINS]
            if not cors:
                raise ValueError("CRITICAL CONFIGURATION ERROR: In production environment, CORS_ORIGINS must not be empty.")
            if "*" in cors:
                raise ValueError("CRITICAL CONFIGURATION ERROR: Wildcard CORS origin ('*') is prohibited in production.")
            for origin in cors:
                parsed = urlparse(origin)
                if not parsed.scheme or not parsed.netloc or parsed.scheme not in ("http", "https"):
                    raise ValueError(f"Invalid CORS origin '{origin}': must be formatted as scheme://host[:port]")
                if parsed.path and parsed.path != "/":
                    raise ValueError(f"Invalid CORS origin '{origin}': origin must not contain paths")
                if parsed.query or parsed.fragment:
                    raise ValueError(f"Invalid CORS origin '{origin}': origin must not contain query parameters or fragments")

            # Trusted hosts validation in production
            hosts = self.TRUSTED_HOSTS if isinstance(self.TRUSTED_HOSTS, list) else [self.TRUSTED_HOSTS]
            if not hosts:
                raise ValueError("CRITICAL CONFIGURATION ERROR: In production environment, TRUSTED_HOSTS must not be empty.")
            if "*" in hosts:
                raise ValueError("CRITICAL CONFIGURATION ERROR: Wildcard Trusted Hosts ('*') is prohibited in production.")

        return self

    @property
    def is_sqlite(self) -> bool:
        """Helper to determine if the configured database is SQLite."""
        return self.DATABASE_URL.startswith("sqlite")

    @property
    def is_production(self) -> bool:
        """Helper to determine if running in production mode."""
        return self.ENVIRONMENT.lower() == "production"

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
