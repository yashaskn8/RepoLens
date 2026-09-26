"""Zero-network check for the runtime imports required by production deployments."""

from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from typing import Callable

from app.core.config import Settings, get_settings


PRODUCTION_REQUIRED_MODULES = (
    "fastapi",
    "uvicorn",
    "pydantic",
    "pydantic_settings",
    "sqlalchemy",
    "alembic",
    "dotenv",
    "httpx",
    "tree_sitter",
    "tree_sitter_python",
    "tree_sitter_javascript",
    "tree_sitter_typescript",
    "langchain_core",
    "langgraph",
    "langgraph.checkpoint.sqlite.aio",
    "langgraph.checkpoint.postgres.aio",
    "aiosqlite",
    "psycopg",
    "networkx",
    "mcp",
    "argon2",
    "jwt",
    "cryptography",
    "email_validator",
    "reportlab",
    "pypdf",
    "redis.asyncio",
    "opentelemetry",
)


@dataclass(frozen=True)
class ProductionPreflightResult:
    production: bool
    missing_modules: tuple[str, ...]

    @property
    def ready(self) -> bool:
        return not self.production or not self.missing_modules


class ProductionDependencyError(RuntimeError):
    """Sanitized failure indicating mandatory deployment dependencies are absent."""

    def __init__(self, missing_count: int) -> None:
        self.missing_count = missing_count
        super().__init__(
            "Production runtime dependencies are missing or failed import validation. "
            'Install the project with `python -m pip install -e ".[production]"`.'
        )


def check_production_dependencies(
    settings: Settings,
    *,
    importer: Callable[[str], object] = import_module,
) -> ProductionPreflightResult:
    """Check required production imports; development does not require PG extras."""
    if not settings.is_production:
        return ProductionPreflightResult(production=False, missing_modules=())

    missing: list[str] = []
    for module_name in PRODUCTION_REQUIRED_MODULES:
        try:
            importer(module_name)
        except Exception:
            # Exception text may contain deployment paths or secret-bearing config.
            missing.append(module_name)
    return ProductionPreflightResult(production=True, missing_modules=tuple(missing))


def require_production_dependencies(
    settings: Settings,
    *,
    importer: Callable[[str], object] = import_module,
) -> ProductionPreflightResult:
    result = check_production_dependencies(settings, importer=importer)
    if result.production and not result.ready:
        raise ProductionDependencyError(len(result.missing_modules)) from None
    return result


def main() -> int:
    """Operator entry point. It never contacts configured external services."""
    try:
        settings = get_settings()
    except Exception:
        print("Production preflight failed: application settings could not be loaded.")
        return 2

    result = check_production_dependencies(settings)
    if not result.production:
        print("Production-only dependency checks skipped outside production mode.")
        return 0
    if not result.ready:
        print(
            "Production preflight failed: required runtime dependencies are unavailable. "
            'Install with `python -m pip install -e ".[production]"`.'
        )
        return 1
    print("Production dependency preflight passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
