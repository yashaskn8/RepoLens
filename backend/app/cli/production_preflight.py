"""Zero-network check for the runtime imports required by production deployments."""

from __future__ import annotations

import argparse
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


@dataclass(frozen=True)
class ProductionReleaseCapabilityResult:
    """Offline capability assessment, not a substitute for live deployment tests."""

    blocked_codes: tuple[str, ...]

    @property
    def eligible(self) -> bool:
        return not self.blocked_codes


def check_production_release_capabilities(settings: Settings) -> ProductionReleaseCapabilityResult:
    """Block release while mandatory OS-enforced untrusted-work boundaries are absent.

    These predicates must only return True after a real resource and egress
    enforcement integration has been implemented and independently tested.
    """
    from app.analysis.base import external_scanner_execution_allowed
    from app.ingestion.acquisition_boundary import acquisition_boundary_available

    blocked: list[str] = []
    if not settings.is_production:
        blocked.append("PRODUCTION_CONFIGURATION_REQUIRED")
    if not acquisition_boundary_available(settings):
        blocked.append("ACQUISITION_HARD_QUOTA_EGRESS_UNAVAILABLE")
    if not external_scanner_execution_allowed(settings):
        blocked.append("EXTERNAL_SCANNER_ISOLATION_UNAVAILABLE")
    return ProductionReleaseCapabilityResult(tuple(blocked))


def main() -> int:
    """Operator entry point. No DB, network or untrusted repository work."""
    parser = argparse.ArgumentParser(description="RepoLens offline production preflight")
    parser.add_argument(
        "--release-gate",
        action="store_true",
        help="Fail if mandatory production analysis isolation is not implemented.",
    )
    args = parser.parse_args()
    try:
        settings = get_settings()
    except Exception:
        print("Production preflight failed: application settings could not be loaded.")
        return 2

    result = check_production_dependencies(settings)
    if not result.production:
        if args.release_gate:
            print("Release gate BLOCKED: PRODUCTION_CONFIGURATION_REQUIRED")
            return 2
        print("Production-only dependency checks skipped outside production mode.")
        return 0
    if not result.ready:
        print(
            "Production preflight failed: required runtime dependencies are unavailable. "
            'Install with `python -m pip install -e ".[production]"`.'
        )
        return 1
    if args.release_gate:
        capabilities = check_production_release_capabilities(settings)
        if not capabilities.eligible:
            print("Release gate BLOCKED: " + ", ".join(capabilities.blocked_codes))
            return 1
        print("Offline release capability preflight passed; live deployment validation still required.")
        return 0
    print("Production dependency preflight passed (imports only; not a release approval).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
