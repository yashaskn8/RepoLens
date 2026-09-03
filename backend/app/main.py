"""RepoLens FastAPI application entry point with production security hardening."""

from contextlib import asynccontextmanager
import asyncio
import logging
import re
import time
import uuid
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api.router import api_router
from app.api.errors import http_exception_handler, validation_exception_handler
from app.api.routes import health
from app.core.config import get_settings
from app.core.database import engine

logger = logging.getLogger(__name__)
settings = get_settings()


def _validate_production_configuration() -> None:
    """Validate critical security settings in production environments."""
    if settings.is_production:
        if settings.is_sqlite:
            raise RuntimeError(
                "CRITICAL CONFIGURATION ERROR: Production execution authority requires PostgreSQL; "
                "SQLite is supported only for local single-worker development."
            )
        if not settings.AUTH_COOKIE_SECURE:
            raise RuntimeError("CRITICAL SECURITY ERROR: In production environment, AUTH_COOKIE_SECURE must be True.")
        if not settings.CORS_ORIGINS or (isinstance(settings.CORS_ORIGINS, list) and "*" in settings.CORS_ORIGINS):
            raise RuntimeError("CRITICAL SECURITY ERROR: Wildcard or empty CORS_ORIGINS is prohibited in production.")
        if not settings.TRUSTED_HOSTS or (isinstance(settings.TRUSTED_HOSTS, list) and "*" in settings.TRUSTED_HOSTS):
            raise RuntimeError("CRITICAL SECURITY ERROR: Wildcard or empty TRUSTED_HOSTS is prohibited in production.")


_validate_production_configuration()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start shared SQL-authoritative workers after validating migrated tables."""
    from sqlalchemy import inspect
    from app.core.database import SessionLocal
    import app.models
    from app.artifacts.runtime import ArtifactLifecycleRuntime
    from app.execution.dispatcher import DurableWorkDispatcher
    from app.governance.outbox import RelationalOutboxRelay
    from app.llm.router import configure_persistent_llm_router

    available_tables = set(inspect(engine).get_table_names())
    from app.core.redis import get_redis_manager
    redis_mgr = get_redis_manager()
    await redis_mgr.initialize()

    try:
        if "ai_executions" in available_tables:
            configure_persistent_llm_router(
                SessionLocal,
                database_authoritative=not settings.is_sqlite,
            )
        if "execution_work_items" in available_tables:
            recovered = await asyncio.to_thread(DurableWorkDispatcher.reconcile_orphaned_domain_work)
            if recovered:
                logger.info("Backfilled %s unfinished domain resources into durable work items.", recovered)
            DurableWorkDispatcher.start()
        if "outbox_events" in available_tables:
            RelationalOutboxRelay.start()
        if "artifact_tombstones" in available_tables:
            ArtifactLifecycleRuntime.start()
    except Exception:
        logger.exception("Platform authority startup failed; background work remains durable and recoverable.")
        if settings.is_production:
            raise

    yield

    await ArtifactLifecycleRuntime.stop()
    RelationalOutboxRelay.stop()
    await DurableWorkDispatcher.stop()
    await redis_mgr.close()


def _record_request_duration(
    *,
    request_id: str,
    path: str,
    method: str,
    status_code: int,
    duration_ms: float,
) -> None:
    """Best-effort vendor-neutral request telemetry; never affects the response."""
    from sqlalchemy import inspect
    from app.core.database import SessionLocal
    from app.governance.telemetry import TelemetryRecorder

    # Local SQLite has one writer and the request transaction may still be open
    # while middleware is finalising the response. Structured request logging is
    # still emitted above; durable request metrics are a PostgreSQL production
    # concern and must never turn local response completion into lock contention.
    if settings.is_sqlite:
        return

    db = SessionLocal()
    try:
        if not inspect(db.get_bind()).has_table("telemetry_metrics"):
            return
        TelemetryRecorder.record(
            db,
            request_id=request_id,
            metric_name="request.duration",
            value=duration_ms,
            unit="milliseconds",
            dimensions={"method": method, "path": path[:256], "status_code": status_code},
        )
        db.commit()
    except Exception:
        db.rollback()
        logger.debug("Request telemetry persistence failed.", exc_info=True)
    finally:
        db.close()


# Conditional API docs configuration based on environment and settings
openapi_url = f"{settings.API_V1_STR}/openapi.json" if settings.ENABLE_API_DOCS else None
docs_url = f"{settings.API_V1_STR}/docs" if settings.ENABLE_API_DOCS else None
redoc_url = f"{settings.API_V1_STR}/redoc" if settings.ENABLE_API_DOCS else None

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=openapi_url,
    docs_url=docs_url,
    redoc_url=redoc_url,
    lifespan=lifespan,
)
app.add_exception_handler(HTTPException, http_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware attaching standard defensive HTTP security headers to all responses."""

    async def dispatch(self, request: Request, call_next):
        candidate = request.headers.get("X-Request-ID", "")
        request_id = candidate if re.fullmatch(r"[A-Za-z0-9._:-]{8,128}", candidate) else str(uuid.uuid4())
        request.state.request_id = request_id
        started = time.monotonic()
        response: Response = await call_next(request)
        duration_ms = max(0.0, (time.monotonic() - started) * 1000.0)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-API-Version"] = settings.API_CURRENT_VERSION
        response.headers["X-API-Minimum-Version"] = settings.API_MINIMUM_SUPPORTED_VERSION
        response.headers["Deprecation"] = "false"
        response.headers["Server-Timing"] = f"app;dur={duration_ms:.2f}"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        if settings.AUTH_COOKIE_SECURE or settings.is_production:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        logger.info(
            "request_completed",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": round(duration_ms, 2),
            },
        )
        await asyncio.to_thread(
            _record_request_duration,
            request_id=request_id,
            path=request.url.path,
            method=request.method,
            status_code=response.status_code,
            duration_ms=duration_ms,
        )
        return response


# Attach security headers middleware
app.add_middleware(SecurityHeadersMiddleware)

# Attach TrustedHostMiddleware if configured
if settings.TRUSTED_HOSTS:
    trusted = settings.TRUSTED_HOSTS if isinstance(settings.TRUSTED_HOSTS, list) else [settings.TRUSTED_HOSTS]
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=trusted)

# Attach CORS middleware configuration
if settings.CORS_ORIGINS:
    origins = settings.CORS_ORIGINS if isinstance(settings.CORS_ORIGINS, list) else [settings.CORS_ORIGINS]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Include health check directly at /health as well as under /api/v1/health
app.include_router(health.router)
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/", tags=["Root"])
def root_redirect():
    """Root landing endpoint providing API status and metadata."""
    return {
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "docs_url": f"{settings.API_V1_STR}/docs" if settings.ENABLE_API_DOCS else None,
        "health_url": "/health",
    }
