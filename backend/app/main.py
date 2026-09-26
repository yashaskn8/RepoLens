"""RepoLens FastAPI application entry point with production security hardening."""

from __future__ import annotations

from contextlib import asynccontextmanager
import asyncio
import inspect as inspect_module
import logging
import re
import time
import uuid
from typing import Any, Callable

from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# Run this before importing routers or the SQLAlchemy engine. Missing production
# database/checkpointer packages therefore fail through a bounded CLI-safe error.
from app.cli.production_preflight import require_production_dependencies

require_production_dependencies(settings)


def _validate_production_configuration(config: Any | None = None) -> None:
    """Validate database/checkpointer and HTTP security configuration early."""
    active_settings = config or settings
    if not active_settings.is_production:
        return
    if active_settings.is_sqlite:
        raise RuntimeError("Production execution authority requires PostgreSQL.") from None
    if not active_settings.AUTH_COOKIE_SECURE:
        raise RuntimeError("Production AUTH_COOKIE_SECURE must be enabled.") from None
    cors = active_settings.CORS_ORIGINS
    hosts = active_settings.TRUSTED_HOSTS
    if not cors or any("*" in origin for origin in cors):
        raise RuntimeError("Production CORS_ORIGINS must be explicit and non-wildcard.") from None
    if not hosts or any("*" in host for host in hosts):
        raise RuntimeError("Production TRUSTED_HOSTS must be explicit and non-wildcard.") from None

    from app.agents.checkpointer import CheckpointBackend, resolve_checkpoint_backend

    try:
        selected = resolve_checkpoint_backend(active_settings)
    except Exception:
        raise RuntimeError("Production PostgreSQL checkpointer configuration is invalid.") from None
    if selected != CheckpointBackend.POSTGRES:
        raise RuntimeError("Production LangGraph execution requires PostgreSQL checkpointing.") from None


_validate_production_configuration()

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api.router import api_router
from app.api.errors import http_exception_handler, validation_exception_handler
from app.api.routes import health
from app.core.database import engine


async def _run_startup_cleanup(actions: list[Callable[[], Any]]) -> None:
    """Release partially initialized runtime resources in reverse order."""
    for action in reversed(actions):
        try:
            result = action()
            if inspect_module.isawaitable(result):
                await result
        except Exception as exc:
            logger.warning("Startup cleanup degraded (%s).", type(exc).__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Validate production authorities before starting optional services/workers."""
    from sqlalchemy import inspect as sqlalchemy_inspect

    import app.models
    from app.agents.checkpointer import validate_analysis_checkpointer_ready
    from app.artifacts.runtime import ArtifactLifecycleRuntime
    from app.core.database import SessionLocal
    from app.core.production_readiness import (
        validate_production_artifact_storage,
        validate_production_database_schema,
    )
    from app.execution.dispatcher import DurableWorkDispatcher
    from app.governance.outbox import RelationalOutboxRelay
    from app.llm.router import configure_persistent_llm_router
    from app.observability import (
        configure_metrics,
        configure_tracing,
        shutdown_metrics,
        shutdown_tracing,
    )

    cleanup_actions: list[Callable[[], Any]] = []
    production = settings.is_production
    try:
        if production:
            require_production_dependencies(settings)
            _validate_production_configuration(settings)
            validate_production_database_schema(SessionLocal)
            await asyncio.wait_for(
                validate_analysis_checkpointer_ready(),
                timeout=settings.DATABASE_POOL_TIMEOUT_SECONDS,
            )
            validate_production_artifact_storage(settings)
            from app.core.schema_readiness import required_application_tables

            available_tables = set(required_application_tables())
        else:
            available_tables = set(sqlalchemy_inspect(engine).get_table_names())
    except Exception as exc:
        await _run_startup_cleanup(cleanup_actions)
        if production:
            logger.error("Production authority validation failed (%s).", type(exc).__name__)
            raise RuntimeError("Production startup authority validation failed.") from None
        raise

    # Telemetry is optional; an unavailable exporter must not block production.
    cleanup_actions.extend([shutdown_tracing, shutdown_metrics])
    try:
        configure_tracing(settings)
    except Exception as exc:
        logger.warning("Optional tracing initialization degraded (%s).", type(exc).__name__)
    try:
        configure_metrics(settings)
    except Exception as exc:
        logger.warning("Optional metrics initialization degraded (%s).", type(exc).__name__)

    # Redis is explicitly optional and degrades to cache-disabled operation.
    redis_mgr = None
    try:
        from app.core.redis import get_redis_manager

        redis_mgr = get_redis_manager()
        cleanup_actions.append(redis_mgr.close)
        await redis_mgr.initialize()
    except Exception as exc:
        logger.warning("Optional Redis initialization degraded (%s).", type(exc).__name__)

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
            cleanup_actions.append(DurableWorkDispatcher.stop)
            DurableWorkDispatcher.start()
        if "outbox_events" in available_tables:
            cleanup_actions.append(RelationalOutboxRelay.stop)
            RelationalOutboxRelay.start()
        if "artifact_tombstones" in available_tables:
            cleanup_actions.append(ArtifactLifecycleRuntime.stop)
            ArtifactLifecycleRuntime.start()
    except Exception as exc:
        await _run_startup_cleanup(cleanup_actions)
        cleanup_actions = []
        if production:
            logger.error("Production runtime initialization failed (%s).", type(exc).__name__)
            raise RuntimeError("Production runtime initialization failed.") from None
        logger.warning("Optional development runtime initialization degraded (%s).", type(exc).__name__)

    try:
        yield
    finally:
        await _run_startup_cleanup(cleanup_actions)


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
        is_process_only_liveness = request.url.path.endswith("/health/live")
        if is_process_only_liveness:
            # Liveness must remain local/process-only even when an OTLP exporter
            # is enabled; do not create spans or metrics that can enqueue exports.
            response: Response = await call_next(request)
            request.state.trace_headers = {}
        else:
            from app.observability import extract_trace_context, span
            from opentelemetry.trace import SpanKind

            trace_headers = extract_trace_context(request.headers)
            request.state.trace_headers = trace_headers
            with span(
                "HTTP request",
                attributes={"http.request.method": request.method, "http.request.id": request_id},
                parent_headers=trace_headers,
                kind=SpanKind.SERVER,
            ) as request_span:
                response = await call_next(request)
                request_span.set_attribute("http.response.status_code", response.status_code)
        duration_ms = max(0.0, (time.monotonic() - started) * 1000.0)
        if not is_process_only_liveness:
            try:
                from app.observability import record_metric

                method = request.method if request.method in {
                    "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"
                } else "UNKNOWN"
                status_class = f"{response.status_code // 100}xx" if 100 <= response.status_code <= 599 else "unknown"
                record_metric(
                    "http.server.request.duration",
                    duration_ms / 1000.0,
                    {
                        "http.request.method": method,
                        "http.response.status_class": status_class,
                    },
                )
            except Exception:
                # Metric/exporter failures never affect the HTTP response.
                pass
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
        if not is_process_only_liveness:
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
