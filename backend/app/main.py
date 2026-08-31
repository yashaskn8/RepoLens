"""RepoLens FastAPI application entry point with production security hardening."""

from contextlib import asynccontextmanager
import logging
import uuid
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api.router import api_router
from app.api.routes import health
from app.core.config import get_settings
from app.core.database import Base, engine

logger = logging.getLogger(__name__)
settings = get_settings()


def _validate_production_configuration() -> None:
    """Validate critical security settings in production environments."""
    if settings.is_production:
        if isinstance(settings.CORS_ORIGINS, list) and "*" in settings.CORS_ORIGINS:
            raise RuntimeError("CRITICAL SECURITY ERROR: Wildcard CORS origin ('*') is prohibited in production.")
        if isinstance(settings.TRUSTED_HOSTS, list) and "*" in settings.TRUSTED_HOSTS:
            raise RuntimeError("CRITICAL SECURITY ERROR: Wildcard Trusted Hosts ('*') is prohibited in production.")


_validate_production_configuration()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle events handler: startup recovery and graceful shutdown."""
    # 1. Startup: discover and dispatch unfinished scans without blocking startup
    from app.core.database import Base, SessionLocal, engine
    import app.models
    from app.services.scan_recovery import ScanDispatcher, ScanRecoveryService

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        recovered = ScanRecoveryService.recover_unfinished_scans(db)
        if recovered:
            logger.info(f"Startup recovery: dispatched {len(recovered)} unfinished scans ({recovered})")
    except Exception as exc:
        logger.error(f"Failed to run startup scan recovery: {str(exc)}", exc_info=True)
    finally:
        db.close()

    yield

    # 2. Shutdown: gracefully cancel active task wrappers without corrupting checkpoints
    ScanDispatcher.cancel_all_active_scans()


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


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware attaching standard defensive HTTP security headers to all responses."""

    async def dispatch(self, request: Request, call_next):
        # Generate or preserve X-Request-ID
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        response: Response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        if settings.AUTH_COOKIE_SECURE or settings.is_production:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
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
