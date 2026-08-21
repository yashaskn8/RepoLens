"""RepoLens FastAPI application entry point."""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.router import api_router
from app.api.routes import health
from app.core.config import get_settings
from app.core.database import Base, engine

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle events handler: startup recovery and graceful shutdown."""
    # 1. Startup: discover and dispatch unfinished scans without blocking startup
    from app.core.database import SessionLocal
    from app.services.scan_recovery import ScanDispatcher, ScanRecoveryService

    db = SessionLocal()
    try:
        recovered = ScanRecoveryService.recover_unfinished_scans(db)
        if recovered:
            import logging
            logging.getLogger(__name__).info(f"Startup recovery: dispatched {len(recovered)} unfinished scans ({recovered})")
    except Exception as exc:
        import logging
        logging.getLogger(__name__).error(f"Failed to run startup scan recovery: {str(exc)}", exc_info=True)
    finally:
        db.close()

    yield

    # 2. Shutdown: gracefully cancel active task wrappers without corrupting checkpoints
    ScanDispatcher.cancel_all_active_scans()


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url=f"{settings.API_V1_STR}/docs",
    redoc_url=f"{settings.API_V1_STR}/redoc",
    lifespan=lifespan,
)

# CORS middleware configuration
if settings.CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
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
        "docs_url": f"{settings.API_V1_STR}/docs",
        "health_url": "/health",
    }
