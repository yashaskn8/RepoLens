from datetime import datetime, timezone
import logging
import os
import tempfile
from typing import Any, Dict, List
from fastapi import APIRouter, Depends, status
from sqlalchemy import func, text
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

from app.core.config import get_settings
from app.core.database import get_db
from app.models.finding import FindingModel
from app.models.patch import PatchModel
from app.models.scan import ScanModel
from app.models.workflow_event import WorkflowEventModel
from app.schemas.enums import PatchStatus, ScanStatus
from app.schemas.telemetry import (
    MetricsTelemetry,
    ProviderTelemetry,
    StorageTelemetry,
    TelemetryReport,
)

router = APIRouter(prefix="/health", tags=["Health & Telemetry"])
settings = get_settings()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@router.get(
    "",
    status_code=status.HTTP_200_OK,
    summary="Health check endpoint",
    description="Validates that the API service is active and the database connection is healthy.",
    response_model=Dict[str, Any],
)
def check_health(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Execute database ping and return basic health status."""
    db_status = "connected"
    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:
        logger.error(f"Database health check failed: {exc}", exc_info=True)
        db_status = "unhealthy"

    from app.core.redis import get_redis_manager
    redis_mgr = get_redis_manager()
    if not redis_mgr.is_configured:
        redis_status = "disabled"
    elif redis_mgr.is_available:
        redis_status = "connected"
    else:
        redis_status = "degraded"

    return {
        "status": "healthy" if db_status == "connected" else "degraded",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "database": db_status,
        "redis": redis_status,
        "timestamp": _utc_now().isoformat(),
    }


def _build_telemetry_report(db: Session) -> TelemetryReport:
    """Collect and assemble comprehensive operational telemetry without leaking credentials or host paths."""
    # 1. Database check
    db_status = "connected"
    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:
        logger.error(f"Database telemetry check failed: {exc}", exc_info=True)
        db_status = "unhealthy"

    # 2. Providers configuration telemetry (booleans only, never keys)
    providers = [
        ProviderTelemetry(
            provider="gemini",
            configured=bool(settings.GEMINI_API_KEY and settings.GEMINI_API_KEY.strip()),
            default_model=settings.MODEL_ARCHITECTURE,
        ),
        ProviderTelemetry(
            provider="groq",
            configured=bool(settings.GROQ_API_KEY and settings.GROQ_API_KEY.strip()),
            default_model=settings.MODEL_BUG_REASONING,
        ),
        ProviderTelemetry(
            provider="nvidia",
            configured=bool(settings.NVIDIA_API_KEY and settings.NVIDIA_API_KEY.strip()),
            default_model=settings.MODEL_VERIFICATION,
        ),
        ProviderTelemetry(
            provider="huggingface",
            configured=bool(settings.HUGGINGFACE_API_KEY and settings.HUGGINGFACE_API_KEY.strip()),
            default_model=settings.MODEL_INTEGRATION_CODE,
        ),
        ProviderTelemetry(
            provider="cloudflare",
            configured=bool(settings.CLOUDFLARE_API_TOKEN and settings.CLOUDFLARE_API_TOKEN.strip()),
            default_model=settings.CLOUDFLARE_DEFAULT_MODEL,
        ),
        ProviderTelemetry(
            provider="mistral",
            configured=bool(settings.MISTRAL_API_KEY and settings.MISTRAL_API_KEY.strip()),
            default_model=settings.MISTRAL_DEFAULT_MODEL,
        ),
        ProviderTelemetry(
            provider="cohere",
            configured=bool(settings.COHERE_API_KEY and settings.COHERE_API_KEY.strip()),
            default_model=settings.COHERE_RERANK_MODEL,
        ),
        ProviderTelemetry(
            provider="openrouter",
            configured=bool(settings.OPENROUTER_API_KEY and settings.OPENROUTER_API_KEY.strip()),
            default_model=settings.OPENROUTER_DEFAULT_MODEL,
        ),
        ProviderTelemetry(
            provider="github",
            configured=bool(settings.GITHUB_DELIVERY_ENABLED and settings.GITHUB_TOKEN and settings.GITHUB_TOKEN.strip()),
            default_model="github-git-data-api",
        ),
    ]

    # 3. Storage filesystem capability (booleans only, no host paths)
    temp_dir = tempfile.gettempdir()
    snapshot_writable = os.access(temp_dir, os.W_OK)
    checkpointer_path = getattr(settings, "CHECKPOINTER_DB_PATH", "repolens_checkpoints.db")
    checkpointer_dir = os.path.dirname(os.path.abspath(checkpointer_path)) or "."
    checkpointer_accessible = os.access(checkpointer_dir, os.W_OK)

    storage = StorageTelemetry(
        snapshot_storage_writable=snapshot_writable,
        checkpointer_storage_accessible=checkpointer_accessible,
    )

    # 4. Metrics aggregation
    metrics = MetricsTelemetry()
    try:
        from app.models.delivery import DeliveryModel
        from app.schemas.enums import DeliveryStatus

        metrics.total_scans = db.query(func.count(ScanModel.id)).scalar() or 0
        metrics.completed_scans = db.query(func.count(ScanModel.id)).filter(ScanModel.status == ScanStatus.COMPLETED.value).scalar() or 0
        metrics.failed_scans = db.query(func.count(ScanModel.id)).filter(ScanModel.status == ScanStatus.FAILED.value).scalar() or 0
        metrics.running_scans = db.query(func.count(ScanModel.id)).filter(ScanModel.status == ScanStatus.RUNNING.value).scalar() or 0
        metrics.pending_scans = db.query(func.count(ScanModel.id)).filter(ScanModel.status == ScanStatus.PENDING.value).scalar() or 0

        metrics.total_findings = db.query(func.count(FindingModel.id)).scalar() or 0
        metrics.total_patches = db.query(func.count(PatchModel.id)).scalar() or 0
        metrics.approved_patches = db.query(func.count(PatchModel.id)).filter(PatchModel.status == PatchStatus.APPROVED.value).scalar() or 0
        metrics.rejected_patches = db.query(func.count(PatchModel.id)).filter(PatchModel.status == PatchStatus.REJECTED.value).scalar() or 0

        metrics.total_deliveries = db.query(func.count(DeliveryModel.id)).scalar() or 0
        metrics.pull_requests_created = db.query(func.count(DeliveryModel.id)).filter(DeliveryModel.status == DeliveryStatus.PR_CREATED.value).scalar() or 0

        metrics.total_workflow_events = db.query(func.count(WorkflowEventModel.id)).scalar() or 0
    except Exception as exc:
        logger.warning(f"Error querying telemetry metrics: {str(exc)}")

    overall_status = "healthy" if db_status == "connected" and snapshot_writable else "degraded"

    from app.core.redis import get_redis_manager
    redis_mgr = get_redis_manager()
    if not redis_mgr.is_configured:
        redis_status = "disabled"
    elif redis_mgr.is_available:
        redis_status = "connected"
    else:
        redis_status = "degraded"

    return TelemetryReport(
        service=settings.PROJECT_NAME,
        version=settings.VERSION,
        status=overall_status,
        environment=settings.ENVIRONMENT,
        database=db_status,
        redis=redis_status,
        providers=providers,
        storage=storage,
        metrics=metrics,
        timestamp=_utc_now(),
    )


@router.get(
    "/detailed",
    status_code=status.HTTP_200_OK,
    summary="Detailed system telemetry endpoint",
    description="Returns comprehensive system observability metrics, database status, provider availability, and storage health.",
    response_model=TelemetryReport,
)
def get_detailed_health(db: Session = Depends(get_db)) -> TelemetryReport:
    """Retrieve complete system observability telemetry."""
    return _build_telemetry_report(db)


@router.get(
    "/telemetry",
    status_code=status.HTTP_200_OK,
    summary="API Telemetry endpoint",
    description="Operational telemetry and observability monitoring endpoint.",
    response_model=TelemetryReport,
)
def get_api_telemetry(db: Session = Depends(get_db)) -> TelemetryReport:
    """Retrieve operational telemetry."""
    return _build_telemetry_report(db)

