"""Health check and service status endpoints."""

from typing import Any, Dict
from fastapi import APIRouter, Depends, status
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.core.config import get_settings
from app.core.database import get_db

router = APIRouter(tags=["Health"])
settings = get_settings()


@router.get(
    "/health",
    status_code=status.HTTP_200_OK,
    summary="Health check endpoint",
    description="Validates that the API service is active and the database connection is healthy.",
    response_model=Dict[str, Any],
)
def check_health(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Execute database ping and return health status."""
    db_status = "connected"
    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:
        db_status = f"unhealthy: {str(exc)}"

    return {
        "status": "healthy" if db_status == "connected" else "degraded",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "database": db_status,
    }
