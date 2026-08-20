"""Aggregated API router for RepoLens."""

from fastapi import APIRouter
from app.api.routes import health, scans

api_router = APIRouter()

# Include health routes under /api/v1 as well as root
api_router.include_router(health.router)
api_router.include_router(scans.router)

