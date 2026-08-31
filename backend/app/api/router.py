"""Aggregated API router for RepoLens."""

from fastapi import APIRouter
from app.api.routes import change_analysis, deliveries, findings, health, patches, review_publication, scans

api_router = APIRouter()

# Include health routes under /api/v1 as well as root
api_router.include_router(health.router)
api_router.include_router(scans.router)
api_router.include_router(findings.router)
api_router.include_router(patches.router)
api_router.include_router(deliveries.router)
api_router.include_router(change_analysis.router)
api_router.include_router(review_publication.router)


