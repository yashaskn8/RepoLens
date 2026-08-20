"""Tests for the backend health check endpoints."""

from fastapi.testclient import TestClient


def test_root_endpoint(client: TestClient):
    """Verify GET / returns basic service info and status."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "RepoLens"
    assert data["version"] == "0.1.0"
    assert "health_url" in data


def test_health_endpoint_root(client: TestClient):
    """Verify GET /health returns healthy status and DB connection."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "RepoLens"
    assert data["database"] == "connected"
    assert data["version"] == "0.1.0"


def test_health_endpoint_api_v1(client: TestClient):
    """Verify GET /api/v1/health returns matching healthy status."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "RepoLens"
    assert data["database"] == "connected"
