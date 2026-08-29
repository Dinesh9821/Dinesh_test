"""Service health, liveness, and readiness probes."""

from fastapi.testclient import TestClient

from network_api import SERVICE_NAME, SERVICE_VERSION, app


def test_root_health() -> None:
    with TestClient(app) as client:
        response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "healthy"
    assert body["service"] == SERVICE_NAME
    assert body["version"] == SERVICE_VERSION
    assert "X-Request-ID" in response.headers


def test_liveness() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/health/liveness")
    assert response.status_code == 200
    assert response.json()["status"] == "alive"


def test_readiness() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/health/readiness")
    assert response.status_code == 200
    assert response.json()["status"] == "ready"


def test_openapi_and_docs_available() -> None:
    with TestClient(app) as client:
        openapi = client.get("/openapi.json")
        docs = client.get("/docs")
        redoc = client.get("/redoc")
    assert openapi.status_code == 200
    assert "paths" in openapi.json()
    assert "/api/v1/device/summary" in openapi.json()["paths"]
    assert docs.status_code == 200
    assert redoc.status_code == 200
