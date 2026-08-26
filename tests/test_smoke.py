from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app


def test_health_endpoint_returns_200() -> None:
    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] in {"ok", "degraded"}


def test_metrics_endpoint_returns_200() -> None:
    with TestClient(app) as client:
        response = client.get("/metrics")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "# HELP" in response.text or "# TYPE" in response.text


def test_api_root_is_reachable() -> None:
    with TestClient(app) as client:
        response = client.get("/")

    assert response.status_code == 200
    payload = response.json()
    assert payload == {"service": "hcvf", "status": "ok"}
    assert response.headers.get("x-request-id")
