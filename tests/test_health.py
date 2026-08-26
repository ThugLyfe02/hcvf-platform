from __future__ import annotations

from fastapi.testclient import TestClient

from app.api.v1 import health


def test_liveness_and_request_id(client: TestClient) -> None:
    response = client.get(
        "/api/v1/health/live",
        headers={"X-Request-ID": "health-test-request"},
    )

    assert response.status_code == 200
    assert response.json() == {"status": "alive"}
    assert response.headers["X-Request-ID"] == "health-test-request"


def test_readiness_reports_dependency_connectivity(
    client: TestClient,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        health,
        "check_postgres",
        lambda: health.DependencyHealth(status="ok", latency_ms=0.1),
    )

    async def healthy_redis() -> health.DependencyHealth:
        return health.DependencyHealth(status="ok", latency_ms=0.2)

    monkeypatch.setattr(health, "check_redis", healthy_redis)
    response = client.get("/api/v1/health/ready")

    assert response.status_code == 200
    assert response.json()["status"] == "ready"
    assert response.json()["postgres"]["status"] == "ok"
    assert response.json()["redis"]["status"] == "ok"


def test_metrics_endpoint_exposes_hcvf_metrics(client: TestClient) -> None:
    client.get("/api/v1/health/live")
    response = client.get("/metrics")

    assert response.status_code == 200
    assert "hcvf_http_requests_total" in response.text
    assert "hcvf_campaigns_current" in response.text
    assert "hcvf_database_metrics_refresh_success 1.0" in response.text


def test_compatibility_health_endpoint(
    client: TestClient,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        health,
        "check_postgres",
        lambda: health.DependencyHealth(status="ok", latency_ms=0.1),
    )

    async def healthy_redis() -> health.DependencyHealth:
        return health.DependencyHealth(status="ok", latency_ms=0.2)

    monkeypatch.setattr(health, "check_redis", healthy_redis)
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ready"
