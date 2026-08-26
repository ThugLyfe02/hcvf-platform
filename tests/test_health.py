from fastapi.testclient import TestClient

from app.main import app


def test_health_reports_dependencies_healthy() -> None:
    with TestClient(app) as client:
        response = client.get("/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["checks"] == {"postgres": True, "redis": True}
