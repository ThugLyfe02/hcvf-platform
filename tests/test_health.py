from fastapi.testclient import TestClient

from app.main import app


def test_health_reports_dependency_state() -> None:
    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] in {"ok", "degraded"}
    assert set(payload["dependencies"]) == {"postgres", "redis"}
    for dependency in payload["dependencies"].values():
        assert dependency["status"] in {"ok", "down"}
        assert dependency["circuit"] in {"closed", "open", "half_open"}
