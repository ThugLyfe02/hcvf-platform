from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app


def _headers() -> dict[str, str]:
    return {settings.api_key_header: settings.hcvf_api_keys[0]}


def _create_campaign(client: TestClient, name: str) -> dict:
    response = client.post(
        "/api/v1/campaigns",
        headers=_headers(),
        json={
            "name": name,
            "target_url": "http://127.0.0.1:8001/",
            "authorization_attested": True,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_campaign_creation_via_api() -> None:
    with TestClient(app) as client:
        campaign = _create_campaign(client, "campaign-flow-create")

    assert campaign["name"] == "campaign-flow-create"
    assert campaign["authorization_attested"] is True
    assert campaign["status"] == "draft"


def test_campaign_listing_via_api() -> None:
    with TestClient(app) as client:
        created = _create_campaign(client, "campaign-flow-list")
        response = client.get("/api/v1/campaigns", headers=_headers())

    assert response.status_code == 200, response.text
    campaigns = response.json()
    assert any(campaign["id"] == created["id"] for campaign in campaigns)


def test_campaign_cancellation_via_api() -> None:
    with TestClient(app) as client:
        created = _create_campaign(client, "campaign-flow-cancel")
        response = client.post(
            f"/api/v1/campaigns/{created['id']}/cancel",
            headers=_headers(),
        )

    assert response.status_code == 200, response.text
    campaign = response.json()
    assert campaign["id"] == created["id"]
    assert campaign["status"] == "cancelled"
