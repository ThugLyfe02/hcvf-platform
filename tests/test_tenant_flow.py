from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app


def _headers() -> dict[str, str]:
    return {settings.api_key_header: settings.api_keys[0]}


def test_tenant_creation_listing_retrieval_and_update() -> None:
    tenant_name = f"tenant-flow-{uuid4()}"
    with TestClient(app) as client:
        create_response = client.post(
            "/api/v1/tenants",
            headers=_headers(),
            json={
                "name": tenant_name,
                "authorized_targets": ["https://owned.example.test", "https://api.owned.example.test"],
            },
        )
        assert create_response.status_code == 201, create_response.text
        created = create_response.json()
        assert created["name"] == tenant_name
        assert created["api_key"]
        tenant_id = created["id"]

        list_response = client.get("/api/v1/tenants", headers=_headers())
        assert list_response.status_code == 200, list_response.text
        assert any(tenant["id"] == tenant_id for tenant in list_response.json())

        get_response = client.get(f"/api/v1/tenants/{tenant_id}", headers=_headers())
        assert get_response.status_code == 200, get_response.text
        assert get_response.json()["id"] == tenant_id

        update_response = client.patch(
            f"/api/v1/tenants/{tenant_id}",
            headers=_headers(),
            json={"authorized_targets": ["https://updated.example.test"]},
        )
        assert update_response.status_code == 200, update_response.text
        assert update_response.json()["authorized_targets"] == ["https://updated.example.test"]
