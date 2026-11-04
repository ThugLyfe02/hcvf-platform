"""PostgreSQL RLS isolation gate.

Runs only when the CI job has enabled the policies and set HCVF_RLS_ENABLED,
so the portable suite stays runnable on SQLite.

The assertions are deliberately adversarial: a second tenant must not be able to
list or fetch the first tenant's campaign, and a raw connection with no tenant
context must see zero rows. The last check is what distinguishes "the query has a
WHERE clause" from "the database enforces it".
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

pytestmark = pytest.mark.skipif(
    os.environ.get("HCVF_RLS_ENABLED", "").lower() != "true",
    reason="RLS policies are not enabled in this environment",
)

API = {"X-API-Key": os.environ.get("HCVF_API_KEYS", "dev-hcvf-key").split(",")[0].strip()}


def _tenant(client: TestClient, name: str, target: str) -> dict:
    response = client.post(
        "/api/v1/tenants",
        headers=API,
        json={"name": name, "authorized_targets": [target]},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_tenant_isolation_under_rls() -> None:
    from app.main import app

    with TestClient(app) as client:
        tenant_a = _tenant(client, "rls-tenant-a", "https://a.example.test")
        tenant_b = _tenant(client, "rls-tenant-b", "https://b.example.test")
        headers_a = {"X-API-Key": tenant_a["api_key"]}
        headers_b = {"X-API-Key": tenant_b["api_key"]}

        created = client.post(
            "/api/v1/campaigns",
            headers=headers_a,
            json={
                "name": "rls-campaign",
                "target_url": "https://a.example.test/",
                "authorization_attested": True,
                "budget_requests": 10,
            },
        )
        assert created.status_code in {200, 201}, created.text
        campaign_id = created.json()["id"]

        visible = client.get("/api/v1/campaigns", headers=headers_a)
        assert visible.status_code == 200
        assert any(item["id"] == campaign_id for item in visible.json()), visible.text

        hidden = client.get("/api/v1/campaigns", headers=headers_b)
        assert hidden.status_code == 200
        assert all(item["id"] != campaign_id for item in hidden.json()), hidden.text

        direct = client.get(f"/api/v1/campaigns/{campaign_id}", headers=headers_b)
        assert direct.status_code == 404, direct.text

    from app.db.session import engine

    with engine.connect() as connection:
        count = connection.execute(text("SELECT count(*) FROM campaigns")).scalar()
    assert count == 0, "RLS is not enforcing: an unbound connection saw campaign rows"
