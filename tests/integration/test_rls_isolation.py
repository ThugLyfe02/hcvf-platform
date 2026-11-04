"""PostgreSQL RLS isolation gate.

Runs only when the CI job has enabled the policies, created the non-superuser
role and set HCVF_RLS_ENABLED, so the portable suite stays runnable on SQLite.

Two layers are proven:

1. the API's query layer still isolates tenants (functional check through HTTP);
2. PostgreSQL enforces isolation itself when the connection is *not* a
   superuser/owner: an unbound connection sees zero rows, a connection bound to
   tenant A sees A's campaign, and a connection bound to B cannot read or insert
   A's rows.

The database-role checks are the ones that prove RLS; the HTTP checks prove the
application binds the GUC correctly.
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

pytestmark = pytest.mark.skipif(
    os.environ.get("HCVF_RLS_ENABLED", "").lower() != "true",
    reason="RLS policies are not enabled in this environment",
)

API = {"X-API-Key": os.environ.get("HCVF_API_KEYS", "dev-hcvf-key").split(",")[0].strip()}
RLS_URL = os.environ.get(
    "RLS_DATABASE_URL",
    "postgresql+psycopg://hcvf_rls:rls-password@localhost:5432/hcvf",
)


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

    # -- database-level proof with a role the policies actually constrain ----
    role_engine = create_engine(RLS_URL, pool_pre_ping=True)
    try:
        with role_engine.connect() as connection:
            unbound = connection.execute(text("SELECT count(*) FROM campaigns")).scalar()
            assert unbound == 0, "RLS is not enforcing: an unbound non-owner connection saw rows"

        with role_engine.connect() as connection:
            transaction = connection.begin()
            connection.execute(text("SELECT set_config('app.tenant_id', :tid, true)"), {"tid": tenant_a["id"]})
            seen = connection.execute(text("SELECT count(*) FROM campaigns")).scalar()
            assert seen >= 1, "RLS hid the tenant's own rows"
            transaction.rollback()

        with role_engine.connect() as connection:
            transaction = connection.begin()
            connection.execute(text("SELECT set_config('app.tenant_id', :tid, true)"), {"tid": tenant_b["id"]})
            other = connection.execute(text("SELECT count(*) FROM campaigns")).scalar()
            assert other == 0, "RLS leaked another tenant's campaigns"
            with pytest.raises(DBAPIError):
                connection.execute(
                    text(
                        "INSERT INTO campaigns "
                        "(id, tenant_id, name, target_url, authorization_attested, status, "
                        "safety_ceiling, budget_requests, mode, origin, genome, created_at, updated_at) "
                        "VALUES (gen_random_uuid(), :tid, 'forged', 'https://a.example.test', true, "
                        "'draft', 'read_only', 10, 'agentic', 'manual', '{}', now(), now())"
                    ),
                    {"tid": tenant_a["id"]},
                )
            transaction.rollback()
    finally:
        role_engine.dispose()
