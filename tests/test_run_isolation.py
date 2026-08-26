from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.security import hash_api_key
from app.db.session import SessionLocal
from app.main import app
from app.models import Campaign, Run, RunStatus, Tenant


def test_tenant_cannot_access_another_tenants_run() -> None:
    other_api_key = f"other-tenant-{uuid4()}"

    with SessionLocal() as db:
        other_tenant = Tenant(
            name=f"run-isolation-{uuid4()}",
            api_key_hash=hash_api_key(other_api_key),
            authorized_targets=["http://127.0.0.1:8001"],
        )
        db.add(other_tenant)
        db.flush()

        campaign = Campaign(
            tenant_id=other_tenant.id,
            name=f"isolated-campaign-{uuid4()}",
            target_url="http://127.0.0.1:8001/",
            authorization_attested=True,
        )
        db.add(campaign)
        db.flush()

        run = Run(campaign_id=campaign.id, status=RunStatus.completed, http_status=200)
        db.add(run)
        db.commit()

        campaign_id = campaign.id
        run_id = run.id

    with TestClient(app) as client:
        response = client.get(
            f"/api/v1/campaigns/{campaign_id}/runs/{run_id}",
            headers={settings.api_key_header: settings.api_keys[0]},
        )

    assert response.status_code == 404
    assert response.json()["detail"] == "Run not found"
