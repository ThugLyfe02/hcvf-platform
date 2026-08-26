from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from worker.scheduler import dispatch_due_campaigns


def test_scheduler_claims_due_campaign_and_executes_it(
    client: TestClient,
    auth_headers: dict[str, str],
    authorized_target_url: str,
) -> None:
    schedule_at = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    create_response = client.post(
        "/api/v1/campaigns",
        headers=auth_headers,
        json={
            "name": "Scheduled local validation",
            "target_url": authorized_target_url,
            "authorization_reference": "TEST-AUTHORIZATION-SCHEDULED",
            "config": {"probe_values": ["ok"]},
            "schedule_at": schedule_at,
        },
    )
    assert create_response.status_code == 201, create_response.text
    campaign_id = create_response.json()["id"]
    assert create_response.json()["status"] == "scheduled"

    assert dispatch_due_campaigns() == 1
    assert dispatch_due_campaigns() == 0

    campaign_response = client.get(
        f"/api/v1/campaigns/{campaign_id}",
        headers=auth_headers,
    )
    assert campaign_response.status_code == 200
    assert campaign_response.json()["status"] == "completed"

    runs_response = client.get(
        f"/api/v1/campaigns/{campaign_id}/runs",
        headers=auth_headers,
    )
    assert len(runs_response.json()) == 1
    assert runs_response.json()[0]["status"] == "completed"
