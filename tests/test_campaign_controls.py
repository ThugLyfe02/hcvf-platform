from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.session import SessionLocal
from app.models.audit import AuditLog
from worker.scheduler import dispatch_due_campaigns


def test_scheduled_campaign_can_be_cancelled_and_is_audited(
    client: TestClient,
    auth_headers: dict[str, str],
    authorized_target_url: str,
) -> None:
    schedule_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    create_response = client.post(
        "/api/v1/campaigns",
        headers=auth_headers,
        json={
            "name": "Scheduled cancellation test",
            "target_url": authorized_target_url,
            "authorization_reference": "TEST-AUTHORIZATION-CANCEL",
            "schedule_at": schedule_at,
        },
    )
    assert create_response.status_code == 201, create_response.text
    campaign_id = create_response.json()["id"]

    cancel_response = client.post(
        f"/api/v1/campaigns/{campaign_id}/cancel",
        headers={**auth_headers, "X-Request-ID": "campaign-cancel-request"},
    )
    assert cancel_response.status_code == 200, cancel_response.text
    assert cancel_response.json()["campaign"]["status"] == "cancelled"
    assert cancel_response.json()["run"] is None
    assert dispatch_due_campaigns() == 0

    with SessionLocal() as db:
        event = db.scalar(
            select(AuditLog).where(AuditLog.action == "campaign.cancelled")
        )
    assert event is not None
    assert event.request_id == "campaign-cancel-request"


def test_completed_campaign_rejects_cancellation(
    client: TestClient,
    auth_headers: dict[str, str],
    authorized_target_url: str,
) -> None:
    create_response = client.post(
        "/api/v1/campaigns",
        headers=auth_headers,
        json={
            "name": "Completed cancellation test",
            "target_url": authorized_target_url,
            "authorization_reference": "TEST-AUTHORIZATION-COMPLETE",
            "config": {"probe_values": ["ok"]},
        },
    )
    campaign_id = create_response.json()["id"]
    execute_response = client.post(
        f"/api/v1/campaigns/{campaign_id}/execute",
        headers=auth_headers,
    )
    assert execute_response.status_code == 202
    assert execute_response.json()["campaign"]["status"] == "completed"

    cancel_response = client.post(
        f"/api/v1/campaigns/{campaign_id}/cancel",
        headers=auth_headers,
    )
    assert cancel_response.status_code == 409
    assert cancel_response.json()["error"]["code"] == "campaign_not_active"


def test_public_target_is_rejected_by_default(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    response = client.post(
        "/api/v1/campaigns",
        headers=auth_headers,
        json={
            "name": "Blocked public target",
            "target_url": "https://8.8.8.8/",
            "authorization_reference": "TEST-AUTHORIZATION-POLICY",
        },
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_campaign_target"


def test_required_text_is_trimmed_before_validation(
    client: TestClient,
    auth_headers: dict[str, str],
    authorized_target_url: str,
) -> None:
    response = client.post(
        "/api/v1/campaigns",
        headers=auth_headers,
        json={
            "name": "   ",
            "target_url": authorized_target_url,
            "authorization_reference": "TEST-AUTHORIZATION-TRIM",
        },
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
