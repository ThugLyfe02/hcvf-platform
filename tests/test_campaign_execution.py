from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.db.session import SessionLocal
from app.models.audit import AuditLog
from app.models.campaign import CampaignStatus
from app.models.finding import Finding
from app.models.run import RunStatus
from worker.pipeline import CampaignPipeline


def test_campaign_executes_end_to_end_and_persists_findings(
    client: TestClient,
    auth_headers: dict[str, str],
    authorized_target_url: str,
) -> None:
    create_headers = {**auth_headers, "X-Request-ID": "campaign-create-request"}
    create_response = client.post(
        "/api/v1/campaigns",
        headers=create_headers,
        json={
            "name": "Local authorized validation",
            "target_url": authorized_target_url,
            "authorization_reference": "TEST-AUTHORIZATION-001",
            "config": {"probe_values": ["ok", "trigger-500"]},
        },
    )

    assert create_response.status_code == 201, create_response.text
    campaign_id = create_response.json()["id"]
    assert create_response.json()["status"] == CampaignStatus.CREATED.value

    execute_response = client.post(
        f"/api/v1/campaigns/{campaign_id}/execute",
        headers={**auth_headers, "X-Request-ID": "campaign-execute-request"},
    )

    assert execute_response.status_code == 202, execute_response.text
    payload = execute_response.json()
    assert payload["campaign"]["status"] == CampaignStatus.COMPLETED.value
    assert payload["run"]["status"] == RunStatus.COMPLETED.value
    assert payload["run"]["summary"]["cases_executed"] == 3
    assert payload["run"]["summary"]["finding_count"] == 2
    assert payload["run"]["celery_task_id"]

    replay_result = CampaignPipeline(
        run_id=payload["run"]["id"],
        task_id=payload["run"]["celery_task_id"],
    ).execute()
    assert replay_result["status"] == RunStatus.COMPLETED.value

    findings_response = client.get(
        f"/api/v1/campaigns/{campaign_id}/findings",
        headers=auth_headers,
    )
    assert findings_response.status_code == 200
    findings = findings_response.json()
    assert {finding["category"] for finding in findings} == {
        "http_server_error",
        "http_status_variance",
    }
    assert any(finding["severity"] == "high" for finding in findings)

    runs_response = client.get(
        f"/api/v1/campaigns/{campaign_id}/runs",
        headers=auth_headers,
    )
    assert runs_response.status_code == 200
    assert len(runs_response.json()) == 1

    with SessionLocal() as db:
        actions = list(db.scalars(select(AuditLog.action).order_by(AuditLog.id)))
        request_ids = set(db.scalars(select(AuditLog.request_id)))
        finding_count = db.scalar(select(func.count(Finding.id)))

    assert finding_count == 2
    assert actions.count("campaign.run_completed") == 1
    assert "campaign.created" in actions
    assert "campaign.execution_requested" in actions
    assert "campaign.run_started" in actions
    assert "campaign.run_completed" in actions
    assert "campaign-create-request" in request_ids
    assert "campaign-execute-request" in request_ids


def test_campaign_requires_authentication(
    client: TestClient,
    authorized_target_url: str,
) -> None:
    response = client.post(
        "/api/v1/campaigns",
        json={
            "name": "Unauthorized request",
            "target_url": authorized_target_url,
            "authorization_reference": "TEST-AUTHORIZATION-002",
        },
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"
