from __future__ import annotations

from uuid import UUID, uuid4

from fastapi.testclient import TestClient

from app.core.config import settings
from app.db.session import SessionLocal
from app.main import app
from app.models import Campaign, Finding, Run, RunStatus


def _headers() -> dict[str, str]:
    return {settings.api_key_header: settings.api_keys[0]}


def test_run_and_finding_flow() -> None:
    campaign_name = f"run-flow-{uuid4()}"

    with TestClient(app) as client:
        create_response = client.post(
            "/api/v1/campaigns",
            headers=_headers(),
            json={
                "name": campaign_name,
                "target_url": "http://127.0.0.1:8001/",
                "authorization_attested": True,
            },
        )
        assert create_response.status_code == 201, create_response.text
        campaign_id = UUID(create_response.json()["id"])

        with SessionLocal() as db:
            campaign = db.get(Campaign, campaign_id)
            assert campaign is not None
            run = Run(campaign_id=campaign.id, status=RunStatus.completed, http_status=200)
            db.add(run)
            db.flush()
            finding = Finding(
                run_id=run.id,
                kind="test_finding",
                severity="info",
                title="Test finding",
                detail="Deterministic run flow finding",
                evidence={"source": "test"},
            )
            db.add(finding)
            db.commit()
            run_id = run.id
            finding_id = finding.id

        list_runs_response = client.get(
            f"/api/v1/campaigns/{campaign_id}/runs",
            headers=_headers(),
        )
        assert list_runs_response.status_code == 200, list_runs_response.text
        assert any(item["id"] == str(run_id) for item in list_runs_response.json())

        get_run_response = client.get(
            f"/api/v1/campaigns/{campaign_id}/runs/{run_id}",
            headers=_headers(),
        )
        assert get_run_response.status_code == 200, get_run_response.text
        assert get_run_response.json()["id"] == str(run_id)
        assert get_run_response.json()["status"] == "completed"

        list_findings_response = client.get(
            f"/api/v1/campaigns/{campaign_id}/runs/{run_id}/findings",
            headers=_headers(),
        )
        assert list_findings_response.status_code == 200, list_findings_response.text
        assert any(item["id"] == str(finding_id) for item in list_findings_response.json())

        get_finding_response = client.get(
            f"/api/v1/campaigns/{campaign_id}/runs/{run_id}/findings/{finding_id}",
            headers=_headers(),
        )
        assert get_finding_response.status_code == 200, get_finding_response.text
        finding_payload = get_finding_response.json()
        assert finding_payload["id"] == str(finding_id)
        assert finding_payload["kind"] == "test_finding"
        assert finding_payload["detail"] == "Deterministic run flow finding"
