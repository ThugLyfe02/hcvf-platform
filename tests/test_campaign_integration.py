"""Postgres-backed end-to-end test (requires the docker compose stack).

The SQLite suite in ``tests/unit`` covers the same flow without infrastructure;
this module exists to prove the real database and JSONB/UUID types behave.
"""

from __future__ import annotations

from uuid import UUID

from fastapi.testclient import TestClient

from app.core.config import settings
from app.db.session import SessionLocal
from app.main import app
from app.models import Campaign, Finding, Run, RunStatus
from app.services.hunt_service import HuntService
from tests.fixtures.vulnerable_app import running_fixture


def test_campaign_can_be_created_and_executed_end_to_end() -> None:
    with running_fixture() as base:
        target_url = f"{base}/"
        with TestClient(app) as client:
            headers = {settings.api_key_header: settings.api_keys[0]}
            create_response = client.post(
                "/api/v1/campaigns",
                headers=headers,
                json={
                    "name": "integration campaign",
                    "target_url": target_url,
                    "authorization_attested": True,
                    "budget_requests": 60,
                },
            )
            assert create_response.status_code == 201, create_response.text
            campaign_id = UUID(create_response.json()["id"])

            execute_response = client.post(
                f"/api/v1/campaigns/{campaign_id}/execute",
                headers=headers,
            )
            assert execute_response.status_code == 202, execute_response.text
            run_id = UUID(execute_response.json()["id"])

            # Execute the outbox-dequeued run in-process: the test asserts the
            # full pipeline, not the broker.
            with SessionLocal() as db:
                HuntService(db).execute_run(run_id)

            with SessionLocal() as db:
                run = db.get(Run, run_id)
                assert run is not None
                assert run.status == RunStatus.completed, run.error_message
                assert run.http_status == 200
                assert run.evidence_root
                campaign = db.get(Campaign, campaign_id)
                assert campaign is not None
                findings = db.query(Finding).filter(Finding.run_id == run_id).all()
                assert findings, "the agentic hunt produced no findings"
                kinds = {finding.kind for finding in findings}
                assert "missing-content-security-policy" in kinds
                for finding in findings:
                    assert finding.fingerprint
                    assert 0.0 <= finding.confidence <= 1.0
                    assert finding.tenant_id is not None
