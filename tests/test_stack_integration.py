from __future__ import annotations

import os
import subprocess
import sys
import time
from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.session import SessionLocal
from app.models.audit import AuditLog
from worker.scheduler import dispatch_due_campaigns

STACK_TEST_ENABLED = os.getenv("HCVF_STACK_TEST", "").lower() in {"1", "true", "yes"}
pytestmark = pytest.mark.skipif(
    not STACK_TEST_ENABLED,
    reason="Set HCVF_STACK_TEST=true with PostgreSQL and Redis to run this test.",
)
PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def celery_worker_process(
    reset_database: None,
    tmp_path: Path,
) -> Generator[subprocess.Popen[bytes], None, None]:
    from redis import Redis

    from worker.celery_app import celery_app

    redis_url = os.environ["REDIS_URL"]
    redis_client = Redis.from_url(redis_url)
    redis_client.flushdb()
    redis_client.close()

    log_path = tmp_path / "celery-worker.log"
    log_handle = log_path.open("wb")
    environment = {**os.environ, "C_FORCE_ROOT": "true"}
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "celery",
            "-A",
            "worker.celery_app:celery_app",
            "worker",
            "--pool=solo",
            "--concurrency=1",
            "--loglevel=INFO",
            "--without-gossip",
            "--without-mingle",
            "--without-heartbeat",
            "--hostname=hcvf-stack-test@%h",
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
    )

    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if process.poll() is not None:
                log_handle.flush()
                raise AssertionError(
                    "Celery worker exited during startup:\n"
                    + log_path.read_text(encoding="utf-8", errors="replace")
                )
            try:
                if celery_app.control.ping(timeout=0.75):
                    break
            except Exception:
                pass
            time.sleep(0.25)
        else:
            log_handle.flush()
            raise AssertionError(
                "Celery worker did not respond before the startup deadline:\n"
                + log_path.read_text(encoding="utf-8", errors="replace")
            )

        yield process
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        log_handle.close()


def test_postgres_redis_worker_scheduler_end_to_end(
    client: TestClient,
    auth_headers: dict[str, str],
    authorized_target_url: str,
    celery_worker_process: subprocess.Popen[bytes],
) -> None:
    readiness = client.get("/api/v1/health/ready")
    assert readiness.status_code == 200, readiness.text
    assert readiness.json()["postgres"]["status"] == "ok"
    assert readiness.json()["redis"]["status"] == "ok"

    campaign_id = _create_campaign(
        client,
        auth_headers,
        authorized_target_url,
        name="Real broker API execution",
        authorization_reference="STACK-AUTHORIZATION-API",
        probe_values=["ok", "trigger-500"],
    )
    execute_response = client.post(
        f"/api/v1/campaigns/{campaign_id}/execute",
        headers={**auth_headers, "X-Request-ID": "stack-api-execute"},
    )
    assert execute_response.status_code == 202, execute_response.text
    assert execute_response.json()["run"]["celery_task_id"]

    completed = _wait_for_campaign_status(
        client,
        auth_headers,
        campaign_id,
        expected="completed",
    )
    assert completed["status"] == "completed"

    findings = client.get(
        f"/api/v1/campaigns/{campaign_id}/findings",
        headers=auth_headers,
    )
    assert findings.status_code == 200
    assert {item["category"] for item in findings.json()} == {
        "http_server_error",
        "http_status_variance",
    }

    scheduled_campaign_id = _create_campaign(
        client,
        auth_headers,
        authorized_target_url,
        name="Real broker scheduler execution",
        authorization_reference="STACK-AUTHORIZATION-SCHEDULER",
        probe_values=["ok"],
        schedule_at="2000-01-01T00:00:00+00:00",
    )
    assert dispatch_due_campaigns() == 1
    scheduled_completed = _wait_for_campaign_status(
        client,
        auth_headers,
        scheduled_campaign_id,
        expected="completed",
    )
    assert scheduled_completed["status"] == "completed"

    with SessionLocal() as db:
        actions = set(db.scalars(select(AuditLog.action)))
    assert "campaign.execution_requested" in actions
    assert "campaign.scheduled_execution_requested" in actions
    assert "campaign.run_completed" in actions
    assert celery_worker_process.poll() is None


def _create_campaign(
    client: TestClient,
    auth_headers: dict[str, str],
    target_url: str,
    *,
    name: str,
    authorization_reference: str,
    probe_values: list[str],
    schedule_at: str | None = None,
) -> str:
    payload: dict[str, object] = {
        "name": name,
        "target_url": target_url,
        "authorization_reference": authorization_reference,
        "config": {"probe_values": probe_values},
    }
    if schedule_at is not None:
        payload["schedule_at"] = schedule_at
    response = client.post("/api/v1/campaigns", headers=auth_headers, json=payload)
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


def _wait_for_campaign_status(
    client: TestClient,
    auth_headers: dict[str, str],
    campaign_id: str,
    *,
    expected: str,
) -> dict[str, object]:
    deadline = time.monotonic() + 30
    last_payload: dict[str, object] = {}
    while time.monotonic() < deadline:
        response = client.get(
            f"/api/v1/campaigns/{campaign_id}",
            headers=auth_headers,
        )
        assert response.status_code == 200, response.text
        last_payload = response.json()
        if last_payload.get("status") == expected:
            return last_payload
        if last_payload.get("status") in {"failed", "cancelled"}:
            break
        time.sleep(0.25)
    raise AssertionError(
        f"Campaign {campaign_id} did not reach {expected!r}; last payload: {last_payload}"
    )
