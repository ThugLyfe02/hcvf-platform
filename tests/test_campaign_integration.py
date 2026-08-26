from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import UUID

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import settings
from app.db.session import SessionLocal
from app.main import app
from app.models import Finding, Run, RunStatus
from worker.tasks import execute_campaign


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"authorized test target")

    def log_message(self, format: str, *args) -> None:
        return


def test_campaign_can_be_created_and_executed_end_to_end(monkeypatch) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        target_url = f"http://127.0.0.1:{server.server_address[1]}/"

        def execute_synchronously(run_id: str) -> None:
            execute_campaign.run(run_id)

        monkeypatch.setattr("app.api.v1.campaigns.execute_campaign.delay", execute_synchronously)

        with TestClient(app) as client:
            headers = {settings.api_key_header: settings.api_keys[0]}
            create_response = client.post(
                "/api/v1/campaigns",
                headers=headers,
                json={
                    "name": "integration campaign",
                    "target_url": target_url,
                    "authorization_attested": True,
                },
            )
            assert create_response.status_code == 201, create_response.text
            campaign_id = create_response.json()["id"]

            execute_response = client.post(
                f"/api/v1/campaigns/{campaign_id}/execute",
                headers=headers,
            )
            assert execute_response.status_code == 202, execute_response.text
            run_id = UUID(execute_response.json()["id"])

        with SessionLocal() as db:
            run = db.get(Run, run_id)
            assert run is not None
            assert run.status == RunStatus.completed
            assert run.http_status == 200
            finding = db.scalar(select(Finding).where(Finding.run_id == run_id))
            assert finding is not None
            assert finding.kind == "http_reachability"
            assert finding.evidence["http_status"] == 200
    finally:
        server.shutdown()
        server.server_close()
