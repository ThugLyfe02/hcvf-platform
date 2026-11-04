"""Admin exports and the SSE stream: signed CSV, signed bundle, tenant scoping."""

from __future__ import annotations

import hashlib
import hmac
import io
import os
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
BUILD.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("DATABASE_URL", f"sqlite:///{(BUILD / 'test_api.db').as_posix()}")
os.environ.setdefault("RATE_LIMIT_ENABLED", "false")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("EVIDENCE_DIR", (BUILD / "test-evidence").as_posix())
os.environ.setdefault("HCVF_API_KEYS", "dev-hcvf-key")

from fastapi.testclient import TestClient

from app.core.config import settings
from app.db.session import engine
from app.engine.evidence import verification_key_from_env
from app.models import Base
from tests.fixtures.vulnerable_app import running_fixture

API = {settings.api_key_header: "dev-hcvf-key"}


class AdminExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        Base.metadata.create_all(bind=engine)
        cls.fixture = running_fixture()
        cls.target = cls.fixture.__enter__()
        from app.main import app

        cls.client = TestClient(app)
        cls.client.__enter__()
        created = cls.client.post(
            "/api/v1/objectives",
            headers=API,
            json={
                "title": "export target",
                "target_url": cls.target + "/",
                "template": "auth",
                "budget_requests": 120,
                "per_task_budget": 15,
            },
        )
        assert created.status_code == 201, created.text
        cls.objective = created.json()
        run = cls.client.post(f"/api/v1/objectives/{cls.objective['id']}/run", headers=API, params={"max_tasks": 30})
        assert run.status_code == 200, run.text

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.__exit__(None, None, None)
        cls.fixture.__exit__(None, None, None)
        engine.dispose()

    def _verify(self, body: bytes, signature_header: str) -> None:
        expected = hmac.new(verification_key_from_env(), body, hashlib.sha256).hexdigest()
        self.assertEqual(signature_header, f"sha256={expected}")

    def test_findings_csv_is_signed(self) -> None:
        response = self.client.get("/api/v1/admin/export/findings.csv", headers=API)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("text/csv", response.headers["content-type"])
        self.assertIn("fingerprint,kind,severity", response.text)
        self._verify(response.content, response.headers["x-hcvf-signature"])

    def test_audit_csv_is_chained(self) -> None:
        response = self.client.get("/api/v1/admin/export/audit.csv", headers=API)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("seq,action,actor", response.text)
        self._verify(response.content, response.headers["x-hcvf-signature"])

    def test_objectives_csv_contains_the_objective(self) -> None:
        response = self.client.get("/api/v1/admin/export/objectives.csv", headers=API)
        self.assertEqual(response.status_code, 200)
        self.assertIn(self.objective["key"], response.text)

    def test_bundle_contains_evidence_and_reports(self) -> None:
        response = self.client.get(f"/api/v1/admin/bundle/{self.objective['id']}.zip", headers=API)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers["content-type"], "application/zip")
        self._verify(response.content, response.headers["x-hcvf-signature"])
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            names = set(archive.namelist())
        self.assertIn("objective.json", names)
        self.assertIn("report.sarif", names)
        self.assertIn("report.md", names)
        self.assertTrue(any(name.endswith("manifest.json") for name in names), names)

    def test_member_tenant_cannot_export(self) -> None:
        created = self.client.post(
            "/api/v1/tenants",
            headers=API,
            json={"name": "export-member", "authorized_targets": []},
        )
        self.assertEqual(created.status_code, 201, created.text)
        member = {settings.api_key_header: created.json()["api_key"]}
        response = self.client.get("/api/v1/admin/export/findings.csv", headers=member)
        self.assertEqual(response.status_code, 403, response.text)

    def test_sse_stream_replays_events(self) -> None:
        response = self.client.get(f"/api/v1/objectives/{self.objective['id']}/events/stream?once=1", headers=API)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("text/event-stream", response.headers["content-type"])
        self.assertIn("data:", response.text)
        self.assertIn("objective.created", response.text)


if __name__ == "__main__":
    unittest.main()
