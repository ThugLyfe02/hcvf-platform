"""API integration tests on SQLite.

These exercise the real FastAPI app, the real services and the real engine. They
need no Postgres, no Redis and no Celery, which is exactly the point: the suite
must run on a laptop and in CI before anyone can call the platform tested.
"""

from __future__ import annotations

import os
from pathlib import Path
from uuid import UUID

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
BUILD.mkdir(parents=True, exist_ok=True)
DB_PATH = BUILD / "test_api.db"
EVIDENCE_PATH = BUILD / "test-evidence"
for path in (DB_PATH,):
    path.unlink(missing_ok=True)

os.environ["DATABASE_URL"] = f"sqlite:///{DB_PATH.as_posix()}"
os.environ["RATE_LIMIT_ENABLED"] = "false"
os.environ["ENVIRONMENT"] = "development"
os.environ["EVIDENCE_DIR"] = EVIDENCE_PATH.as_posix()
os.environ["HCVF_API_KEYS"] = "dev-hcvf-key"

import unittest

from fastapi.testclient import TestClient

from app.core.config import settings
from app.db.session import SessionLocal, engine
from app.models import Base
from app.services.hunt_service import HuntService
from tests.fixtures.vulnerable_app import running_fixture

HEADERS = {settings.api_key_header: "dev-hcvf-key"}


class ApiFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        Base.metadata.create_all(bind=engine)
        cls.fixture = running_fixture()
        cls.target = cls.fixture.__enter__()
        from app.main import app

        cls.client = TestClient(app)
        cls.client.__enter__()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.__exit__(None, None, None)
        cls.fixture.__exit__(None, None, None)
        engine.dispose()

    # -- helpers ---------------------------------------------------------
    def _create_campaign(self, *, target: str | None = None, budget: int = 60) -> dict:
        response = self.client.post(
            "/api/v1/campaigns",
            headers=HEADERS,
            json={
                "name": f"api-flow-{os.urandom(4).hex()}",
                "target_url": target or f"{self.target}/",
                "authorization_attested": True,
                "budget_requests": budget,
                "safety_ceiling": "read_only",
            },
        )
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def _execute_inline(self, run_id: str) -> None:
        with SessionLocal() as db:
            HuntService(db).execute_run(UUID(run_id))

    # -- tests -----------------------------------------------------------
    def test_root_health_and_metrics(self) -> None:
        root = self.client.get("/")
        self.assertEqual(root.status_code, 200)
        self.assertEqual(root.json()["service"], "hcvf")

        health = self.client.get("/health")
        self.assertEqual(health.status_code, 200)
        self.assertIn(health.json()["status"], {"ok", "degraded"})

        metrics = self.client.get("/metrics")
        self.assertEqual(metrics.status_code, 200)
        self.assertIn("hcvf_http_requests_total", metrics.text)
        self.assertTrue(root.headers.get("x-request-id"))

    def test_authentication_is_required(self) -> None:
        self.assertEqual(self.client.get("/api/v1/campaigns").status_code, 401)
        self.assertEqual(
            self.client.get("/api/v1/campaigns", headers={settings.api_key_header: "nope"}).status_code,
            401,
        )

    def test_attestation_is_required(self) -> None:
        response = self.client.post(
            "/api/v1/campaigns",
            headers=HEADERS,
            json={"name": "x", "target_url": "http://127.0.0.1:8099/", "authorization_attested": False},
        )
        self.assertEqual(response.status_code, 400, response.text)

    def test_unauthorized_target_is_rejected(self) -> None:
        response = self.client.post(
            "/api/v1/campaigns",
            headers=HEADERS,
            json={
                "name": "outside-scope",
                "target_url": "https://not-owned.example.test/",
                "authorization_attested": True,
            },
        )
        self.assertEqual(response.status_code, 400, response.text)

    def test_full_hunt_produces_findings_plan_and_sarif(self) -> None:
        campaign = self._create_campaign()
        executed = self.client.post(f"/api/v1/campaigns/{campaign['id']}/execute", headers=HEADERS)
        self.assertEqual(executed.status_code, 202, executed.text)
        run = executed.json()
        self.assertEqual(run["status"], "queued")

        self._execute_inline(run["id"])

        after = self.client.get(f"/api/v1/campaigns/{campaign['id']}/runs/{run['id']}", headers=HEADERS)
        self.assertEqual(after.status_code, 200, after.text)
        body = after.json()
        self.assertEqual(body["status"], "completed", body)
        self.assertTrue(body["evidence_root"])
        self.assertIsNotNone(body["plan_seed"])

        findings = self.client.get(f"/api/v1/campaigns/{campaign['id']}/runs/{run['id']}/findings", headers=HEADERS)
        self.assertEqual(findings.status_code, 200, findings.text)
        items = findings.json()
        self.assertGreaterEqual(len(items), 8)
        kinds = {item["kind"] for item in items}
        self.assertIn("missing-content-security-policy", kinds)
        self.assertIn("cors-reflected-origin-with-credentials", kinds)
        for item in items:
            self.assertTrue(item["fingerprint"])
            self.assertIn(
                item["status"], {"open", "triaged", "confirmed", "false_positive", "risk_accepted", "fixed", "verified"}
            )

        plan = self.client.get(f"/api/v1/campaigns/{campaign['id']}/runs/{run['id']}/plan", headers=HEADERS)
        self.assertEqual(plan.status_code, 200, plan.text)
        plan_body = plan.json()
        self.assertTrue(plan_body["plan"]["decisions"])
        self.assertTrue(plan_body["plan"]["proposals"])
        self.assertTrue(plan_body["plan"]["critiques"])
        agents = {proposal["agent"] for proposal in plan_body["plan"]["proposals"]}
        self.assertGreaterEqual(len(agents), 3)
        self.assertTrue(plan_body["plan"]["deliberation"]["messages"])
        self.assertGreaterEqual(plan_body["plan"]["deliberation"]["rounds"], 2)

        transcript = self.client.get(f"/api/v1/campaigns/{campaign['id']}/runs/{run['id']}/transcript", headers=HEADERS)
        self.assertEqual(transcript.status_code, 200, transcript.text)
        debate = transcript.json()
        self.assertGreaterEqual(debate["rounds"], 2)
        self.assertGreaterEqual(len(debate["agents"]), 5)
        self.assertIn("# Deliberation", debate["content"])
        self.assertIn("## Final allocation", debate["content"])

        sarif = self.client.get(f"/api/v1/campaigns/{campaign['id']}/runs/{run['id']}/report.sarif", headers=HEADERS)
        self.assertEqual(sarif.status_code, 200, sarif.text)
        payload = sarif.json()
        self.assertEqual(payload["version"], "2.1.0")
        self.assertEqual(len(payload["runs"][0]["results"]), len(items))

        global_findings = self.client.get("/api/v1/findings", headers=HEADERS)
        self.assertEqual(global_findings.status_code, 200)
        self.assertGreaterEqual(global_findings.json()["total"], len(items))

        self.assertTrue(any(EVIDENCE_PATH.rglob("*")), "evidence artifacts were not written")

    def test_outbox_relay_claims_and_publishes_once(self) -> None:
        from app.services.outbox import dispatch_pending

        campaign = self._create_campaign()
        run = self.client.post(f"/api/v1/campaigns/{campaign['id']}/execute", headers=HEADERS).json()

        published: list[tuple[str, dict]] = []
        with SessionLocal() as db:
            first = dispatch_pending(db, lambda topic, payload: published.append((topic, payload)), limit=10)
        self.assertGreaterEqual(first, 1)
        self.assertTrue(any(payload.get("run_id") == run["id"] for _, payload in published))

        # A second relay pass must not re-publish an already delivered intent.
        with SessionLocal() as db:
            second = dispatch_pending(db, lambda topic, payload: published.append((topic, payload)), limit=10)
        self.assertEqual(second, 0)

    def test_finding_triage_and_filter(self) -> None:
        campaign = self._create_campaign()
        run = self.client.post(f"/api/v1/campaigns/{campaign['id']}/execute", headers=HEADERS).json()
        self._execute_inline(run["id"])

        findings = self.client.get("/api/v1/findings", headers=HEADERS).json()["items"]
        self.assertTrue(findings)
        target = findings[0]

        patched = self.client.patch(
            f"/api/v1/findings/{target['id']}",
            headers=HEADERS,
            json={"status": "confirmed", "note": "verified manually"},
        )
        self.assertEqual(patched.status_code, 200, patched.text)
        self.assertEqual(patched.json()["status"], "confirmed")

        filtered = self.client.get("/api/v1/findings", headers=HEADERS, params={"status": "confirmed"}).json()
        self.assertGreaterEqual(filtered["total"], 1)

        bad = self.client.patch(f"/api/v1/findings/{target['id']}", headers=HEADERS, json={"status": "nonsense"})
        self.assertEqual(bad.status_code, 400)

    def test_cancel_stops_a_queued_run(self) -> None:
        campaign = self._create_campaign()
        run = self.client.post(f"/api/v1/campaigns/{campaign['id']}/execute", headers=HEADERS).json()

        cancelled = self.client.post(f"/api/v1/campaigns/{campaign['id']}/cancel", headers=HEADERS)
        self.assertEqual(cancelled.status_code, 200, cancelled.text)
        self.assertEqual(cancelled.json()["status"], "cancelled")

        run_after = self.client.get(f"/api/v1/campaigns/{campaign['id']}/runs/{run['id']}", headers=HEADERS).json()
        self.assertEqual(run_after["status"], "cancelled")

    def test_cross_tenant_access_is_denied(self) -> None:
        campaign = self._create_campaign()

        created = self.client.post(
            "/api/v1/tenants",
            headers=HEADERS,
            json={"name": f"iso-{os.urandom(4).hex()}", "authorized_targets": []},
        )
        self.assertEqual(created.status_code, 201, created.text)
        other = created.json()
        other_headers = {settings.api_key_header: other["api_key"]}

        # The newly minted key authenticates (this was broken before) ...
        own = self.client.get("/api/v1/campaigns", headers=other_headers)
        self.assertEqual(own.status_code, 200, own.text)
        self.assertEqual(own.json(), [])

        # ... but cannot see or touch the other tenant.
        self.assertEqual(
            self.client.get(f"/api/v1/campaigns/{campaign['id']}", headers=other_headers).status_code,
            404,
        )
        self.assertEqual(self.client.get("/api/v1/findings", headers=other_headers).json()["total"], 0)
        tenants = self.client.get("/api/v1/tenants", headers=other_headers).json()
        self.assertEqual(len(tenants), 1)
        self.assertEqual(tenants[0]["id"], other["id"])

        # A member cannot widen its own scope or mint new tenants.
        self.assertEqual(
            self.client.patch(
                f"/api/v1/tenants/{other['id']}",
                headers=other_headers,
                json={"authorized_targets": ["http://169.254.169.254"]},
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.post(
                "/api/v1/tenants", headers=other_headers, json={"name": "escalated", "authorized_targets": []}
            ).status_code,
            403,
        )

    def test_tenant_targets_are_normalized(self) -> None:
        created = self.client.post(
            "/api/v1/tenants",
            headers=HEADERS,
            json={
                "name": f"norm-{os.urandom(4).hex()}",
                "authorized_targets": ["https://App.Example.test:443/path"],
            },
        )
        self.assertEqual(created.status_code, 201, created.text)
        self.assertEqual(created.json()["authorized_targets"], ["https://app.example.test"])

        bad = self.client.post(
            "/api/v1/tenants",
            headers=HEADERS,
            json={"name": f"bad-{os.urandom(4).hex()}", "authorized_targets": ["not-a-url"]},
        )
        self.assertEqual(bad.status_code, 409, bad.text)


if __name__ == "__main__":
    unittest.main()
