"""Tests for governance, continuity and hardening endpoints added in 0.6.0."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import UUID

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
BUILD.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("DATABASE_URL", f"sqlite:///{(BUILD / 'test_api.db').as_posix()}")
os.environ.setdefault("RATE_LIMIT_ENABLED", "false")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("EVIDENCE_DIR", (BUILD / "test-evidence").as_posix())
os.environ.setdefault("HCVF_API_KEYS", "dev-hcvf-key")

from datetime import UTC

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import settings
from app.db.session import SessionLocal, engine
from app.engine.diff import diff as diff_hunts
from app.models import AuditLog, Base, Campaign, Tenant
from app.services import webhooks
from app.services.campaign_service import CampaignService
from app.services.hunt_service import HuntService
from app.services.outbox import dispatch_pending
from tests.fixtures.vulnerable_app import running_fixture

HEADERS = {settings.api_key_header: "dev-hcvf-key"}

RECEIVED: list[dict] = []


class _Receiver(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b""
        RECEIVED.append(
            {
                "body": body,
                "signature": self.headers.get("X-HCVF-Signature", ""),
                "event": self.headers.get("X-HCVF-Event", ""),
                "timestamp": self.headers.get("X-HCVF-Timestamp", ""),
            }
        )
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


class GovernanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        Base.metadata.create_all(bind=engine)
        cls.fixture = running_fixture()
        cls.target = cls.fixture.__enter__()
        cls.receiver = ThreadingHTTPServer(("127.0.0.1", 0), _Receiver)
        threading.Thread(target=cls.receiver.serve_forever, daemon=True).start()
        cls.receiver_url = f"http://127.0.0.1:{cls.receiver.server_address[1]}/hook"

        from app.main import app

        cls.client = TestClient(app)
        cls.client.__enter__()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.__exit__(None, None, None)
        cls.receiver.shutdown()
        cls.receiver.server_close()
        cls.fixture.__exit__(None, None, None)
        engine.dispose()

    # -- helpers ---------------------------------------------------------
    def _new_tenant(self, *, scopes: list[str] | None = None, quota: int | None = None) -> tuple[str, str]:
        created = self.client.post(
            "/api/v1/tenants",
            headers=HEADERS,
            json={"name": f"gov-{os.urandom(4).hex()}", "authorized_targets": [self.target]},
        )
        self.assertEqual(created.status_code, 201, created.text)
        body = created.json()
        if scopes is not None or quota is not None:
            with SessionLocal() as db:
                tenant = db.get(Tenant, UUID(body["id"]))
                assert tenant is not None
                if scopes is not None:
                    tenant.scopes = scopes
                if quota is not None:
                    tenant.daily_run_quota = quota
                db.commit()
        return body["id"], body["api_key"]

    def _campaign(self, key: str, *, profile: str | None = None, budget: int = 60) -> dict:
        payload = {
            "name": f"gov-campaign-{os.urandom(3).hex()}",
            "target_url": f"{self.target}/",
            "authorization_attested": True,
            "budget_requests": budget,
        }
        if profile:
            payload["profile"] = profile
        response = self.client.post("/api/v1/campaigns", headers={settings.api_key_header: key}, json=payload)
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def _execute(self, key: str, campaign_id: str, *, idem: str | None = None) -> object:
        headers = {settings.api_key_header: key}
        if idem:
            headers["Idempotency-Key"] = idem
        return self.client.post(f"/api/v1/campaigns/{campaign_id}/execute", headers=headers)

    def _run_inline(self, run_id: str) -> None:
        with SessionLocal() as db:
            HuntService(db).execute_run(UUID(run_id))

    # -- scopes ----------------------------------------------------------
    def test_scopes_restrict_what_a_key_can_do(self) -> None:
        _, key = self._new_tenant(scopes=["findings:read"])
        headers = {settings.api_key_header: key}
        self.assertEqual(self.client.get("/api/v1/findings", headers=headers).status_code, 200)
        denied = self.client.post(
            "/api/v1/campaigns",
            headers=headers,
            json={"name": "x", "target_url": f"{self.target}/", "authorization_attested": True},
        )
        self.assertEqual(denied.status_code, 403, denied.text)
        self.assertIn("campaigns:write", denied.text)

    def test_key_rotation_invalidates_the_old_key(self) -> None:
        tenant_id, key = self._new_tenant()
        rotated = self.client.post(f"/api/v1/tenants/{tenant_id}/rotate-key", headers={settings.api_key_header: key})
        self.assertEqual(rotated.status_code, 200, rotated.text)
        new_key = rotated.json()["api_key"]
        self.assertNotEqual(new_key, key)
        self.assertEqual(self.client.get("/api/v1/campaigns", headers={settings.api_key_header: key}).status_code, 401)
        self.assertEqual(
            self.client.get("/api/v1/campaigns", headers={settings.api_key_header: new_key}).status_code, 200
        )

    # -- idempotency and quotas ------------------------------------------
    def test_execute_is_idempotent(self) -> None:
        _, key = self._new_tenant()
        campaign = self._campaign(key)
        key_id = "retry-" + os.urandom(4).hex()
        first = self._execute(key, campaign["id"], idem=key_id)
        second = self._execute(key, campaign["id"], idem=key_id)
        self.assertEqual(first.status_code, 202, first.text)
        self.assertEqual(second.status_code, 202, second.text)
        self.assertEqual(first.json()["id"], second.json()["id"])

    def test_idempotency_conflict_on_different_request(self) -> None:
        _, key = self._new_tenant()
        first_campaign = self._campaign(key)
        second_campaign = self._campaign(key)
        key_id = "conflict-" + os.urandom(4).hex()
        self.assertEqual(self._execute(key, first_campaign["id"], idem=key_id).status_code, 202)
        conflict = self._execute(key, second_campaign["id"], idem=key_id)
        self.assertEqual(conflict.status_code, 409, conflict.text)

    def test_daily_run_quota_is_enforced(self) -> None:
        _, key = self._new_tenant(quota=1)
        first = self._campaign(key)
        self.assertEqual(self._execute(key, first["id"]).status_code, 202)
        second = self._campaign(key)
        blocked = self._execute(key, second["id"])
        self.assertEqual(blocked.status_code, 429, blocked.text)
        self.assertIn("quota", blocked.text.lower())

    # -- suppressions ----------------------------------------------------
    def test_suppressed_findings_are_not_stored(self) -> None:
        _, key = self._new_tenant()
        headers = {settings.api_key_header: key}
        suppressed = self.client.post(
            "/api/v1/suppressions",
            headers=headers,
            json={"kind": "missing-content-security-policy", "reason": "accepted by risk owner"},
        )
        self.assertEqual(suppressed.status_code, 202, suppressed.text)

        campaign = self._campaign(key)
        run = self._execute(key, campaign["id"]).json()
        self._run_inline(run["id"])

        findings = self.client.get(f"/api/v1/campaigns/{campaign['id']}/runs/{run['id']}/findings", headers=headers)
        kinds = {item["kind"] for item in findings.json()}
        self.assertNotIn("missing-content-security-policy", kinds)
        self.assertTrue(kinds, "everything was suppressed")

    # -- audit chain -----------------------------------------------------
    def test_audit_chain_detects_tampering(self) -> None:
        # Ensure at least one audited action exists before verifying/tampering.
        self.client.post(
            "/api/v1/suppressions",
            headers=HEADERS,
            json={"kind": "chain-probe", "reason": "seed an audit record"},
        )
        self.assertEqual(self.client.get("/api/v1/audit/verify", headers=HEADERS).json()["ok"], True)
        with SessionLocal() as db:
            row = db.scalar(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(1))
            assert row is not None
            row.detail = {"tampered": True}
            db.commit()
        verdict = self.client.get("/api/v1/audit/verify", headers=HEADERS).json()
        self.assertFalse(verdict["ok"])
        self.assertTrue(verdict["first_invalid_id"])

    # -- webhooks --------------------------------------------------------
    def test_webhook_delivery_is_signed(self) -> None:
        RECEIVED.clear()
        created = self.client.post(
            "/api/v1/webhooks",
            headers=HEADERS,
            json={"url": self.receiver_url, "events": ["run.completed"]},
        )
        self.assertEqual(created.status_code, 201, created.text)
        secret = created.json()["secret"]
        self.assertTrue(secret)

        campaign = self._campaign("dev-hcvf-key")
        run = self.client.post(f"/api/v1/campaigns/{campaign['id']}/execute", headers=HEADERS).json()
        self._run_inline(run["id"])

        with SessionLocal() as db:
            delivered = dispatch_pending(
                db,
                lambda topic, payload: webhooks.deliver_payload(payload) if topic == "webhook.deliver" else None,
                limit=50,
            )
        self.assertGreaterEqual(delivered, 1)

        self.assertTrue(RECEIVED, "no webhook was delivered")
        message = RECEIVED[-1]
        self.assertEqual(message["event"], "run.completed")
        expected = hmac.new(
            secret.encode(),
            f"{message['timestamp']}.".encode() + message["body"],
            hashlib.sha256,
        ).hexdigest()
        self.assertEqual(message["signature"], f"sha256={expected}")

    # -- profiles, risk, baseline ---------------------------------------
    def test_profile_sets_budget_and_genome(self) -> None:
        _, key = self._new_tenant()
        campaign = self._campaign(key, profile="exposure", budget=200)
        self.assertEqual(campaign["budget_requests"], 100)

        profiles = self.client.get("/api/v1/profiles", headers={settings.api_key_header: key}).json()
        self.assertTrue(any(item["name"] == "exposure" for item in profiles))

    def test_risk_trend_and_baseline_diff(self) -> None:
        _, key = self._new_tenant()
        headers = {settings.api_key_header: key}
        campaign = self._campaign(key)

        first = self._execute(key, campaign["id"]).json()
        self._run_inline(first["id"])
        second = self._execute(key, campaign["id"]).json()
        self._run_inline(second["id"])

        diff = self.client.get(f"/api/v1/campaigns/{campaign['id']}/runs/{second['id']}/diff", headers=headers)
        self.assertEqual(diff.status_code, 200, diff.text)
        body = diff.json()
        self.assertEqual(body["counts"]["new"], 0)
        self.assertGreater(body["counts"]["recurring"], 0)
        self.assertEqual(body["baseline_run_id"], first["id"])

        trend = self.client.get(f"/api/v1/campaigns/{campaign['id']}/risk-trend", headers=headers)
        self.assertEqual(trend.status_code, 200, trend.text)
        points = trend.json()["points"]
        self.assertGreaterEqual(len(points), 2)
        self.assertTrue(all(point["risk_score"] is not None for point in points))

    # -- evidence verification -------------------------------------------
    def test_evidence_verification_endpoint(self) -> None:
        _, key = self._new_tenant()
        headers = {settings.api_key_header: key}
        campaign = self._campaign(key)
        run = self._execute(key, campaign["id"]).json()
        self._run_inline(run["id"])

        verdict = self.client.get(
            f"/api/v1/campaigns/{campaign['id']}/runs/{run['id']}/evidence/verify", headers=headers
        )
        self.assertEqual(verdict.status_code, 200, verdict.text)
        body = verdict.json()
        self.assertTrue(body["ok"], body)
        self.assertGreater(body["leaves"], 0)
        self.assertTrue(body["root_recomputed"])
        self.assertTrue(body["signature"])

    # -- openapi ingestion ------------------------------------------------
    def test_openapi_spec_expands_the_surface(self) -> None:
        _, key = self._new_tenant()
        headers = {settings.api_key_header: key}
        campaign = self._campaign(key, profile="exposure", budget=100)
        run = self._execute(key, campaign["id"]).json()
        self._run_inline(run["id"])

        findings = self.client.get(
            f"/api/v1/campaigns/{campaign['id']}/runs/{run['id']}/findings", headers=headers
        ).json()
        kinds = {item["kind"] for item in findings}
        self.assertIn("openapi-specification-exposed", kinds)

        plan = self.client.get(f"/api/v1/campaigns/{campaign['id']}/runs/{run['id']}/plan", headers=headers).json()
        routes = [route["target"] for route in plan["plan"]["routes"]]
        self.assertTrue(any("/api/v1/orders" in route for route in routes), routes)

    # -- transport hardening ---------------------------------------------
    def test_problem_details_shape(self) -> None:
        response = self.client.get("/api/v1/campaigns", headers={settings.api_key_header: "wrong"})
        self.assertEqual(response.status_code, 401)
        self.assertTrue(response.headers["content-type"].startswith("application/problem+json"))
        body = response.json()
        self.assertEqual(body["status"], 401)
        self.assertTrue(body["title"])
        self.assertTrue(body["trace_id"])

    def test_traceparent_is_echoed(self) -> None:
        incoming = "00-" + "a" * 32 + "-" + "b" * 16 + "-01"
        response = self.client.get("/healthz", headers={"traceparent": incoming})
        self.assertEqual(response.status_code, 200)
        outgoing = response.headers["traceparent"]
        self.assertTrue(outgoing.startswith("00-" + "a" * 32 + "-"))

    def test_body_size_limit(self) -> None:
        oversized = json.dumps({"name": "x" * (settings.max_request_bytes + 100)})
        response = self.client.post(
            "/api/v1/campaigns",
            headers={**HEADERS, "Content-Type": "application/json"},
            content=oversized,
        )
        self.assertEqual(response.status_code, 413, response.text)

    def test_readiness_reflects_dependencies(self) -> None:
        self.assertEqual(self.client.get("/healthz").status_code, 200)
        ready = self.client.get("/readyz")
        self.assertIn(ready.status_code, {200, 503})
        self.assertIn(ready.json()["status"], {"ok", "degraded"})


class CampaignCronStorageTests(unittest.TestCase):
    def test_cron_is_persisted(self) -> None:
        Base.metadata.create_all(bind=engine)
        with SessionLocal() as db:
            tenant = db.scalar(select(Tenant))
            if tenant is None:
                tenant = Tenant(name="cron-tenant", api_key_hash="x" * 64, authorized_targets=[])
                db.add(tenant)
                db.commit()
                db.refresh(tenant)
            campaign = Campaign(
                tenant_id=tenant.id,
                name="cron-campaign",
                target_url="https://example.test/",
                authorization_attested=True,
                cron="0 3 * * 1-5",
            )
            db.add(campaign)
            db.commit()
            stored = db.get(Campaign, campaign.id)
            self.assertEqual(stored.cron, "0 3 * * 1-5")
            db.delete(stored)
            db.commit()

    def test_cron_campaign_is_claimed_and_rescheduled(self) -> None:
        from datetime import datetime, timedelta

        Base.metadata.create_all(bind=engine)
        now = datetime(2026, 11, 3, 12, 0, tzinfo=UTC)
        with SessionLocal() as db:
            tenant = db.scalar(select(Tenant))
            if tenant is None:
                tenant = Tenant(name="cron-tenant-2", api_key_hash="y" * 64, authorized_targets=[])
                db.add(tenant)
                db.commit()
                db.refresh(tenant)
            campaign = Campaign(
                tenant_id=tenant.id,
                name="cron-due",
                target_url="https://example.test/",
                authorization_attested=True,
                cron="*/5 * * * *",
                scheduled_at=now - timedelta(minutes=1),
            )
            db.add(campaign)
            db.commit()
            campaign_id = campaign.id

            runs = CampaignService(db).claim_cron_campaigns(now=now)
            self.assertEqual(len(runs), 1)
            refreshed = db.get(Campaign, campaign_id)
            assert refreshed is not None
            self.assertEqual(refreshed.scheduled_at.replace(tzinfo=UTC), now + timedelta(minutes=5))
            self.assertEqual(len(CampaignService(db).claim_cron_campaigns(now=now)), 0)

    def test_hunt_diff_counts_changes(self) -> None:
        left = {
            "target": "https://a.test",
            "findings": [{"fingerprint": "one", "title": "old", "severity": "low", "location": "https://a.test/x"}],
        }
        right = {
            "target": "https://a.test",
            "findings": [
                {"fingerprint": "two", "title": "new", "severity": "high", "location": "https://a.test/y"},
                {"fingerprint": "one", "title": "old", "severity": "low", "location": "https://a.test/x"},
            ],
        }
        result = diff_hunts(left, right)
        self.assertEqual(result["counts"], {"new": 1, "fixed": 0, "recurring": 1})


if __name__ == "__main__":
    unittest.main()
