"""Triage workflow, SLA summary, asset inventory and outbox dead letters."""

from __future__ import annotations

import os
import unittest
from datetime import UTC, datetime, timedelta
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
from sqlalchemy import select

from app.core.config import settings
from app.db.session import SessionLocal, engine
from app.models import (
    AuditLog,
    Base,
    Campaign,
    Finding,
    FindingStatus,
    Objective,
    Outbox,
    Run,
    RunStatus,
    Tenant,
)
from app.services.objective_service import ObjectiveService
from tests.fixtures.vulnerable_app import running_fixture

HEADERS = {settings.api_key_header: "dev-hcvf-key"}


class TriageAssetsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        Base.metadata.create_all(bind=engine)
        cls.fixture = running_fixture()
        cls.target = cls.fixture.__enter__()
        from app.main import app

        cls.client = TestClient(app)
        cls.client.__enter__()
        with SessionLocal() as db:
            tenant = db.scalar(select(Tenant))
            assert tenant is not None
            tenant.authorized_targets = sorted({*tenant.authorized_targets, cls.target})
            campaign = Campaign(
                tenant_id=tenant.id,
                name="triage-fixture",
                target_url=cls.target,
                authorization_attested=True,
                budget_requests=50,
            )
            db.add(campaign)
            db.flush()
            run = Run(campaign_id=campaign.id, tenant_id=tenant.id, status=RunStatus.completed)
            db.add(run)
            db.flush()
            cls.run_id = run.id
            cls.tenant_id = tenant.id
            db.commit()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.__exit__(None, None, None)
        cls.fixture.__exit__(None, None, None)
        engine.dispose()

    def setUp(self) -> None:
        with SessionLocal() as db:
            for row in db.scalars(select(Finding)):
                db.delete(row)
            for note in db.scalars(select(__import__("app.models", fromlist=["FindingNote"]).FindingNote)):
                db.delete(note)
            for outbox in db.scalars(select(Outbox)):
                db.delete(outbox)
            for obj in db.scalars(select(Objective)):
                db.delete(obj)
            db.commit()
        self._login()

    def _login(self) -> None:
        self.client.post("/console/login", data={"api_key": "dev-hcvf-key"}, follow_redirects=False)

    def _finding(self, *, severity: str = "high", status: str = FindingStatus.open, age_hours: int = 1) -> str:
        with SessionLocal() as db:
            created = datetime.now(UTC) - timedelta(hours=age_hours)
            finding = Finding(
                run_id=self.run_id,
                tenant_id=self.tenant_id,
                fingerprint=f"fp-{datetime.now(UTC).timestamp()}",
                probe_id="security-headers",
                kind="missing-content-security-policy",
                severity=severity,
                confidence=0.9,
                status=status,
                cwe="CWE-693",
                title="No Content-Security-Policy",
                detail="detail",
                remediation="set csp",
                evidence_refs={},
                occurrences=1,
                last_seen_at=created,
                sla_due_at=created + timedelta(hours=24),
            )
            db.add(finding)
            db.commit()
            return str(finding.id)

    def test_transition_and_note_are_recorded(self) -> None:
        finding_id = self._finding()
        response = self.client.patch(
            f"/api/v1/findings/{finding_id}",
            headers=HEADERS,
            json={"status": "triaged", "note": "owned by platform team", "assignee": "platform"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["status"], "triaged")
        self.assertEqual(body["assignee"], "platform")
        self.assertIsNotNone(body["triaged_at"])

        notes = self.client.get(f"/api/v1/findings/{finding_id}/notes", headers=HEADERS).json()
        self.assertEqual(len(notes), 1)
        self.assertIn("platform team", notes[0]["note"])
        self.assertEqual(notes[0]["status_from"], "open")

        with SessionLocal() as db:
            actions = [row.action for row in db.scalars(select(AuditLog))]
        self.assertIn("finding.triage", actions)

    def test_invalid_transition_is_rejected(self) -> None:
        finding_id = self._finding(status=FindingStatus.fixed)
        response = self.client.patch(f"/api/v1/findings/{finding_id}", headers=HEADERS, json={"status": "confirmed"})
        self.assertEqual(response.status_code, 409, response.text)
        self.assertIn("cannot move", response.text)

    def test_summary_reports_overdue_findings(self) -> None:
        self._finding(severity="critical", age_hours=48)
        response = self.client.get("/api/v1/findings/summary", headers=HEADERS)
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertGreaterEqual(body["overdue_count"], 1)
        self.assertIn("critical", body["by_severity"])
        self.assertIn("sla_hours", body)

    def test_note_endpoint_without_status_change(self) -> None:
        finding_id = self._finding()
        response = self.client.post(
            f"/api/v1/findings/{finding_id}/notes",
            headers=HEADERS,
            json={"status": "open", "note": "still investigating"},
        )
        self.assertEqual(response.status_code, 201, response.text)
        notes = self.client.get(f"/api/v1/findings/{finding_id}/notes", headers=HEADERS).json()
        self.assertEqual(notes[0]["note"], "still investigating")

    def test_objective_records_assets_and_changes(self) -> None:
        with SessionLocal() as db:
            tenant = db.get(Tenant, self.tenant_id)
            assert tenant is not None
            objective = ObjectiveService(db).create(
                tenant=tenant,
                title="asset objective",
                target_url=self.target + "/",
                template="coverage",
                budget_requests=120,
                per_task_budget=15,
                criteria_payload=None,
                safety_ceiling="read_only",
                priority=5,
                deadline_minutes=120,
                description="",
                actor="test",
                origin="test",
            )
            ObjectiveService(db).run_to_completion(objective, max_tasks=30)

        assets = self.client.get("/api/v1/assets", headers=HEADERS)
        self.assertEqual(assets.status_code, 200, assets.text)
        body = assets.json()
        self.assertGreater(body["total"], 0)
        routes = {item["route"] for item in body["items"]}
        self.assertTrue(any(route.endswith("/admin") for route in routes), routes)

        summary = self.client.get("/api/v1/assets/summary", headers=HEADERS).json()
        self.assertGreater(summary["total"], 0)
        changes = self.client.get("/api/v1/assets/changes?days=1", headers=HEADERS).json()
        self.assertGreaterEqual(len(changes["new"]), 1)

        page = self.client.get("/console/assets")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Asset inventory", page.text)

    def test_console_finding_detail_and_triage_action(self) -> None:
        finding_id = self._finding()
        page = self.client.get(f"/console/findings/{finding_id}")
        self.assertEqual(page.status_code, 200, page.text)
        self.assertIn("Decision history", page.text)

        action = self.client.post(
            f"/console/findings/{finding_id}/triage",
            data={"status": "confirmed", "note": "verified in console", "assignee": "secops"},
            follow_redirects=False,
        )
        self.assertEqual(action.status_code, 303)
        with SessionLocal() as db:
            finding = db.get(Finding, __import__("uuid").UUID(finding_id))
            assert finding is not None
            self.assertEqual(finding.status, "confirmed")
            self.assertEqual(finding.assignee, "secops")

    def test_outbox_dead_letter_retry_and_discard(self) -> None:
        with SessionLocal() as db:
            entry = Outbox(topic="webhook.deliver", payload={"event": "x"}, attempts=7, last_error="boom")
            db.add(entry)
            db.commit()
            entry_id = str(entry.id)

        dead = self.client.get("/api/v1/admin/outbox/dead", headers=HEADERS)
        self.assertEqual(dead.status_code, 200, dead.text)
        self.assertIn(entry_id, {item["id"] for item in dead.json()})

        retry = self.client.post(f"/api/v1/admin/outbox/{entry_id}/retry", headers=HEADERS)
        self.assertEqual(retry.status_code, 200, retry.text)
        with SessionLocal() as db:
            row = db.get(Outbox, __import__("uuid").UUID(entry_id))
            assert row is not None
            self.assertEqual(row.attempts, 0)

        discard = self.client.post(f"/api/v1/admin/outbox/{entry_id}/discard", headers=HEADERS)
        self.assertEqual(discard.status_code, 200, discard.text)
        with SessionLocal() as db:
            row = db.get(Outbox, __import__("uuid").UUID(entry_id))
            assert row is not None
            self.assertIsNotNone(row.published_at)
            self.assertIn("discarded", row.last_error)


if __name__ == "__main__":
    unittest.main()
