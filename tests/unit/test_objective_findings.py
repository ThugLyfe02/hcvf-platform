"""Objective findings land in the ledger: identity, recurrence, triage."""

from __future__ import annotations

import os
import unittest
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
from app.models import Base, Finding, Objective, Tenant
from tests.fixtures.vulnerable_app import running_fixture

HEADERS = {settings.api_key_header: "dev-hcvf-key"}


class ObjectiveFindingsTests(unittest.TestCase):
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
            for objective in db.scalars(select(Objective)):
                db.delete(objective)
            db.commit()

    def _objective(self, title: str) -> dict:
        created = self.client.post(
            "/api/v1/objectives",
            headers=HEADERS,
            json={
                "title": title,
                "target_url": self.target + "/",
                "template": "auth",
                "budget_requests": 140,
                "per_task_budget": 15,
            },
        )
        self.assertEqual(created.status_code, 201, created.text)
        body = created.json()
        run = self.client.post(f"/api/v1/objectives/{body['id']}/run", headers=HEADERS, params={"max_tasks": 30})
        self.assertEqual(run.status_code, 200, run.text)
        return body

    def test_objective_findings_are_persisted_with_objective_identity(self) -> None:
        objective = self._objective("ledger objective")
        response = self.client.get(
            f"/api/v1/findings?objective_id={objective['id']}", headers=HEADERS, params={"limit": 200}
        )
        self.assertEqual(response.status_code, 200, response.text)
        rows = response.json()["items"]
        self.assertTrue(rows, "objective findings were not persisted")
        for row in rows:
            self.assertIsNone(row["run_id"])
            self.assertEqual(row["objective_id"], objective["id"])
            self.assertIsNotNone(row["sla_due_at"])
            self.assertTrue(row["title"])

        with SessionLocal() as db:
            all_rows = list(db.scalars(select(Finding)))
        self.assertTrue(all(row.evidence_refs.get("objective_id") for row in all_rows))
        self.assertTrue(all(row.evidence_refs.get("manifest") for row in all_rows))

    def test_repeat_objective_increments_occurrences_instead_of_duplicating(self) -> None:
        self._objective("first pass")
        with SessionLocal() as db:
            first = {row.fingerprint: row.occurrences for row in db.scalars(select(Finding))}
        self.assertTrue(first)

        self._objective("second pass")
        with SessionLocal() as db:
            rows = list(db.scalars(select(Finding)))
        second = {row.fingerprint: row.occurrences for row in rows}
        self.assertEqual(set(first), set(second), "fingerprints changed between runs")
        for fingerprint, count in first.items():
            self.assertGreaterEqual(second[fingerprint], count + 1)

    def test_objective_finding_can_be_triaged(self) -> None:
        objective = self._objective("triage me")
        rows = self.client.get(f"/api/v1/findings?objective_id={objective['id']}", headers=HEADERS).json()["items"]
        self.assertTrue(rows)
        finding_id = rows[0]["id"]
        triaged = self.client.patch(
            f"/api/v1/findings/{finding_id}",
            headers=HEADERS,
            json={"status": "triaged", "note": "objective finding", "assignee": "appsec"},
        )
        self.assertEqual(triaged.status_code, 200, triaged.text)
        notes = self.client.get(f"/api/v1/findings/{finding_id}/notes", headers=HEADERS).json()
        self.assertEqual(notes[0]["note"], "objective finding")

    def test_summary_includes_objective_findings(self) -> None:
        self._objective("summary objective")
        summary = self.client.get("/api/v1/findings/summary", headers=HEADERS).json()
        self.assertGreater(summary["total"], 0)


if __name__ == "__main__":
    unittest.main()
