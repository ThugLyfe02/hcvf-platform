"""Concurrent objective execution: atomic claims and a worker pool."""

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

from sqlalchemy import select

from app.db.session import SessionLocal, engine
from app.models import Base, Objective, ObjectiveTask, Tenant
from app.services.bootstrap import provision_configured_tenants
from app.services.objective_pool import run_batch
from app.services.objective_service import ObjectiveService
from tests.fixtures.vulnerable_app import running_fixture


class ObjectiveConcurrencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        Base.metadata.create_all(bind=engine)
        provision_configured_tenants()
        cls.fixture = running_fixture()
        cls.target = cls.fixture.__enter__()
        with SessionLocal() as db:
            tenant = db.scalar(select(Tenant))
            assert tenant is not None
            tenant.authorized_targets = sorted({*tenant.authorized_targets, cls.target})
            db.commit()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture.__exit__(None, None, None)
        engine.dispose()

    def setUp(self) -> None:
        with SessionLocal() as db:
            for task in db.scalars(select(ObjectiveTask)):
                db.delete(task)
            for objective in db.scalars(select(Objective)):
                db.delete(objective)
            db.commit()

    def _create(self, title: str) -> str:
        with SessionLocal() as db:
            tenant = db.scalar(select(Tenant))
            assert tenant is not None
            objective = ObjectiveService(db).create(
                tenant=tenant,
                title=title,
                target_url=self.target + "/",
                template="posture",
                budget_requests=80,
                per_task_budget=10,
                criteria_payload=None,
                safety_ceiling="read_only",
                priority=5,
                deadline_minutes=120,
                description="",
                actor="test",
                origin="test",
            )
            return str(objective.id)

    def test_two_workers_never_claim_the_same_task(self) -> None:
        objective_id = self._create("claim contention")
        with SessionLocal() as first, SessionLocal() as second:
            first_service = ObjectiveService(first)
            second_service = ObjectiveService(second)
            objective_a = first.get(Objective, __import__("uuid").UUID(objective_id))
            objective_b = second.get(Objective, __import__("uuid").UUID(objective_id))
            assert objective_a is not None and objective_b is not None

            claimed_a = first_service._claim_next(objective_a)
            claimed_b = second_service._claim_next(objective_b)
            self.assertIsNotNone(claimed_a)
            # The second worker must not receive the already-claimed task; it
            # either gets the next ready one or nothing at all.
            keys_a = {claimed_a[2].key} if claimed_a else set()
            keys_b = {claimed_b[2].key} if claimed_b else set()
            self.assertFalse(keys_a & keys_b, (keys_a, keys_b))

        with SessionLocal() as db:
            running = list(
                db.scalars(
                    select(ObjectiveTask).where(
                        ObjectiveTask.objective_id == __import__("uuid").UUID(objective_id),
                        ObjectiveTask.status == "running",
                    )
                )
            )
        self.assertGreaterEqual(len(running), 1)
        self.assertTrue(all(task.attempts >= 1 for task in running))
        self.assertTrue(all(task.lease_expires_at is not None for task in running))

    def test_batch_runs_independent_objectives_to_completion(self) -> None:
        ids = [self._create("batch one"), self._create("batch two")]
        outcomes = run_batch([__import__("uuid").UUID(item) for item in ids], max_workers=2, max_tasks=25)
        self.assertEqual(len(outcomes), 2)
        for outcome in outcomes:
            self.assertEqual(outcome.status, "completed", outcome.verdict)
        with SessionLocal() as db:
            statuses = [row.status for row in db.scalars(select(Objective))]
        self.assertEqual(statuses.count("completed"), 2)

    def test_batch_isolates_a_missing_objective(self) -> None:
        import uuid

        outcomes = run_batch([uuid.UUID(int=1)], max_workers=2)
        self.assertEqual(outcomes[0].status, "missing")


if __name__ == "__main__":
    unittest.main()
