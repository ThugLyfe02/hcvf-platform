"""Autonomy controller tests.

Exercised through the real API and the real services on SQLite: policy
authorization, scope containment, scheduling choice, caps, quiet hours, backoff,
kill switch, and finding recurrence. No broker, no worker process.
"""

from __future__ import annotations

import os
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
BUILD.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("DATABASE_URL", f"sqlite:///{(BUILD / 'test_api.db').as_posix()}")
os.environ.setdefault("RATE_LIMIT_ENABLED", "false")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("EVIDENCE_DIR", (BUILD / "test-evidence").as_posix())
os.environ.setdefault("HCVF_API_KEYS", "dev-hcvf-key")

from fastapi.testclient import TestClient
from sqlalchemy import delete, select, update

from app.core.config import settings
from app.db.session import SessionLocal, engine
from app.models import (
    AutonomyDecision,
    AutonomyPolicy,
    Base,
    Campaign,
    CampaignStatus,
    Finding,
    HuntTarget,
    Run,
    RunStatus,
    Tenant,
)
from app.services.autonomy_service import AutonomyService
from app.services.hunt_service import HuntService
from tests.fixtures.vulnerable_app import running_fixture

HEADERS = {settings.api_key_header: "dev-hcvf-key"}


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.hostname}" + (f":{parts.port}" if parts.port else "")


class AutonomyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        Base.metadata.create_all(bind=engine)
        cls.fixture = running_fixture()
        cls.target = cls.fixture.__enter__()
        cls.origin = _origin(cls.target)

        from app.main import app

        cls.client = TestClient(app)
        cls.client.__enter__()

        with SessionLocal() as db:
            tenant = db.scalar(select(Tenant).where(Tenant.name == "configured-tenant-1"))
            assert tenant is not None
            authorized = set(tenant.authorized_targets or [])
            authorized.add(cls.origin)
            authorized.add("http://127.0.0.1:8001")
            tenant.authorized_targets = sorted(authorized)
            db.commit()
            cls.tenant_id = tenant.id

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.__exit__(None, None, None)
        cls.fixture.__exit__(None, None, None)
        engine.dispose()

    def setUp(self) -> None:
        with SessionLocal() as db:
            db.execute(delete(AutonomyDecision))
            db.execute(delete(HuntTarget))
            db.execute(delete(AutonomyPolicy))
            db.execute(delete(Finding))
            db.execute(delete(Run))
            db.execute(delete(Campaign))
            db.commit()

    # -- helpers ---------------------------------------------------------
    def _put_policy(self, **overrides) -> dict:
        payload = {
            "enabled": True,
            "target_allowlist": [self.origin],
            "safety_ceiling": "read_only",
            "budget_requests_per_run": 40,
            "max_runs_per_day": 8,
            "min_interval_minutes": 5,
            "timezone": "UTC",
            "max_consecutive_failures": 3,
            "min_utility": 0.0,
            "approved_by": "unit-test",
            "approval_statement": "I authorize autonomous validation of this target.",
        }
        payload.update(overrides)
        response = self.client.put("/api/v1/autonomy", headers=HEADERS, json=payload)
        return {"status": response.status_code, "body": response.json()}

    def _tick(self, *, force: bool = True, now: datetime | None = None):
        with SessionLocal() as db:
            policy = AutonomyService(db).get_policy(self.tenant_id)
            assert policy is not None
            return AutonomyService(db).tick_policy(policy, now=now, force=force)

    def _run_id(self, run_id) -> Run:
        with SessionLocal() as db:
            run = db.get(Run, run_id)
            assert run is not None
            return run

    # -- authorization ---------------------------------------------------
    def test_enabling_requires_an_approval_statement(self) -> None:
        result = self._put_policy(approval_statement="")
        self.assertEqual(result["status"], 400, result)
        self.assertIn("approval statement", result["body"]["detail"])

    def test_autonomy_cannot_escape_tenant_scope(self) -> None:
        result = self._put_policy(target_allowlist=["https://not-owned.example.test"])
        self.assertEqual(result["status"], 400, result)
        self.assertIn("not in the tenant's authorized targets", result["body"]["detail"])

    def test_destructive_ceiling_is_rejected(self) -> None:
        result = self._put_policy(safety_ceiling="destructive")
        self.assertEqual(result["status"], 422, result)

    def test_policy_records_approval_hash_and_normalizes_targets(self) -> None:
        result = self._put_policy(target_allowlist=[self.target + "/ignored/path"])
        self.assertEqual(result["status"], 200, result)
        body = result["body"]
        self.assertEqual(body["target_allowlist"], [self.origin])
        self.assertEqual(len(body["approval_sha256"]), 64)
        self.assertTrue(body["approved_at"])

    def test_global_switch_blocks_ticks_unless_forced(self) -> None:
        self._put_policy()
        with SessionLocal() as db:
            policy = AutonomyService(db).get_policy(self.tenant_id)
            report = AutonomyService(db).tick_policy(policy, force=False)
        self.assertEqual(report.action, "disabled")
        self.assertEqual(report.reason, "global autonomy switch is off")
        with SessionLocal() as db:
            self.assertIsNone(db.scalar(select(Campaign.id)))

    def test_pause_and_resume(self) -> None:
        self._put_policy()
        paused = self.client.post("/api/v1/autonomy/pause", headers=HEADERS)
        self.assertEqual(paused.status_code, 200, paused.text)
        self.assertFalse(paused.json()["enabled"])
        resumed = self.client.post("/api/v1/autonomy/resume", headers=HEADERS)
        self.assertEqual(resumed.status_code, 200, resumed.text)
        self.assertTrue(resumed.json()["enabled"])

    # -- scheduling ------------------------------------------------------
    def test_tick_launches_a_hunt_and_records_the_decision(self) -> None:
        self._put_policy()
        report = self._tick()
        self.assertEqual(report.action, "hunt", report)
        self.assertIsNotNone(report.run_id)

        with SessionLocal() as db:
            campaign = db.scalar(select(Campaign))
            assert campaign is not None
            self.assertEqual(campaign.origin, "autonomy")
            self.assertEqual(campaign.status, CampaignStatus.queued)
            run = db.get(Run, report.run_id)
            assert run is not None
            self.assertEqual(run.status, RunStatus.queued)
            decision = db.scalar(select(AutonomyDecision).where(AutonomyDecision.action == "hunt"))
            assert decision is not None
            self.assertEqual(str(decision.run_id), str(report.run_id))
            self.assertIn("utility", decision.reason)
            target = db.scalar(select(HuntTarget))
            assert target is not None
            self.assertEqual(target.runs_total, 1)
            self.assertIsNotNone(target.next_eligible_at)

    def test_second_tick_backs_off_until_interval(self) -> None:
        self._put_policy()
        first = self._tick()
        self.assertEqual(first.action, "hunt")
        second = self._tick()
        self.assertEqual(second.action, "skip")
        self.assertIn("no eligible target", second.reason)

    def test_stalest_target_wins(self) -> None:
        self._put_policy(target_allowlist=[self.origin, "http://127.0.0.1:8001"])
        with SessionLocal() as db:
            targets = {t.url: t for t in db.scalars(select(HuntTarget))}
            self.assertEqual(len(targets), 2)
            fresh = targets[self.origin]
            fresh.last_run_at = datetime.now(UTC) - timedelta(minutes=1)
            fresh.runs_total = 5
            db.commit()

        report = self._tick()
        self.assertEqual(report.action, "hunt")
        self.assertEqual(_origin(report.target_url), "http://127.0.0.1:8001")

    def test_daily_cap_is_enforced(self) -> None:
        self._put_policy(max_runs_per_day=1, min_interval_minutes=5)
        first = self._tick()
        self.assertEqual(first.action, "hunt", first)

        with SessionLocal() as db:
            db.execute(update(HuntTarget).values(next_eligible_at=None))
            db.commit()

        second = self._tick()
        self.assertEqual(second.action, "skip")
        self.assertIn("daily cap", second.reason)

    def test_quiet_hours_skip(self) -> None:
        self._put_policy(quiet_hours_start=0, quiet_hours_end=23)
        fixed = datetime(2026, 11, 3, 12, 0, tzinfo=UTC)
        report = self._tick(now=fixed)
        self.assertEqual(report.action, "skip")
        self.assertEqual(report.reason, "quiet hours")

    def test_utility_falls_after_repeated_failures(self) -> None:
        self._put_policy()
        with SessionLocal() as db:
            service = AutonomyService(db)
            policy = service.get_policy(self.tenant_id)
            target = db.scalar(select(HuntTarget))
            baseline = service.utility(target, now=datetime.now(UTC), policy=policy)
            target.consecutive_failures = 2
            degraded = service.utility(target, now=datetime.now(UTC), policy=policy)
        self.assertLess(degraded, baseline)

    # -- outcomes --------------------------------------------------------
    def test_outcome_feedback_updates_target_and_disables_after_failures(self) -> None:
        self._put_policy(max_consecutive_failures=3)
        report = self._tick()
        self.assertEqual(report.action, "hunt")

        with SessionLocal() as db:
            campaign = db.get(Campaign, self._run_id(report.run_id).campaign_id)
            assert campaign is not None
            HuntService(db).execute_run(report.run_id)

        with SessionLocal() as db:
            target = db.scalar(select(HuntTarget))
            assert target is not None
            self.assertEqual(target.last_status, "completed")
            self.assertEqual(target.consecutive_failures, 0)
            self.assertGreater(target.findings_total, 0)

        # Force three consecutive failures for the same target.
        with SessionLocal() as db:
            service = AutonomyService(db)
            campaign = db.scalar(select(Campaign))
            assert campaign is not None
            for _ in range(3):
                service.record_run_outcome(campaign=campaign, success=False, findings=0)

        with SessionLocal() as db:
            target = db.scalar(select(HuntTarget))
            assert target is not None
            self.assertFalse(target.enabled)
            self.assertGreaterEqual(target.consecutive_failures, 3)
            disabled = db.scalar(select(AutonomyDecision).where(AutonomyDecision.action == "disable"))
            self.assertIsNotNone(disabled)

    def test_kill_cancels_in_flight_and_disables_policy(self) -> None:
        self._put_policy()
        report = self._tick()
        self.assertEqual(report.action, "hunt")

        killed = self.client.post("/api/v1/autonomy/kill", headers=HEADERS)
        self.assertEqual(killed.status_code, 200, killed.text)
        self.assertGreaterEqual(killed.json()["cancelled_runs"], 1)
        self.assertFalse(killed.json()["enabled"])

        with SessionLocal() as db:
            run = db.get(Run, report.run_id)
            assert run is not None
            self.assertEqual(run.status, RunStatus.cancelled)
            self.assertTrue(run.cancel_requested)

    # -- learning & recurrence -------------------------------------------
    def test_genome_is_derived_from_learned_probe_stats(self) -> None:
        self._put_policy()
        first = self._tick()
        with SessionLocal() as db:
            HuntService(db).execute_run(first.run_id)

        with SessionLocal() as db:
            db.execute(update(HuntTarget).values(next_eligible_at=None, enabled=True, consecutive_failures=0))
            db.commit()

        second = self._tick()
        self.assertEqual(second.action, "hunt", second)
        with SessionLocal() as db:
            run = db.get(Run, second.run_id)
            assert run is not None
            campaign = db.get(Campaign, run.campaign_id)
            assert campaign is not None
            self.assertTrue(campaign.genome.get("probes"), campaign.genome)
            self.assertIn("surface-crawl", campaign.genome["probes"])

    def test_repeated_findings_aggregate_instead_of_duplicating(self) -> None:
        self._put_policy()
        first = self._tick()
        with SessionLocal() as db:
            HuntService(db).execute_run(first.run_id)
        with SessionLocal() as db:
            count_before = len(list(db.scalars(select(Finding))))
            self.assertGreater(count_before, 0)

        # Run the same target again through a fresh campaign.
        with SessionLocal() as db:
            db.execute(update(HuntTarget).values(next_eligible_at=None))
            db.commit()
        second = self._tick()
        with SessionLocal() as db:
            HuntService(db).execute_run(second.run_id)

        with SessionLocal() as db:
            findings = list(db.scalars(select(Finding)))
            self.assertEqual(len(findings), count_before, "duplicate issue rows were created")
            self.assertTrue(any(f.occurrences >= 2 for f in findings))
            self.assertTrue(all(f.last_seen_at is not None for f in findings))

    def test_recurrence_reopens_a_fixed_finding(self) -> None:
        self._put_policy()
        first = self._tick()
        with SessionLocal() as db:
            HuntService(db).execute_run(first.run_id)

        with SessionLocal() as db:
            finding = db.scalar(select(Finding))
            assert finding is not None
            finding.status = "fixed"
            fingerprint = finding.fingerprint
            db.commit()

        with SessionLocal() as db:
            db.execute(update(HuntTarget).values(next_eligible_at=None))
            db.commit()
        second = self._tick()
        with SessionLocal() as db:
            HuntService(db).execute_run(second.run_id)

        with SessionLocal() as db:
            finding = db.scalar(select(Finding).where(Finding.fingerprint == fingerprint))
            assert finding is not None
            self.assertEqual(finding.status, "open", "a recurrence must reopen a fixed issue")
            self.assertGreaterEqual(finding.occurrences, 2)

    def test_status_endpoint_explains_the_next_move(self) -> None:
        self._put_policy()
        status = self.client.get("/api/v1/autonomy", headers=HEADERS)
        self.assertEqual(status.status_code, 200, status.text)
        body = status.json()
        self.assertTrue(body["policy"]["enabled"])
        self.assertEqual(body["daily_cap"], 8)
        self.assertEqual(len(body["targets"]), 1)
        self.assertGreater(body["targets"][0]["utility"], 0.0)
        self.assertFalse(body["global_enabled"])


if __name__ == "__main__":
    unittest.main()
