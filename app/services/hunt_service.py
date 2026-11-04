"""Bridge between the persistence layer and the agentic engine.

This module owns the *lifecycle* of a hunt: authorization re-check, lease,
execution, evidence persistence, finding materialisation and failure handling.
The engine itself knows nothing about databases.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.metrics import (
    CAMPAIGNS_COMPLETED,
    FINDINGS_BY_SEVERITY,
    FINDINGS_DETECTED,
    HUNT_REQUESTS,
    HUNTS_FINISHED,
    HUNTS_STARTED,
    PROBES_EXECUTED,
    SUPPRESSED_FINDINGS,
)
from app.engine.bandit import ProbeBandit
from app.engine.budget import KillSwitch
from app.engine.errors import EngineError
from app.engine.evidence import FileEvidenceStore, verification_key_from_env, write_manifest
from app.engine.evolution import Genome
from app.engine.executor import HuntExecutor
from app.engine.policy import EgressPolicy
from app.engine.target import build_grant, parse_target
from app.engine.types import SafetyClass
from app.models import (
    Campaign,
    CampaignStatus,
    EvidenceBlob,
    Finding,
    FindingStatus,
    ProbeStat,
    Run,
    RunStatus,
    Tenant,
)
from app.services import risk, suppressions, webhooks
from app.services.findings_service import SLA_HOURS

logger = logging.getLogger(__name__)


class DbKillSwitch(KillSwitch):
    """Kill switch that honours an operator cancellation stored in the database.

    Polling every few checks keeps the database load negligible while bounding
    the number of requests that can be sent after a cancel is requested.
    """

    def __init__(self, db: Session, run_id: UUID, *, interval: int = 5) -> None:
        super().__init__()
        self.db = db
        self.run_id = run_id
        self.interval = interval
        self._checks = 0

    def check(self) -> None:
        super().check()
        self._checks += 1
        if self._checks % self.interval:
            return
        requested = self.db.scalar(select(Run.cancel_requested).where(Run.id == self.run_id))
        if requested:
            self.halt("cancelled by operator")


def _sla_hours(severity: str) -> int:
    return SLA_HOURS.get(severity, SLA_HOURS["info"])


class HuntService:
    def __init__(
        self, db: Session, *, evidence_root: Path | str | None = None, policy: EgressPolicy | None = None
    ) -> None:
        self.db = db
        self.evidence_root = Path(evidence_root or settings.evidence_dir)
        self.policy = policy or EgressPolicy(
            allow_private=settings.allow_private_targets or settings.environment.lower() == "development"
        )

    # -- public ----------------------------------------------------------
    def execute_run(self, run_id: UUID) -> Run:
        run = self.db.scalar(select(Run).where(Run.id == run_id).with_for_update())
        if run is None:
            raise ValueError(f"Run {run_id} not found")
        if run.status in {RunStatus.completed, RunStatus.failed, RunStatus.cancelled}:
            return run

        campaign = self.db.get(Campaign, run.campaign_id)
        tenant = self.db.get(Tenant, run.tenant_id) if run.tenant_id else None
        if campaign is None or tenant is None:
            self._fail(run, campaign, "Campaign or tenant disappeared before execution")
            return run

        if not campaign.authorization_attested:
            self._fail(run, campaign, "Campaign authorization attestation is missing")
            return run

        # Re-authorize at execution time: scope may have been revoked since the
        # campaign was created, and a queued run must not outlive its authority.
        from app.services.campaign_service import CampaignService

        if not CampaignService._is_authorized_target(campaign.target_url, tenant.authorized_targets):
            self._fail(run, campaign, "Target is no longer authorized for this tenant")
            return run

        now = datetime.now(UTC)
        run.status = RunStatus.running
        run.started_at = now
        run.lease_expires_at = now + timedelta(seconds=settings.hunt_lease_seconds)
        campaign.status = CampaignStatus.running
        self.db.commit()
        HUNTS_STARTED.inc()

        try:
            target = parse_target(campaign.target_url)
            safety = self._safety(campaign.safety_ceiling)
            grant = build_grant(
                target,
                safety=safety,
                max_rps=settings.hunt_max_rps,
                approver=f"tenant:{tenant.name}",
                evidence_sha256=hashlib.sha256(
                    f"{campaign.id}|{campaign.authorization_attested}|{target.origin}".encode()
                ).hexdigest(),
            )
            seed = int(run.id.int % 1_000_000)
            genome = None
            if campaign.genome:
                from app.engine.probes import registry as probe_registry

                genome = Genome.from_dict(campaign.genome, list(probe_registry().keys()))
            store = FileEvidenceStore(self.evidence_root / str(run.id))
            executor = HuntExecutor(
                policy=self.policy,
                store=store,
                signer_key=verification_key_from_env() or settings.evidence_key.encode("utf-8") or None,
            )
            result = executor.run(
                target,
                grant,
                seed=seed,
                budget_requests=campaign.budget_requests,
                bandit=self._load_bandit(target.host),
                genome=genome,
                kill_switch=DbKillSwitch(self.db, run.id),
            )
        except (EngineError, OSError, ValueError) as exc:
            logger.exception("hunt failed for run %s", run_id)
            self._fail(run, campaign, f"{exc.__class__.__name__}: {exc}")
            HUNTS_FINISHED.labels("failed").inc()
            return run

        self._persist(run, campaign, tenant, result)
        HUNTS_FINISHED.labels("halted" if result.halted else "completed").inc()
        return run

    # -- persistence -----------------------------------------------------
    def _persist(self, run: Run, campaign: Campaign, tenant: Tenant, result) -> None:
        now = datetime.now(UTC)

        rules = suppressions.active_rules(self.db, tenant.id)
        persisted: list = []
        new_findings = 0
        for finding in result.findings:
            FINDINGS_BY_SEVERITY.labels(finding.severity.value).inc()
            if suppressions.is_suppressed(rules, kind=finding.kind, fingerprint=finding.fingerprint):
                SUPPRESSED_FINDINGS.inc()
                continue
            persisted.append(finding)
            existing = self.db.scalar(
                select(Finding).where(
                    Finding.tenant_id == tenant.id,
                    Finding.fingerprint == finding.fingerprint,
                )
            )
            if existing is not None:
                # One issue seen again, not a new issue. If it had been marked
                # fixed, a recurrence is a regression and reopens it.
                existing.occurrences += 1
                existing.last_seen_at = now
                existing.last_run_id = run.id
                existing.confidence = finding.confidence
                if existing.status in {FindingStatus.fixed, FindingStatus.verified}:
                    existing.status = FindingStatus.open
                    existing.detail = finding.detail
                continue

            new_findings += 1
            self.db.add(
                Finding(
                    run_id=run.id,
                    tenant_id=tenant.id,
                    fingerprint=finding.fingerprint,
                    probe_id=finding.probe_id,
                    kind=finding.kind,
                    severity=finding.severity.value,
                    confidence=finding.confidence,
                    status=FindingStatus.open,
                    sla_due_at=datetime.now(UTC) + timedelta(hours=_sla_hours(finding.severity.value)),
                    cwe=finding.cwe,
                    title=finding.title[:255],
                    detail=finding.detail,
                    remediation=finding.remediation,
                    evidence=list(finding.evidence),
                    evidence_refs={"location": finding.location, "root": result.evidence_root},
                    occurrences=1,
                    last_seen_at=now,
                    last_run_id=run.id,
                )
            )
        FINDINGS_DETECTED.inc(len(result.findings))

        seen_digests: set[str] = set()
        for entry in result.manifest.get("entries", []):
            digest = str(entry.get("digest", ""))
            if not digest or digest in seen_digests:
                continue
            seen_digests.add(digest)
            exists = self.db.scalar(select(EvidenceBlob.id).where(EvidenceBlob.digest == digest))
            if exists is None:
                self.db.add(
                    EvidenceBlob(
                        digest=digest,
                        kind=str(entry.get("kind", "observation"))[:64],
                        label=str(entry.get("label", ""))[:512],
                        size=int(entry.get("size", 0) or 0),
                    )
                )

        for stat in result.probe_runs:
            PROBES_EXECUTED.labels(stat.probe_id, stat.status).inc()

        self._store_bandit(result.target.host, result.bandit_after)

        run.plan = result.plan.to_dict()
        run.plan_seed = result.plan.seed
        run.evidence_root = result.evidence_root or None
        run.http_status = next((obs.response.status for obs in result.observations), None)
        run.risk_score = risk.score([(finding.severity.value, finding.confidence) for finding in persisted])
        try:
            write_manifest(self.evidence_root / str(run.id) / "manifest.json", result.manifest)
        except OSError:
            logger.warning("could not persist evidence manifest for run %s", run.id, exc_info=True)
        run.lease_expires_at = None
        run.completed_at = now
        run.status = RunStatus.completed
        if result.halted:
            run.status = RunStatus.failed
            run.error_message = f"halted: {result.halted}"
        if run.cancel_requested:
            run.status = RunStatus.cancelled
            run.error_message = "cancelled by operator"
        if campaign.status != CampaignStatus.cancelled:
            campaign.status = CampaignStatus.completed if run.status == RunStatus.completed else CampaignStatus.failed

        HUNT_REQUESTS.observe(result.budget.get("used_requests", 0))
        if campaign.status == CampaignStatus.completed:
            CAMPAIGNS_COMPLETED.inc()
        self.db.commit()
        try:
            webhooks.publish(
                self.db,
                tenant_id=tenant.id,
                event="run.completed" if run.status == RunStatus.completed else "run.failed",
                payload={
                    "run_id": str(run.id),
                    "campaign_id": str(campaign.id),
                    "target": campaign.target_url,
                    "status": run.status.value,
                    "findings": new_findings,
                    "risk_score": run.risk_score,
                    "evidence_root": run.evidence_root,
                },
            )
            self.db.commit()
        except Exception:
            self.db.rollback()
            logger.warning("could not enqueue webhook events for run %s", run.id, exc_info=True)
        # Only new issues count toward the target's risk signal: recurrence is
        # evidence of a persistent problem, not of a newly discovered one.
        self._record_autonomy_outcome(campaign, success=run.status == RunStatus.completed, findings=new_findings)

    def _load_bandit(self, host: str) -> ProbeBandit:
        stats = list(self.db.scalars(select(ProbeStat).where(ProbeStat.target_host == host)))
        return ProbeBandit.from_dict({stat.probe_id: {"alpha": stat.alpha, "beta": stat.beta} for stat in stats})

    def _store_bandit(self, host: str, bandit: ProbeBandit) -> None:
        existing = {
            stat.probe_id: stat for stat in self.db.scalars(select(ProbeStat).where(ProbeStat.target_host == host))
        }
        for probe_id, arm in bandit.arms.items():
            stat = existing.get(probe_id)
            if stat is None:
                self.db.add(
                    ProbeStat(
                        probe_id=probe_id,
                        target_host=host,
                        alpha=arm.alpha,
                        beta=arm.beta,
                        trials=int(arm.trials),
                    )
                )
            else:
                stat.alpha = arm.alpha
                stat.beta = arm.beta
                stat.trials = int(arm.trials)

    def _record_autonomy_outcome(self, campaign: Campaign, *, success: bool, findings: int) -> None:
        """Feed the outcome back into autonomous scheduling (no-op for manual runs)."""

        if campaign.origin != "autonomy":
            return
        from app.services.autonomy_service import AutonomyService

        try:
            AutonomyService(self.db).record_run_outcome(campaign=campaign, success=success, findings=findings)
        except Exception:
            self.db.rollback()
            logger.warning("failed to record autonomy outcome", exc_info=True)

    # -- helpers ---------------------------------------------------------
    def _fail(self, run: Run, campaign: Campaign | None, message: str) -> None:
        run.status = RunStatus.failed
        run.completed_at = run.completed_at or datetime.now(UTC)
        run.error_message = message[:1000]
        run.lease_expires_at = None
        if campaign is not None and campaign.status != CampaignStatus.cancelled:
            campaign.status = CampaignStatus.failed
        self.db.commit()
        if campaign is not None:
            self._record_autonomy_outcome(campaign, success=False, findings=0)

    @staticmethod
    def _safety(value: str) -> SafetyClass:
        try:
            return SafetyClass[value]
        except KeyError:
            return SafetyClass.read_only
