"""Autonomous hunt controller.

The engine can decide *how* to hunt. This module decides *when* and *where*,
without a human in the loop — but only inside a standing authorization the
operator approved.

Four properties matter and each is enforced here rather than in a prompt:

1. **Bounded**: a per-day run cap, a per-run request budget, a minimum interval
   and a safety ceiling. All are hard checks.
2. **Explainable**: every launch or refusal is written to ``autonomy_decisions``
   with a utility score and a reason. "Why did it scan that?" has an answer.
3. **Self-correcting**: consecutive failures back a target off exponentially and
   eventually disable it; success resets the streak.
4. **Self-improving**: the probe set for each launch is derived from the
   per-target Beta posteriors (``probe_stats``), so autonomy inherits everything
   the bandit has learned about that host.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit
from uuid import UUID
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.engine.evolution import Genome
from app.models import (
    AutonomyDecision,
    AutonomyPolicy,
    Campaign,
    CampaignStatus,
    HuntTarget,
    ProbeStat,
    RunStatus,
    Tenant,
)
from app.services.audit_service import AuditService

logger = logging.getLogger(__name__)

ALLOWED_CEILINGS = {"read_only", "state_changing"}
ALLOWED_SOURCES = {"granted", "discovered"}
QUIET_HOURS_MAX = 23


class AutonomyError(ValueError):
    """A policy or controller action that would exceed its authorization."""


def _zone(name: str):
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, KeyError):
        # No tzdata on the host: scheduling still works, in UTC.
        return UTC


def _aware(value: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes even for timezone-aware columns."""

    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def _origin(url: str) -> str:
    parts = urlsplit(url)
    default = 443 if parts.scheme == "https" else 80
    suffix = "" if (parts.port or default) == default else f":{parts.port}"
    return f"{parts.scheme.lower()}://{(parts.hostname or '').lower()}{suffix}"


@dataclass(frozen=True)
class Decision:
    action: str
    target_url: str
    reason: str
    utility: float = 0.0
    run_id: UUID | None = None
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "action": self.action,
            "target_url": self.target_url,
            "reason": self.reason,
            "utility": round(self.utility, 4),
            "run_id": str(self.run_id) if self.run_id else None,
            "detail": self.detail,
        }


@dataclass
class TickReport:
    tenant_id: UUID
    action: str
    reason: str
    target_url: str = ""
    run_id: UUID | None = None
    utility: float = 0.0
    decisions: list[Decision] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "tenant_id": str(self.tenant_id),
            "action": self.action,
            "reason": self.reason,
            "target_url": self.target_url,
            "run_id": str(self.run_id) if self.run_id else None,
            "utility": round(self.utility, 4),
            "decisions": [decision.to_dict() for decision in self.decisions],
        }


class AutonomyService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.audit = AuditService(db)

    # -- policy ----------------------------------------------------------
    def get_policy(self, tenant_id: UUID) -> AutonomyPolicy | None:
        return self.db.scalar(select(AutonomyPolicy).where(AutonomyPolicy.tenant_id == tenant_id))

    def upsert_policy(
        self,
        *,
        tenant: Tenant,
        enabled: bool,
        target_allowlist: list[str],
        safety_ceiling: str,
        budget_requests_per_run: int,
        max_runs_per_day: int,
        min_interval_minutes: int,
        quiet_hours_start: int | None,
        quiet_hours_end: int | None,
        tz_name: str,
        max_consecutive_failures: int,
        min_utility: float,
        mode: str = "hunt",
        objective_template: str = "posture",
        max_objectives_per_day: int = 4,
        objective_budget_requests: int = 120,
        escalation_cooldown_minutes: int = 180,
        template_auto: bool = True,
        narrow_on_retry: bool = True,
        max_active_objectives: int = 2,
        daily_objective_requests: int = 400,
        approved_by: str,
        approval_statement: str,
        actor: str,
        request_id: str | None,
    ) -> AutonomyPolicy:
        if safety_ceiling not in ALLOWED_CEILINGS:
            raise AutonomyError(
                f"autonomy safety_ceiling must be one of {sorted(ALLOWED_CEILINGS)}; destructive is never autonomous"
            )
        if not 1 <= budget_requests_per_run <= 1000:
            raise AutonomyError("budget_requests_per_run must be between 1 and 1000")
        if not 1 <= max_runs_per_day <= 96:
            raise AutonomyError("max_runs_per_day must be between 1 and 96")
        if not 5 <= min_interval_minutes <= 10080:
            raise AutonomyError("min_interval_minutes must be between 5 and 10080")
        if not 1 <= max_consecutive_failures <= 20:
            raise AutonomyError("max_consecutive_failures must be between 1 and 20")
        if not 0.0 <= min_utility <= 1.0:
            raise AutonomyError("min_utility must be between 0 and 1")
        if mode not in {"hunt", "objective"}:
            raise AutonomyError("mode must be 'hunt' (schedule campaigns) or 'objective' (delegate work)")
        if objective_template not in {"posture", "auth", "exposure", "coverage", "adaptive", "custom"}:
            raise AutonomyError("unknown objective_template")
        if not 1 <= max_objectives_per_day <= 96:
            raise AutonomyError("max_objectives_per_day must be between 1 and 96")
        if not 20 <= objective_budget_requests <= 5000:
            raise AutonomyError("objective_budget_requests must be between 20 and 5000")
        if not 15 <= escalation_cooldown_minutes <= 10080:
            raise AutonomyError("escalation_cooldown_minutes must be between 15 and 10080")
        if not 1 <= max_active_objectives <= 16:
            raise AutonomyError("max_active_objectives must be between 1 and 16")
        if not 20 <= daily_objective_requests <= 100000:
            raise AutonomyError("daily_objective_requests must be between 20 and 100000")
        for value in (quiet_hours_start, quiet_hours_end):
            if value is not None and not 0 <= value <= QUIET_HOURS_MAX:
                raise AutonomyError("quiet hours must be hours 0-23")
        if (quiet_hours_start is None) != (quiet_hours_end is None):
            raise AutonomyError("quiet_hours_start and quiet_hours_end must be set together")
        _zone(tz_name)  # validate; falls back silently only when tzdata is absent

        normalized = self._authorized_allowlist(tenant, target_allowlist)

        if enabled and not approval_statement.strip():
            raise AutonomyError("enabling autonomy requires an approval statement describing the granted authority")

        policy = self.get_policy(tenant.id)
        created = policy is None
        if policy is None:
            policy = AutonomyPolicy(tenant_id=tenant.id)
            self.db.add(policy)

        was_enabled = policy.enabled
        policy.enabled = enabled
        policy.target_allowlist = normalized
        policy.safety_ceiling = safety_ceiling
        policy.budget_requests_per_run = budget_requests_per_run
        policy.max_runs_per_day = max_runs_per_day
        policy.min_interval_minutes = min_interval_minutes
        policy.quiet_hours_start = quiet_hours_start
        policy.quiet_hours_end = quiet_hours_end
        policy.timezone = tz_name
        policy.max_consecutive_failures = max_consecutive_failures
        policy.min_utility = min_utility
        policy.mode = mode
        policy.objective_template = objective_template
        policy.max_objectives_per_day = max_objectives_per_day
        policy.objective_budget_requests = objective_budget_requests
        policy.escalation_cooldown_minutes = escalation_cooldown_minutes
        policy.template_auto = template_auto
        policy.narrow_on_retry = narrow_on_retry
        policy.max_active_objectives = max_active_objectives
        policy.daily_objective_requests = daily_objective_requests

        if approval_statement.strip():
            approved_at = datetime.now(UTC)
            statement = approval_statement.strip()[:1024]
            policy.approved_by = approved_by[:255] or actor[:255]
            policy.approval_statement = statement
            policy.approved_at = approved_at
            policy.approval_sha256 = hashlib.sha256(
                f"{tenant.id}|{statement}|{approved_at.isoformat()}".encode()
            ).hexdigest()

        self.db.flush()
        self._sync_targets(policy)

        self.audit.record(
            tenant_id=tenant.id,
            action="autonomy.policy.update",
            details={
                "enabled": enabled,
                "targets": normalized,
                "safety_ceiling": safety_ceiling,
                "budget_requests_per_run": budget_requests_per_run,
                "max_runs_per_day": max_runs_per_day,
                "min_interval_minutes": min_interval_minutes,
                "approval_sha256": policy.approval_sha256,
                "created": created,
                "transition": f"{was_enabled}->{enabled}",
            },
            user_id=actor,
            resource_type="autonomy_policy",
            resource_id=str(policy.id),
            request_id=request_id,
        )
        self.db.commit()
        self.db.refresh(policy)
        return policy

    def set_enabled(
        self, *, tenant: Tenant, enabled: bool, actor: str, request_id: str | None, reason: str = ""
    ) -> AutonomyPolicy:
        policy = self.get_policy(tenant.id)
        if policy is None:
            raise AutonomyError("no autonomy policy exists for this tenant")
        if enabled and not policy.approval_sha256:
            raise AutonomyError("policy has no recorded approval; re-submit with an approval statement")
        policy.enabled = enabled
        self.audit.record(
            tenant_id=tenant.id,
            action="autonomy.pause" if not enabled else "autonomy.resume",
            details={"reason": reason},
            user_id=actor,
            resource_type="autonomy_policy",
            resource_id=str(policy.id),
            request_id=request_id,
        )
        self.db.commit()
        self.db.refresh(policy)
        return policy

    def kill(self, *, tenant: Tenant, actor: str, request_id: str | None, reason: str = "operator kill switch") -> int:
        """Disable autonomy and cancel anything it currently has in flight."""

        from app.models import Campaign as CampaignModel
        from app.models import Run

        policy = self.get_policy(tenant.id)
        cancelled = 0
        if policy is not None:
            policy.enabled = False

        active = list(
            self.db.scalars(
                select(Run).where(
                    Run.tenant_id == tenant.id,
                    Run.status.in_([RunStatus.queued, RunStatus.running]),
                )
            )
        )
        for run in active:
            run.cancel_requested = True
            cancelled += 1
            campaign = self.db.get(CampaignModel, run.campaign_id)
            if campaign is not None and campaign.origin == "autonomy":
                campaign.status = CampaignStatus.cancelled
                if run.status == RunStatus.queued:
                    run.status = RunStatus.cancelled
                    run.completed_at = datetime.now(UTC)

        self.audit.record(
            tenant_id=tenant.id,
            action="autonomy.kill",
            details={"cancelled_runs": cancelled, "reason": reason},
            user_id=actor,
            resource_type="autonomy_policy",
            resource_id=str(policy.id) if policy else "",
            request_id=request_id,
        )
        self.db.commit()
        return cancelled

    # -- targets ---------------------------------------------------------
    def sync_targets_now(self, tenant: Tenant) -> int:
        policy = self.get_policy(tenant.id)
        if policy is None:
            return 0
        return self._sync_targets(policy)

    def _sync_targets(self, policy: AutonomyPolicy) -> int:
        existing = {
            target.url: target
            for target in self.db.scalars(select(HuntTarget).where(HuntTarget.tenant_id == policy.tenant_id))
        }
        created = 0
        allowlist = set(policy.target_allowlist or [])
        for url in sorted(allowlist):
            target = existing.get(url)
            if target is None:
                self.db.add(HuntTarget(tenant_id=policy.tenant_id, url=url, enabled=True, source="granted"))
                created += 1
            elif not target.enabled and target.consecutive_failures == 0:
                target.enabled = True
        # Targets removed from the allowlist stop being scheduled but keep history.
        for url, target in existing.items():
            if url not in allowlist:
                target.enabled = False
        self.db.flush()
        return created

    @staticmethod
    def _authorized_allowlist(tenant: Tenant, requested: list[str]) -> list[str]:
        authorized = {_origin(item) for item in (tenant.authorized_targets or [])}
        if not requested:
            return sorted(authorized)
        normalized: set[str] = set()
        for item in requested:
            origin = _origin(item.strip())
            if origin not in authorized:
                raise AutonomyError(
                    f"target {origin!r} is not in the tenant's authorized targets; autonomy cannot widen scope"
                )
            normalized.add(origin)
        return sorted(normalized)

    # -- scheduling ------------------------------------------------------
    def daily_runs_used(self, tenant_id: UUID, now: datetime, tz_name: str) -> int:
        zone = _zone(tz_name)
        local_now = now.astimezone(zone)
        local_midnight = local_now.replace(hour=0, minute=0, second=0, microsecond=0)
        since = local_midnight.astimezone(UTC)
        return int(
            self.db.scalar(
                select(func.count())
                .select_from(Campaign)
                .where(
                    Campaign.tenant_id == tenant_id,
                    Campaign.origin == "autonomy",
                    Campaign.created_at >= since,
                )
            )
            or 0
        )

    def _active_target_urls(self, tenant_id: UUID) -> set[str]:
        rows = self.db.scalars(
            select(Campaign.target_url).where(
                Campaign.tenant_id == tenant_id,
                Campaign.status.in_([CampaignStatus.queued, CampaignStatus.running]),
            )
        )
        return {_origin(url) for url in rows}

    def utility(self, target: HuntTarget, *, now: datetime, policy: AutonomyPolicy) -> float:
        """Scheduling score: staleness, accumulated risk, novelty, reliability."""

        interval_hours = max(1, policy.min_interval_minutes) / 60.0
        last_run_at = _aware(target.last_run_at)
        if last_run_at is None:
            staleness = 1.0
        else:
            age_hours = max(0.0, (now - last_run_at).total_seconds() / 3600.0)
            staleness = min(1.0, age_hours / max(interval_hours * 4.0, 1.0))

        # A target that has produced issues historically deserves attention.
        risk = min(1.0, target.findings_total / 10.0)
        novelty = 1.0 / (1.0 + 0.5 * target.runs_total)
        reliability_penalty = min(0.9, 0.3 * target.consecutive_failures)
        return max(0.0, 0.45 * staleness + 0.30 * risk + 0.25 * novelty - reliability_penalty)

    def _is_quiet(self, policy: AutonomyPolicy, now: datetime) -> bool:
        if policy.quiet_hours_start is None or policy.quiet_hours_end is None:
            return False
        hour = now.astimezone(_zone(policy.timezone)).hour
        start, end = policy.quiet_hours_start, policy.quiet_hours_end
        if start == end:
            return False
        if start < end:
            return start <= hour < end
        return hour >= start or hour < end  # wraps midnight

    def _recent_decision(self, tenant_id: UUID, action: str, reason: str, *, within_minutes: int = 55) -> bool:
        cutoff = datetime.now(UTC) - timedelta(minutes=within_minutes)
        return (
            self.db.scalar(
                select(AutonomyDecision.id).where(
                    AutonomyDecision.tenant_id == tenant_id,
                    AutonomyDecision.action == action,
                    AutonomyDecision.reason == reason,
                    AutonomyDecision.at >= cutoff,
                )
            )
            is not None
        )

    def _record(self, tenant_id: UUID, decision: Decision, *, now: datetime) -> AutonomyDecision:
        row = AutonomyDecision(
            tenant_id=tenant_id,
            action=decision.action,
            target_url=decision.target_url[:2048],
            reason=decision.reason[:512],
            utility=decision.utility,
            run_id=decision.run_id,
            detail=decision.detail,
            at=now,
        )
        self.db.add(row)
        return row

    def derive_genome(self, host: str, policy: AutonomyPolicy) -> dict:
        """Build a probe set from what the bandit has learned about this host."""

        stats = list(self.db.scalars(select(ProbeStat).where(ProbeStat.target_host == host)))
        if not stats:
            return {}
        ranked = sorted(stats, key=lambda stat: stat.alpha / max(1e-9, stat.alpha + stat.beta), reverse=True)
        probes = ["surface-crawl"]
        for stat in ranked:
            if stat.probe_id not in probes and len(probes) < 9:
                probes.append(stat.probe_id)
        genome = Genome(
            probes=tuple(probes),
            budget_requests=policy.budget_requests_per_run,
            rps=settings.hunt_max_rps,
            route_bias="value",
            aggression=0.4,
        )
        return genome.to_dict()

    def tick_policy(self, policy: AutonomyPolicy, *, now: datetime | None = None, force: bool = False) -> TickReport:
        now = now or datetime.now(UTC)

        if not force and not settings.autonomy_enabled:
            return TickReport(policy.tenant_id, "disabled", "global autonomy switch is off")
        if not policy.enabled:
            return TickReport(policy.tenant_id, "disabled", "policy is paused")
        if self._is_quiet(policy, now):
            return TickReport(policy.tenant_id, "skip", "quiet hours")

        if policy.mode == "objective":
            return self._tick_objective_mode(policy, now=now)

        used = self.daily_runs_used(policy.tenant_id, now, policy.timezone)
        if used >= policy.max_runs_per_day:
            reason = f"daily cap reached ({used}/{policy.max_runs_per_day})"
            if not self._recent_decision(policy.tenant_id, "skip", reason):
                self._record(policy.tenant_id, Decision("skip", "", reason, 0.0), now=now)
                self.db.commit()
            return TickReport(policy.tenant_id, "skip", reason)

        targets = list(
            self.db.scalars(
                select(HuntTarget).where(HuntTarget.tenant_id == policy.tenant_id, HuntTarget.enabled.is_(True))
            )
        )
        if not targets:
            return TickReport(policy.tenant_id, "skip", "no enabled hunt targets")

        active = self._active_target_urls(policy.tenant_id)
        candidates: list[tuple[float, HuntTarget]] = []
        for target in targets:
            if target.consecutive_failures >= policy.max_consecutive_failures:
                continue
            next_eligible_at = _aware(target.next_eligible_at)
            if next_eligible_at is not None and next_eligible_at > now:
                continue
            if _origin(target.url) in active:
                continue
            candidates.append((self.utility(target, now=now, policy=policy), target))

        if not candidates:
            reason = "no eligible target (backoff or in-flight run)"
            if not self._recent_decision(policy.tenant_id, "skip", reason):
                self._record(policy.tenant_id, Decision("skip", "", reason, 0.0), now=now)
                self.db.commit()
            return TickReport(policy.tenant_id, "skip", reason)

        candidates.sort(key=lambda item: item[0], reverse=True)
        score, target = candidates[0]
        if score < policy.min_utility:
            reason = f"best utility {score:.3f} below threshold {policy.min_utility:.3f}"
            if not self._recent_decision(policy.tenant_id, "skip", reason):
                self._record(policy.tenant_id, Decision("skip", target.url, reason, score), now=now)
                self.db.commit()
            return TickReport(policy.tenant_id, "skip", reason, target.url, utility=score)

        tenant = self.db.get(Tenant, policy.tenant_id)
        if tenant is None:
            return TickReport(policy.tenant_id, "skip", "tenant missing")

        # probe_stats is keyed by hostname (what the engine reports), not by origin.
        genome = self.derive_genome(urlsplit(target.url).hostname or "", policy)
        try:
            from app.services.campaign_service import CampaignService

            service = CampaignService(self.db)
            campaign = service.create_campaign(
                tenant=tenant,
                name=f"autonomy {target.url} {now.date().isoformat()}",
                target_url=target.url,
                authorization_attested=True,
                scheduled_at=None,
                actor=f"autonomy:{policy.id}",
                request_id=None,
                safety_ceiling=policy.safety_ceiling,
                budget_requests=policy.budget_requests_per_run,
                mode="agentic",
                origin="autonomy",
                genome=genome,
            )
            run = service.create_run(
                campaign_id=campaign.id,
                tenant_id=tenant.id,
                actor=f"autonomy:{policy.id}",
                request_id=None,
            )
        except (ValueError, LookupError) as exc:
            reason = f"launch refused: {exc}"
            self._record(policy.tenant_id, Decision("skip", target.url, reason, score), now=now)
            self.db.commit()
            logger.info("autonomy launch refused for %s: %s", target.url, exc)
            return TickReport(policy.tenant_id, "skip", reason, target.url, utility=score)

        target.last_run_at = now
        target.last_status = "queued"
        target.last_run_id = run.id
        target.runs_total += 1
        target.next_eligible_at = now + timedelta(minutes=policy.min_interval_minutes)
        policy.last_tick_at = now

        probe_count = len(genome.get("probes", []))
        basis = f"{probe_count} learned probes" if probe_count else "default probe set (no priors yet)"
        decision = Decision(
            "hunt",
            target.url,
            f"utility {score:.3f} (staleness/risk/novelty) with {basis}",
            score,
            run.id,
            {"campaign_id": str(campaign.id), "genome": genome, "daily_runs_used": used + 1},
        )
        self._record(policy.tenant_id, decision, now=now)
        self.db.commit()

        logger.info(
            "autonomous hunt launched",
            extra={
                "tenant_id": str(policy.tenant_id),
                "target": target.url,
                "run_id": str(run.id),
                "utility": round(score, 4),
            },
        )
        return TickReport(
            policy.tenant_id,
            "hunt",
            decision.reason,
            target.url,
            run.id,
            score,
            [decision],
        )

    def tick_all(self, *, now: datetime | None = None, force: bool = False) -> list[TickReport]:
        now = now or datetime.now(UTC)
        policies = list(self.db.scalars(select(AutonomyPolicy).where(AutonomyPolicy.enabled.is_(True))))
        return [self.tick_policy(policy, now=now, force=force) for policy in policies]

    # -- outcome feedback -------------------------------------------------
    def record_run_outcome(self, *, campaign: Campaign, success: bool, findings: int) -> None:
        """Fold a finished run back into the target's scheduling state."""

        if campaign.origin != "autonomy":
            return
        target = self.db.scalar(
            select(HuntTarget).where(
                HuntTarget.tenant_id == campaign.tenant_id,
                HuntTarget.url == campaign.target_url,
            )
        )
        if target is None:
            return

        policy = self.get_policy(campaign.tenant_id)
        now = datetime.now(UTC)
        target.last_status = "completed" if success else "failed"
        target.last_findings = findings
        if success:
            target.consecutive_failures = 0
            target.findings_total += findings
        else:
            target.consecutive_failures += 1
            base = max(5, policy.min_interval_minutes if policy else 60)
            backoff = min(24 * 60, base * (2**target.consecutive_failures))
            target.next_eligible_at = now + timedelta(minutes=backoff)
            if policy is not None and target.consecutive_failures >= policy.max_consecutive_failures:
                target.enabled = False
                self._record(
                    campaign.tenant_id,
                    Decision(
                        "disable",
                        target.url,
                        f"disabled after {target.consecutive_failures} consecutive failures",
                        0.0,
                        detail={"backoff_minutes": backoff},
                    ),
                    now=now,
                )
        self.db.commit()

    # -- objective mode ---------------------------------------------------
    def _tick_objective_mode(self, policy: AutonomyPolicy, *, now: datetime) -> TickReport:
        """Delegate a work objective instead of scheduling another raw hunt.

        Selection is surgical: the target with the best utility wins, then the
        template that covers the most *unproven* doctrine is chosen for it.
        """

        used = self.daily_objectives_used(policy.tenant_id, now, policy.timezone)
        if used >= policy.max_objectives_per_day:
            reason = f"daily objective cap reached ({used}/{policy.max_objectives_per_day})"
            if not self._recent_decision(policy.tenant_id, "skip", reason):
                self._record(policy.tenant_id, Decision("skip", "", reason, 0.0), now=now)
                self.db.commit()
            return TickReport(policy.tenant_id, "skip", reason)

        targets = list(
            self.db.scalars(
                select(HuntTarget).where(HuntTarget.tenant_id == policy.tenant_id, HuntTarget.enabled.is_(True))
            )
        )
        if not targets:
            return TickReport(policy.tenant_id, "skip", "no enabled hunt targets")

        active_targets = self._active_objective_targets(policy.tenant_id)
        if len(active_targets) >= max(1, policy.max_active_objectives):
            reason = (
                f"fleet is full ({len(active_targets)}/{policy.max_active_objectives} active objective(s)); "
                "waiting for one to finish before delegating more"
            )
            if not self._recent_decision(policy.tenant_id, "skip", reason):
                self._record(policy.tenant_id, Decision("skip", "", reason, 0.0), now=now)
                self.db.commit()
            return TickReport(policy.tenant_id, "skip", reason)

        requests_today = self.daily_objective_requests_used(policy.tenant_id, now, policy.timezone)
        if requests_today >= policy.daily_objective_requests:
            reason = f"daily objective request budget spent ({requests_today}/{policy.daily_objective_requests})"
            if not self._recent_decision(policy.tenant_id, "skip", reason):
                self._record(policy.tenant_id, Decision("skip", "", reason, 0.0), now=now)
                self.db.commit()
            return TickReport(policy.tenant_id, "skip", reason)

        candidates: list[tuple[float, HuntTarget]] = []
        for target in targets:
            if target.consecutive_failures >= policy.max_consecutive_failures:
                continue
            next_eligible = _aware(target.next_eligible_at)
            if next_eligible is not None and next_eligible > now:
                continue
            if _origin(target.url) in active_targets:
                continue
            candidates.append((self.utility(target, now=now, policy=policy), target))

        if not candidates:
            reason = "no eligible target for a delegated objective"
            if not self._recent_decision(policy.tenant_id, "skip", reason):
                self._record(policy.tenant_id, Decision("skip", "", reason, 0.0), now=now)
                self.db.commit()
            return TickReport(policy.tenant_id, "skip", reason)

        candidates.sort(key=lambda item: item[0], reverse=True)
        score, target = candidates[0]
        tenant = self.db.get(Tenant, policy.tenant_id)
        if tenant is None:
            return TickReport(policy.tenant_id, "skip", "tenant missing")

        narrow = self._narrow_retry(policy, target, now) if policy.narrow_on_retry else None
        if narrow is not None:
            template, criteria_payload, retry_of = narrow
            action = "delegate-narrow"
        else:
            criteria_payload, retry_of = None, ""
            template = policy.objective_template
            if policy.template_auto or template in {"custom", "auto"}:
                template = self._choose_template(policy, target)
            cooldown_key = f"objective escalation cooldown ({template})"
            if self._recent_decision(
                policy.tenant_id, "escalate", cooldown_key, within_minutes=policy.escalation_cooldown_minutes
            ):
                reason = f"{template} objective for {target.url} is cooling down after an earlier block"
                return TickReport(policy.tenant_id, "skip", reason, target.url, utility=score)
            action = "delegate"

        alternatives = [
            {"target": candidate.url, "utility": round(utility, 4)} for utility, candidate in candidates[1:3]
        ][:2]

        from app.services.objective_service import ObjectiveError, ObjectiveService

        try:
            objective = ObjectiveService(self.db).create(
                tenant=tenant,
                title=(
                    f"{template} retry for {_origin(target.url)}"
                    if narrow is not None
                    else f"{template} objective for {_origin(target.url)}"
                ),
                target_url=target.url,
                template=template,
                budget_requests=policy.objective_budget_requests,
                per_task_budget=max(8, policy.objective_budget_requests // 8),
                criteria_payload=criteria_payload,
                safety_ceiling=policy.safety_ceiling,
                priority=max(1, min(10, 10 - int(score * 5))),
                deadline_minutes=240,
                description=(
                    "Narrow retry: the previous objective blocked on these criteria and only these are requested now."
                    if narrow is not None
                    else "Delegated by the autonomy controller. Complete only when every acceptance criterion "
                    "is verified."
                ),
                actor=f"autonomy:{policy.id}",
                origin="autonomy",
            )
        except (ObjectiveError, ValueError) as exc:
            reason = f"delegation refused: {exc}"
            self._record(policy.tenant_id, Decision("skip", target.url, reason, score), now=now)
            self.db.commit()
            return TickReport(policy.tenant_id, "skip", reason, target.url, utility=score)

        target.last_status = "objective"
        target.runs_total += 1
        target.next_eligible_at = now + timedelta(minutes=policy.min_interval_minutes)
        policy.last_tick_at = now

        history = dict(policy.template_history or {})
        rotation = list(history.get(_origin(target.url), []))
        rotation.append(template)
        history[_origin(target.url)] = rotation[-5:]
        policy.template_history = history

        decision = Decision(
            action,
            target.url,
            (
                f"delegated narrow retry {objective.key} of {retry_of} ({len(criteria_payload or [])} criterion/criteria)"
                if narrow is not None
                else f"delegated {template} objective {objective.key} "
                f"(utility {score:.3f}, {objective.budget_requests} requests)"
            ),
            score,
            None,
            {
                "objective_id": str(objective.id),
                "template": template,
                "criteria": objective.criteria,
                "narrow_retry": narrow is not None,
                "retry_of": retry_of,
                "alternatives_considered": alternatives,
            },
        )
        self._record(policy.tenant_id, decision, now=now)
        self.db.commit()
        logger.info(
            "autonomous objective delegated",
            extra={
                "tenant_id": str(policy.tenant_id),
                "target": target.url,
                "objective": objective.key,
                "template": template,
            },
        )
        return TickReport(
            policy.tenant_id,
            action,
            decision.reason,
            target.url,
            None,
            score,
            [decision],
        )

    def daily_objectives_used(self, tenant_id: UUID, now: datetime, tz_name: str) -> int:
        from app.models import Objective

        zone = _zone(tz_name)
        local_now = now.astimezone(zone)
        local_midnight = local_now.replace(hour=0, minute=0, second=0, microsecond=0)
        since = local_midnight.astimezone(UTC)
        return int(
            self.db.scalar(
                select(func.count())
                .select_from(Objective)
                .where(
                    Objective.tenant_id == tenant_id,
                    Objective.origin == "autonomy",
                    Objective.created_at >= since,
                )
            )
            or 0
        )

    def _active_objective_targets(self, tenant_id: UUID) -> set[str]:
        from app.models import Objective

        rows = self.db.scalars(
            select(Objective.target_url).where(
                Objective.tenant_id == tenant_id,
                Objective.status.in_(["queued", "running"]),
            )
        )
        return {_origin(url) for url in rows}

    def daily_objective_requests_used(self, tenant_id: UUID, now: datetime, tz_name: str) -> int:
        from app.models import Objective

        zone = _zone(tz_name)
        local_now = now.astimezone(zone)
        since = local_now.replace(hour=0, minute=0, second=0, microsecond=0).astimezone(UTC)
        total = self.db.scalar(
            select(func.coalesce(func.sum(Objective.budget_requests), 0)).where(
                Objective.tenant_id == tenant_id,
                Objective.origin == "autonomy",
                Objective.created_at >= since,
            )
        )
        return int(total or 0)

    def _narrow_retry(
        self, policy: AutonomyPolicy, target: HuntTarget, now: datetime
    ) -> tuple[str, list[dict], str] | None:
        """Return the criteria that blocked the last objective, once cooldown elapsed.

        This is the escalation ladder: instead of re-running an entire doctrine
        and hoping the missing observation appears, ask only for the observation
        that was missing.
        """

        origin = _origin(target.url)
        row = self.db.scalar(
            select(AutonomyDecision)
            .where(
                AutonomyDecision.tenant_id == policy.tenant_id,
                AutonomyDecision.action == "escalate",
                AutonomyDecision.target_url == origin,
            )
            .order_by(AutonomyDecision.at.desc())
            .limit(1)
        )
        if row is None:
            return None
        detail = dict(row.detail or {})
        criteria = list(detail.get("failed_criteria") or [])
        if not criteria:
            return None
        blocked_at = _aware(row.at)
        if blocked_at is None or blocked_at > now - timedelta(minutes=policy.escalation_cooldown_minutes):
            return None
        retry_of = str(detail.get("objective_id", ""))
        already = self.db.scalar(
            select(AutonomyDecision.id).where(
                AutonomyDecision.tenant_id == policy.tenant_id,
                AutonomyDecision.action == "delegate-narrow",
                AutonomyDecision.target_url == origin,
            )
        )
        if already is not None and retry_of:
            for prior in self.db.scalars(
                select(AutonomyDecision).where(
                    AutonomyDecision.tenant_id == policy.tenant_id,
                    AutonomyDecision.action == "delegate-narrow",
                    AutonomyDecision.target_url == origin,
                )
            ):
                if str((prior.detail or {}).get("retry_of", "")) == retry_of:
                    return None
        template = str(detail.get("template") or policy.objective_template or "posture")
        return template, criteria, retry_of

    def _choose_template(self, policy: AutonomyPolicy, target: HuntTarget) -> str:
        """Pick the doctrine with the largest unproven surface for this host.

        Coverage is estimated from the bandit: a probe with recorded trials on
        this host has been exercised, one with none has not. The template whose
        probes are least covered wins, which keeps autonomy from re-running the
        same three checks forever.
        """

        from app.engine.workforce.decompose import TEMPLATE_PROBES
        from app.models import ProbeStat

        host = urlsplit(target.url).hostname or ""
        tried = {stat.probe_id for stat in self.db.scalars(select(ProbeStat).where(ProbeStat.target_host == host))}
        recent = set((policy.template_history or {}).get(_origin(target.url), [])[-1:])
        scored: list[tuple[int, int, str]] = []
        for template, probes in TEMPLATE_PROBES.items():
            if template == "coverage":
                continue
            gap = len([probe for probe in probes if probe not in tried])
            # Prefer the largest unproven surface; rotate away from the template
            # used last so a single doctrine cannot monopolise a target.
            scored.append((-gap, 1 if template in recent else 0, template))
        scored.sort()
        if not scored:
            return "posture"
        best_gap = -scored[0][0]
        fresh = [item for item in scored if -item[0] == best_gap and item[1] == 0]
        return (fresh or [scored[0]])[0][2]

    def record_objective_outcome(self, objective) -> None:
        """Fold an objective's verdict back into scheduling state and decisions."""

        # Hunt targets are stored as origins; an objective stores a full URL with
        # a path. Compare origins, not raw strings.
        objective_origin = _origin(objective.target_url)
        target = None
        for candidate in self.db.scalars(select(HuntTarget).where(HuntTarget.tenant_id == objective.tenant_id)):
            if _origin(candidate.url) == objective_origin:
                target = candidate
                break
        if target is None:
            return
        policy = self.get_policy(objective.tenant_id)
        now = datetime.now(UTC)
        completed = objective.status == "completed"
        findings = int((objective.result or {}).get("evidence", {}).get("findings", 0) or 0)

        report = objective.result or {}
        failed_criteria: list[dict] = []
        for item in report.get("criteria", []) or []:
            if not item.get("satisfied", False) and item.get("required", True):
                failed_criteria.append(
                    {
                        "kind": item.get("kind"),
                        "value": item.get("value"),
                        "key": item.get("key", ""),
                        "label": item.get("description", ""),
                        "required": True,
                    }
                )

        target.last_status = objective.status
        target.last_findings = findings
        if completed:
            target.consecutive_failures = 0
            target.findings_total += findings
        else:
            target.consecutive_failures += 1
            cooldown = policy.escalation_cooldown_minutes if policy else 180
            target.next_eligible_at = now + timedelta(minutes=cooldown)
            self._record(
                objective.tenant_id,
                Decision(
                    "escalate",
                    _origin(objective.target_url),
                    f"objective escalation cooldown ({objective.template})",
                    0.0,
                    detail={
                        "objective_id": str(objective.id),
                        "template": objective.template,
                        "status": objective.status,
                        "verdict": objective.verdict[:400],
                        "cooldown_minutes": cooldown,
                        "failed_criteria": failed_criteria,
                    },
                ),
                now=now,
            )
        self.db.commit()
