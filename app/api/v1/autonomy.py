from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import require_scope
from app.db.session import get_db
from app.models import AutonomyDecision, AutonomyPolicy, HuntTarget, Tenant
from app.services.autonomy_service import AutonomyError, AutonomyService

router = APIRouter(prefix="/api/v1/autonomy", tags=["autonomy"])


class AutonomyPolicyUpsert(BaseModel):
    enabled: bool = False
    target_allowlist: list[str] = Field(default_factory=list)
    mode: Literal["hunt", "objective"] = "hunt"
    objective_template: str = "posture"
    max_objectives_per_day: int = Field(default=4, ge=1, le=96)
    objective_budget_requests: int = Field(default=120, ge=20, le=5000)
    escalation_cooldown_minutes: int = Field(default=180, ge=15, le=10080)
    safety_ceiling: Literal["read_only", "state_changing"] = "read_only"
    budget_requests_per_run: int = Field(default=120, ge=1, le=1000)
    max_runs_per_day: int = Field(default=8, ge=1, le=96)
    min_interval_minutes: int = Field(default=60, ge=5, le=10080)
    quiet_hours_start: int | None = Field(default=None, ge=0, le=23)
    quiet_hours_end: int | None = Field(default=None, ge=0, le=23)
    timezone: str = "UTC"
    max_consecutive_failures: int = Field(default=3, ge=1, le=20)
    min_utility: float = Field(default=0.08, ge=0.0, le=1.0)
    approved_by: str = Field(default="", max_length=255)
    approval_statement: str = Field(default="", max_length=1024)


class AutonomyPolicyResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    enabled: bool
    target_allowlist: list[str]
    safety_ceiling: str
    budget_requests_per_run: int
    max_runs_per_day: int
    min_interval_minutes: int
    quiet_hours_start: int | None
    quiet_hours_end: int | None
    timezone: str
    max_consecutive_failures: int
    min_utility: float
    mode: str
    objective_template: str
    max_objectives_per_day: int
    objective_budget_requests: int
    escalation_cooldown_minutes: int
    approved_by: str
    approval_statement: str
    approval_sha256: str
    approved_at: datetime | None
    last_tick_at: datetime | None


class TargetStatus(BaseModel):
    url: str
    enabled: bool
    source: str
    last_run_at: datetime | None
    last_status: str
    next_eligible_at: datetime | None
    consecutive_failures: int
    runs_total: int
    findings_total: int
    utility: float


class DecisionResponse(BaseModel):
    id: UUID
    at: datetime
    action: str
    target_url: str
    reason: str
    utility: float
    run_id: UUID | None


class AutonomyStatus(BaseModel):
    policy: AutonomyPolicyResponse | None
    global_enabled: bool
    daily_runs_used: int
    daily_cap: int
    in_quiet_hours: bool
    targets: list[TargetStatus]
    recent_decisions: list[DecisionResponse]


def _policy_response(policy: AutonomyPolicy) -> AutonomyPolicyResponse:
    return AutonomyPolicyResponse(
        id=policy.id,
        tenant_id=policy.tenant_id,
        enabled=policy.enabled,
        target_allowlist=list(policy.target_allowlist or []),
        safety_ceiling=policy.safety_ceiling,
        budget_requests_per_run=policy.budget_requests_per_run,
        max_runs_per_day=policy.max_runs_per_day,
        min_interval_minutes=policy.min_interval_minutes,
        quiet_hours_start=policy.quiet_hours_start,
        quiet_hours_end=policy.quiet_hours_end,
        timezone=policy.timezone,
        max_consecutive_failures=policy.max_consecutive_failures,
        min_utility=policy.min_utility,
        mode=policy.mode,
        objective_template=policy.objective_template,
        max_objectives_per_day=policy.max_objectives_per_day,
        objective_budget_requests=policy.objective_budget_requests,
        escalation_cooldown_minutes=policy.escalation_cooldown_minutes,
        approved_by=policy.approved_by,
        approval_statement=policy.approval_statement,
        approval_sha256=policy.approval_sha256,
        approved_at=policy.approved_at,
        last_tick_at=policy.last_tick_at,
    )


@router.get("", response_model=AutonomyStatus)
def get_autonomy(
    tenant: Tenant = Depends(require_scope("autonomy:read")),
    db: Session = Depends(get_db),
) -> AutonomyStatus:
    """Everything an operator needs to see what autonomy will do next, and why."""

    from app.core.config import settings

    service = AutonomyService(db)
    policy = service.get_policy(tenant.id)
    now = datetime.now(UTC)
    targets: list[TargetStatus] = []
    used = 0
    quiet = False

    if policy is not None:
        used = service.daily_runs_used(tenant.id, now, policy.timezone)
        quiet = service._is_quiet(policy, now)
        for target in db.scalars(select(HuntTarget).where(HuntTarget.tenant_id == tenant.id)):
            targets.append(
                TargetStatus(
                    url=target.url,
                    enabled=target.enabled,
                    source=target.source,
                    last_run_at=target.last_run_at,
                    last_status=target.last_status,
                    next_eligible_at=target.next_eligible_at,
                    consecutive_failures=target.consecutive_failures,
                    runs_total=target.runs_total,
                    findings_total=target.findings_total,
                    utility=round(service.utility(target, now=now, policy=policy), 4),
                )
            )
        targets.sort(key=lambda item: item.utility, reverse=True)

    decisions = [
        DecisionResponse(
            id=row.id,
            at=row.at,
            action=row.action,
            target_url=row.target_url,
            reason=row.reason,
            utility=row.utility,
            run_id=row.run_id,
        )
        for row in db.scalars(
            select(AutonomyDecision)
            .where(AutonomyDecision.tenant_id == tenant.id)
            .order_by(AutonomyDecision.at.desc())
            .limit(20)
        )
    ]

    return AutonomyStatus(
        policy=_policy_response(policy) if policy is not None else None,
        global_enabled=settings.autonomy_enabled,
        daily_runs_used=used,
        daily_cap=policy.max_runs_per_day if policy else 0,
        in_quiet_hours=quiet,
        targets=targets,
        recent_decisions=decisions,
    )


@router.put("", response_model=AutonomyPolicyResponse)
def upsert_autonomy(
    payload: AutonomyPolicyUpsert,
    request: Request,
    admin: Tenant = Depends(require_scope("autonomy:admin")),
    db: Session = Depends(get_db),
) -> AutonomyPolicyResponse:
    try:
        policy = AutonomyService(db).upsert_policy(
            tenant=admin,
            enabled=payload.enabled,
            target_allowlist=payload.target_allowlist,
            safety_ceiling=payload.safety_ceiling,
            budget_requests_per_run=payload.budget_requests_per_run,
            max_runs_per_day=payload.max_runs_per_day,
            min_interval_minutes=payload.min_interval_minutes,
            quiet_hours_start=payload.quiet_hours_start,
            quiet_hours_end=payload.quiet_hours_end,
            tz_name=payload.timezone,
            max_consecutive_failures=payload.max_consecutive_failures,
            min_utility=payload.min_utility,
            mode=payload.mode,
            objective_template=payload.objective_template,
            max_objectives_per_day=payload.max_objectives_per_day,
            objective_budget_requests=payload.objective_budget_requests,
            escalation_cooldown_minutes=payload.escalation_cooldown_minutes,
            approved_by=payload.approved_by,
            approval_statement=payload.approval_statement,
            actor=request.state.actor,
            request_id=request.state.request_id,
        )
    except AutonomyError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return _policy_response(policy)


@router.post("/pause", response_model=AutonomyPolicyResponse)
def pause_autonomy(
    request: Request,
    admin: Tenant = Depends(require_scope("autonomy:admin")),
    db: Session = Depends(get_db),
    reason: str = Query(default="", max_length=512),
) -> AutonomyPolicyResponse:
    try:
        policy = AutonomyService(db).set_enabled(
            tenant=admin, enabled=False, actor=request.state.actor, request_id=request.state.request_id, reason=reason
        )
    except AutonomyError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return _policy_response(policy)


@router.post("/resume", response_model=AutonomyPolicyResponse)
def resume_autonomy(
    request: Request,
    admin: Tenant = Depends(require_scope("autonomy:admin")),
    db: Session = Depends(get_db),
) -> AutonomyPolicyResponse:
    try:
        policy = AutonomyService(db).set_enabled(
            tenant=admin, enabled=True, actor=request.state.actor, request_id=request.state.request_id
        )
    except AutonomyError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return _policy_response(policy)


@router.post("/kill")
def kill_autonomy(
    request: Request,
    admin: Tenant = Depends(require_scope("autonomy:admin")),
    db: Session = Depends(get_db),
    reason: str = Query(default="operator kill switch", max_length=512),
) -> dict[str, object]:
    """Stop autonomy and cancel anything it has in flight."""

    cancelled = AutonomyService(db).kill(
        tenant=admin, actor=request.state.actor, request_id=request.state.request_id, reason=reason
    )
    return {"enabled": False, "cancelled_runs": cancelled}


@router.get("/decisions", response_model=list[DecisionResponse])
def list_decisions(
    tenant: Tenant = Depends(require_scope("autonomy:read")),
    db: Session = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=200),
    action: str | None = None,
) -> list[DecisionResponse]:
    query = select(AutonomyDecision).where(AutonomyDecision.tenant_id == tenant.id)
    if action:
        query = query.where(AutonomyDecision.action == action)
    rows = db.scalars(query.order_by(AutonomyDecision.at.desc()).limit(limit))
    return [
        DecisionResponse(
            id=row.id,
            at=row.at,
            action=row.action,
            target_url=row.target_url,
            reason=row.reason,
            utility=row.utility,
            run_id=row.run_id,
        )
        for row in rows
    ]


@router.post("/tick")
def tick_now(
    request: Request,
    admin: Tenant = Depends(require_scope("autonomy:admin")),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """Run one controller cycle immediately (manual go-ahead or testing)."""

    service = AutonomyService(db)
    policy = service.get_policy(admin.id)
    if policy is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="No autonomy policy configured")
    report = service.tick_policy(policy, force=True)
    return report.to_dict()
