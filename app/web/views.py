"""Read models for the operator console.

Queries are plain SQLAlchemy selects scoped to the console tenant. Nothing here
mutates state; writes go through the service layer so the same audit rules apply
whether a change came from the API or the console.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.engine.probes import registry as probe_registry
from app.engine.workforce.decompose import TEMPLATE_PROBES
from app.engine.workforce.workers import worker_catalog
from app.models import (
    AuditLog,
    AutonomyDecision,
    AutonomyPolicy,
    Base,
    Campaign,
    Finding,
    FindingStatus,
    HuntTarget,
    Objective,
    ObjectiveEvent,
    Run,
    Tenant,
)
from app.services import asset_service, findings_service, memory_service
from app.services.objective_service import ObjectiveService


def _pct(part: int, whole: int) -> float:
    return round(100.0 * part / whole, 1) if whole else 0.0


@dataclass(frozen=True)
class Page:
    items: list
    total: int
    offset: int
    limit: int

    @property
    def has_prev(self) -> bool:
        return self.offset > 0

    @property
    def has_next(self) -> bool:
        return self.offset + self.limit < self.total


def dashboard(db: Session, tenant: Tenant) -> dict[str, object]:
    objective_counts = dict(
        db.execute(
            select(Objective.status, func.count()).where(Objective.tenant_id == tenant.id).group_by(Objective.status)
        ).all()
    )
    finding_counts = dict(
        db.execute(
            select(Finding.severity, func.count()).where(Finding.tenant_id == tenant.id).group_by(Finding.severity)
        ).all()
    )
    run_counts = dict(
        db.execute(select(Run.status, func.count()).where(Run.tenant_id == tenant.id).group_by(Run.status)).all()
    )
    recent_objectives = list(
        db.scalars(
            select(Objective).where(Objective.tenant_id == tenant.id).order_by(Objective.created_at.desc()).limit(8)
        )
    )
    recent_findings = list(
        db.scalars(
            select(Finding).where(Finding.tenant_id == tenant.id).order_by(Finding.last_seen_at.desc()).limit(10)
        )
    )
    policy = db.scalar(select(AutonomyPolicy).where(AutonomyPolicy.tenant_id == tenant.id))
    campaigns = int(db.scalar(select(func.count()).select_from(Campaign).where(Campaign.tenant_id == tenant.id)) or 0)
    total_objectives = sum(objective_counts.values())
    completed = int(objective_counts.get("completed", 0))
    return {
        "tenant": tenant,
        "objective_counts": objective_counts,
        "finding_counts": finding_counts,
        "run_counts": run_counts,
        "recent_objectives": recent_objectives,
        "recent_findings": recent_findings,
        "campaigns": campaigns,
        "policy": policy,
        "total_objectives": total_objectives,
        "completion_rate": _pct(completed, total_objectives),
        "high_severity": int(finding_counts.get("critical", 0)) + int(finding_counts.get("high", 0)),
    }


def objectives_page(
    db: Session, tenant: Tenant, *, status: str = "", query: str = "", offset: int = 0, limit: int = 20
) -> Page:
    stmt = select(Objective).where(Objective.tenant_id == tenant.id)
    count_stmt = select(func.count()).select_from(Objective).where(Objective.tenant_id == tenant.id)
    if status:
        stmt = stmt.where(Objective.status == status)
        count_stmt = count_stmt.where(Objective.status == status)
    if query:
        like = f"%{query}%"
        stmt = stmt.where(or_(Objective.title.ilike(like), Objective.key.ilike(like), Objective.target_url.ilike(like)))
        count_stmt = count_stmt.where(
            or_(Objective.title.ilike(like), Objective.key.ilike(like), Objective.target_url.ilike(like))
        )
    total = int(db.scalar(count_stmt) or 0)
    items = list(db.scalars(stmt.order_by(Objective.created_at.desc()).offset(offset).limit(limit)))
    return Page(items=items, total=total, offset=offset, limit=limit)


def objective_detail(db: Session, tenant: Tenant, objective_id: UUID) -> dict[str, object] | None:
    objective = db.scalar(select(Objective).where(Objective.id == objective_id, Objective.tenant_id == tenant.id))
    if objective is None:
        return None
    service = ObjectiveService(db)
    supervisor = service._supervisor(objective)
    report = supervisor.report()
    tasks = service.tasks(objective.id)
    events = list(
        db.scalars(
            select(ObjectiveEvent)
            .where(ObjectiveEvent.objective_id == objective.id)
            .order_by(ObjectiveEvent.at.desc())
            .limit(120)
        )
    )
    artifacts_ready = any(event.type == "objective.artifacts" for event in events)
    verify_tasks = [task for task in tasks if task.kind == "verify"]
    adaptive_tasks = [task for task in tasks if (task.payload or {}).get("adaptive")]
    return {
        "objective": objective,
        "tasks": tasks,
        "events": events,
        "report": report,
        "criteria": report.get("criteria", []),
        "evidence": report.get("evidence", {}),
        "coverage": report.get("evidence", {}).get("coverage", {}),
        "artifacts_ready": artifacts_ready,
        "verify_tasks": verify_tasks,
        "adaptive_tasks": adaptive_tasks,
        "terminal": objective.status in {"completed", "blocked", "failed", "cancelled"},
    }


def findings_page(
    db: Session,
    tenant: Tenant,
    *,
    severity: str = "",
    status_filter: str = "",
    query: str = "",
    offset: int = 0,
    limit: int = 25,
) -> Page:
    stmt = select(Finding).where(Finding.tenant_id == tenant.id)
    count_stmt = select(func.count()).select_from(Finding).where(Finding.tenant_id == tenant.id)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
        count_stmt = count_stmt.where(Finding.severity == severity)
    if status_filter:
        stmt = stmt.where(Finding.status == status_filter)
        count_stmt = count_stmt.where(Finding.status == status_filter)
    if query:
        like = f"%{query}%"
        stmt = stmt.where(or_(Finding.title.ilike(like), Finding.kind.ilike(like)))
        count_stmt = count_stmt.where(or_(Finding.title.ilike(like), Finding.kind.ilike(like)))
    total = int(db.scalar(count_stmt) or 0)
    items = list(db.scalars(stmt.order_by(Finding.last_seen_at.desc()).offset(offset).limit(limit)))
    return Page(items=items, total=total, offset=offset, limit=limit)


def runs_page(db: Session, tenant: Tenant, *, offset: int = 0, limit: int = 25) -> Page:
    stmt = (
        select(Run, Campaign)
        .join(Campaign, Run.campaign_id == Campaign.id)
        .where(Campaign.tenant_id == tenant.id)
        .order_by(Run.created_at.desc())
    )
    count_stmt = (
        select(func.count())
        .select_from(Run)
        .join(Campaign, Run.campaign_id == Campaign.id)
        .where(Campaign.tenant_id == tenant.id)
    )
    total = int(db.scalar(count_stmt) or 0)
    rows = list(db.execute(stmt.offset(offset).limit(limit)).all())
    return Page(
        items=[{"run": run, "campaign": campaign} for run, campaign in rows], total=total, offset=offset, limit=limit
    )


def autonomy_view(db: Session, tenant: Tenant) -> dict[str, object]:
    policy = db.scalar(select(AutonomyPolicy).where(AutonomyPolicy.tenant_id == tenant.id))
    targets = list(db.scalars(select(HuntTarget).where(HuntTarget.tenant_id == tenant.id)))
    decisions = list(
        db.scalars(
            select(AutonomyDecision)
            .where(AutonomyDecision.tenant_id == tenant.id)
            .order_by(AutonomyDecision.at.desc())
            .limit(40)
        )
    )
    return {"policy": policy, "targets": targets, "decisions": decisions}


def memory_view(db: Session, tenant: Tenant) -> list[dict[str, object]]:
    return memory_service.recipes(db, tenant_id=tenant.id, limit=100)


def workers_view() -> list[dict[str, object]]:
    return worker_catalog()


def templates_view() -> list[dict[str, object]]:
    return [
        {"name": name, "probes": list(probes), "probe_count": len(probes)}
        for name, probes in sorted(TEMPLATE_PROBES.items())
    ]


def audit_page(db: Session, tenant: Tenant, *, offset: int = 0, limit: int = 50) -> Page:
    stmt = select(AuditLog).where(AuditLog.tenant_id == tenant.id).order_by(AuditLog.id.desc())
    count_stmt = select(func.count()).select_from(AuditLog).where(AuditLog.tenant_id == tenant.id)
    total = int(db.scalar(count_stmt) or 0)
    items = list(db.scalars(stmt.offset(offset).limit(limit)))
    return Page(items=items, total=total, offset=offset, limit=limit)


def health_view(db: Session, tenant: Tenant) -> dict[str, object]:
    now = datetime.now(UTC)
    terminal = {"completed", "blocked", "failed", "cancelled"}
    active = int(
        db.scalar(
            select(func.count())
            .select_from(Objective)
            .where(Objective.tenant_id == tenant.id, ~Objective.status.in_(terminal))
        )
        or 0
    )
    return {
        "now": now,
        "active_objectives": active,
        "engine_probes": len(probe_registry()),
        "tables": len(Base.metadata.tables),
    }


def finding_detail(db: Session, tenant: Tenant, finding_id: UUID) -> dict[str, object] | None:
    finding = db.scalar(select(Finding).where(Finding.id == finding_id, Finding.tenant_id == tenant.id))
    if finding is None:
        return None
    findings_service.ensure_sla(db, tenant.id)
    db.commit()
    return {
        "finding": finding,
        "notes": findings_service.notes(db, finding.id, limit=100),
        "statuses": list(FindingStatus.ALL),
        "sla_hours": findings_service.SLA_HOURS,
        "transitions": sorted(findings_service.TRANSITIONS.get(finding.status, set())),
    }


def triage_summary(db: Session, tenant: Tenant) -> dict[str, object]:
    result = findings_service.summary(db, tenant)
    db.commit()
    return result


def assets_page(
    db: Session,
    tenant: Tenant,
    *,
    query: str = "",
    role: str = "",
    status_filter: str = "",
    offset: int = 0,
    limit: int = 50,
) -> dict[str, object]:
    items, total = asset_service.list_assets(
        db, tenant.id, query=query, role=role, status_filter=status_filter, offset=offset, limit=limit
    )
    return {
        "items": items,
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_prev": offset > 0,
        "has_next": offset + limit < total,
        "summary": asset_service.summary(db, tenant.id),
        "changes": asset_service.changes(db, tenant.id, days=7),
        "query": query,
        "role": role,
        "status_filter": status_filter,
    }
