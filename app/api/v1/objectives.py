from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.security import require_scope
from app.db.session import get_db
from app.engine.workforce.decompose import TEMPLATE_CRITERIA, TEMPLATE_PROBES
from app.engine.workforce.workers import worker_catalog
from app.models import Objective, Tenant
from app.services.objective_service import ObjectiveError, ObjectiveService

router = APIRouter(prefix="/api/v1/objectives", tags=["objectives"])


class ObjectiveCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=2000)
    target_url: str = Field(min_length=8, max_length=2048)
    template: str = Field(default="posture", pattern="^(posture|auth|exposure|coverage|custom)$")
    budget_requests: int = Field(default=120, ge=10, le=5000)
    per_task_budget: int = Field(default=20, ge=4, le=500)
    safety_ceiling: str = Field(default="read_only", pattern="^(read_only|state_changing)$")
    priority: int = Field(default=5, ge=1, le=10)
    deadline_minutes: int = Field(default=120, ge=5, le=10080)
    criteria: list[dict] | None = None


class ObjectiveSummary(BaseModel):
    id: UUID
    key: str
    title: str
    target_url: str
    template: str
    status: str
    priority: int
    verdict: str
    requests_used: int
    budget_requests: int
    created_at: datetime
    completed_at: datetime | None
    origin: str


class TaskView(BaseModel):
    key: str
    seq: int
    kind: str
    title: str
    worker: str
    status: str
    attempts: int
    route: str
    probe_id: str
    depends_on: list[str]
    error: str


def _summary(objective: Objective) -> ObjectiveSummary:
    return ObjectiveSummary(
        id=objective.id,
        key=objective.key,
        title=objective.title,
        target_url=objective.target_url,
        template=objective.template,
        status=objective.status,
        priority=objective.priority,
        verdict=objective.verdict,
        requests_used=objective.requests_used,
        budget_requests=objective.budget_requests,
        created_at=objective.created_at,
        completed_at=objective.completed_at,
        origin=objective.origin,
    )


@router.post("", response_model=ObjectiveSummary, status_code=status.HTTP_201_CREATED)
def create_objective(
    payload: ObjectiveCreate,
    request: Request,
    tenant: Tenant = Depends(require_scope("campaigns:write")),
    db: Session = Depends(get_db),
) -> ObjectiveSummary:
    """Delegate work. The workforce decomposes it and reports when it is done."""

    try:
        objective = ObjectiveService(db).create(
            tenant=tenant,
            title=payload.title,
            target_url=payload.target_url,
            template=payload.template,
            budget_requests=payload.budget_requests,
            per_task_budget=payload.per_task_budget,
            criteria_payload=payload.criteria,
            safety_ceiling=payload.safety_ceiling,
            priority=payload.priority,
            deadline_minutes=payload.deadline_minutes,
            description=payload.description,
            actor=request.state.actor,
            request_id=request.state.request_id,
        )
    except ObjectiveError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return _summary(objective)


@router.get("", response_model=list[ObjectiveSummary])
def list_objectives(
    tenant: Tenant = Depends(require_scope("campaigns:read")),
    db: Session = Depends(get_db),
    objective_status: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[ObjectiveSummary]:
    return [
        _summary(row) for row in ObjectiveService(db).list(tenant_id=tenant.id, status=objective_status, limit=limit)
    ]


@router.get("/{objective_id}")
def get_objective(
    objective_id: UUID,
    tenant: Tenant = Depends(require_scope("campaigns:read")),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    service = ObjectiveService(db)
    objective = service.get(tenant_id=tenant.id, objective_id=objective_id)
    if objective is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Objective not found")
    return {
        "objective": _summary(objective).model_dump(mode="json"),
        "criteria": objective.criteria,
        "plan": objective.plan,
        "verdict": objective.verdict,
    }


@router.get("/{objective_id}/tasks", response_model=list[TaskView])
def list_tasks(
    objective_id: UUID,
    tenant: Tenant = Depends(require_scope("campaigns:read")),
    db: Session = Depends(get_db),
) -> list[TaskView]:
    service = ObjectiveService(db)
    objective = service.get(tenant_id=tenant.id, objective_id=objective_id)
    if objective is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Objective not found")
    return [
        TaskView(
            key=task.key,
            seq=task.seq,
            kind=task.kind,
            title=task.title,
            worker=task.worker,
            status=task.status,
            attempts=task.attempts,
            route=task.route,
            probe_id=task.probe_id,
            depends_on=list(task.depends_on or []),
            error=task.error,
        )
        for task in service.tasks(objective.id)
    ]


@router.get("/{objective_id}/events")
def list_events(
    objective_id: UUID,
    tenant: Tenant = Depends(require_scope("campaigns:read")),
    db: Session = Depends(get_db),
    limit: int = Query(default=100, ge=1, le=500),
) -> list[dict[str, object]]:
    service = ObjectiveService(db)
    objective = service.get(tenant_id=tenant.id, objective_id=objective_id)
    if objective is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Objective not found")
    return [
        {
            "type": event.type,
            "message": event.message,
            "at": event.at.isoformat(),
            "payload": event.payload,
        }
        for event in service.events(objective.id, limit=limit)
    ]


@router.post("/{objective_id}/step")
def step_objective(
    objective_id: UUID,
    tenant: Tenant = Depends(require_scope("campaigns:write")),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """Execute exactly one ready task — the surgical unit of progress."""

    service = ObjectiveService(db)
    objective = service.get(tenant_id=tenant.id, objective_id=objective_id)
    if objective is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Objective not found")
    return service.run_step(objective).to_dict()


@router.post("/{objective_id}/run")
def run_objective(
    objective_id: UUID,
    tenant: Tenant = Depends(require_scope("campaigns:write")),
    db: Session = Depends(get_db),
    max_tasks: int = Query(default=12, ge=1, le=60),
) -> dict[str, object]:
    """Drive the objective forward until it completes, blocks, or hits the cap."""

    service = ObjectiveService(db)
    objective = service.get(tenant_id=tenant.id, objective_id=objective_id)
    if objective is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Objective not found")
    verdict = service.run_to_completion(objective, max_tasks=max_tasks)
    return {"verdict": verdict.to_dict(), "report": service.report(objective)}


@router.post("/{objective_id}/cancel", response_model=ObjectiveSummary)
def cancel_objective(
    objective_id: UUID,
    request: Request,
    tenant: Tenant = Depends(require_scope("campaigns:write")),
    db: Session = Depends(get_db),
) -> ObjectiveSummary:
    service = ObjectiveService(db)
    objective = service.get(tenant_id=tenant.id, objective_id=objective_id)
    if objective is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Objective not found")
    try:
        objective = service.cancel(objective, actor=request.state.actor, request_id=request.state.request_id)
    except ObjectiveError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return _summary(objective)


@router.get("/{objective_id}/report")
def objective_report(
    objective_id: UUID,
    tenant: Tenant = Depends(require_scope("campaigns:read")),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    service = ObjectiveService(db)
    objective = service.get(tenant_id=tenant.id, objective_id=objective_id)
    if objective is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Objective not found")
    return service.report(objective)


@router.get("/{objective_id}/coverage")
def objective_coverage(
    objective_id: UUID,
    tenant: Tenant = Depends(require_scope("campaigns:read")),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """What the objective measured: discovered routes, probed routes, the gap."""

    service = ObjectiveService(db)
    objective = service.get(tenant_id=tenant.id, objective_id=objective_id)
    if objective is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Objective not found")
    supervisor = service._supervisor(objective)
    evidence = supervisor.evidence()
    return {
        "coverage": evidence.coverage.to_dict(),
        "routes": list((objective.plan or {}).get("spec", {}).get("target", "")),
        "tasks": [
            {"key": task.key, "kind": task.kind, "route": task.route, "status": task.status}
            for task in service.tasks(objective.id)
            if (task.payload or {}).get("coverage") or task.kind == "recon"
        ],
        "criteria": objective.criteria,
    }


# -- static catalogs --------------------------------------------------------
catalog_router = APIRouter(prefix="/api/v1", tags=["objectives"])


@catalog_router.get("/workers")
def list_workers(_: Tenant = Depends(require_scope("campaigns:read"))) -> list[dict[str, object]]:
    """The specialists that can be delegated work."""

    return worker_catalog()


@catalog_router.get("/objective-templates")
def list_templates(_: Tenant = Depends(require_scope("campaigns:read"))) -> list[dict[str, object]]:
    return [
        {
            "name": name,
            "probes": list(probes),
            "default_criteria": [
                {"kind": criterion.kind.value, "value": criterion.value, "label": criterion.description}
                for criterion in TEMPLATE_CRITERIA[name]
            ],
        }
        for name, probes in TEMPLATE_PROBES.items()
    ]
