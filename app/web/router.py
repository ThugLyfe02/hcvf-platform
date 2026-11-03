"""The operator console: server-rendered pages over the same services the API uses.

No second permission model, no parallel state: every page reads the tenant-scoped
queries in ``views`` and every action calls ``ObjectiveService`` (or the autonomy
service) exactly as the API would. The console exists because an operator wants
to watch a hunt, not curl JSON.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qs, quote
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models import Objective, Tenant
from app.services.objective_service import ObjectiveError, ObjectiveService
from app.web import views
from app.web.auth import COOKIE_NAME, SESSION_SECONDS, current_tenant, issue_token, resolve_tenant
from app.web.streams import event_stream

TEMPLATE_DIR = Path(__file__).parent / "templates"
router = APIRouter(prefix="/console", tags=["console"], include_in_schema=False)
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))

NAV = (
    {"href": "/console", "label": "Overview"},
    {"href": "/console/objectives", "label": "Objectives"},
    {"href": "/console/findings", "label": "Findings"},
    {"href": "/console/runs", "label": "Runs"},
    {"href": "/console/autonomy", "label": "Autonomy"},
    {"href": "/console/memory", "label": "Memory"},
    {"href": "/console/workers", "label": "Workforce"},
)


def _render(request: Request, name: str, context: dict) -> HTMLResponse:
    tenant = getattr(request.state, "console_tenant", None)
    base = {
        "request": request,
        "nav": NAV,
        "tenant": tenant,
        "active": request.url.path,
    }
    base.update(context)
    return templates.TemplateResponse(request, name, base)


# -- session ---------------------------------------------------------------
@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request) -> HTMLResponse:
    return _render(request, "login.html", {"error": "", "next": request.query_params.get("next", "/console")})


@router.post("/login")
async def login_submit(request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    # Parse the urlencoded body directly: the login form needs exactly two
    # fields, and requiring python-multipart for that would add a deployment
    # dependency for no benefit.
    body = (await request.body()).decode("utf-8", "replace")
    form = parse_qs(body, keep_blank_values=True)
    api_key = (form.get("api_key") or [""])[0]
    target = (form.get("next") or ["/console"])[0] or "/console"
    if not target.startswith("/console"):
        target = "/console"
    tenant = resolve_tenant(db, api_key)
    if tenant is None:
        return _redirect_with_error(request, "That API key does not resolve to an active tenant.", target)
    response = RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        COOKIE_NAME,
        issue_token(tenant.id),
        max_age=SESSION_SECONDS,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
        path="/console",
    )
    return response


def _redirect_with_error(request: Request, message: str, target: str) -> RedirectResponse:
    response = RedirectResponse(
        f"/console/login?error={quote(message)}&next={quote(target)}",
        status_code=status.HTTP_303_SEE_OTHER,
    )
    return response


@router.post("/logout")
def logout() -> RedirectResponse:
    response = RedirectResponse("/console/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(COOKIE_NAME, path="/console")
    return response


# -- pages -----------------------------------------------------------------
@router.get("", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request, tenant: Tenant = Depends(current_tenant), db: Session = Depends(get_db)
) -> HTMLResponse:
    context = views.dashboard(db, tenant)
    context["templates"] = views.templates_view()
    context["workers"] = views.workers_view()
    return _render(request, "dashboard.html", context)


@router.get("/objectives", response_class=HTMLResponse)
def objectives_page(
    request: Request,
    tenant: Tenant = Depends(current_tenant),
    db: Session = Depends(get_db),
    objective_status: str = Query(default="", alias="status"),
    q: str = Query(default=""),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=5, le=100),
) -> HTMLResponse:
    page = views.objectives_page(db, tenant, status=objective_status, query=q, offset=offset, limit=limit)
    return _render(
        request,
        "objectives.html",
        {"page": page, "query": q, "status_filter": objective_status},
    )


@router.get("/objectives/{objective_id}", response_class=HTMLResponse)
def objective_detail(
    objective_id: UUID,
    request: Request,
    tenant: Tenant = Depends(current_tenant),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    detail = views.objective_detail(db, tenant, objective_id)
    if detail is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Objective not found")
    return _render(request, "objective_detail.html", detail)


@router.post("/objectives/{objective_id}/run")
def objective_run(
    objective_id: UUID,
    tenant: Tenant = Depends(current_tenant),
    db: Session = Depends(get_db),
    max_tasks: int = Query(default=12, ge=1, le=40),
) -> RedirectResponse:
    service = ObjectiveService(db)
    objective = service.get(tenant_id=tenant.id, objective_id=objective_id)
    if objective is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Objective not found")
    try:
        service.run_to_completion(objective, max_tasks=max_tasks)
    except ObjectiveError:
        db.rollback()
    return RedirectResponse(f"/console/objectives/{objective_id}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/objectives/{objective_id}/cancel")
def objective_cancel(
    objective_id: UUID,
    request: Request,
    tenant: Tenant = Depends(current_tenant),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    service = ObjectiveService(db)
    objective = service.get(tenant_id=tenant.id, objective_id=objective_id)
    if objective is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Objective not found")
    try:
        service.cancel(
            objective,
            actor=getattr(request.state, "actor", "console"),
            request_id=getattr(request.state, "request_id", ""),
        )
    except ObjectiveError:
        db.rollback()
    return RedirectResponse(f"/console/objectives/{objective_id}", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/objectives/{objective_id}/events.sse")
def objective_events_sse(
    objective_id: UUID,
    tenant: Tenant = Depends(current_tenant),
    db: Session = Depends(get_db),
    once: bool = Query(default=False),
) -> StreamingResponse:
    objective = db.scalar(select(Objective).where(Objective.id == objective_id, Objective.tenant_id == tenant.id))
    if objective is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Objective not found")
    return StreamingResponse(
        event_stream(objective_id=objective.id, tenant_id=tenant.id, once=once),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/findings", response_class=HTMLResponse)
def findings_page(
    request: Request,
    tenant: Tenant = Depends(current_tenant),
    db: Session = Depends(get_db),
    severity: str = Query(default=""),
    finding_status: str = Query(default="", alias="status"),
    q: str = Query(default=""),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=25, ge=5, le=200),
) -> HTMLResponse:
    page = views.findings_page(
        db, tenant, severity=severity, status_filter=finding_status, query=q, offset=offset, limit=limit
    )
    return _render(
        request,
        "findings.html",
        {"page": page, "severity": severity, "status_filter": finding_status, "query": q},
    )


@router.get("/runs", response_class=HTMLResponse)
def runs_page(
    request: Request,
    tenant: Tenant = Depends(current_tenant),
    db: Session = Depends(get_db),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=25, ge=5, le=200),
) -> HTMLResponse:
    return _render(request, "runs.html", {"page": views.runs_page(db, tenant, offset=offset, limit=limit)})


@router.get("/autonomy", response_class=HTMLResponse)
def autonomy_page(
    request: Request, tenant: Tenant = Depends(current_tenant), db: Session = Depends(get_db)
) -> HTMLResponse:
    return _render(request, "autonomy.html", views.autonomy_view(db, tenant))


@router.get("/memory", response_class=HTMLResponse)
def memory_page(
    request: Request, tenant: Tenant = Depends(current_tenant), db: Session = Depends(get_db)
) -> HTMLResponse:
    return _render(request, "memory.html", {"recipes": views.memory_view(db, tenant)})


@router.get("/workers", response_class=HTMLResponse)
def workers_page(request: Request) -> HTMLResponse:
    return _render(
        request,
        "workers.html",
        {"workers": views.workers_view(), "templates": views.templates_view()},
    )


@router.get("/audit", response_class=HTMLResponse)
def audit_page(
    request: Request,
    tenant: Tenant = Depends(current_tenant),
    db: Session = Depends(get_db),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=5, le=200),
) -> HTMLResponse:
    return _render(request, "audit.html", {"page": views.audit_page(db, tenant, offset=offset, limit=limit)})


@router.get("/health", response_class=HTMLResponse)
def health_page(
    request: Request, tenant: Tenant = Depends(current_tenant), db: Session = Depends(get_db)
) -> HTMLResponse:
    return _render(request, "health.html", views.health_view(db, tenant))
