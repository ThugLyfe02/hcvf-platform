from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api.v1 import (
    admin_router,
    autonomy_router,
    campaign_runs_router,
    catalog_router,
    findings_router,
    governance_router,
    objectives_router,
)
from app.api.v1.campaigns import router as campaigns_router
from app.api.v1.health import router as health_router
from app.api.v1.metrics import router as metrics_router
from app.api.v1.tenants import router as tenants_router
from app.core.audit_middleware import AuditMiddleware
from app.core.body_limit import BodySizeLimitMiddleware
from app.core.config import settings
from app.core.logging import setup_logging
from app.core.observability import ObservabilityMiddleware
from app.core.problem import install_error_handlers
from app.core.rate_limit import RateLimitMiddleware
from app.core.request_id import RequestIDMiddleware
from app.core.security_headers import SecurityHeadersMiddleware
from app.core.tracing import TraceContextMiddleware
from app.db.session import engine
from app.services.bootstrap import provision_configured_tenants
from app.web.router import router as console_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    provision_configured_tenants()
    try:
        yield
    finally:
        current = app.middleware_stack
        while current is not None:
            if isinstance(current, RateLimitMiddleware):
                await current.close()
                break
            current = getattr(current, "app", None)
        engine.dispose()


app = FastAPI(
    title="HCVF - Hybrid Concolic Validation Fabric",
    description=(
        "Authorized, evidence-grade validation control plane. Campaigns execute an "
        "agentic hunt: specialist agents propose probes, critique each other's "
        "proposals, and a deterministic arbiter allocates the budget under a hard "
        "safety ceiling."
    ),
    version="0.4.0",
    lifespan=lifespan,
)

# Middleware is added inner-first because Starlette prepends. Effective order
# (outermost first): Observability -> RequestID -> SecurityHeaders -> RateLimit
# -> Audit -> application. Security headers and request ids therefore still
# apply to rate-limit rejections.
app.add_middleware(AuditMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestIDMiddleware)
app.add_middleware(ObservabilityMiddleware)
app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_bytes)
app.add_middleware(TraceContextMiddleware)

app.include_router(health_router)
app.include_router(metrics_router)
app.include_router(campaigns_router)
app.include_router(campaign_runs_router)
app.include_router(findings_router)
app.include_router(autonomy_router)
app.include_router(tenants_router)
app.include_router(governance_router)
app.include_router(objectives_router)
app.include_router(catalog_router)
app.include_router(admin_router)
app.include_router(console_router)
app.mount(
    "/console/static",
    StaticFiles(directory=Path(__file__).parent / "web" / "static"),
    name="console-static",
)


install_error_handlers(app)


@app.get("/", tags=["system"])
def root() -> dict[str, str]:
    return {
        "service": "hcvf",
        "status": "ok",
        "engine": "agentic",
        "version": app.version,
    }
