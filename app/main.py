from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.v1.campaigns import router as campaigns_router
from app.api.v1.health import router as health_router
from app.api.v1.metrics import router as metrics_router
from app.core.audit_middleware import AuditMiddleware
from app.core.logging import setup_logging
from app.core.rate_limit import RateLimitMiddleware
from app.core.request_id import RequestIDMiddleware
from app.db.session import engine
from app.services.bootstrap import provision_configured_tenants

setup_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    provision_configured_tenants()
    yield

    for middleware in app.user_middleware:
        instance = getattr(middleware, "cls", None)
        if instance is RateLimitMiddleware:
            break

    engine.dispose()


app = FastAPI(
    title="HCVF - Hybrid Concolic Validation Fabric",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(AuditMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(RequestIDMiddleware)

app.include_router(health_router)
app.include_router(metrics_router)
app.include_router(campaigns_router)
