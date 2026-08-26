from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app.api.v1.campaigns import router as campaigns_router
from app.api.v1.health import router as health_router
from app.core.logging import configure_logging
from app.core.middleware import RateLimitMiddleware, RequestContextMiddleware
from app.services.bootstrap import provision_configured_tenants

configure_logging()


@asynccontextmanager
async def lifespan(_: FastAPI):
    provision_configured_tenants()
    yield


app = FastAPI(
    title="HCVF - Hybrid Concolic Validation Fabric",
    version="0.1.0",
    lifespan=lifespan,
)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(RequestContextMiddleware)
app.include_router(health_router)
app.include_router(campaigns_router)


@app.get("/metrics", include_in_schema=False)
def metrics() -> Response:
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
