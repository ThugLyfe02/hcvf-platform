from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

import structlog
from fastapi import FastAPI, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from redis.asyncio import Redis

from app.api.v1 import campaigns, health
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.core.metrics import prometheus_response
from app.core.middleware import MetricsMiddleware, RateLimitMiddleware, RequestIDMiddleware
from app.db.session import engine

configure_logging()
settings = get_settings()
logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    rate_limit_redis: Redis | None = None
    if settings.rate_limit_enabled:
        rate_limit_redis = Redis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
            socket_connect_timeout=0.5,
            socket_timeout=0.5,
        )
    application.state.rate_limit_redis = rate_limit_redis
    logger.info(
        "api_started",
        environment=settings.environment,
        app_name=settings.app_name,
    )
    try:
        yield
    finally:
        if rate_limit_redis is not None:
            await rate_limit_redis.aclose()
        engine.dispose()
        logger.info("api_stopped")


def create_app() -> FastAPI:
    application = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        lifespan=lifespan,
    )

    application.add_middleware(RateLimitMiddleware)
    application.add_middleware(MetricsMiddleware)
    application.add_middleware(RequestIDMiddleware)

    application.include_router(health.router, prefix="/api/v1")
    application.include_router(campaigns.router, prefix="/api/v1")

    @application.get("/")
    def root() -> dict[str, str]:
        return {
            "name": settings.app_name,
            "status": "operational",
            "authorization": "authorized defensive use only",
        }

    @application.get("/health", include_in_schema=False)
    async def compatibility_health():  # type: ignore[no-untyped-def]
        """Backward-compatible aggregate health endpoint."""

        return await health.readiness()

    @application.get("/metrics", include_in_schema=False)
    def metrics():  # type: ignore[no-untyped-def]
        return prometheus_response()

    @application.exception_handler(HTTPException)
    async def http_exception_handler(_: Request, exc: HTTPException) -> JSONResponse:
        if isinstance(exc.detail, dict) and {"code", "message"} <= exc.detail.keys():
            error = exc.detail
        else:
            error = {"code": "http_error", "message": str(exc.detail)}
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": jsonable_encoder(error)},
            headers=exc.headers or {},
        )

    @application.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        _: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "validation_error",
                    "message": "The request payload or path parameters are invalid.",
                    "details": jsonable_encoder(exc.errors()),
                }
            },
        )

    @application.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception(
            "unhandled_api_exception",
            method=request.method,
            path=request.url.path,
            error_type=exc.__class__.__name__,
        )
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "internal_server_error",
                    "message": "An unexpected internal error occurred.",
                }
            },
        )

    return application


app = create_app()
