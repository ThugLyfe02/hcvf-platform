from __future__ import annotations

import asyncio
import time
from typing import Literal

import structlog
from fastapi import APIRouter, status
from pydantic import BaseModel
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse

from app.core.config import get_settings
from app.db.session import engine

router = APIRouter(prefix="/health", tags=["health"])
logger = structlog.get_logger(__name__)
settings = get_settings()


class DependencyHealth(BaseModel):
    status: Literal["ok", "error"]
    latency_ms: float
    detail: str | None = None


class ReadinessResponse(BaseModel):
    status: Literal["ready", "not_ready"]
    postgres: DependencyHealth
    redis: DependencyHealth


@router.get("/live")
def liveness() -> dict[str, str]:
    return {"status": "alive"}


@router.get("", response_model=ReadinessResponse)
@router.get("/ready", response_model=ReadinessResponse)
async def readiness() -> ReadinessResponse | JSONResponse:
    postgres, redis = await asyncio.gather(
        run_in_threadpool(check_postgres),
        check_redis(),
    )
    ready = postgres.status == "ok" and redis.status == "ok"
    payload = ReadinessResponse(
        status="ready" if ready else "not_ready",
        postgres=postgres,
        redis=redis,
    )
    if ready:
        return payload
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content=payload.model_dump(),
    )


def check_postgres() -> DependencyHealth:
    started = time.perf_counter()
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return DependencyHealth(
            status="ok",
            latency_ms=round((time.perf_counter() - started) * 1000, 3),
        )
    except SQLAlchemyError as exc:
        logger.warning("postgres_health_check_failed", error_type=exc.__class__.__name__)
        return DependencyHealth(
            status="error",
            latency_ms=round((time.perf_counter() - started) * 1000, 3),
            detail="PostgreSQL connectivity check failed.",
        )


async def check_redis() -> DependencyHealth:
    started = time.perf_counter()
    client = Redis.from_url(
        settings.redis_url,
        encoding="utf-8",
        decode_responses=True,
        socket_connect_timeout=1.0,
        socket_timeout=1.0,
    )
    try:
        response = await client.ping()
        if response is not True:
            raise RuntimeError("Redis PING returned an unexpected response.")
        return DependencyHealth(
            status="ok",
            latency_ms=round((time.perf_counter() - started) * 1000, 3),
        )
    except Exception as exc:
        logger.warning("redis_health_check_failed", error_type=exc.__class__.__name__)
        return DependencyHealth(
            status="error",
            latency_ms=round((time.perf_counter() - started) * 1000, 3),
            detail="Redis connectivity check failed.",
        )
    finally:
        await client.aclose()
