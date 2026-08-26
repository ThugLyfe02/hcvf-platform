from __future__ import annotations

from fastapi import APIRouter, Response, status
from redis import Redis
from sqlalchemy import text

from app.core.config import settings
from app.db.session import SessionLocal

router = APIRouter(tags=["health"])


@router.get("/health")
def health(response: Response) -> dict:
    checks = {"postgres": False, "redis": False}
    errors: dict[str, str] = {}

    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
        checks["postgres"] = True
    except Exception as exc:
        errors["postgres"] = exc.__class__.__name__

    try:
        client = Redis.from_url(settings.redis_url, decode_responses=True)
        checks["redis"] = bool(client.ping())
    except Exception as exc:
        errors["redis"] = exc.__class__.__name__

    healthy = all(checks.values())
    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {"status": "ok" if healthy else "degraded", "checks": checks, "errors": errors}
