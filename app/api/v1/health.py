from __future__ import annotations

from fastapi import APIRouter, Response, status
from redis import Redis
from sqlalchemy import text

from app.core.config import settings
from app.db.session import SessionLocal

router = APIRouter(tags=["health"])


@router.get("/health")
def health(response: Response) -> dict[str, object]:
    dependencies: dict[str, dict[str, object]] = {
        "postgres": {"status": "down"},
        "redis": {"status": "down"},
    }

    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
        dependencies["postgres"] = {"status": "ok"}
    except Exception as exc:
        dependencies["postgres"] = {
            "status": "down",
            "error": exc.__class__.__name__,
        }

    redis_client: Redis | None = None
    try:
        redis_client = Redis.from_url(settings.redis_url, decode_responses=True)
        redis_ok = bool(redis_client.ping())
        dependencies["redis"] = {"status": "ok" if redis_ok else "down"}
    except Exception as exc:
        dependencies["redis"] = {
            "status": "down",
            "error": exc.__class__.__name__,
        }
    finally:
        if redis_client is not None:
            redis_client.close()

    healthy = all(dep["status"] == "ok" for dep in dependencies.values())
    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "ok" if healthy else "degraded",
        "dependencies": dependencies,
    }
