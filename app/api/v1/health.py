from __future__ import annotations

from fastapi import APIRouter, Response, status
from redis import Redis
from sqlalchemy import text

from app.core.circuit_breaker import CircuitBreaker, CircuitOpenError
from app.core.config import settings
from app.db.session import SessionLocal

router = APIRouter(tags=["health"])

_postgres_breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=15.0)
_redis_breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=15.0)


def _check_postgres() -> None:
    with SessionLocal() as db:
        db.execute(text("SELECT 1"))


def _check_redis() -> None:
    client = Redis.from_url(settings.redis_url, decode_responses=True)
    try:
        if not client.ping():
            raise RuntimeError("Redis PING returned false")
    finally:
        client.close()


@router.get("/health")
def health(response: Response) -> dict[str, object]:
    dependencies: dict[str, dict[str, object]] = {
        "postgres": {"status": "down"},
        "redis": {"status": "down"},
    }

    try:
        _postgres_breaker.call(_check_postgres)
        dependencies["postgres"] = {
            "status": "ok",
            "circuit": _postgres_breaker.state.value,
        }
    except CircuitOpenError:
        dependencies["postgres"] = {
            "status": "down",
            "error": "CircuitOpenError",
            "circuit": _postgres_breaker.state.value,
        }
    except Exception as exc:
        dependencies["postgres"] = {
            "status": "down",
            "error": exc.__class__.__name__,
            "circuit": _postgres_breaker.state.value,
        }

    try:
        _redis_breaker.call(_check_redis)
        dependencies["redis"] = {
            "status": "ok",
            "circuit": _redis_breaker.state.value,
        }
    except CircuitOpenError:
        dependencies["redis"] = {
            "status": "down",
            "error": "CircuitOpenError",
            "circuit": _redis_breaker.state.value,
        }
    except Exception as exc:
        dependencies["redis"] = {
            "status": "down",
            "error": exc.__class__.__name__,
            "circuit": _redis_breaker.state.value,
        }

    healthy = all(dep["status"] == "ok" for dep in dependencies.values())
    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "ok" if healthy else "degraded",
        "dependencies": dependencies,
    }
