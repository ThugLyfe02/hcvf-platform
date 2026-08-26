from __future__ import annotations

import hashlib
import re
import time
import uuid
from collections.abc import Awaitable, Callable

import structlog
from fastapi import Request
from redis.asyncio import Redis
from redis.exceptions import RedisError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

from app.core.config import get_settings
from app.core.logging import bind_request_context, clear_request_context
from app.core.metrics import HTTP_REQUEST_DURATION, HTTP_REQUESTS, RATE_LIMIT_REJECTIONS

logger = structlog.get_logger(__name__)

_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_UUID_PATH_SEGMENT = re.compile(
    r"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}(?=/|$)"
)
_RATE_LIMIT_SCRIPT = """
local current = redis.call('INCR', KEYS[1])
if current == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return current
"""


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Attach a validated request ID to every response and log context."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        supplied = request.headers.get("X-Request-ID", "")
        request_id = supplied if _REQUEST_ID_PATTERN.fullmatch(supplied) else str(uuid.uuid4())
        request.state.request_id = request_id
        bind_request_context(request_id)

        try:
            response = await call_next(request)
            response.headers["X-Request-ID"] = request_id
            return response
        finally:
            clear_request_context()


class MetricsMiddleware(BaseHTTPMiddleware):
    """Record bounded-cardinality HTTP metrics and structured access events."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        started = time.perf_counter()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            elapsed_seconds = time.perf_counter() - started
            route = request.scope.get("route")
            route_path = getattr(route, "path", None) or _normalize_unmatched_path(request.url.path)
            HTTP_REQUESTS.labels(
                method=request.method,
                route=route_path,
                status=str(status_code),
            ).inc()
            HTTP_REQUEST_DURATION.labels(
                method=request.method,
                route=route_path,
            ).observe(elapsed_seconds)
            logger.info(
                "http_request_completed",
                method=request.method,
                route=route_path,
                status_code=status_code,
                duration_ms=round(elapsed_seconds * 1000, 3),
            )


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Redis-backed fixed-window rate limiting for authenticated API routes."""

    def __init__(self, app: object) -> None:
        super().__init__(app)
        self.settings = get_settings()
        self.redis: Redis | None = None

    def _client(self, request: Request) -> Redis:
        shared_client = getattr(request.app.state, "rate_limit_redis", None)
        if shared_client is not None:
            return shared_client
        if self.redis is None:
            self.redis = Redis.from_url(
                self.settings.redis_url,
                encoding="utf-8",
                decode_responses=True,
                socket_connect_timeout=0.5,
                socket_timeout=0.5,
            )
        return self.redis

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if not self.settings.rate_limit_enabled or not request.url.path.startswith(
            "/api/v1/campaigns"
        ):
            return await call_next(request)

        client_host = request.client.host if request.client else "unknown"
        supplied_api_key = request.headers.get(self.settings.api_key_header, "")
        api_key_component = (
            hashlib.sha256(supplied_api_key.encode("utf-8")).hexdigest()
            if supplied_api_key
            else "anonymous"
        )
        identity_material = f"{client_host}|{api_key_component}"
        identity = hashlib.sha256(identity_material.encode("utf-8")).hexdigest()

        now = int(time.time())
        window = self.settings.rate_limit_window_seconds
        bucket = now // window
        reset_at = (bucket + 1) * window
        key = f"hcvf:rate-limit:{identity}:{bucket}"

        try:
            current = int(
                await self._client(request).eval(
                    _RATE_LIMIT_SCRIPT,
                    1,
                    key,
                    window + 1,
                )
            )
        except RedisError as exc:
            logger.warning(
                "rate_limit_backend_unavailable",
                error_type=exc.__class__.__name__,
            )
            return JSONResponse(
                status_code=503,
                content={
                    "error": {
                        "code": "rate_limit_unavailable",
                        "message": "The API rate-limit dependency is unavailable.",
                    }
                },
            )

        limit = self.settings.rate_limit_requests
        remaining = max(0, limit - current)
        headers = {
            "X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(reset_at),
        }

        if current > limit:
            RATE_LIMIT_REJECTIONS.inc()
            headers["Retry-After"] = str(max(1, reset_at - now))
            return JSONResponse(
                status_code=429,
                content={
                    "error": {
                        "code": "rate_limit_exceeded",
                        "message": "Rate limit exceeded for this API identity.",
                    }
                },
                headers=headers,
            )

        response = await call_next(request)
        response.headers.update(headers)
        return response


def _normalize_unmatched_path(path: str) -> str:
    normalized = _UUID_PATH_SEGMENT.sub("/{id}", path)
    return normalized if len(normalized) <= 200 else "unmatched"
