from __future__ import annotations

import hashlib
import logging

from fastapi import HTTPException, Request, status
from redis.asyncio import Redis
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from app.core.config import settings
from app.core.gcra import RedisGcra

logger = logging.getLogger(__name__)

EXEMPT_PATHS = {"/health", "/healthz", "/readyz", "/metrics", "/", "/openapi.json", "/docs", "/redoc"}


class RateLimited(HTTPException):
    def __init__(self, retry_after: int) -> None:
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(retry_after)},
        )


class RateLimitMiddleware(BaseHTTPMiddleware):
    """GCRA-based throttling with availability-first failure semantics.

    GCRA removes the fixed-window boundary burst: the allowance is a schedule,
    not a bucket that resets, so a client cannot spend its whole minute at 59.9s
    and again at 60.1s. When Redis is unreachable the request is allowed and a
    warning is logged — a rate limiter is a fairness control, not an
    authorization control. Scope, budget and egress checks fail closed instead.
    """

    def __init__(self, app) -> None:
        super().__init__(app)
        self.enabled = settings.rate_limit_enabled
        self.redis = Redis.from_url(settings.redis_url, decode_responses=True) if self.enabled else None
        self.limiter = (
            RedisGcra(
                self.redis,
                limit=settings.rate_limit_requests,
                window_seconds=settings.rate_limit_window_seconds,
            )
            if self.redis is not None
            else None
        )

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if not self.enabled or self.limiter is None or request.url.path in EXEMPT_PATHS:
            return await call_next(request)

        identity = request.headers.get(settings.api_key_header)
        if not identity:
            identity = request.client.host if request.client else "unknown"
        identity_hash = hashlib.sha256(identity.encode("utf-8", "replace")).hexdigest()[:32]

        try:
            allowed, retry_after = await self.limiter.check(identity_hash)
        except Exception as exc:
            logger.warning("rate limiter unavailable, allowing request: %s", exc)
            return await call_next(request)

        if not allowed:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Rate limit exceeded"},
                headers={"Retry-After": str(max(1, round(retry_after)))},
            )
        return await call_next(request)

    async def close(self) -> None:
        if self.redis is not None:
            await self.redis.aclose()
