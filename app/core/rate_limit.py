from __future__ import annotations

import hashlib
import time

from fastapi import HTTPException, Request, status
from redis.asyncio import Redis
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from app.core.config import settings


class RedisRateLimiter:
    def __init__(self, redis: Redis, limit: int, window_seconds: int) -> None:
        if limit < 1:
            raise ValueError("limit must be at least 1")
        if window_seconds < 1:
            raise ValueError("window_seconds must be at least 1")
        self.redis = redis
        self.limit = limit
        self.window_seconds = window_seconds

    async def check(self, identity: str) -> None:
        identity_hash = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]
        bucket = int(time.time()) // self.window_seconds
        key = f"hcvf:rate-limit:{identity_hash}:{bucket}"

        try:
            count = await self.redis.incr(key)
            if count == 1:
                await self.redis.expire(key, self.window_seconds + 1)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Rate limiter unavailable",
            ) from exc

        if count > self.limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded",
                headers={"Retry-After": str(self.window_seconds)},
            )


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app) -> None:
        super().__init__(app)
        self.redis = Redis.from_url(settings.redis_url, decode_responses=True)
        self.limiter = RedisRateLimiter(
            redis=self.redis,
            limit=settings.rate_limit_requests,
            window_seconds=settings.rate_limit_window_seconds,
        )

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path in {"/health", "/metrics"}:
            return await call_next(request)

        identity = request.headers.get(settings.api_key_header)
        if not identity:
            identity = request.client.host if request.client else "unknown"

        await self.limiter.check(identity)
        return await call_next(request)

    async def close(self) -> None:
        await self.redis.aclose()
