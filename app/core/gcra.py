"""GCRA rate limiting.

The previous fixed-window counter allowed a 2x burst across a boundary: a client
could spend the whole allowance at 59.9s and again at 60.1s. GCRA (the algorithm
behind leaky-bucket and "token bucket as a schedule") gives a smooth rate with a
bounded burst and no boundary artefact.

``GcraLimiter`` is pure and clock-injected, so the arithmetic is unit-testable
without Redis. ``RedisGcra`` is the shared-state adapter used by the middleware.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field

SCRIPT = """
local tat = tonumber(redis.call('get', KEYS[1]) or '0')
local now = tonumber(ARGV[1])
local interval = tonumber(ARGV[2])
local burst = tonumber(ARGV[3])
local allow_at = tat - (burst - 1) * interval
if now < allow_at then
  return {0, math.ceil(allow_at - now)}
end
local new_tat = math.max(tat, now) + interval
local ttl = math.ceil(new_tat - now) + 1000
redis.call('set', KEYS[1], new_tat, 'PX', ttl)
return {1, 0}
"""


@dataclass
class GcraLimiter:
    """Pure GCRA. Times are milliseconds."""

    rate_per_second: float
    burst: int = 1
    clock: object = field(default=time.monotonic)

    def __post_init__(self) -> None:
        if self.rate_per_second <= 0:
            raise ValueError("rate_per_second must be positive")
        if self.burst < 1:
            raise ValueError("burst must be at least 1")
        self.interval_ms = 1000.0 / self.rate_per_second
        self._tat: dict[str, float] = {}

    def now_ms(self) -> float:
        return float(self.clock() * 1000.0)  # type: ignore[operator]

    def check(self, identity: str, *, cost: int = 1) -> tuple[bool, float]:
        """Return (allowed, retry_after_seconds)."""

        now = self.now_ms()
        tat = self._tat.get(identity, 0.0)
        # A burst of N permits N in-flight requests: the tolerance window is
        # (N-1) intervals, not N, or the first burst over-admits by one.
        allow_at = tat - (self.burst - 1) * self.interval_ms
        if now < allow_at:
            return False, math.ceil(allow_at - now) / 1000.0
        new_tat = max(tat, now) + self.interval_ms * cost
        self._tat[identity] = new_tat
        return True, 0.0


class RedisGcra:
    """Shared GCRA state in Redis, evaluated atomically in Lua."""

    def __init__(self, redis, *, limit: int, window_seconds: int, burst: int | None = None) -> None:
        if limit < 1 or window_seconds < 1:
            raise ValueError("limit and window must be positive")
        self.redis = redis
        self.interval_ms = (window_seconds * 1000.0) / limit
        self.burst = max(1, burst if burst is not None else limit)

    async def check(self, identity_hash: str, *, cost: int = 1) -> tuple[bool, float]:
        now_ms = time.time() * 1000.0
        allowed, retry_ms = await self.redis.eval(
            SCRIPT,
            1,
            f"hcvf:gcra:{identity_hash}",
            now_ms,
            self.interval_ms * cost,
            self.burst,
        )
        return bool(int(allowed)), (float(retry_ms) / 1000.0 if not allowed else 0.0)
