from __future__ import annotations

from uuid import uuid4

from redis import Redis

_RELEASE_SCRIPT = """
if redis.call('get', KEYS[1]) == ARGV[1] then
    return redis.call('del', KEYS[1])
end
return 0
"""


class DistributedLock:
    def __init__(self, redis: Redis, name: str, *, ttl_seconds: int = 30):
        if ttl_seconds < 1:
            raise ValueError("ttl_seconds must be at least 1")
        self.redis = redis
        self.key = f"hcvf:lock:{name}"
        self.ttl_seconds = ttl_seconds
        self.owner = str(uuid4())
        self.acquired = False

    def acquire(self) -> bool:
        acquired = bool(self.redis.set(self.key, self.owner, nx=True, ex=self.ttl_seconds))
        self.acquired = acquired
        return acquired

    def release(self) -> bool:
        released = bool(self.redis.eval(_RELEASE_SCRIPT, 1, self.key, self.owner))
        if released:
            self.acquired = False
        return released

    def __enter__(self) -> "DistributedLock":
        if not self.acquire():
            raise RuntimeError(f"Could not acquire distributed lock {self.key}")
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()
