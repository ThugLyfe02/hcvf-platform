"""Process-local registry of configured agent pools.

The database heartbeat table is the cross-process truth; this registry answers
"what is this process configured to run", which the admin endpoint reports
alongside it. It is deliberately tiny and lock-free: a dict assignment is enough
for a value only set at startup.
"""

from __future__ import annotations

from threading import Lock

_LOCK = Lock()
_POOLS: dict[str, int] = {}


def register_pools(pools: dict[str, int]) -> None:
    with _LOCK:
        _POOLS.clear()
        _POOLS.update({worker: int(count) for worker, count in pools.items()})


def clear() -> None:
    with _LOCK:
        _POOLS.clear()


def running_pools() -> dict[str, int]:
    with _LOCK:
        return dict(_POOLS)
