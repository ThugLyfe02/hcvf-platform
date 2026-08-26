from __future__ import annotations

import functools
import random
import time
from collections.abc import Callable
from typing import ParamSpec, TypeVar

P = ParamSpec("P")
R = TypeVar("R")


def retry(
    *,
    max_retries: int = 3,
    base_delay: float = 0.5,
    jitter: float = 0.25,
    exceptions: tuple[type[BaseException], ...] = (Exception,),
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    if max_retries < 0:
        raise ValueError("max_retries must be non-negative")
    if base_delay < 0:
        raise ValueError("base_delay must be non-negative")
    if jitter < 0:
        raise ValueError("jitter must be non-negative")

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            attempt = 0
            while True:
                try:
                    return func(*args, **kwargs)
                except exceptions:
                    if attempt >= max_retries:
                        raise
                    delay = base_delay * (2**attempt)
                    if jitter:
                        delay += random.uniform(0, jitter)
                    time.sleep(delay)
                    attempt += 1

        return wrapper

    return decorator
