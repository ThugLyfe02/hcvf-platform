from __future__ import annotations

import threading
import time
from enum import Enum
from typing import Callable, TypeVar

T = TypeVar("T")


class CircuitState(str, Enum):
    closed = "closed"
    open = "open"
    half_open = "half_open"


class CircuitOpenError(RuntimeError):
    pass


class CircuitBreaker:
    def __init__(self, *, failure_threshold: int = 5, recovery_timeout: float = 30.0):
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be at least 1")
        if recovery_timeout <= 0:
            raise ValueError("recovery_timeout must be greater than 0")
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._state = CircuitState.closed
        self._failure_count = 0
        self._opened_at: float | None = None
        self._lock = threading.RLock()

    def _current_state(self) -> CircuitState:
        if self._state == CircuitState.open and self._opened_at is not None:
            if time.monotonic() - self._opened_at >= self.recovery_timeout:
                self._state = CircuitState.half_open
        return self._state

    @property
    def state(self) -> CircuitState:
        with self._lock:
            return self._current_state()

    def call(self, func: Callable[..., T], *args, **kwargs) -> T:
        with self._lock:
            if self._current_state() == CircuitState.open:
                raise CircuitOpenError("Circuit breaker is open")
        try:
            result = func(*args, **kwargs)
        except Exception:
            self.record_failure()
            raise
        self.record_success()
        return result

    def record_success(self) -> None:
        with self._lock:
            self._failure_count = 0
            self._opened_at = None
            self._state = CircuitState.closed

    def record_failure(self) -> None:
        with self._lock:
            if self._state == CircuitState.half_open:
                self._state = CircuitState.open
                self._opened_at = time.monotonic()
                return
            self._failure_count += 1
            if self._failure_count >= self.failure_threshold:
                self._state = CircuitState.open
                self._opened_at = time.monotonic()
