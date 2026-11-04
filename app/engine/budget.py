from __future__ import annotations

import time
from dataclasses import dataclass, field
from types import TracebackType

from app.engine.errors import BudgetExceeded


@dataclass(slots=True)
class Budget:
    """Hard resource ceiling for one hunt.

    A budget is not an estimate. Every outbound request must spend from it, and
    the hunt stops at the first field that is exhausted — an over-running
    scanner is an authorization incident waiting to happen.
    """

    max_requests: int = 400
    max_bytes: int = 16_000_000
    max_seconds: float = 300.0
    started_at: float = field(default_factory=time.monotonic)
    used_requests: int = 0
    used_bytes: int = 0

    def elapsed(self) -> float:
        return time.monotonic() - self.started_at

    def remaining_seconds(self) -> float:
        return max(0.0, self.max_seconds - self.elapsed())

    def spend(self, *, requests: int = 0, bytes_in: int = 0) -> None:
        if self.used_requests + requests > self.max_requests:
            raise BudgetExceeded(f"request budget exhausted ({self.max_requests})")
        if self.used_bytes + bytes_in > self.max_bytes:
            raise BudgetExceeded(f"byte budget exhausted ({self.max_bytes})")
        if self.elapsed() > self.max_seconds:
            raise BudgetExceeded(f"time budget exhausted ({self.max_seconds}s)")
        self.used_requests += requests
        self.used_bytes += bytes_in

    def check_deadline(self) -> None:
        if self.elapsed() > self.max_seconds:
            raise BudgetExceeded(f"time budget exhausted ({self.max_seconds}s)")

    def snapshot(self) -> dict[str, float | int]:
        return {
            "max_requests": self.max_requests,
            "used_requests": self.used_requests,
            "max_bytes": self.max_bytes,
            "used_bytes": self.used_bytes,
            "max_seconds": round(self.max_seconds, 3),
            "elapsed_seconds": round(self.elapsed(), 3),
        }

    #: Convenience so a budget can be used as a deadline scope guard.
    def __enter__(self) -> Budget:
        self.check_deadline()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        return None


class KillSwitch:
    """Cooperative halt flag checked before every outbound request.

    Deliberately not a thread/process kill: validation must stop between
    requests so the audit trail shows exactly what was and was not sent.
    """

    def __init__(self) -> None:
        self._halted = False
        self._reason = ""

    def halt(self, reason: str = "operator halt") -> None:
        self._halted = True
        self._reason = reason

    @property
    def halted(self) -> bool:
        return self._halted

    @property
    def reason(self) -> str:
        return self._reason

    def check(self) -> None:
        if self._halted:
            from app.engine.errors import HuntHalted

            raise HuntHalted(self._reason)
