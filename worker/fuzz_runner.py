from __future__ import annotations

from dataclasses import dataclass

from app.core.config import settings
from app.engine.budget import Budget
from app.engine.http import GuardedHttpClient, RateLimiter
from app.engine.policy import EgressPolicy
from app.engine.target import build_grant, parse_target


@dataclass(frozen=True)
class ValidationResult:
    http_status: int
    final_url: str
    headers: dict[str, str]


class FuzzRunner:
    """Legacy reachability primitive, now routed through the guarded client.

    Kept for callers that only need a reachability check; it enforces the same
    scope, egress policy and budget as the full engine, so there is no second,
    weaker network path into a customer's estate.
    """

    def __init__(self, *, timeout_seconds: float = 10.0):
        self.timeout_seconds = timeout_seconds

    def run(self, target_url: str) -> ValidationResult:
        target = parse_target(target_url)
        grant = build_grant(target, max_rps=settings.hunt_max_rps)
        client = GuardedHttpClient(
            EgressPolicy(allow_private=settings.allow_private_targets or settings.environment.lower() == "development"),
            grant,
            Budget(max_requests=1, max_seconds=self.timeout_seconds),
            timeout=self.timeout_seconds,
            rate_limiter=RateLimiter(grant.max_rps),
        )
        response = client.request("GET", target_url)
        return ValidationResult(
            http_status=response.status,
            final_url=response.url,
            headers=dict(response.headers),
        )
