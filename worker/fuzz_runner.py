from __future__ import annotations

from dataclasses import dataclass

import httpx


@dataclass(frozen=True)
class ValidationResult:
    http_status: int
    final_url: str
    headers: dict[str, str]


class FuzzRunner:
    """Bounded HTTP validation primitive for explicitly authorized campaign targets."""

    def __init__(self, *, timeout_seconds: float = 10.0):
        self.timeout_seconds = timeout_seconds

    def run(self, target_url: str) -> ValidationResult:
        with httpx.Client(
            timeout=self.timeout_seconds,
            follow_redirects=True,
            headers={"User-Agent": "HCVF-Authorized-Validation/1.0"},
        ) as client:
            response = client.get(target_url)
        return ValidationResult(
            http_status=response.status_code,
            final_url=str(response.url),
            headers={key.lower(): value for key, value in response.headers.items()},
        )
