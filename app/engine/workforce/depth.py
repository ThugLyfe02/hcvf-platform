"""Objective depth: how hard an objective is allowed to look.

A surface pass is cheap and bounded. A deep pass re-plans more, sweeps more
routes, and verifies medium findings as well as high ones. Depth is a declared
property of the work order, so cost and thoroughness are explicit rather than
implicit in a template.
"""

from __future__ import annotations

from dataclasses import dataclass

DEPTHS = ("surface", "standard", "deep")


@dataclass(frozen=True, slots=True)
class DepthProfile:
    name: str
    adaptive_max_tasks: int
    adaptive_batch: int
    coverage_max_routes: int
    coverage_max_tasks: int
    verify_severities: tuple[str, ...]
    per_task_min: int

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "adaptive_max_tasks": self.adaptive_max_tasks,
            "adaptive_batch": self.adaptive_batch,
            "coverage_max_routes": self.coverage_max_routes,
            "coverage_max_tasks": self.coverage_max_tasks,
            "verify_severities": list(self.verify_severities),
        }


PROFILES: dict[str, DepthProfile] = {
    "surface": DepthProfile(
        name="surface",
        adaptive_max_tasks=4,
        adaptive_batch=1,
        coverage_max_routes=3,
        coverage_max_tasks=4,
        verify_severities=("critical",),
        per_task_min=4,
    ),
    "standard": DepthProfile(
        name="standard",
        adaptive_max_tasks=10,
        adaptive_batch=2,
        coverage_max_routes=6,
        coverage_max_tasks=12,
        verify_severities=("critical", "high"),
        per_task_min=4,
    ),
    "deep": DepthProfile(
        name="deep",
        adaptive_max_tasks=24,
        adaptive_batch=4,
        coverage_max_routes=12,
        coverage_max_tasks=30,
        verify_severities=("critical", "high", "medium"),
        per_task_min=4,
    ),
}


def profile(depth: str | None) -> DepthProfile:
    return PROFILES.get(str(depth or "standard"), PROFILES["standard"])
