"""Named hunt profiles: reusable doctrine for campaigns."""

from __future__ import annotations

from copy import deepcopy

PROFILES: dict[str, dict[str, object]] = {
    "external-baseline": {
        "description": "Configuration, transport and trust-boundary checks on a public estate.",
        "budget_requests": 120,
        "safety_ceiling": "read_only",
        "genome": {
            "probes": [
                "surface-crawl",
                "security-headers",
                "tls-posture",
                "cookie-flags",
                "cors-policy",
                "jwt-posture",
                "error-disclosure",
                "security-txt",
            ]
        },
    },
    "auth-surface": {
        "description": "Token, redirect and throttling posture where authentication lives.",
        "budget_requests": 150,
        "safety_ceiling": "read_only",
        "genome": {
            "probes": [
                "surface-crawl",
                "jwt-posture",
                "cors-policy",
                "cookie-flags",
                "rate-limit",
            ]
        },
    },
    "exposure": {
        "description": "Static exposure: VCS metadata, env files, traversal and API docs.",
        "budget_requests": 100,
        "safety_ceiling": "read_only",
        "genome": {
            "probes": [
                "surface-crawl",
                "exposed-config",
                "security-txt",
                "openapi-surface",
            ]
        },
    },
    "full-catalog": {
        "description": "Everything the grant's safety ceiling allows; use for deep assessments.",
        "budget_requests": 400,
        "safety_ceiling": "read_only",
        "genome": {},
    },
}


class ProfileError(ValueError):
    pass


def list_profiles() -> list[dict[str, object]]:
    return [
        {"name": name, "description": spec["description"], "budget_requests": spec["budget_requests"]}
        for name, spec in sorted(PROFILES.items())
    ]


def get_profile(name: str) -> dict[str, object]:
    if name not in PROFILES:
        raise ProfileError(f"unknown profile {name!r}")
    return deepcopy(PROFILES[name])
