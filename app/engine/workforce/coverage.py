"""Surface coverage: routes by probes, chosen by role, measured not assumed.

The first workforce generation probed a fixed set of doctrines against one route.
That is cheap and predictable, but it cannot answer "did we actually cover the
application?" — so objectives could complete while half the discovered surface
was never touched.

This module does three things:

* classifies a discovered route by role (entry, auth, admin, api, data, other);
* assigns the probes that matter for that role, bounded by budget and caps;
* measures coverage from task outcomes, so a criterion can require it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

from app.engine.types import Endpoint

ROLE_TOKENS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("auth", ("login", "signin", "auth", "token", "oauth", "session", "sso", "password", "mfa", "otp")),
    ("admin", ("admin", "internal", "manage", "console", "actuator", "superuser", "staff")),
    ("api", ("/api", "graphql", "gql", "rest", "rpc")),
    ("data", ("export", "download", "upload", "file", "invoice", "report", "backup")),
)

#: Which probes are worth spending on a route of each role.
ROLE_PROBES: dict[str, tuple[str, ...]] = {
    "entry": ("security-headers", "cookie-flags", "error-disclosure"),
    "auth": ("jwt-posture", "cors-policy", "cookie-flags"),
    "admin": ("http-methods", "exposed-config", "security-headers"),
    "api": ("cors-policy", "http-methods", "openapi-surface"),
    "data": ("exposed-config", "error-disclosure"),
    "other": ("security-headers",),
}

#: Never assign these as coverage work: they are whole-surface, not per-route.
WHOLE_SURFACE_PROBES = frozenset({"surface-crawl", "openapi-surface", "security-txt", "rate-limit"})


def normalize_route(url: str) -> str:
    """Origin + path, no query and no trailing slash, for set comparisons."""

    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    default = 443 if scheme == "https" else 80
    port = parts.port or default
    suffix = "" if port == default else f":{port}"
    path = (parts.path or "/").rstrip("/") or "/"
    return f"{scheme}://{host}{suffix}{path}"


def classify_route(url: str) -> str:
    path = urlsplit(url).path.lower()
    if path in {"", "/"}:
        return "entry"
    for role, tokens in ROLE_TOKENS:
        if any(token in path for token in tokens):
            return role
    return "other"


def route_value(url: str) -> float:
    """Cheap ordering heuristic so budget goes to the interesting routes first."""

    from app.engine.graph import endpoint_value

    base = endpoint_value(url)
    role_bonus = {"auth": 0.25, "admin": 0.25, "api": 0.15, "data": 0.2, "entry": 0.1, "other": 0.0}
    return min(1.0, base + role_bonus.get(classify_route(url), 0.0))


@dataclass(frozen=True, slots=True)
class CoveragePlan:
    """Routes worth probing, the probes assigned, and what was left out."""

    routes: tuple[str, ...] = ()
    assignments: tuple[tuple[str, str], ...] = ()
    skipped_routes: tuple[str, ...] = ()
    skipped_reasons: tuple[str, ...] = ()

    @property
    def task_count(self) -> int:
        return len(self.assignments)

    def to_dict(self) -> dict[str, object]:
        return {
            "routes": list(self.routes),
            "assignments": [{"route": route, "probe": probe} for route, probe in self.assignments],
            "skipped_routes": list(self.skipped_routes),
            "skipped_reasons": list(self.skipped_reasons),
            "task_count": self.task_count,
        }


@dataclass
class CoverageState:
    """Accumulates what has actually been probed, for the coverage criterion."""

    discovered: set[str] = field(default_factory=set)
    probed: dict[str, set[str]] = field(default_factory=dict)

    def discover(self, urls) -> None:
        for url in urls:
            if url:
                self.discovered.add(normalize_route(str(url)))

    def record(self, route: str, probes) -> None:
        probed_probes = {str(probe) for probe in probes if probe}
        if not probed_probes:
            return
        normalized = normalize_route(route)
        self.discovered.add(normalized)
        self.probed.setdefault(normalized, set()).update(probed_probes)

    @property
    def covered_routes(self) -> set[str]:
        return {route for route, probes in self.probed.items() if probes}

    def ratio(self) -> float:
        if not self.discovered:
            return 1.0
        return len(self.covered_routes & self.discovered) / len(self.discovered)

    def missing(self) -> list[str]:
        return sorted(self.discovered - self.covered_routes)

    def to_dict(self) -> dict[str, object]:
        return {
            "discovered": len(self.discovered),
            "covered": len(self.covered_routes & self.discovered),
            "ratio": round(self.ratio(), 4),
            "missing": self.missing()[:25],
            "probes": {route: sorted(probes) for route, probes in sorted(self.probed.items())[:50]},
        }


def plan_coverage(
    *,
    origin: str,
    routes: tuple[str, ...],
    endpoints: tuple[Endpoint, ...] = (),
    allowed_probes: tuple[str, ...],
    max_routes: int,
    max_tasks: int,
    min_probability: float = 0.0,
) -> CoveragePlan:
    """Assign role-appropriate probes to the most valuable discovered routes.

    Budget is spent breadth-first: one high-value probe on many routes beats five
    probes on one route when the deltas come from misconfiguration, so routes are
    ranked by value and each receives its most important probe before any route
    receives a second.
    """

    allow = {probe for probe in allowed_probes if probe not in WHOLE_SURFACE_PROBES}
    if not allow:
        return CoveragePlan(skipped_reasons=("no per-route probes are permitted by the safety ceiling",))

    observed: dict[str, Endpoint] = {}
    for endpoint in endpoints:
        observed.setdefault(normalize_route(endpoint.url), endpoint)

    candidates: list[str] = []
    seen: set[str] = set()
    for url in (origin + "/", *routes):
        normalized = normalize_route(url)
        if normalized in seen:
            continue
        seen.add(normalized)
        candidates.append(normalized)

    candidates.sort(key=route_value, reverse=True)
    selected = candidates[: max(0, max_routes)]
    skipped = [route for route in candidates if route not in set(selected)]

    staged: list[list[tuple[str, str]]] = []
    for route in selected:
        role = classify_route(route)
        ranked = [probe for probe in ROLE_PROBES.get(role, ROLE_PROBES["other"]) if probe in allow]
        if not ranked:
            ranked = [probe for probe in ("security-headers", "cookie-flags") if probe in allow]
        staged.append([(route, probe) for probe in ranked])

    assignments: list[tuple[str, str]] = []
    depth = 0
    while len(assignments) < max_tasks:
        added = False
        for stage in staged:
            if depth < len(stage) and len(assignments) < max_tasks:
                route, probe = stage[depth]
                assignments.append((route, probe))
                added = True
        if not added:
            break
        depth += 1

    reasons: list[str] = []
    if skipped:
        reasons.append(f"{len(skipped)} lower-value route(s) outside the route cap")
    if len(assignments) >= max_tasks:
        reasons.append(f"task cap reached at {max_tasks}")
    if min_probability > 0:
        reasons.append(f"routes below value {min_probability:.2f} were not scheduled")

    return CoveragePlan(
        routes=tuple(selected),
        assignments=tuple(assignments),
        skipped_routes=tuple(skipped),
        skipped_reasons=tuple(reasons),
    )
