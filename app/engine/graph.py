"""Attack-surface graph and route ranking.

Agents disagree about *where* to spend effort. This module gives them a shared,
inspectable map: a graph of discovered endpoints with a heuristic value per node
and a search that proposes the highest-yield routes of approach.

The value model is intentionally simple and explainable — a planner that cannot
explain why it went left instead of right is not auditable.
"""

from __future__ import annotations

import heapq
from collections import defaultdict
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.engine.types import Endpoint

#: Path vocabulary that correlates with reachable authority or sensitive data.
VALUE_TOKENS: dict[str, float] = {
    "admin": 1.00,
    "administrator": 1.00,
    "internal": 0.95,
    "debug": 0.90,
    "actuator": 0.90,
    "console": 0.90,
    "manage": 0.85,
    "backup": 0.85,
    "private": 0.85,
    "upload": 0.80,
    "export": 0.80,
    "billing": 0.80,
    "invoice": 0.75,
    "payment": 0.80,
    "token": 0.85,
    "auth": 0.75,
    "login": 0.75,
    "oauth": 0.75,
    "sso": 0.75,
    "graphql": 0.70,
    "api": 0.60,
    "v1": 0.35,
    "v2": 0.35,
    "user": 0.55,
    "account": 0.55,
    "profile": 0.50,
    "config": 0.75,
    "settings": 0.55,
    "swagger": 0.70,
    "openapi": 0.70,
    "docs": 0.35,
    "metrics": 0.60,
    "status": 0.30,
    "health": 0.20,
    "static": 0.05,
    "assets": 0.05,
    "images": 0.05,
    "css": 0.05,
    "js": 0.05,
    "favicon": 0.02,
}

STATIC_SUFFIXES = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".css",
    ".js",
    ".map",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp4",
    ".webp",
    ".avif",
)

SENSITIVE_PATHS = ("/.git", "/.env", "/backup", "/.svn", "/.aws", "/.ssh", "/server-status", "/actuator/env")


def endpoint_value(url: str, *, status: int | None = None, content_type: str = "") -> float:
    """Heuristic 0..1 worth of probing an endpoint, with a short rationale."""

    parts = urlsplit(url)
    segments = [segment for segment in parts.path.lower().split("/") if segment]
    score = 0.0
    for segment in segments:
        for token, weight in VALUE_TOKENS.items():
            if token in segment:
                score = max(score, weight * (1.0 if token == segment else 0.8))
    if any(parts.path.lower().endswith(suffix) for suffix in STATIC_SUFFIXES):
        score *= 0.15
    if parts.query:
        score += 0.15  # parameters are where injection lives
    if any(token in parts.path.lower() for token in SENSITIVE_PATHS):
        score = max(score, 0.95)
    if status is not None:
        if status >= 500:
            score += 0.10
        if status in (401, 403):
            score += 0.20  # an access boundary worth probing
        if status == 404:
            score *= 0.5
    if "json" in content_type:
        score += 0.10
    return max(0.0, min(1.0, score))


@dataclass(frozen=True, slots=True)
class Route:
    path: tuple[Endpoint, ...]
    score: float
    rationale: str

    @property
    def target(self) -> Endpoint:
        return self.path[-1]

    def to_dict(self) -> dict[str, object]:
        return {
            "score": round(self.score, 4),
            "rationale": self.rationale,
            "hops": len(self.path) - 1,
            "target": self.target.url,
            "path": [node.url for node in self.path],
        }


def _normalize(url: str) -> str:
    return url.rstrip("/") or "/"


def build_adjacency(endpoints: list[Endpoint], seed_url: str) -> dict[str, list[Endpoint]]:
    adjacency: dict[str, list[Endpoint]] = defaultdict(list)
    known = {_normalize(seed_url)}
    for endpoint in endpoints:
        known.add(_normalize(endpoint.url))
    for endpoint in endpoints:
        parent = _normalize(endpoint.source) if endpoint.source else _normalize(seed_url)
        if parent not in known:
            parent = _normalize(seed_url)
        adjacency[parent].append(endpoint)
    return adjacency


def best_routes(
    endpoints: list[Endpoint],
    seed_url: str,
    *,
    limit: int = 5,
    max_depth: int = 4,
) -> list[Route]:
    """Return the most promising approach routes, best first.

    Search is best-first on node value rather than blind BFS: at each step we
    expand the frontier node with the highest value, which keeps the search
    cheap while still surfacing deep, high-value surfaces.
    """

    if not endpoints:
        return []

    seed = Endpoint(url=seed_url, source=seed_url, value=endpoint_value(seed_url))
    adjacency = build_adjacency(endpoints, seed_url)
    frontier: list[tuple[float, int, Endpoint, tuple[Endpoint, ...]]] = []
    counter = 0
    heapq.heappush(frontier, (-seed.value, counter, seed, (seed,)))
    seen_routes: list[Route] = []
    visited: set[str] = set()

    while frontier and len(seen_routes) < limit * 4:
        _, _, node, path = heapq.heappop(frontier)
        key = _normalize(node.url)
        if key in visited:
            continue
        visited.add(key)

        if len(path) > 1:
            interior = path[1:-1]
            mean_interior = sum(item.value for item in interior) / len(interior) if interior else 0.0
            depth = len(path) - 1
            score = 0.6 * path[-1].value + 0.3 * mean_interior + 0.1 * (1.0 / (1.0 + depth))
            seen_routes.append(
                Route(
                    path=path,
                    score=score,
                    rationale=_rationale(path[-1], depth),
                )
            )

        if len(path) - 1 >= max_depth:
            continue
        for child in sorted(adjacency.get(key, []), key=lambda item: item.value, reverse=True):
            child_key = _normalize(child.url)
            if child_key in visited:
                continue
            counter += 1
            heapq.heappush(frontier, (-child.value, counter, child, (*path, child)))

    seen_routes.sort(key=lambda route: route.score, reverse=True)
    return seen_routes[:limit]


def _rationale(target: Endpoint, depth: int) -> str:
    reasons: list[str] = []
    lowered = target.path.lower()
    for token, weight in sorted(VALUE_TOKENS.items(), key=lambda kv: kv[1], reverse=True):
        if token in lowered and weight >= 0.55:
            reasons.append(f"path token {token!r}")
            break
    if target.status in (401, 403):
        reasons.append("authentication boundary")
    if "?" in target.url:
        reasons.append("parameterized input")
    if target.status is not None and target.status >= 500:
        reasons.append("server error observed")
    if not reasons:
        reasons.append("reachable surface")
    return f"depth {depth}: " + ", ".join(reasons)


def rank_endpoints(endpoints: list[Endpoint], *, limit: int = 50) -> list[Endpoint]:
    ranked = sorted(endpoints, key=lambda item: item.value, reverse=True)
    return ranked[:limit]
