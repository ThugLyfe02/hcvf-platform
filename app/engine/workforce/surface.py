"""The objective's own picture of the surface: nodes, edges, saturation, value.

Coverage asked "did we touch every route". The adaptive planner needs a richer
question: *which route is worth touching next, for which probe, and how much
would we learn?* That requires state per route, not just a set.

The graph is built from what the objective actually observed (recon endpoints,
task routes, findings), never from a global cache, so two objectives on the same
host cannot contaminate each other's reasoning.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

from app.engine.types import Endpoint
from app.engine.workforce.coverage import ROLE_PROBES, classify_route, normalize_route, route_value


@dataclass(frozen=True, slots=True)
class SurfaceNode:
    """One addressable route and what the objective knows about it."""

    route: str
    role: str
    value: float
    depth: int = 1
    probes: tuple[str, ...] = ()
    finding_kinds: tuple[str, ...] = ()
    risk: float = 0.0

    def saturation(self) -> float:
        expected = max(1, len(ROLE_PROBES.get(self.role, ROLE_PROBES["other"])))
        return min(1.0, len(self.probes) / expected)

    def to_dict(self) -> dict[str, object]:
        return {
            "route": self.route,
            "role": self.role,
            "value": round(self.value, 4),
            "depth": self.depth,
            "probes": list(self.probes),
            "findings": list(self.finding_kinds),
            "risk": round(self.risk, 2),
            "saturation": round(self.saturation(), 3),
        }


@dataclass
class SurfaceGraph:
    """Nodes plus parent/child edges derived from path ancestry."""

    origin: str
    nodes: dict[str, SurfaceNode] = field(default_factory=dict)
    edges: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def discover(self, urls, *, depth: int = 1) -> None:
        for url in urls:
            route = normalize_route(str(url))
            if route not in self.nodes:
                path_depth = max(1, len([part for part in urlsplit(route).path.split("/") if part]))
                self.nodes[route] = SurfaceNode(
                    route=route,
                    role=classify_route(route),
                    value=route_value(route),
                    depth=min(depth, path_depth),
                )
            # Implied ancestors are part of the surface too: /admin/users implies
            # /admin, which is often the more interesting route.
            self._ensure_ancestors(route)
        self._rebuild_edges()

    def _ensure_ancestors(self, route: str) -> None:
        path = urlsplit(route).path.rstrip("/")
        scheme_host = route[: len(route) - len(path)] if path else route
        while "/" in path:
            path = path.rsplit("/", 1)[0]
            ancestor = scheme_host + (path or "/")
            ancestor = normalize_route(ancestor)
            if ancestor in self.nodes or ancestor == route:
                continue
            self.nodes[ancestor] = SurfaceNode(
                route=ancestor,
                role=classify_route(ancestor),
                value=route_value(ancestor),
                depth=1,
            )

    def observe(
        self,
        *,
        route: str,
        probes=(),
        finding_kinds=(),
        risk: float = 0.0,
    ) -> None:
        normalized = normalize_route(route)
        node = self.nodes.get(normalized)
        if node is None:
            node = SurfaceNode(
                route=normalized,
                role=classify_route(normalized),
                value=route_value(normalized),
            )
        merged_probes = tuple(sorted({*node.probes, *[str(probe) for probe in probes if probe]}))
        merged_kinds = tuple(sorted({*node.finding_kinds, *[str(kind) for kind in finding_kinds if kind]}))
        self.nodes[normalized] = SurfaceNode(
            route=node.route,
            role=node.role,
            value=node.value,
            depth=node.depth,
            probes=merged_probes,
            finding_kinds=merged_kinds,
            risk=max(node.risk, float(risk)),
        )

    def _rebuild_edges(self) -> None:
        routes = sorted(self.nodes)
        edges: dict[str, tuple[str, ...]] = dict.fromkeys(routes, ())
        for route in routes:
            parent = self._parent_of(route, routes)
            if parent and parent != route:
                edges[parent] = (*edges[parent], route)
        self.edges = edges

    def _parent_of(self, route: str, routes: list[str]) -> str | None:
        path = urlsplit(route).path.rstrip("/")
        scheme_host = route[: len(route) - len(path)] if path else route
        while "/" in path:
            path = path.rsplit("/", 1)[0]
            candidate = scheme_host + path
            if candidate in self.nodes:
                return candidate
        return None

    # -- selection -------------------------------------------------------
    def ranked(self, limit: int | None = None) -> list[SurfaceNode]:
        ordered = sorted(
            self.nodes.values(),
            key=lambda node: (node.value * (1.0 - node.saturation()) * (1.0 + node.risk / 100.0), node.route),
            reverse=True,
        )
        return ordered[:limit] if limit else ordered

    def frontier(self, allowed_probes: tuple[str, ...], *, limit: int = 8) -> list[tuple[SurfaceNode, str]]:
        """Unprobed (route, probe) pairs, best first.

        Routes are visited in value order and each contributes only the probes its
        role suggests that it has not already received.
        """

        allowed = set(allowed_probes)
        pairs: list[tuple[SurfaceNode, str]] = []
        for node in self.ranked():
            role_probes = [probe for probe in ROLE_PROBES.get(node.role, ROLE_PROBES["other"]) if probe in allowed]
            for probe in role_probes:
                if probe not in node.probes:
                    pairs.append((node, probe))
            if len(pairs) >= limit * 4:
                break
        return pairs[:limit]

    def unprobed_routes(self) -> list[str]:
        return [node.route for node in self.nodes.values() if not node.probes]

    def to_dict(self) -> dict[str, object]:
        return {
            "origin": self.origin,
            "nodes": [node.to_dict() for node in self.ranked(100)],
            "edges": {parent: list(children) for parent, children in self.edges.items() if children},
            "unprobed": len(self.unprobed_routes()),
        }


def build_surface(
    origin: str,
    *,
    discovered: tuple[str, ...] = (),
    endpoints: tuple[Endpoint, ...] = (),
    observations: tuple[tuple[str, tuple[str, ...], tuple[str, ...], float], ...] = (),
) -> SurfaceGraph:
    """Assemble a graph from discovery plus per-task observations.

    ``observations`` is ``(route, probes, finding_kinds, risk)`` per executed
    task, which is exactly what the supervisor already persists.
    """

    graph = SurfaceGraph(origin=normalize_route(origin))
    graph.discover((origin, *discovered))
    graph.discover(endpoint.url for endpoint in endpoints)
    for route, probes, kinds, risk in observations:
        graph.observe(route=route, probes=probes, finding_kinds=kinds, risk=risk)
    return graph
