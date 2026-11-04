"""Specialist agents and their deliberative protocol.

The design goal is *auditable disagreement*. Each agent has a narrow doctrine,
proposes work from that doctrine, and must then score every other agent's
proposals with a stated reason. The final plan is an aggregation of those
judgements — not the output of one model and not a hard-coded probe order.

Self-critique is excluded on purpose: an agent scoring its own proposal is the
single fastest way to make a consensus mechanism decorative.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from app.engine.bandit import ProbeBandit
from app.engine.bayes import Posterior, VulnClass
from app.engine.graph import Route, endpoint_value
from app.engine.probes import ProbeSpec, registry
from app.engine.types import Cost, SafetyClass, Target, stable_hash

#: Doctrine-specific route preferences. A JWT check belongs where tokens are
#: issued; a header check belongs on a page that actually renders.
ROUTE_AFFINITY: dict[VulnClass, tuple[str, ...]] = {
    VulnClass.jwt: ("login", "auth", "token", "oauth", "session", "sso"),
    VulnClass.redirect: ("login", "auth", "sso", "redirect", "callback"),
    VulnClass.graphql: ("graphql", "gql"),
    VulnClass.methods: ("admin", "internal", "api", "actuator", "manage"),
    VulnClass.traversal: ("admin", "download", "upload", "file", "export", "backup"),
    VulnClass.error_disclosure: ("api", "admin", "search"),
    VulnClass.rate_limit: ("login", "auth", "token", "otp"),
    VulnClass.cors: ("api", "graphql"),
}


@dataclass(frozen=True, slots=True)
class HuntView:
    """The shared, read-mostly world state every agent reasons over."""

    target: Target
    endpoints: tuple = ()
    routes: tuple[Route, ...] = ()
    posterior: Posterior = field(default_factory=Posterior)
    bandit: ProbeBandit = field(default_factory=ProbeBandit)
    budget_requests: int = 200
    aggression: float = 0.4
    max_safety: SafetyClass = SafetyClass.read_only

    def route_for(self, probe: ProbeSpec) -> str:
        """Pick a route that fits the probe's doctrine, spreading the swarm.

        Every probe aiming at the single highest-scoring URL wastes the surface
        graph and concentrates the budget on one endpoint. Probes are ranked by
        doctrine affinity, then by whether the route actually renders, and
        near-equal winners are rotated deterministically per probe.
        """

        if not self.routes:
            return self.target.url

        tokens: tuple[str, ...] = ()
        for vuln in probe.targets:
            tokens += ROUTE_AFFINITY.get(vuln, ())

        def locality(route: Route) -> float:
            url = route.target.url.lower()
            affinity = 1.0 if tokens and any(token in url for token in tokens) else 0.0
            status = route.target.status
            renders = 1.0 if status is None or status < 400 else 0.0
            return 2.0 * affinity + 0.6 * renders + route.score

        ranked = sorted(self.routes, key=locality, reverse=True)
        best = locality(ranked[0])
        # Rotate only among routes that are genuinely as good as the winner, so
        # doctrine still dominates and ties are spread deterministically.
        near = [route for route in ranked if locality(route) >= best - 0.05][:3]
        index = int(stable_hash(probe.id)[:8], 16) % len(near)
        return near[index].target.url

    def route_quality(self, url: str) -> float:
        if not self.routes:
            return 0.5 if url.rstrip("/") == self.target.url.rstrip("/") else 0.0
        best = max(self.routes, key=lambda route: route.score)
        if url == best.target.url:
            return 1.0
        for route in self.routes:
            if route.target.url == url:
                return min(1.0, route.score / max(best.score, 1e-6))
        return 0.1


@dataclass(frozen=True, slots=True)
class Proposal:
    proposal_id: str
    probe_id: str
    agent: str
    route: str
    rationale: str
    priority: float
    safety: SafetyClass
    cost: Cost
    expected_gain: float

    def to_dict(self) -> dict[str, object]:
        return {
            "proposal_id": self.proposal_id,
            "probe_id": self.probe_id,
            "agent": self.agent,
            "route": self.route,
            "rationale": self.rationale,
            "priority": round(self.priority, 4),
            "safety": self.safety.name,
            "cost_requests": self.cost.requests,
            "expected_gain": round(self.expected_gain, 4),
        }


@dataclass(frozen=True, slots=True)
class Critique:
    proposal_id: str
    agent: str
    score: float
    reason: str
    blocker: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "proposal_id": self.proposal_id,
            "agent": self.agent,
            "score": round(self.score, 4),
            "reason": self.reason,
            "blocker": self.blocker,
        }


@dataclass(frozen=True, slots=True)
class Objection:
    """A specific, adjudicable argument against an option."""

    code: str
    text: str
    blocking: bool = False
    penalty: float = 0.2
    rival_probe: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "text": self.text,
            "blocking": self.blocking,
            "penalty": self.penalty,
            "rival_probe": self.rival_probe,
        }


@dataclass(frozen=True, slots=True)
class Rebuttal:
    """A sponsor's answer to an objection."""

    text: str
    resolves: bool = False


@dataclass(frozen=True, slots=True)
class Ruling:
    """The risk officer's adjudication of an objection."""

    upheld: bool
    text: str
    penalty: float = 0.2


class HuntingAgent(ABC):
    """A doctrine: what to propose, and how to judge someone else's proposal."""

    name: str = "agent"
    weight: float = 1.0
    focus: tuple[VulnClass, ...] = ()

    @abstractmethod
    def propose(self, view: HuntView) -> list[Proposal]: ...

    def critique(self, proposal: Proposal, view: HuntView) -> Critique:
        relevance = 1.0 if set(self.focus) & set(self._targets(proposal.probe_id)) else 0.25
        history = view.bandit.arm(proposal.probe_id).mean
        route_quality = view.route_quality(proposal.route)
        efficiency = 1.0 / (1.0 + proposal.cost.requests / 4.0)
        score = 0.10 + 0.30 * relevance + 0.25 * route_quality + 0.20 * history + 0.15 * efficiency
        score = max(0.0, min(1.0, score))
        reason = (
            f"relevance={relevance:.2f} route={route_quality:.2f} history={history:.2f} efficiency={efficiency:.2f}"
        )
        blocker = ""
        if proposal.safety > view.max_safety:
            blocker = f"safety class {proposal.safety.name} exceeds grant ceiling {view.max_safety.name}"
            score = 0.0
        return Critique(proposal.proposal_id, self.name, score, reason, blocker)

    def spawn(self, view: HuntView) -> list[tuple[HuntingAgent, str]]:
        """Convene a specialist when the discovered surface justifies one."""

        return []

    def reply(self, objection: Objection, option, view: HuntView) -> Rebuttal | None:
        """Answer an objection with a concrete, checkable claim."""

        spec = _spec(option.probe_id)
        if spec is None:
            return None

        if objection.code == "over_budget":
            return Rebuttal(
                "Cost is intrinsic to the probe; if the budget is contested this option should be "
                "withdrawn rather than defended.",
                False,
            )
        if objection.code == "low_information":
            gain = view.posterior.expected_information_gain(spec.model())
            if gain >= 0.02:
                return Rebuttal(f"Posterior expected information gain is {gain:.3f} bits, above 0.02.", True)
            return None
        if objection.code == "high_false_positive":
            if spec.false_positive_rate < 0.5:
                return Rebuttal(
                    f"Findings are emitted at info severity with a manual-review tag; modelled "
                    f"false-positive rate is {spec.false_positive_rate:.2f}.",
                    True,
                )
            return None
        if objection.code == "unverified_route":
            if option.route in {route.target.url for route in view.routes}:
                return Rebuttal(
                    "The route came from the scored surface graph, which is built from links on the entry "
                    "page; confirming its behaviour is precisely what this probe is for.",
                    True,
                )
            return None
        if objection.code == "inefficient_tradeoff":
            rival = _spec(objection.rival_probe)
            mine = _spec(option.probe_id)
            if rival is not None and mine is not None and set(rival.targets).isdisjoint(mine.targets):
                return Rebuttal(
                    f"The rival covers different vulnerability classes "
                    f"({', '.join(v.value for v in rival.targets)} vs {', '.join(v.value for v in mine.targets)}); "
                    "the comparison is not like-for-like.",
                    True,
                )
            return None
        if objection.code == "low_route_value":
            best = max(view.routes, key=lambda route: route.score, default=None)
            if best is not None and option.route == best.target.url:
                return Rebuttal("This is the highest-value route in the surface graph.", True)
            return None
        return None

    @staticmethod
    def _targets(probe_id: str) -> tuple[VulnClass, ...]:
        spec = registry().get(probe_id)
        return spec.spec.targets if spec else ()


def _proposal(
    agent: str,
    spec: ProbeSpec,
    view: HuntView,
    rationale: str,
    priority: float,
    route: str | None = None,
) -> Proposal:
    return Proposal(
        proposal_id=f"{agent}:{spec.id}@{route or ''}",
        probe_id=spec.id,
        agent=agent,
        route=route or view.route_for(spec),
        rationale=rationale,
        priority=priority,
        safety=spec.safety,
        cost=spec.cost,
        expected_gain=view.posterior.expected_information_gain(spec.model()),
    )


def _spec(probe_id: str) -> ProbeSpec | None:
    cls = registry().get(probe_id)
    return cls.spec if cls else None


class ReconAgent(HuntingAgent):
    name = "recon"
    weight = 1.2
    focus = (VulnClass.infra,)

    def propose(self, view: HuntView) -> list[Proposal]:
        proposals: list[Proposal] = []
        spec = _spec("surface-crawl")
        if spec:
            proposals.append(
                _proposal(
                    self.name,
                    spec,
                    view,
                    "Surface is unmeasured; discovery must precede targeted validation.",
                    1.0 if not view.endpoints else 0.35,
                )
            )
        for probe_id, priority, rationale in (
            ("security-txt", 0.4, "Passive metadata often reveals unlinked surface."),
            (
                "openapi-surface",
                0.55,
                "A published API specification is the highest-fidelity route map available; ingest it before probing blindly.",
            ),
        ):
            candidate = _spec(probe_id)
            if candidate:
                proposals.append(_proposal(self.name, candidate, view, rationale, priority))
        return proposals

    def spawn(self, view: HuntView) -> list[tuple[HuntingAgent, str]]:
        urls = [route.target.url for route in view.routes] + [endpoint.url for endpoint in view.endpoints]
        lowered = " ".join(urls).lower()
        spawned: list[tuple[HuntingAgent, str]] = []

        if "graphql" in lowered:
            spawned.append((GraphqlSpecialist(), "a GraphQL surface is in the discovered route set"))
        if any(token in lowered for token in ("/login", "oauth", "token", "/auth", "session", "sso")):
            spawned.append((AuthSpecialist(), "an authentication surface is reachable"))
        if any(token in lowered for token in ("/admin", "internal", "manage", "actuator", "console")):
            spawned.append((AdminSurfaceSpecialist(), "an administrative surface is reachable"))

        return spawned


class ConfigAgent(HuntingAgent):
    name = "config"
    weight = 1.0
    focus = (VulnClass.headers, VulnClass.tls, VulnClass.cookies, VulnClass.methods)

    def propose(self, view: HuntView) -> list[Proposal]:
        proposals: list[Proposal] = []
        for probe_id in ("security-headers", "tls-posture", "cookie-flags", "http-methods"):
            spec = _spec(probe_id)
            if not spec:
                continue
            if probe_id == "tls-posture" and not view.target.is_tls:
                continue
            gain = view.posterior.expected_information_gain(spec.model())
            proposals.append(
                _proposal(
                    self.name,
                    spec,
                    view,
                    f"Configuration posture for {', '.join(v.value for v in spec.targets)} (expected gain {gain:.3f} bits).",
                    0.5 + min(0.5, gain),
                )
            )
        return proposals


class TrustBoundaryAgent(HuntingAgent):
    name = "trust-boundary"
    weight = 1.1
    focus = (VulnClass.jwt, VulnClass.cors, VulnClass.redirect)

    def propose(self, view: HuntView) -> list[Proposal]:
        proposals: list[Proposal] = []
        for probe_id in ("cors-policy", "jwt-posture", "open-redirect"):
            spec = _spec(probe_id)
            if not spec:
                continue
            if probe_id == "open-redirect" and not any("?" in route.target.url for route in view.routes):
                continue
            proposals.append(
                _proposal(
                    self.name,
                    spec,
                    view,
                    "Cross-origin and token trust are the highest-impact boundary on most web estates.",
                    0.6 + view.posterior.expected_information_gain(spec.model()),
                )
            )
        return proposals


class InputAgent(HuntingAgent):
    name = "input"
    weight = 1.0
    focus = (VulnClass.traversal, VulnClass.xss, VulnClass.sqli, VulnClass.ssrf, VulnClass.graphql)

    def propose(self, view: HuntView) -> list[Proposal]:
        proposals: list[Proposal] = []
        parameterized = [route for route in view.routes if "?" in route.target.url]
        spec = _spec("exposed-config")
        if spec:
            proposals.append(
                _proposal(self.name, spec, view, "Static path exposure is cheap and decisive when present.", 0.55)
            )
        graphql_spec = _spec("graphql-introspection")
        if graphql_spec and any("graphql" in route.target.url.lower() for route in view.routes):
            proposals.append(
                _proposal(
                    self.name, graphql_spec, view, "GraphQL surface discovered; schema disclosure is likely.", 0.7
                )
            )
        if parameterized:
            # Reserved for schema-aware injection probes in a later release.
            pass
        return proposals


class ReliabilityAgent(HuntingAgent):
    name = "reliability"
    weight = 0.8
    focus = (VulnClass.error_disclosure, VulnClass.rate_limit)

    def propose(self, view: HuntView) -> list[Proposal]:
        proposals: list[Proposal] = []
        for probe_id in ("error-disclosure",):
            spec = _spec(probe_id)
            if spec:
                proposals.append(
                    _proposal(self.name, spec, view, "Error handling is a high-signal, low-cost check.", 0.45)
                )
        return proposals


class RiskOfficer(HuntingAgent):
    """The veto holder. Cheap, safe, high-confidence work only."""

    name = "risk-officer"
    weight = 1.5
    focus = (VulnClass.headers, VulnClass.tls, VulnClass.error_disclosure)

    def propose(self, view: HuntView) -> list[Proposal]:
        return []

    def critique(self, proposal: Proposal, view: HuntView) -> Critique:
        base = super().critique(proposal, view)
        if proposal.safety > view.max_safety:
            return base
        confidence_penalty = 0.0
        spec = registry().get(proposal.probe_id)
        if spec and spec.spec.false_positive_rate > 0.2:
            confidence_penalty = 0.25
        if proposal.cost.requests > max(20, view.budget_requests // 4):
            confidence_penalty += 0.15
        score = max(0.0, base.score - confidence_penalty)
        reason = base.reason + f" fp_penalty={confidence_penalty:.2f}"
        return Critique(base.proposal_id, self.name, score, reason, base.blocker)

    def rule(self, objection: Objection, reply: Rebuttal | None, option, view: HuntView) -> Ruling:
        """Adjudicate an objection on evidence, not rhetoric."""

        if objection.blocking:
            return Ruling(True, f"Objection {objection.code!r} is blocking and admittance is not negotiable.", 1.0)

        if reply is not None and reply.resolves:
            return Ruling(False, f"Objection {objection.code!r} answered: {reply.text}", 0.0)

        if objection.code == "low_information":
            spec = _spec(option.probe_id)
            gain = view.posterior.expected_information_gain(spec.model()) if spec else 0.0
            if gain >= 0.02:
                return Ruling(False, f"Expected information gain {gain:.3f} bits clears the threshold.", 0.0)
            return Ruling(True, f"Expected information gain {gain:.3f} bits is too low to justify a round.", 0.15)

        if objection.code == "high_false_positive":
            spec = _spec(option.probe_id)
            if spec is not None and spec.false_positive_rate < 0.5:
                return Ruling(False, "Noise is bounded and findings are marked for manual review.", 0.0)
            return Ruling(True, "The probe is too noisy to act on without corroboration.", objection.penalty)

        if objection.code == "unverified_route":
            if reply is not None and reply.resolves:
                return Ruling(
                    False,
                    "Route provenance is adequate for a first pass; the objection is noted but not upheld.",
                    0.0,
                )
            return Ruling(True, "Probing an unconfirmed route is speculation; uphold.", objection.penalty)

        if objection.code == "inefficient_tradeoff":
            if reply is not None and reply.resolves:
                return Ruling(False, f"Objection answered: {reply.text}", 0.0)
            return Ruling(
                True,
                "A cheaper option buys at least as much information; the expensive leader is demoted this round.",
                objection.penalty,
            )

        if objection.code == "over_budget":
            return Ruling(True, "The option does not fit the remaining budget envelope.", objection.penalty)

        return Ruling(False, f"No rule for {objection.code!r}; objection dismissed.", 0.0)


class DevilsAdvocate(HuntingAgent):
    """Argues against the current leader so consensus is tested, not assumed."""

    name = "devils-advocate"
    weight = 1.3
    focus = ()

    def propose(self, view: HuntView) -> list[Proposal]:
        return []

    def challenge(self, option, view: HuntView, round_no: int, rivals: tuple = ()) -> Objection | None:
        spec = _spec(option.probe_id)
        if spec is None:
            return None

        budget_ceiling = max(20, view.budget_requests // 4)
        if option.cost.requests > budget_ceiling:
            return Objection(
                "over_budget",
                f"{option.probe_id} needs {option.cost.requests} requests, above the {budget_ceiling} "
                "per-option ceiling.",
                False,
                0.25,
            )
        if spec.false_positive_rate >= 0.2:
            return Objection(
                "high_false_positive",
                f"{option.probe_id} has a modelled false-positive rate of {spec.false_positive_rate:.2f}; "
                "acting on it could waste an analyst's day.",
                False,
                0.2,
            )
        gain = view.posterior.expected_information_gain(spec.model())
        if gain < 0.02:
            return Objection(
                "low_information",
                f"{option.probe_id} is expected to yield only {gain:.3f} bits against the current posterior.",
                False,
                0.2,
            )
        if view.route_quality(option.route) < 0.15:
            return Objection(
                "low_route_value",
                f"{option.probe_id} is aimed at a low-value route ({option.route}); the surface graph "
                "suggests better targets.",
                False,
                0.2,
            )

        cheaper = [
            rival
            for rival in rivals
            if rival.cost.requests < option.cost.requests
            and rival.proposal.expected_gain >= option.proposal.expected_gain * 0.8
        ]
        if cheaper:
            rival = min(cheaper, key=lambda candidate: candidate.cost.requests)
            return Objection(
                "inefficient_tradeoff",
                f"{option.probe_id} costs {option.cost.requests} requests for "
                f"{option.proposal.expected_gain:.2f} bits, while {rival.probe_id} costs "
                f"{rival.cost.requests} for {rival.proposal.expected_gain:.2f}. Spend the budget where "
                "it buys more information.",
                False,
                0.15,
                rival.probe_id,
            )

        observed = {endpoint.url for endpoint in view.endpoints}
        if option.route not in observed:
            return Objection(
                "unverified_route",
                f"{option.probe_id} is aimed at {option.route}, which the crawl has not confirmed yet. "
                "We may be spending a round on an assumption.",
                False,
                0.1,
            )
        return None


class GraphqlSpecialist(HuntingAgent):
    name = "graphql-specialist"
    weight = 1.1
    focus = (VulnClass.graphql,)

    def propose(self, view: HuntView) -> list[Proposal]:
        spec = _spec("graphql-introspection")
        if spec is None:
            return []
        route = next((route for route in view.routes if "graphql" in route.target.url.lower()), None)
        if route is None:
            return []
        return [
            _proposal(
                self.name,
                spec,
                view,
                "A GraphQL endpoint is reachable; schema disclosure is the highest-yield first move.",
                0.8,
                route.target.url,
            )
        ]


class AuthSpecialist(HuntingAgent):
    name = "auth-specialist"
    weight = 1.15
    focus = (VulnClass.jwt, VulnClass.redirect, VulnClass.rate_limit)

    def propose(self, view: HuntView) -> list[Proposal]:
        spec = _spec("jwt-posture")
        if spec is None:
            return []
        tokens = ("login", "oauth", "token", "auth", "session", "sso")
        route = next((route for route in view.routes if any(t in route.target.url.lower() for t in tokens)), None)
        if route is None:
            return []
        return [
            _proposal(
                self.name,
                spec,
                view,
                "An authentication surface is reachable; token construction is worth a dedicated look.",
                0.75,
                route.target.url,
            )
        ]


class AdminSurfaceSpecialist(HuntingAgent):
    name = "admin-specialist"
    weight = 1.05
    focus = (VulnClass.methods, VulnClass.traversal, VulnClass.infra)

    def propose(self, view: HuntView) -> list[Proposal]:
        spec = _spec("http-methods")
        if spec is None:
            return []
        tokens = ("/admin", "internal", "manage", "actuator", "console")
        route = next((route for route in view.routes if any(t in route.target.url.lower() for t in tokens)), None)
        if route is None:
            return []
        return [
            _proposal(
                self.name,
                spec,
                view,
                "An administrative surface is reachable; method exposure there matters more than at the root.",
                0.7,
                route.target.url,
            )
        ]


def default_agents() -> list[HuntingAgent]:
    return [
        ReconAgent(),
        ConfigAgent(),
        TrustBoundaryAgent(),
        InputAgent(),
        ReliabilityAgent(),
        RiskOfficer(),
        DevilsAdvocate(),
    ]


def summarize_routes(routes: tuple[Route, ...], limit: int = 3) -> list[dict[str, object]]:
    return [route.to_dict() for route in routes[:limit]]


def value_of(url: str) -> float:
    return endpoint_value(url)
