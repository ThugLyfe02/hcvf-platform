"""Hunt planning: the deliberate, reproducible decision layer.

A plan is a pure function of (grant, target, genome, priors, seed). Re-running
with the same inputs reproduces the same probe set and the same conversation,
which is what makes an agentic system auditable rather than merely impressive.
"""

from __future__ import annotations

import random
from collections.abc import Iterable
from dataclasses import dataclass, field

from app.engine.agents import Critique, HuntView, Proposal, default_agents
from app.engine.arbiter import ArbiterDecision, decide, selected_probe_ids
from app.engine.bandit import ProbeBandit
from app.engine.bayes import Posterior
from app.engine.deliberation import Deliberation, Message
from app.engine.evolution import Genome
from app.engine.graph import Route, best_routes
from app.engine.probes import default_probe_ids, filter_by_safety, registry
from app.engine.types import Endpoint, SafetyClass, ScopeGrant, Target


@dataclass(frozen=True, slots=True)
class HuntPlan:
    target: Target
    grant: ScopeGrant
    probes: tuple[str, ...]
    routes: tuple[Route, ...]
    decisions: tuple[ArbiterDecision, ...]
    proposals: tuple[Proposal, ...]
    critiques: tuple[Critique, ...]
    posterior: Posterior
    genome: Genome
    seed: int
    budget_requests: int
    strategy: dict[str, object] = field(default_factory=dict)

    #: The conversation that produced this plan.
    transcript: tuple[Message, ...] = ()
    rounds: int = 0
    converged: bool = False
    consensus_round: int | None = None
    agents: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target.origin,
            "seed": self.seed,
            "budget_requests": self.budget_requests,
            "probes": list(self.probes),
            "routes": [route.to_dict() for route in self.routes],
            "genome": self.genome.to_dict(),
            "strategy": self.strategy,
            "posterior_before": self.posterior.to_dict(),
            "proposals": [proposal.to_dict() for proposal in self.proposals],
            "critiques": [critique.to_dict() for critique in self.critiques],
            "decisions": [decision.to_dict() for decision in self.decisions],
            "deliberation": {
                "rounds": self.rounds,
                "converged": self.converged,
                "consensus_round": self.consensus_round,
                "agents": list(self.agents),
                "messages": [message.to_dict() for message in self.transcript],
            },
        }

    def explain(self) -> str:
        """Narrative for humans, reports and the CLI."""

        selected = [d for d in self.decisions if d.selected]
        rejected = [d for d in self.decisions if not d.selected]
        top_routes = ", ".join(route.target.url for route in self.routes[:2]) or self.target.url
        verdict = (
            f"consensus in round {self.consensus_round}" if self.converged else "no consensus; forced decision recorded"
        )
        lines = [
            f"{len(self.probes)} probes selected for {self.target.origin} after "
            f"{self.rounds} round(s) of deliberation with {len(self.agents)} agents ({verdict}).",
            f"Highest-value routes: {top_routes}.",
            "Selection rationale:",
        ]
        for decision in selected[:6]:
            lines.append(f"  + {decision.probe_id} (score {decision.score:.2f}) — {decision.reason[:160]}")
        for decision in rejected[:3]:
            lines.append(f"  - {decision.probe_id} — {decision.reason[:160]}")
        return "\n".join(lines)


class HuntPlanner:
    def __init__(self, agents=None) -> None:
        self.agents = list(agents or default_agents())
        self._weights = {agent.name: agent.weight for agent in self.agents}

    def plan(
        self,
        target: Target,
        grant: ScopeGrant,
        *,
        endpoints: Iterable[Endpoint] = (),
        posterior: Posterior | None = None,
        bandit: ProbeBandit | None = None,
        genome: Genome | None = None,
        budget_requests: int | None = None,
        aggression: float = 0.4,
        seed: int = 0,
        max_routes: int = 6,
    ) -> HuntPlan:
        rng = random.Random(seed)
        known = list(registry().keys())
        genome = (genome or Genome(probes=tuple(default_probe_ids()))).normalized(known)

        candidate_ids = list(genome.probes) or list(default_probe_ids())
        allowed = filter_by_safety(
            candidate_ids, grant.max_safety if grant.max_safety is not None else SafetyClass.read_only
        )
        # Discovery first: everything downstream is better with a surface map.
        if (
            "surface-crawl" in known
            and "surface-crawl" not in allowed
            and SafetyClass.read_only.allowed_by(grant.max_safety)
        ):
            allowed.insert(0, "surface-crawl")

        endpoint_list = list(endpoints)
        routes = tuple(best_routes(endpoint_list, target.url, limit=max_routes))

        view = HuntView(
            target=target,
            endpoints=tuple(endpoint_list),
            routes=routes,
            posterior=posterior or Posterior(),
            bandit=bandit or ProbeBandit(),
            budget_requests=budget_requests or genome.budget_requests,
            aggression=aggression,
            max_safety=grant.max_safety,
        )

        # The swarm deliberates, then the arbiter allocates. Spawned specialists
        # may introduce probes outside the genome, but never above the safety
        # ceiling: a conversation may discover new work, never new authority.
        deliberation = Deliberation(self.agents, view, grant, allowed=set(allowed))
        outcome = deliberation.run()

        proposals: list[Proposal] = [
            option.proposal for option_id, option in outcome.options.items() if option_id not in outcome.withdrawn
        ]

        critiques: list[Critique] = []
        for option_id, option in outcome.options.items():
            if option_id in outcome.withdrawn:
                continue
            score = outcome.scores.get(option_id, 0.0)
            critiques.append(
                Critique(
                    proposal_id=option.proposal.proposal_id,
                    agent="deliberation",
                    score=max(0.0, min(1.0, score)),
                    reason=(
                        f"deliberated {outcome.rounds} round(s), {'consensus' if outcome.converged else 'no consensus'}"
                    ),
                )
            )

        weights = {agent.name: agent.weight for agent in deliberation.agents}
        decisions = decide(
            proposals,
            critiques,
            view,
            grant,
            rng=rng,
            budget_requests=view.budget_requests,
            agent_weights=weights,
        )

        selected = selected_probe_ids(decisions)
        # Surface acquisition first: planning re-runs after these, and specialists
        # can only be convened for a surface that has been measured.
        discovery_ids = ("surface-crawl", "openapi-surface")
        ordered = [pid for pid in discovery_ids if pid in selected]
        ordered += [pid for pid in selected if pid not in discovery_ids]

        strategy = {
            "route_bias": genome.route_bias,
            "aggression": round(aggression, 3),
            "agents": [agent.name for agent in deliberation.agents],
            "candidate_probes": len(candidate_ids),
            "options": len(outcome.options),
            "rounds": outcome.rounds,
            "converged": outcome.converged,
            "safety_ceiling": view.max_safety.name,
            "routes_considered": len(routes),
        }

        return HuntPlan(
            target=target,
            grant=grant,
            probes=tuple(ordered),
            routes=routes,
            decisions=tuple(decisions),
            proposals=tuple(proposals),
            critiques=tuple(critiques),
            posterior=view.posterior,
            genome=genome,
            seed=seed,
            budget_requests=view.budget_requests,
            strategy=strategy,
            transcript=tuple(outcome.messages),
            rounds=outcome.rounds,
            converged=outcome.converged,
            consensus_round=outcome.consensus_round,
            agents=tuple(agent.name for agent in deliberation.agents),
        )
