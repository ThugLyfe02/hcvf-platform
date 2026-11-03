"""The arbiter: turns proposals and critiques into a defensible plan.

Selection is a hard-constrained greedy knapsack — hard constraints first
(safety ceiling, scope coverage, known probe), then a score that blends
consensus, expected information gain and historical yield. Every rejection is
recorded with a reason, because "why didn't it check X?" is the question a
customer will ask.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from app.engine.agents import Critique, HuntView, Proposal
from app.engine.probes import registry
from app.engine.types import ScopeGrant


@dataclass(frozen=True, slots=True)
class ArbiterDecision:
    proposal_id: str
    probe_id: str
    agent: str
    selected: bool
    score: float
    consensus: float
    information_gain: float
    bandit_sample: float
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "proposal_id": self.proposal_id,
            "probe_id": self.probe_id,
            "agent": self.agent,
            "selected": self.selected,
            "score": round(self.score, 4),
            "consensus": round(self.consensus, 4),
            "information_gain": round(self.information_gain, 4),
            "bandit_sample": round(self.bandit_sample, 4),
            "reason": self.reason,
        }


def aggregate_critiques(
    proposals: list[Proposal],
    critiques: list[Critique],
    weights: dict[str, float],
) -> dict[str, tuple[float, list[str]]]:
    """Weighted mean of non-blocking critiques, plus the reasons attached."""

    by_proposal: dict[str, list[Critique]] = {}
    for critique in critiques:
        by_proposal.setdefault(critique.proposal_id, []).append(critique)

    consensus: dict[str, tuple[float, list[str]]] = {}
    for proposal in proposals:
        relevant = by_proposal.get(proposal.proposal_id, [])
        blockers = [c for c in relevant if c.blocker]
        if blockers:
            consensus[proposal.proposal_id] = (0.0, [f"blocked: {blockers[0].blocker}"])
            continue
        total_weight = sum(weights.get(c.agent, 1.0) for c in relevant) or 1.0
        score = sum(c.score * weights.get(c.agent, 1.0) for c in relevant) / total_weight
        reasons = [f"{c.agent}: {c.score:.2f} ({c.reason})" for c in relevant]
        consensus[proposal.proposal_id] = (score, reasons)
    return consensus


def decide(
    proposals: list[Proposal],
    critiques: list[Critique],
    view: HuntView,
    grant: ScopeGrant,
    *,
    rng: random.Random,
    budget_requests: int,
    agent_weights: dict[str, float],
) -> list[ArbiterDecision]:
    consensus_map = aggregate_critiques(proposals, critiques, agent_weights)
    max_gain = max((proposal.expected_gain for proposal in proposals), default=1.0) or 1.0

    scored: list[tuple[Proposal, float, float, float, str]] = []
    for proposal in proposals:
        consensus, reasons = consensus_map.get(proposal.proposal_id, (0.0, []))
        spec = registry().get(proposal.probe_id)
        if consensus <= 0.0:
            scored.append((proposal, 0.0, consensus, 0.0, "; ".join(reasons) or "no consensus"))
            continue
        if spec is None:
            scored.append((proposal, 0.0, 0.0, 0.0, "unknown probe"))
            continue
        if not grant.covers(proposal.route, "GET", spec.spec.safety):
            scored.append((proposal, 0.0, consensus, 0.0, f"route outside scope: {proposal.route}"))
            continue
        normalized_gain = min(1.0, proposal.expected_gain / max_gain)
        sample = view.bandit.arm(proposal.probe_id).sample(rng)
        score = 0.45 * consensus + 0.35 * normalized_gain + 0.20 * sample
        scored.append((proposal, score, consensus, sample, "; ".join(reasons)))

    scored.sort(key=lambda item: item[1], reverse=True)

    decisions: list[ArbiterDecision] = []
    chosen_probes: set[str] = set()
    spent = 0
    allowance = max(0, int(budget_requests * 0.85))
    for proposal, score, consensus, sample, reasons in scored:
        reason = reasons or "no critique recorded"
        if score <= 0.0:
            decisions.append(
                ArbiterDecision(
                    proposal.proposal_id,
                    proposal.probe_id,
                    proposal.agent,
                    False,
                    0.0,
                    consensus,
                    proposal.expected_gain,
                    sample,
                    reason,
                )
            )
            continue
        if proposal.probe_id in chosen_probes:
            decisions.append(
                ArbiterDecision(
                    proposal.proposal_id,
                    proposal.probe_id,
                    proposal.agent,
                    False,
                    score,
                    consensus,
                    proposal.expected_gain,
                    sample,
                    "duplicate probe (higher-ranked route already chosen)",
                )
            )
            continue
        if spent + proposal.cost.requests > allowance:
            decisions.append(
                ArbiterDecision(
                    proposal.proposal_id,
                    proposal.probe_id,
                    proposal.agent,
                    False,
                    score,
                    consensus,
                    proposal.expected_gain,
                    sample,
                    f"over budget (needs {proposal.cost.requests}, {allowance - spent} remaining)",
                )
            )
            continue
        chosen_probes.add(proposal.probe_id)
        spent += proposal.cost.requests
        decisions.append(
            ArbiterDecision(
                proposal.proposal_id,
                proposal.probe_id,
                proposal.agent,
                True,
                score,
                consensus,
                proposal.expected_gain,
                sample,
                reason,
            )
        )

    # Discovery must run before probes that consume discovered endpoints.
    decisions.sort(key=lambda d: (not d.selected, d.probe_id != "surface-crawl", -d.score))
    return decisions


def selected_probe_ids(decisions: list[ArbiterDecision]) -> list[str]:
    return [decision.probe_id for decision in decisions if decision.selected]
