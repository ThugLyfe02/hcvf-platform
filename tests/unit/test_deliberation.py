"""Deliberation protocol tests: conversation shape, convergence, spawning, safety."""

from __future__ import annotations

import json
import unittest

from app.engine.agents import (
    DevilsAdvocate,
    HuntingAgent,
    HuntView,
    Objection,
    Proposal,
    Rebuttal,
    RiskOfficer,
)
from app.engine.bayes import Posterior
from app.engine.deliberation import Deliberation, Option
from app.engine.planner import HuntPlanner
from app.engine.probes import registry
from app.engine.target import build_grant, parse_target
from app.engine.transcript import render_markdown
from app.engine.types import Cost, Endpoint, SafetyClass

TARGET = parse_target("https://app.example.test/")


def _endpoints() -> list[Endpoint]:
    seed = Endpoint(url="https://app.example.test/", source="https://app.example.test/", value=0.4)
    return [
        seed,
        Endpoint(url="https://app.example.test/graphql", source=seed.url, value=0.95),
        Endpoint(url="https://app.example.test/login", source=seed.url, value=0.85),
        Endpoint(url="https://app.example.test/admin/users", source=seed.url, value=0.9),
        Endpoint(url="https://app.example.test/api/v1/users?page=1", source=seed.url, value=0.8),
    ]


class _FixedSponsor(HuntingAgent):
    name = "config"
    weight = 1.0

    def __init__(self, proposal: Proposal) -> None:
        self._proposal = proposal

    def propose(self, view: HuntView) -> list[Proposal]:
        return [self._proposal]


class TestDeliberationProtocol(unittest.TestCase):
    def _expensive_option(self) -> Proposal:
        spec = registry()["security-headers"].spec
        return Proposal(
            proposal_id="config:security-headers",
            probe_id="security-headers",
            agent="config",
            route=TARGET.url,
            rationale="expensive test option",
            priority=1.0,
            safety=spec.safety,
            cost=Cost(requests=500),
            expected_gain=0.2,
        )

    def _view(self, *, safety: SafetyClass = SafetyClass.read_only, endpoints=()) -> HuntView:
        from app.engine.graph import best_routes

        routes = tuple(best_routes(list(endpoints), TARGET.url, limit=6))
        grant = build_grant(TARGET, safety=safety)
        return HuntView(
            target=TARGET,
            endpoints=tuple(endpoints),
            routes=routes,
            posterior=Posterior(),
            budget_requests=200,
            max_safety=grant.max_safety,
        )

    def test_devils_advocate_challenges_an_expensive_option_and_risk_rules(self) -> None:
        view = self._view()
        grant = build_grant(TARGET)
        deliberation = Deliberation(
            [_FixedSponsor(self._expensive_option()), RiskOfficer(), DevilsAdvocate()],
            view,
            grant,
            allowed=None,
            max_rounds=3,
        )
        outcome = deliberation.run()
        acts = [message.act for message in outcome.messages]

        self.assertIn("challenge", acts, "the devil's advocate never objected")
        self.assertIn("reply", acts, "the sponsor never answered")
        self.assertIn("ruling", acts, "the risk officer never adjudicated")

        challenge = next(message for message in outcome.messages if message.act == "challenge")
        self.assertEqual(challenge.evidence["code"], "over_budget")
        ruling = next(message for message in outcome.messages if message.act == "ruling")
        self.assertTrue(ruling.evidence["upheld"])
        self.assertGreater(ruling.evidence["penalty"], 0)

    def test_a_resolving_reply_dismisses_the_objection(self) -> None:
        option = Option(self._expensive_option(), sponsor="config")
        objection = Objection("low_information", "too little signal", blocking=False, penalty=0.2)
        ruling = RiskOfficer().rule(
            objection, Rebuttal("the probe reaches a distinct surface", True), option, self._view()
        )
        self.assertFalse(ruling.upheld)

    def test_challenge_is_skipped_for_a_cheap_high_signal_option(self) -> None:
        spec = registry()["security-headers"].spec
        proposal = Proposal(
            proposal_id="config:security-headers",
            probe_id="security-headers",
            agent="config",
            route=TARGET.url,
            rationale="cheap",
            priority=1.0,
            safety=spec.safety,
            cost=spec.cost,
            expected_gain=0.3,
        )
        # The route must be observed, otherwise the advocate legitimately objects
        # that the swarm is about to probe an unconfirmed assumption.
        observed = [Endpoint(url=TARGET.url, source=TARGET.url, value=0.5, status=200)]
        objection = DevilsAdvocate().challenge(Option(proposal, "config"), self._view(endpoints=observed), round_no=2)
        self.assertIsNone(objection)

    def test_conversation_is_bounded_and_closes_with_a_consensus_message(self) -> None:
        plan = HuntPlanner().plan(TARGET, build_grant(TARGET), seed=3)
        acts = [message.act for message in plan.transcript]
        self.assertLessEqual(plan.rounds, 5)
        self.assertGreaterEqual(plan.rounds, 2)
        self.assertIn("consensus", acts)
        self.assertIn("propose", acts)
        self.assertTrue({"support", "oppose"} & set(acts))
        self.assertIn("moderate", acts)


class TestSwarmAndSafety(unittest.TestCase):
    def test_specialists_are_convened_for_discovered_surfaces(self) -> None:
        grant = build_grant(TARGET, safety=SafetyClass.state_changing)
        plan = HuntPlanner().plan(TARGET, grant, endpoints=_endpoints(), seed=11)
        self.assertIn("graphql-specialist", plan.agents)
        self.assertIn("auth-specialist", plan.agents)
        spawns = [message for message in plan.transcript if message.act == "spawn"]
        self.assertTrue(spawns)
        self.assertIn("GraphQL", " ".join(message.text for message in spawns))

    def test_safety_ceiling_applies_to_spawned_options(self) -> None:
        # GraphQL introspection is state_changing; a read-only grant must exclude it
        # even though the specialist was convened.
        grant = build_grant(TARGET, safety=SafetyClass.read_only)
        plan = HuntPlanner().plan(TARGET, grant, endpoints=_endpoints(), seed=11)
        proposed = {proposal.probe_id for proposal in plan.proposals}
        self.assertNotIn("graphql-introspection", proposed)
        for probe_id in plan.probes:
            self.assertLessEqual(registry()[probe_id].spec.safety, SafetyClass.read_only)

    def test_conversation_is_reproducible(self) -> None:
        grant = build_grant(TARGET, safety=SafetyClass.state_changing)
        first = HuntPlanner().plan(TARGET, grant, endpoints=_endpoints(), seed=99)
        second = HuntPlanner().plan(TARGET, grant, endpoints=_endpoints(), seed=99)
        self.assertEqual(
            json.dumps(first.to_dict()["deliberation"], sort_keys=True),
            json.dumps(second.to_dict()["deliberation"], sort_keys=True),
        )

    def test_transcript_renders_as_markdown(self) -> None:
        plan = HuntPlanner().plan(TARGET, build_grant(TARGET), endpoints=_endpoints(), seed=5)
        markdown = render_markdown(plan)
        self.assertIn("# Deliberation", markdown)
        self.assertIn("## Final allocation", markdown)
        self.assertIn("### Round 2", markdown)
        for agent in plan.agents:
            self.assertIn(agent, markdown)

    def test_votes_can_be_omitted_for_a_readable_minute(self) -> None:
        plan = HuntPlanner().plan(TARGET, build_grant(TARGET), seed=5)
        full = render_markdown(plan, include_votes=True)
        summary = render_markdown(plan, include_votes=False)
        self.assertLess(len(summary), len(full))


class TestOptionAccounting(unittest.TestCase):
    def test_options_are_route_specific(self) -> None:
        grant = build_grant(TARGET, safety=SafetyClass.state_changing)
        plan = HuntPlanner().plan(TARGET, grant, endpoints=_endpoints(), seed=2)
        routes = {proposal.route for proposal in plan.proposals}
        self.assertGreater(len(routes), 1, "the swarm only ever considered a single route")

    def test_withdrawn_options_do_not_reach_the_arbiter(self) -> None:
        plan = HuntPlanner().plan(TARGET, build_grant(TARGET), budget_requests=40, seed=4)
        retired = {proposal.probe_id for proposal in plan.proposals}
        selected = set(plan.probes)
        self.assertTrue(selected.issubset(retired | {"surface-crawl"}))


if __name__ == "__main__":
    unittest.main()
