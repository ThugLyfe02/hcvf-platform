"""Adaptive planning: surface graph, belief updates, EIG selection, memory bias."""

from __future__ import annotations

import unittest

from app.engine.types import SafetyClass
from app.engine.workforce.replan import (
    Belief,
    belief_from_outcomes,
    plan_adaptive,
    score_candidates,
)
from app.engine.workforce.surface import build_surface
from app.engine.workforce.types import FindingLite, TaskOutcome, TaskStatus

ALLOWED = ("security-headers", "jwt-posture", "cors-policy", "http-methods", "cookie-flags", "exposed-config")


def graph():
    return build_surface(
        "https://app.test",
        discovered=(
            "https://app.test/login",
            "https://app.test/admin/users",
            "https://app.test/api/v1/orders",
            "https://app.test/landing",
        ),
    )


class TestSurfaceGraph(unittest.TestCase):
    def test_nodes_roles_and_edges(self) -> None:
        g = graph()
        self.assertEqual(g.nodes["https://app.test/login"].role, "auth")
        self.assertEqual(g.nodes["https://app.test/admin/users"].role, "admin")
        self.assertEqual(g.nodes["https://app.test/api/v1/orders"].role, "api")
        # admin/users hangs off admin only if the parent was discovered; here it
        # was, so the ancestry edge exists.
        self.assertIn("https://app.test/admin/users", g.edges.get("https://app.test/admin", ()))

    def test_observe_merges_probes_findings_and_risk(self) -> None:
        g = graph()
        g.observe(
            route="https://app.test/login",
            probes=("jwt-posture",),
            finding_kinds=("jwt-alg-none",),
            risk=80.0,
        )
        node = g.nodes["https://app.test/login"]
        self.assertIn("jwt-posture", node.probes)
        self.assertIn("jwt-alg-none", node.finding_kinds)
        self.assertGreater(node.saturation(), 0.0)
        self.assertEqual(node.risk, 80.0)

    def test_frontier_excludes_probed_pairs(self) -> None:
        g = graph()
        g.observe(route="https://app.test/login", probes=("jwt-posture", "cors-policy", "cookie-flags"))
        pairs = g.frontier(ALLOWED, limit=20)
        login_pairs = [(node.route, probe) for node, probe in pairs if "login" in node.route]
        self.assertFalse(any(probe in {"jwt-posture", "cors-policy", "cookie-flags"} for _, probe in login_pairs))

    def test_ranked_prefers_valuable_unsaturated_routes(self) -> None:
        g = graph()
        g.observe(route="https://app.test/admin/users", probes=("http-methods", "exposed-config", "security-headers"))
        ranked = g.ranked()
        self.assertNotEqual(ranked[0].route, "https://app.test/admin/users")

    def test_unprobed_routes(self) -> None:
        g = graph()
        self.assertEqual(len(g.unprobed_routes()), len(g.nodes))
        g.observe(route="https://app.test/login", probes=("jwt-posture",))
        self.assertEqual(len(g.unprobed_routes()), len(g.nodes) - 1)


class TestBelief(unittest.TestCase):
    def test_observing_a_clean_result_reduces_entropy(self) -> None:
        belief = Belief.start()
        before = belief.information_gain("security-headers")
        belief.observe("security-headers", ())
        after = belief.information_gain("security-headers")
        self.assertLess(after, before)

    def test_observing_a_finding_raises_class_probability(self) -> None:
        belief = Belief.start()
        belief.observe("exposed-config", ("vcs-metadata",))
        self.assertIn("vcs-metadata", belief.findings)
        self.assertIn("exposed-config", belief.probes_run)
        top = dict(belief.top(10))
        key = next(iter(top))
        self.assertGreater(top[key], 0.0)

    def test_belief_from_outcomes(self) -> None:
        outcomes = [
            TaskOutcome(
                task_key="t1",
                status=TaskStatus.done,
                probes_run=("jwt-posture",),
                route="https://app.test/login",
                findings=(
                    FindingLite("f1", "jwt-alg-none", "critical", 0.95, "jwt-posture", "https://app.test/login"),
                ),
            )
        ]
        belief = belief_from_outcomes(outcomes)
        self.assertIn("jwt-posture", belief.probes_run)
        self.assertIn("jwt-alg-none", belief.findings)
        self.assertEqual(belief.observations, 1)


class TestAdaptiveSelection(unittest.TestCase):
    def test_candidates_exclude_known_pairs(self) -> None:
        g = graph()
        known = {("https://app.test/login", "cors-policy")}
        candidates = score_candidates(g, Belief.start(), allowed_probes=ALLOWED, known=known, limit=40)
        self.assertFalse(any(c.route == "https://app.test/login" and c.probe_id == "cors-policy" for c in candidates))

    def test_memory_biases_but_is_capped(self) -> None:
        g = graph()
        belief = Belief.start()
        memory = {("cors-policy", "auth"): 5.0}
        candidates = score_candidates(g, belief, allowed_probes=ALLOWED, memory=memory, limit=40)
        boosted = [c for c in candidates if c.probe_id == "cors-policy" and "login" in c.route]
        self.assertTrue(boosted)
        self.assertLessEqual(boosted[0].memory_boost, 0.6)

    def test_plan_is_deterministic_and_respects_caps(self) -> None:
        first = plan_adaptive(
            graph=graph(),
            belief=Belief.start(),
            allowed_probes=ALLOWED,
            per_task_budget=10,
            max_tasks=4,
            start_seq=0,
            safety=SafetyClass.read_only,
            recon_key="t00",
        )
        second = plan_adaptive(
            graph=graph(),
            belief=Belief.start(),
            allowed_probes=ALLOWED,
            per_task_budget=10,
            max_tasks=4,
            start_seq=0,
            safety=SafetyClass.read_only,
            recon_key="t00",
        )
        self.assertEqual([task.key for task in first], [task.key for task in second])
        self.assertEqual(len(first), 4)
        self.assertTrue(all(task.depends_on == ("t00",) for task in first))
        self.assertTrue(all(task.payload["adaptive"] for task in first))
        scores = [task.payload["expected_information_gain"] for task in first]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_state_changing_probes_are_not_planned_under_read_only(self) -> None:
        tasks = plan_adaptive(
            graph=graph(),
            belief=Belief.start(),
            allowed_probes=("graphql-introspection", "security-headers"),
            per_task_budget=10,
            max_tasks=4,
            start_seq=0,
            safety=SafetyClass.read_only,
        )
        self.assertTrue(all(task.probe_id != "graphql-introspection" for task in tasks))

    def test_information_gain_is_recorded_per_task(self) -> None:
        tasks = plan_adaptive(
            graph=graph(),
            belief=Belief.start(),
            allowed_probes=ALLOWED,
            per_task_budget=10,
            max_tasks=2,
            start_seq=0,
            safety=SafetyClass.read_only,
        )
        self.assertTrue(all(float(task.payload["expected_information_gain"]) >= 0.0 for task in tasks))


if __name__ == "__main__":
    unittest.main()
