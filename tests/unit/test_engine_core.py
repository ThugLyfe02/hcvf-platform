"""Unit tests for the deterministic core: policy, Bayes, bandit, graph, GA, evidence."""

from __future__ import annotations

import random
import unittest

from app.engine.bandit import ProbeBandit
from app.engine.bayes import DEFAULT_PRIOR, Posterior, ProbeModel, VulnClass, entropy
from app.engine.budget import Budget, KillSwitch
from app.engine.errors import BudgetExceeded, EgressDenied, HuntHalted, ScopeViolation
from app.engine.evidence import (
    EvidenceBundle,
    InMemoryEvidenceStore,
    MerkleTree,
    seal_bundle,
    verify_inclusion,
    verify_manifest,
)
from app.engine.evolution import Genome, evolve, seed_population
from app.engine.graph import best_routes, endpoint_value
from app.engine.http import GuardedHttpClient, RateLimiter
from app.engine.planner import HuntPlanner
from app.engine.policy import EgressPolicy
from app.engine.probes import default_probe_ids, registry
from app.engine.target import build_grant, parse_target
from app.engine.types import Endpoint, SafetyClass


class TestEgressPolicy(unittest.TestCase):
    def test_blocks_loopback_by_default(self) -> None:
        policy = EgressPolicy()
        with self.assertRaises(EgressDenied):
            policy.validate("127.0.0.1", 80)

    def test_allows_loopback_when_explicitly_permitted(self) -> None:
        policy = EgressPolicy(allow_private=True)
        self.assertEqual(policy.validate("127.0.0.1", 8080), ["127.0.0.1"])

    def test_metadata_address_blocked_even_with_private_allowed(self) -> None:
        policy = EgressPolicy(allow_private=True)
        with self.assertRaises(EgressDenied):
            policy.validate("169.254.169.254", 80)

    def test_metadata_hostname_blocked(self) -> None:
        policy = EgressPolicy(allow_private=True)
        with self.assertRaises(EgressDenied):
            policy.validate_hostname("metadata.google.internal")

    def test_ipv4_mapped_loopback_is_blocked(self) -> None:
        policy = EgressPolicy()
        with self.assertRaises(EgressDenied):
            policy.validate("::ffff:127.0.0.1", 80)

    def test_database_ports_are_refused(self) -> None:
        policy = EgressPolicy(allow_private=True)
        with self.assertRaises(EgressDenied):
            policy.validate_port(6379)


class TestScopeGrant(unittest.TestCase):
    def test_origin_and_method_enforced(self) -> None:
        target = parse_target("https://app.example.test/")
        grant = build_grant(target)
        self.assertTrue(grant.covers("https://app.example.test/login", "GET", SafetyClass.read_only))
        self.assertFalse(grant.covers("https://other.example.test/login", "GET", SafetyClass.read_only))
        self.assertFalse(grant.covers("https://app.example.test/login", "POST", SafetyClass.read_only))

    def test_safety_ceiling_enforced(self) -> None:
        target = parse_target("https://app.example.test/")
        grant = build_grant(target, safety=SafetyClass.read_only)
        self.assertFalse(grant.covers("https://app.example.test/", "GET", SafetyClass.state_changing))

    def test_read_only_probe_cannot_send_post(self) -> None:
        target = parse_target("http://127.0.0.1:9/")
        grant = build_grant(target, safety=SafetyClass.state_changing)
        client = GuardedHttpClient(
            EgressPolicy(allow_private=True),
            grant,
            Budget(max_requests=5),
            rate_limiter=RateLimiter(100),
        )
        with self.assertRaises(ScopeViolation):
            client.authorize("POST", target.url, SafetyClass.read_only)


class TestBudgetAndKillSwitch(unittest.TestCase):
    def test_budget_exhaustion(self) -> None:
        budget = Budget(max_requests=2)
        budget.spend(requests=2)
        with self.assertRaises(BudgetExceeded):
            budget.spend(requests=1)

    def test_kill_switch_stops_before_network(self) -> None:
        target = parse_target("http://127.0.0.1:9/")
        grant = build_grant(target)
        kill = KillSwitch()
        kill.halt("test halt")
        client = GuardedHttpClient(EgressPolicy(allow_private=True), grant, Budget(max_requests=5), kill_switch=kill)
        with self.assertRaises(HuntHalted):
            client.request("GET", target.url)


class TestBayes(unittest.TestCase):
    def test_finding_raises_posterior_and_clean_lowers_it(self) -> None:
        model = ProbeModel("p", (VulnClass.headers,), sensitivity=0.9, false_positive_rate=0.05)
        prior = Posterior()
        raised = prior.update(model, "finding").probability(VulnClass.headers)
        lowered = prior.update(model, "clean").probability(VulnClass.headers)
        self.assertGreater(raised, prior.probability(VulnClass.headers))
        self.assertLess(lowered, prior.probability(VulnClass.headers))

    def test_eig_is_positive_and_bounded(self) -> None:
        model = ProbeModel("p", (VulnClass.tls,), sensitivity=0.9, false_positive_rate=0.01)
        value = model.eig(DEFAULT_PRIOR[VulnClass.tls])
        self.assertGreater(value, 0.0)
        self.assertLessEqual(value, entropy(DEFAULT_PRIOR[VulnClass.tls]))

    def test_risk_score_in_unit_interval(self) -> None:
        score = Posterior().risk_score()
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)

    def test_roundtrip(self) -> None:
        posterior = Posterior()
        payload = posterior.to_dict()
        self.assertEqual(Posterior.from_dict(payload).to_dict(), payload)


class TestBandit(unittest.TestCase):
    def test_reward_moves_the_arm(self) -> None:
        bandit = ProbeBandit()
        before = bandit.arm("a").mean
        for _ in range(20):
            bandit.update("a", 1.0)
        self.assertGreater(bandit.arm("a").mean, before)

    def test_choose_prefers_the_stronger_arm(self) -> None:
        bandit = ProbeBandit()
        for _ in range(40):
            bandit.update("good", 1.0)
            bandit.update("bad", 0.0)
        picks = bandit.choose(["good", "bad"], 1, random.Random(3))
        self.assertEqual(picks, ["good"])

    def test_serialization_roundtrip(self) -> None:
        bandit = ProbeBandit()
        bandit.update("x", 0.5)
        restored = ProbeBandit.from_dict(bandit.to_dict())
        self.assertAlmostEqual(restored.arm("x").mean, bandit.arm("x").mean)


class TestGraph(unittest.TestCase):
    def test_admin_ranks_above_static(self) -> None:
        self.assertGreater(endpoint_value("https://x/admin/users"), endpoint_value("https://x/static/logo.png"))

    def test_best_route_prefers_high_value_surface(self) -> None:
        seed = "https://x/"
        endpoints = [
            Endpoint(url="https://x/static/logo.png", source=seed, value=0.01),
            Endpoint(url="https://x/admin", source=seed, value=0.95),
            Endpoint(url="https://x/api/v1/users?page=1", source=seed, value=0.8),
        ]
        routes = best_routes(endpoints, seed, limit=3)
        self.assertTrue(routes)
        self.assertIn("admin", routes[0].target.url)


class TestEvolution(unittest.TestCase):
    def test_best_fitness_is_monotonic_with_elitism(self) -> None:
        known = list(registry().keys())
        rng = random.Random(11)
        population = seed_population(8, known, rng)
        history = evolve(population, lambda g: float(len(g.probes)), generations=5, known_probes=known, rng=rng)
        scores = [generation.best_fitness for generation in history]
        self.assertEqual(scores, sorted(scores))

    def test_same_seed_same_best(self) -> None:
        known = list(registry().keys())

        def run(seed: int):
            rng = random.Random(seed)
            population = seed_population(8, known, rng)
            history = evolve(
                population,
                lambda g: float(len(g.probes)) + (1.0 if "surface-crawl" in g.probes else 0.0),
                generations=4,
                known_probes=known,
                rng=rng,
            )
            return history[-1].best.to_dict()

        self.assertEqual(run(5), run(5))

    def test_mutation_stays_valid(self) -> None:
        known = list(registry().keys())
        rng = random.Random(2)
        genome = Genome(probes=("security-headers",))
        for _ in range(50):
            genome = genome.mutate(rng, known)
            self.assertTrue(genome.probes)
            self.assertGreater(genome.budget_requests, 0)


class TestMerkleEvidence(unittest.TestCase):
    def test_proofs_verify_for_every_leaf(self) -> None:
        leaves = [f"leaf-{i}".encode() for i in range(7)]
        tree = MerkleTree(leaves)
        for index, leaf in enumerate(leaves):
            self.assertTrue(verify_inclusion(leaf, tree.proof(index), tree.root), f"leaf {index}")

    def test_tampered_leaf_fails(self) -> None:
        leaves = [b"a", b"b", b"c"]
        tree = MerkleTree(leaves)
        self.assertFalse(verify_inclusion(b"z", tree.proof(0), tree.root))

    def test_manifest_signature_roundtrip(self) -> None:
        store = InMemoryEvidenceStore()
        bundle = EvidenceBundle(store=store)
        bundle.add(b"one", kind="observation", label="x")
        bundle.add(b"two", kind="observation", label="y")
        key = b"unit-test-key"
        manifest = seal_bundle(bundle, key=key, metadata={"target": "https://x"})
        self.assertTrue(verify_manifest(manifest, manifest["signature"]["value"], key))
        self.assertFalse(verify_manifest(manifest, manifest["signature"]["value"], b"other"))
        broken = dict(manifest)
        broken["entries"] = list(manifest["entries"])[:-1]
        self.assertFalse(verify_manifest(broken, manifest["signature"]["value"], key))


class TestPlannerDeterminism(unittest.TestCase):
    def setUp(self) -> None:
        self.target = parse_target("https://app.example.test/")
        self.grant = build_grant(self.target, safety=SafetyClass.read_only)

    def test_same_seed_same_plan(self) -> None:
        planner = HuntPlanner()
        first = planner.plan(self.target, self.grant, seed=42)
        second = planner.plan(self.target, self.grant, seed=42)
        self.assertEqual(first.probes, second.probes)
        self.assertEqual(
            [(d.probe_id, round(d.score, 6)) for d in first.decisions],
            [(d.probe_id, round(d.score, 6)) for d in second.decisions],
        )

    def test_safety_ceiling_filters_state_changing_probes(self) -> None:
        planner = HuntPlanner()
        plan = planner.plan(self.target, self.grant, seed=1)
        for probe_id in plan.probes:
            self.assertLessEqual(registry()[probe_id].spec.safety, SafetyClass.read_only)

    def test_plan_records_rejections(self) -> None:
        planner = HuntPlanner()
        plan = planner.plan(self.target, self.grant, seed=1, budget_requests=4)
        self.assertTrue(any(not decision.selected for decision in plan.decisions))

    def test_every_selected_probe_has_critiques(self) -> None:
        plan = HuntPlanner().plan(self.target, self.grant, seed=1)
        for decision in plan.decisions:
            if decision.selected:
                self.assertIn(decision.probe_id, {p.probe_id for p in plan.proposals})

    def test_explain_is_human_readable(self) -> None:
        plan = HuntPlanner().plan(self.target, self.grant, seed=1)
        text = plan.explain()
        self.assertIn("Selection rationale", text)
        self.assertIn(self.target.origin, text)


class TestProbeRegistry(unittest.TestCase):
    def test_default_ids_are_registered_and_unique(self) -> None:
        ids = default_probe_ids()
        self.assertEqual(len(ids), len(set(ids)))
        for probe_id in ids:
            self.assertIn(probe_id, registry())

    def test_every_spec_has_safety_and_targets(self) -> None:
        for probe_id, cls in registry().items():
            self.assertTrue(cls.spec.targets, probe_id)
            self.assertIn(cls.spec.safety, SafetyClass)

    def test_off_by_default_probes_are_state_changing_or_noisy(self) -> None:
        for probe_id, cls in registry().items():
            if not cls.spec.default_enabled:
                self.assertTrue(
                    cls.spec.safety >= SafetyClass.state_changing or cls.spec.false_positive_rate > 0.2,
                    probe_id,
                )


if __name__ == "__main__":
    unittest.main()
