"""End-to-end hunt tests against the deliberately vulnerable local fixture."""

from __future__ import annotations

import unittest

from app.engine.budget import KillSwitch
from app.engine.evidence import InMemoryEvidenceStore, MerkleTree, verify_manifest
from app.engine.executor import HuntExecutor
from app.engine.policy import EgressPolicy
from app.engine.report import to_html, to_markdown, to_sarif
from app.engine.target import build_grant, parse_target
from app.engine.types import SafetyClass
from tests.fixtures.vulnerable_app import running_fixture

KEY = b"test-evidence-key"

EXPECTED_KINDS = {
    "missing-content-security-policy",
    "missing-nosniff",
    "cookie-attributes:session",
    "cors-reflected-origin-with-credentials",
    "trace-method-enabled",
    "verbose-error-page",
    "vcs-metadata",
    "env-file",
    "path-traversal",
    "jwt-alg-none",
    "missing-security-txt",
}


def _hunt(base_url: str, **kwargs):
    target = parse_target(base_url + "/")
    grant = build_grant(target, safety=SafetyClass.read_only, max_rps=200)
    executor = HuntExecutor(
        policy=EgressPolicy(allow_private=True),
        store=InMemoryEvidenceStore(),
        signer_key=KEY,
    )
    return executor.run(target, grant, seed=kwargs.pop("seed", 5), **kwargs)


class TestHuntAgainstFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._context = running_fixture()
        cls.base_url = cls._context.__enter__()
        cls.result = _hunt(cls.base_url, budget_requests=200, seed=9)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._context.__exit__(None, None, None)

    def test_finds_the_planted_issues(self) -> None:
        kinds = {finding.kind for finding in self.result.findings}
        missing = EXPECTED_KINDS - kinds
        self.assertFalse(missing, f"missing findings: {sorted(missing)}; got {sorted(kinds)}")

    def test_findings_carry_confidence_cwe_and_evidence(self) -> None:
        for finding in self.result.findings:
            self.assertGreater(finding.confidence, 0.0)
            self.assertLessEqual(finding.confidence, 1.0)
            self.assertTrue(finding.fingerprint)
            self.assertTrue(finding.location)

    def test_fingerprints_are_stable_and_unique_per_kind(self) -> None:
        fingerprints = [finding.fingerprint for finding in self.result.findings]
        self.assertEqual(len(fingerprints), len(set(fingerprints)))

    def test_evidence_manifest_is_signature_verified(self) -> None:
        manifest = self.result.manifest
        self.assertTrue(manifest["entries"])
        self.assertTrue(verify_manifest(manifest, manifest["signature"]["value"], KEY))
        self.assertFalse(verify_manifest(manifest, manifest["signature"]["value"], b"wrong-key"))

    def test_manifest_root_recomputes_from_entries(self) -> None:
        entries = self.result.manifest["entries"]
        tree = MerkleTree([bytes.fromhex(entry["digest"]) for entry in entries])
        self.assertEqual(tree.root, self.result.manifest["root"])
        self.assertEqual(tree.root, self.result.evidence_root)

    def test_budget_was_respected(self) -> None:
        self.assertLessEqual(self.result.budget["used_requests"], self.result.budget["max_requests"])
        self.assertGreater(self.result.budget["used_requests"], 0)

    def test_endpoints_discovered_for_route_graph(self) -> None:
        urls = {endpoint.url for endpoint in self.result.endpoints}
        self.assertTrue(any("/admin" in url for url in urls))

    def test_posterior_moved_and_bandit_learned(self) -> None:
        self.assertTrue(self.result.bandit_after.arms)
        self.assertNotEqual(self.result.posterior_after.to_dict(), {})
        for value in self.result.posterior_after.to_dict().values():
            self.assertGreaterEqual(value, 0.0)
            self.assertLessEqual(value, 1.0)

    def test_sarif_is_valid_and_complete(self) -> None:
        sarif = to_sarif(self.result)
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
        self.assertEqual(len(run["results"]), len(self.result.findings))
        for result in run["results"]:
            self.assertIn(result["ruleId"], rule_ids)
            self.assertIn(result["level"], {"error", "warning", "note"})
            self.assertTrue(result["partialFingerprints"]["hcvfFingerprint"])

    def test_html_report_contains_key_facts(self) -> None:
        html = to_html(self.result)
        self.assertIn(self.result.target.origin, html)
        self.assertIn(self.result.evidence_root, html)
        self.assertNotIn("<script", html)

    def test_markdown_report_lists_findings(self) -> None:
        markdown = to_markdown(self.result)
        self.assertIn("HCVF hunt report", markdown)
        self.assertIn("## Findings", markdown)

    def test_plan_records_agent_deliberation(self) -> None:
        self.assertTrue(self.result.plan.proposals)
        self.assertTrue(self.result.plan.critiques)
        self.assertTrue(self.result.plan.decisions)
        agents = {proposal.agent for proposal in self.result.plan.proposals}
        self.assertGreaterEqual(len(agents), 3)


class TestDeterminism(unittest.TestCase):
    def test_same_seed_reproduces_probes_and_findings(self) -> None:
        with running_fixture() as base:
            first = _hunt(base, budget_requests=120, seed=1234)
            second = _hunt(base, budget_requests=120, seed=1234)
        self.assertEqual([run.probe_id for run in first.probe_runs], [run.probe_id for run in second.probe_runs])
        self.assertEqual(
            sorted(f.fingerprint for f in first.findings),
            sorted(f.fingerprint for f in second.findings),
        )


class TestSafetyAndBudgets(unittest.TestCase):
    def test_state_changing_probe_refused_under_read_only_grant(self) -> None:
        with running_fixture() as base:
            result = _hunt(base, budget_requests=20, requested_probes=["graphql-introspection"])
        self.assertEqual(result.findings, [])
        self.assertTrue(any(run.status == "error" for run in result.probe_runs))

    def test_private_target_blocked_by_default_policy(self) -> None:
        with running_fixture() as base:
            target = parse_target(base + "/")
            grant = build_grant(target, max_rps=100)
            executor = HuntExecutor(store=InMemoryEvidenceStore(), signer_key=KEY)
            result = executor.run(target, grant, seed=1, budget_requests=20)
        self.assertEqual(result.findings, [])
        self.assertTrue(any(run.status == "error" for run in result.probe_runs))

    def test_budget_halt_is_recorded(self) -> None:
        with running_fixture() as base:
            result = _hunt(base, budget_requests=3, requested_probes=["surface-crawl"])
        self.assertTrue(result.halted.startswith("budget"), result.halted)
        self.assertLessEqual(result.budget["used_requests"], 3)

    def test_kill_switch_prevents_all_requests(self) -> None:
        with running_fixture() as base:
            target = parse_target(base + "/")
            grant = build_grant(target, max_rps=100)
            kill = KillSwitch()
            kill.halt("operator stop")
            executor = HuntExecutor(
                policy=EgressPolicy(allow_private=True),
                store=InMemoryEvidenceStore(),
                signer_key=KEY,
            )
            result = executor.run(target, grant, seed=1, budget_requests=50, kill_switch=kill)
        self.assertEqual(result.budget["used_requests"], 0)
        self.assertEqual(result.halted, "operator stop")


if __name__ == "__main__":
    unittest.main()
