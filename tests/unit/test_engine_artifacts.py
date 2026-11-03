"""Artifact probes: bundles, source maps, manifests and cache trust.

Each probe runs through the real executor against the local fixture, so the
guarded HTTP client, budget and evidence sealing are all exercised.
"""

from __future__ import annotations

import unittest

from app.engine.evidence import InMemoryEvidenceStore
from app.engine.executor import HuntExecutor
from app.engine.policy import EgressPolicy
from app.engine.probes import registry
from app.engine.target import build_grant, parse_target
from app.engine.types import SafetyClass
from tests.fixtures.vulnerable_app import running_fixture

KEY = b"test-evidence-key"


def _run_probe(base_url: str, probe_id: str, *, budget: int = 40):
    target = parse_target(base_url + "/")
    grant = build_grant(target, safety=SafetyClass.read_only, max_rps=200)
    executor = HuntExecutor(
        policy=EgressPolicy(allow_private=True),
        store=InMemoryEvidenceStore(),
        signer_key=KEY,
    )
    return executor.run(
        target,
        grant,
        seed=7,
        budget_requests=budget,
        requested_probes=[probe_id],
    )


class ArtifactProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._context = running_fixture()
        cls.base_url = cls._context.__enter__()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._context.__exit__(None, None, None)

    def _kinds(self, probe_id: str) -> set[str]:
        result = _run_probe(self.base_url, probe_id)
        return {finding.kind for finding in result.findings}

    def test_registry_exposes_the_new_probes(self) -> None:
        ids = set(registry())
        self.assertIn("secrets-in-bundle", ids)
        self.assertIn("source-map-exposure", ids)
        self.assertIn("dependency-manifest", ids)
        self.assertIn("cache-poisoning-surface", ids)

    def test_secret_in_bundle_is_found_and_masked(self) -> None:
        result = _run_probe(self.base_url, "secrets-in-bundle")
        kinds = {finding.kind for finding in result.findings}
        self.assertIn("secret-in-bundle:aws-access-key", kinds)
        finding = next(item for item in result.findings if item.kind.endswith("aws-access-key"))
        self.assertEqual(finding.severity.value, "critical")
        self.assertIn("...", finding.detail)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", finding.detail)

    def test_source_map_exposure_is_found(self) -> None:
        kinds = self._kinds("source-map-exposure")
        self.assertIn("source-map-published", kinds)

    def test_dependency_manifest_is_found(self) -> None:
        kinds = self._kinds("dependency-manifest")
        self.assertIn("dependency-manifest:npm", kinds)

    def test_cache_trust_surface_detects_reflection(self) -> None:
        kinds = self._kinds("cache-poisoning-surface")
        self.assertTrue(
            any(kind.startswith("forwarded-header-reflected:") for kind in kinds),
            kinds,
        )

    def test_artifact_probes_are_read_only(self) -> None:
        for probe_id in (
            "secrets-in-bundle",
            "source-map-exposure",
            "dependency-manifest",
            "cache-poisoning-surface",
        ):
            self.assertEqual(registry()[probe_id].spec.safety, SafetyClass.read_only, probe_id)

    def test_artifact_probes_are_not_in_the_default_hunt(self) -> None:
        from app.engine.probes import default_probe_ids

        default = set(default_probe_ids())
        self.assertNotIn("secrets-in-bundle", default)
        self.assertNotIn("dependency-manifest", default)


if __name__ == "__main__":
    unittest.main()
