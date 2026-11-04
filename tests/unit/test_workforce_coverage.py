"""Route-graph coverage: classification, planning, measurement, criteria."""

from __future__ import annotations

import unittest

from app.engine.workforce.coverage import (
    CoverageState,
    classify_route,
    normalize_route,
    plan_coverage,
    route_value,
)
from app.engine.workforce.criteria import EvidenceBundle, evaluate
from app.engine.workforce.types import Criterion, CriterionKind, FindingLite, TaskOutcome


class TestRouteClassification(unittest.TestCase):
    def test_roles(self) -> None:
        cases = {
            "https://app.test/": "entry",
            "https://app.test/login": "auth",
            "https://app.test/oauth/token": "auth",
            "https://app.test/admin/users": "admin",
            "https://app.test/api/v1/users": "api",
            "https://app.test/graphql": "api",
            "https://app.test/export/csv": "data",
            "https://app.test/landing": "other",
        }
        for url, expected in cases.items():
            self.assertEqual(classify_route(url), expected, url)

    def test_normalize_ignores_query_port_defaults_and_slashes(self) -> None:
        self.assertEqual(
            normalize_route("https://App.Test:443/api/users/?page=2#x"),
            "https://app.test/api/users",
        )
        self.assertEqual(normalize_route("http://app.test:8080/"), "http://app.test:8080/")
        self.assertEqual(normalize_route("https://app.test"), "https://app.test/")

    def test_role_affects_value(self) -> None:
        self.assertGreater(route_value("https://app.test/admin"), route_value("https://app.test/landing"))


class TestCoveragePlanning(unittest.TestCase):
    def test_spends_breadth_first(self) -> None:
        plan = plan_coverage(
            origin="https://app.test",
            routes=(
                "https://app.test/login",
                "https://app.test/admin/users",
                "https://app.test/api/v1/orders",
                "https://app.test/landing",
            ),
            allowed_probes=("security-headers", "jwt-posture", "cors-policy", "http-methods", "exposed-config"),
            max_routes=4,
            max_tasks=8,
        )
        routes = [route for route, _ in plan.assignments]
        # Every selected route receives its first probe before any gets a second.
        self.assertEqual(len(set(routes)), 4)
        self.assertEqual(plan.task_count, 8)
        self.assertIn("jwt-posture", {probe for _, probe in plan.assignments})

    def test_route_and_task_caps_are_reported(self) -> None:
        plan = plan_coverage(
            origin="https://app.test",
            routes=tuple(f"https://app.test/api/v1/thing{i}" for i in range(20)),
            allowed_probes=("security-headers", "cors-policy"),
            max_routes=2,
            max_tasks=2,
        )
        self.assertEqual(len(plan.routes), 2)
        self.assertEqual(plan.task_count, 2)
        self.assertTrue(any("route cap" in reason for reason in plan.skipped_reasons))

    def test_whole_surface_probes_are_not_assigned_per_route(self) -> None:
        plan = plan_coverage(
            origin="https://app.test",
            routes=("https://app.test/",),
            allowed_probes=("openapi-surface", "surface-crawl", "security-txt"),
            max_routes=4,
            max_tasks=8,
        )
        self.assertEqual(plan.task_count, 0)
        self.assertTrue(plan.skipped_reasons)

    def test_safety_filter_can_leave_nothing(self) -> None:
        plan = plan_coverage(
            origin="https://app.test",
            routes=("https://app.test/",),
            allowed_probes=("graphql-introspection",),
            max_routes=4,
            max_tasks=8,
        )
        self.assertEqual(plan.task_count, 0)


class TestCoverageMeasurement(unittest.TestCase):
    def _bundle(self) -> EvidenceBundle:
        bundle = EvidenceBundle()
        bundle.coverage.discover(
            ("https://app.test/", "https://app.test/login", "https://app.test/admin", "https://app.test/api")
        )
        bundle.coverage.record("https://app.test/", ("surface-crawl",))
        bundle.coverage.record("https://app.test/login", ("jwt-posture",))
        return bundle

    def test_ratio_and_missing(self) -> None:
        bundle = self._bundle()
        self.assertAlmostEqual(bundle.coverage.ratio(), 0.5)
        self.assertEqual(len(bundle.coverage.missing()), 2)

    def test_criterion_uses_coverage(self) -> None:
        bundle = self._bundle()
        passing = evaluate((Criterion(CriterionKind.min_route_coverage, 0.5),), bundle)[0]
        failing = evaluate((Criterion(CriterionKind.min_route_coverage, 0.9),), bundle)[0]
        self.assertTrue(passing.satisfied)
        self.assertIn("50%", passing.observed)
        self.assertFalse(failing.satisfied)

    def test_outcome_route_feeds_coverage(self) -> None:
        bundle = EvidenceBundle()
        outcome = TaskOutcome(
            task_key="t1",
            status=__import__("app.engine.workforce.types", fromlist=["TaskStatus"]).TaskStatus.done,
            probes_run=("security-headers",),
            endpoints=("https://app.test/a", "https://app.test/b"),
            route="https://app.test/a",
            findings=(FindingLite("f", "x", "low", 0.5, "security-headers", "https://app.test/a"),),
        )
        bundle.absorb(outcome)
        self.assertAlmostEqual(bundle.coverage.ratio(), 0.5)

    def test_empty_surface_counts_as_covered(self) -> None:
        self.assertEqual(CoverageState().ratio(), 1.0)


if __name__ == "__main__":
    unittest.main()
