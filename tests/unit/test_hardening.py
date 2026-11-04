"""Unit tests for the hardening primitives added in 0.6.0."""

from __future__ import annotations

import logging
import unittest
from datetime import UTC, datetime

from app.core import rls
from app.core.gcra import GcraLimiter
from app.core.redaction import RedactionFilter, redact_text
from app.core.tracing import format_traceparent, new_trace_id, parse_traceparent
from app.services.cron import CronError, CronExpression, next_run
from app.services.risk import band, score


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class TestGcra(unittest.TestCase):
    def test_burst_then_throttle(self) -> None:
        clock = FakeClock()
        limiter = GcraLimiter(rate_per_second=2.0, burst=2, clock=clock)
        self.assertTrue(limiter.check("a")[0])
        self.assertTrue(limiter.check("a")[0])
        allowed, retry_after = limiter.check("a")
        self.assertFalse(allowed)
        self.assertGreater(retry_after, 0)

    def test_refills_smoothly(self) -> None:
        clock = FakeClock()
        limiter = GcraLimiter(rate_per_second=1.0, burst=1, clock=clock)
        self.assertTrue(limiter.check("a")[0])
        clock.advance(1.0)
        self.assertTrue(limiter.check("a")[0])

    def test_identities_are_independent(self) -> None:
        clock = FakeClock()
        limiter = GcraLimiter(rate_per_second=1.0, burst=1, clock=clock)
        self.assertTrue(limiter.check("a")[0])
        self.assertTrue(limiter.check("b")[0])

    def test_spacing_is_enforced_after_the_burst(self) -> None:
        # Two requests may be in flight; the third must wait one interval
        # (0.5s at 2/s), regardless of where a wall-clock minute boundary falls.
        clock = FakeClock()
        limiter = GcraLimiter(rate_per_second=2.0, burst=2, clock=clock)
        limiter.check("a")
        limiter.check("a")
        clock.advance(0.49)
        self.assertFalse(limiter.check("a")[0])
        clock.advance(0.02)
        self.assertTrue(limiter.check("a")[0])


class TestRedaction(unittest.TestCase):
    def test_inline_secrets_are_scrubbed(self) -> None:
        text = "POST /api key=X-API-Key: super-secret-value and authorization: Bearer abc.def"
        scrubbed = redact_text(text)
        self.assertNotIn("super-secret-value", scrubbed)
        self.assertNotIn("abc.def", scrubbed)

    def test_sensitive_extra_fields_are_replaced(self) -> None:
        record = logging.LogRecord("x", logging.INFO, __file__, 1, "hello", (), None)
        record.api_key = "abc123"
        record.normal_field = "visible"
        RedactionFilter().filter(record)
        self.assertEqual(record.api_key, "[redacted]")
        self.assertEqual(record.normal_field, "visible")

    def test_nested_dicts_are_redacted(self) -> None:
        record = logging.LogRecord("x", logging.INFO, __file__, 1, "hello", (), None)
        record.headers = {"authorization": "Bearer xyz", "accept": "application/json"}
        RedactionFilter().filter(record)
        self.assertEqual(record.headers["authorization"], "[redacted]")
        self.assertEqual(record.headers["accept"], "application/json")


class TestTracing(unittest.TestCase):
    def test_roundtrip(self) -> None:
        trace_id = new_trace_id()
        header = format_traceparent(trace_id, "0" * 15 + "1")
        parsed = parse_traceparent(header)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed[0], trace_id)

    def test_rejects_zero_and_invalid(self) -> None:
        self.assertIsNone(parse_traceparent("00-" + "0" * 32 + "-" + "1" * 16 + "-01"))
        self.assertIsNone(parse_traceparent("garbage"))
        self.assertIsNone(parse_traceparent(None))


class TestCron(unittest.TestCase):
    def test_every_fifteen_minutes(self) -> None:
        start = datetime(2026, 11, 3, 12, 7, tzinfo=UTC)
        self.assertEqual(next_run("*/15 * * * *", after=start), datetime(2026, 11, 3, 12, 15, tzinfo=UTC))

    def test_weekday_morning(self) -> None:
        # 2026-11-03 is a Tuesday; next 03:00 weekday occurrence is Wednesday.
        start = datetime(2026, 11, 3, 9, 0, tzinfo=UTC)
        nxt = next_run("0 3 * * 1-5", after=start)
        self.assertEqual((nxt.hour, nxt.minute), (3, 0))
        self.assertEqual(nxt.weekday(), 2)

    def test_rejects_bad_expression(self) -> None:
        with self.assertRaises(CronError):
            CronExpression("not a cron")
        with self.assertRaises(CronError):
            CronExpression("99 * * * *")

    def test_dom_or_dow_semantics(self) -> None:
        expression = CronExpression("0 0 1 * 1")
        self.assertTrue(expression.matches(datetime(2026, 12, 1, 0, 0, tzinfo=UTC)))  # dom match
        self.assertTrue(expression.matches(datetime(2026, 12, 7, 0, 0, tzinfo=UTC)))  # monday


class TestRisk(unittest.TestCase):
    def test_monotonic_and_bounded(self) -> None:
        low = score([("low", 1.0)])
        high = score([("high", 1.0)])
        mixed = score([("high", 1.0), ("critical", 1.0)])
        self.assertLess(low, high)
        self.assertLess(high, mixed)
        self.assertLessEqual(mixed, 100.0)

    def test_empty_is_zero(self) -> None:
        self.assertEqual(score([]), 0.0)
        self.assertEqual(band(0.0), "none")
        self.assertEqual(band(80.0), "critical")


class TestRlsDdl(unittest.TestCase):
    def test_session_sql_validates_uuid(self) -> None:
        statement = rls.rls_session_sql("6f1c2c3e-0000-4000-8000-000000000000")
        self.assertEqual(statement, "SET LOCAL app.tenant_id = '6f1c2c3e-0000-4000-8000-000000000000'")
        with self.assertRaises(ValueError):
            rls.rls_session_sql("'; DROP TABLE users; --")

    def test_policy_ddl_is_strict(self) -> None:
        statements = rls.policy_sql("findings")
        joined = "\n".join(statements)
        self.assertIn("ENABLE ROW LEVEL SECURITY", joined)
        self.assertIn("FORCE ROW LEVEL SECURITY", joined)
        self.assertIn("current_setting('app.tenant_id', true)::uuid", joined)


if __name__ == "__main__":
    unittest.main()
