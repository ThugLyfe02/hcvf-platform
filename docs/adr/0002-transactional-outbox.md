# ADR 0002 — Transactional outbox instead of dispatch-in-request

**Status:** accepted (2026-11-03)

## Context

The original `execute` endpoint committed a run and then called
`execute_campaign.delay(run_id)`. If Redis was unavailable the client received a
500 *after* the run row was committed as `queued`, and nothing would ever
dequeue it. During testing, the synchronous publish also opened a Celery result
backend pubsub connection, making a 202 take around twenty seconds with Redis
down.

## Decision

Write an `outbox` row in the same transaction as the run. A relay
(`dispatch_pending`) claims rows with `FOR UPDATE SKIP LOCKED`, publishes with
exponential backoff, and marks them delivered. The request path never talks to
the broker.

## Consequences

- Broker health no longer affects API latency or correctness.
- Dispatch is at-least-once; `HuntService.execute_run` must therefore be
  idempotent, which it is (terminal runs return unchanged).
- One more table and one more loop to operate. Acceptable: the alternative is an
  orphan class that cannot be reconciled.
