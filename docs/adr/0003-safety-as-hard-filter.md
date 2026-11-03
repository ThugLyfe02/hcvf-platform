# ADR 0003 — Safety class is a hard filter, never a score

**Status:** accepted (2026-11-03)

## Context

The planner ranks probes by expected value. A natural implementation multiplies
value by a safety penalty. That is wrong for an authorization product: a
sufficiently attractive state-changing probe could outvote a safety constraint.

## Decision

Every probe carries an ordered `SafetyClass` (`read_only` < `state_changing` <
`destructive`). The planner filters candidates by the grant's ceiling *before*
scoring, the arbiter re-checks coverage, the HTTP client refuses a method that
exceeds the class, and the executor never runs a probe the grant does not cover.

## Consequences

- Safety decisions cannot be traded off by the optimiser, the bandit or the GA.
- A misconfigured campaign fails closed: it produces fewer probes, never more
  dangerous ones.
- Adding a destructive probe in future requires a new ceiling value and an
  approval path, not a weight tweak.
