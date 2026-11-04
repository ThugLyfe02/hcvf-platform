# Contributing

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest tests/unit -q     # no database, no Redis
```

The unit suite must stay runnable on a bare machine. If a change requires
PostgreSQL to test, put the test in `tests/` (integration), not `tests/unit`.

## Standards

- `ruff check .` and `ruff format --check .` must pass; `line-length = 120`.
- Every module gets type annotations. `mypy` is advisory today; new modules
  under `app/engine` and `app/services` should be clean.
- No new dependency in `app/engine`. The engine is standard-library-only by
  design (see `docs/adr/0001-dependency-free-engine.md`).
- Public behaviour changes need a test and a line in `CHANGELOG.md`.

## Adding a probe

1. Create a class in `app/engine/probes/*.py` with a `ProbeSpec`:
   `id`, `safety`, `targets` (vulnerability classes), `cost`, `description`,
   `cwe`, `remediation`, and honest `sensitivity` / `false_positive_rate`.
2. Register it with `@register` and import the module in `probes/__init__.py`.
3. Implement `run(ctx) -> ProbeOutcome` using only `ctx.client.request`.
4. Record every request as an `Observation` via `self.observe(...)` — a finding
   without evidence is not shippable.
5. Add a fixture case in `tests/fixtures/vulnerable_app.py` and a test asserting
   the finding kind appears (and that the same seed is deterministic).
6. Report only what you can defend. If a signal is weak, emit `Severity.info`
   with `tags=("needs-manual-review",)` rather than guessing.

**Safety class discipline:** anything that sends a non-idempotent request must
be `state_changing` and default-disabled. `destructive` requires an explicit
product decision, not a code change.

## Database changes

```bash
alembic revision --autogenerate -m "describe change"
# review the generated file, then
python scripts/check_alembic_graph.py   # exactly one head, no dangling parents
alembic upgrade head
```

A migration must have a working `downgrade()`. The one historical exception
(PostgreSQL cannot drop an enum value in place) is documented in the migration.

## Commit style

Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`).
One concern per commit. The repository's history shows what happens when a
boot-breaking change lands without a gate — keep the gates green.

## Review checklist

- [ ] Does it fail closed on authorization, and fail open only on availability?
- [ ] Is every new outbound request going through `GuardedHttpClient`?
- [ ] Is the new state reachable *and* leavable (worker death, cancel, timeout)?
- [ ] Are fingerprints stable across runs with the same seed?
- [ ] Are logs free of secrets, tokens and response bodies?
