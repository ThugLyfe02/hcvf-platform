# Concurrency

Objectives are independent, so they run in parallel. Safety comes from the
database, not from trusting the scheduler.

## Atomic claim

`run_step` never executes a task it merely selected. Selection produces a
candidate; execution requires a conditional update:

```sql
UPDATE objective_tasks
SET status = 'running', attempts = attempts + 1, lease_expires_at = now() + 300s
WHERE id = :id AND status IN ('pending', 'ready')
```

Only the statement that changes the row wins. If `rowcount` is 0 another worker
won the race, and the caller re-reads the plan and tries the next candidate
(bounded to four attempts) instead of reporting a phantom success.

The in-memory supervisor snapshot is aligned to the database row after the claim
(`state.status`, `state.attempts`), so verification and retry logic see truth,
not a local guess.

## Worker pool

`app/services/objective_pool.py` runs a batch with a `ThreadPoolExecutor`:

- each thread creates its own `Session` (SQLAlchemy sessions are not thread-safe);
- each objective runs the same `run_to_completion` the API uses;
- one failing objective returns a `BatchOutcome(status="error")` and the rest of
  the batch continues;
- `worker/objectives.py` uses the pool for due objectives, bounded by
  `HCVF_OBJECTIVE_WORKERS` and `HCVF_OBJECTIVE_TASKS_PER_BATCH`.

## What this does not solve

- Two concurrent workers on the same objective may each claim a different ready
  task; that is intended (the DAG is independent by construction).
- The report task still runs after everything else by dependency, so a report
  cannot race a probe.
- Postgres row locks do the heavy lifting. SQLite serializes writers; the local
  suite still exercises claim semantics, but throughput claims belong to the
  PostgreSQL integration job.

## RLS interaction

With RLS enabled, the pool must run with a role that bypasses RLS or bind the
tenant per thread before querying. The pool opens its own sessions and therefore
does not inherit the request binding; this is documented in HARDENING.md and is
the safe failure mode (empty results, not cross-tenant reads).
