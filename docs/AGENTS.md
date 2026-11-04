# Background agents

Objectives are executed by specialised agents running continuously, not by a
request handler. Each agent claims only the work it is qualified for, holds a
lease while it works, and reports a heartbeat other processes can read.

```
objective (DB) ??? task queue ??? agent slot (worker type) ??? executor
                      ?   ?
                 atomic?   ?lease + heartbeat
                    claim?   ?
                 reaper ??? expired lease ??? pending again
```

## Fleet

Default pools (override with `HCVF_AGENT_POOL=recon-worker=1,config-worker=3,...`):

| Worker | Slots | Qualified for |
|---|---|---|
| recon-worker | 1 | bounded surface discovery |
| config-worker | 2 | headers, TLS, cookies, methods, errors, cache trust |
| auth-worker | 2 | JWT, CORS, cookies |
| exposure-worker | 1 | exposure, manifests, bundles, source maps |
| surface-worker | 1 | redirects, GraphQL |
| verifier-worker | 2 | independent reproduction |
| auditor-worker | 1 | evidence integrity gate |
| diagnose-worker | 1 | failure classification |
| report-worker | 1 | report assembly |

Run it with `python -m worker.agent_runtime` (the compose stack ships an
`agents` service). For a single-process deployment set
`HCVF_AGENT_RUNTIME_INLINE=true` and the scheduler starts the same fleet
in-process.

## Queue semantics

- Readiness is evaluated from the persisted dependency list, so a restart cannot
  resurrect a task whose dependencies are unsatisfied.
- A claim is a single conditional UPDATE (`pending/ready` -> `running`). Two
  agents cannot win the same task; the loser re-plans.
- A lease is 300s and is renewed every 30s while the task runs. A crashed agent
  stops renewing, and the reaper returns the task to the queue every 15s.
  `POST /api/v1/admin/queue/reap` triggers the same recovery manually.
- Attempts are counted at claim, so retries are auditable and bounded by the
  task's `max_attempts`.

## Heartbeats

Every agent upserts `agent_heartbeats(agent_id, worker, state, objective_id,
task_key, completed_tasks, failed_tasks, last_seen_at)`. `GET
/api/v1/admin/agents` returns the fleet, a stale flag (90s without a beat), the
queue depth and the pools this process is configured to run. `GET
/api/v1/admin/queue` returns pending / running / expired leases / blocked.

The row is a liveness record, not a lock: locks are leases, so a stale heartbeat
can never block work.

## Depth

Objectives declare `depth` (`surface`, `standard`, `deep`). Depth changes how far
the planners are allowed to go:

| Depth | Adaptive tasks | Coverage routes/tasks | Verifies |
|---|---|---|---|
| surface | 4 | 3 / 4 | critical |
| standard | 10 | 6 / 12 | critical + high |
| deep | 24 | 12 / 30 | critical + high + medium |

A deep objective is a deliberate choice, visible in the API response and the
plan, rather than a hidden cost multiplier.

## Operations

- Liveness: `GET /api/v1/admin/agents` (admin). Stale agents with fresh tasks
  mean a crashed process or a blocked network path.
- Restart: kill the process; leases expire; the reaper recovers. Nothing needs
  manual database surgery.
- RLS: workers operate across tenants by design. With `HCVF_RLS_ENABLED=true`
  the fleet must use a role with `BYPASSRLS` or bind a tenant per thread, exactly
  as documented in HARDENING.md. The API path always binds.
- Shutdown: SIGTERM sets the stop event; each agent finishes its current task
  (bounded by the lease) and exits. The compose healthcheck fails when no fresh
  heartbeat exists, so orchestrators surface a dead fleet rather than a silent
  one.

## Tests

`tests/unit/test_agent_runtime.py` proves worker affinity and dependency gating,
lease expiry recovery, fleet visibility through the admin API, an objective
drained to `completed` by the agent loop, and depth profile/API wiring.
