# Architecture

## 1. Shape

```
                ┌──────────────────────── FastAPI ────────────────────────┐
 clients ──────▶│ Observability → RequestID → SecurityHeaders → RateLimit  │
                │            → Audit → routers → services                 │
                └──────────────┬───────────────────────┬──────────────────┘
                               │                       │
                     ┌─────────▼────────┐   ┌──────────▼───────────┐
                     │ PostgreSQL       │   │ Outbox (same txn)    │
                     │ control plane    │   └──────────┬───────────┘
                     └──────────────────┘              │ relay
                                                       ▼
                                            ┌─────────────────────┐
                                            │ Celery worker       │
                                            │ HuntService         │
                                            │  └─ app.engine      │
                                            └──────────┬──────────┘
                                                       │ guarded HTTP
                                                       ▼
                                            ┌─────────────────────┐
                                            │ authorized targets  │
                                            └─────────────────────┘
                     filesystem / object store: evidence blobs
```

Two rules make the rest legible:

1. **The API never touches a target.** Egress happens only inside a worker, only
   through `GuardedHttpClient`.
2. **The engine never touches a database.** `app/engine` has no SQLAlchemy import;
   it is pure Python plus a `Protocol`. That is why 56 engine tests run with no
   services.

## 2. A run, end to end

```
POST /campaigns/{id}/execute
  ├─ CampaignService.create_run   (SELECT ... FOR UPDATE on the campaign)
  │    ├─ INSERT runs(queued, tenant_id)
  │    ├─ INSERT outbox(campaign.run, run_id)      ── same transaction
  │    └─ audit_logs
  └─ 202 Accepted                        (no broker call in the request path)

scheduler / relay loop
  ├─ outbox relay    (FOR UPDATE SKIP LOCKED, exponential backoff, 5 attempts)
  ├─ reaper          (lease expiry + cancel requests)
  └─ claim_due_campaigns (scheduled campaigns)

worker: execute_campaign(run_id)
  └─ HuntService.execute_run
       ├─ re-authorize target against current tenant scope   ← scope can be revoked
       ├─ lease = now + HUNT_LEASE_SECONDS
       ├─ planner: propose → critique → arbitrate → plan(seed)
       ├─ executor: probes with budget, kill switch, evidence sealing
       ├─ persist findings (+fingerprint), probe_stats, evidence_blobs
       └─ run completed | failed | cancelled, campaign terminal
```

## 3. Run state machine

```
queued ──▶ running ──▶ completed
   │           │
   │           ├──▶ failed      (probe/engine error, halt)
   │           └──▶ cancelled   (operator, honoured between requests)
   └──▶ cancelled               (cancelled before dequeue)
```

Rules:

- Terminal runs are never re-executed; `execute_run` returns them unchanged, so
  a duplicate Celery delivery is harmless.
- A run whose worker disappears is failed by the reaper once
  `lease_expires_at` passes. There is no state a run can enter that has no exit.
- Cancellation is cooperative: `DbKillSwitch` polls `runs.cancel_requested`
  every five checks and halts at a request boundary, so the audit trail shows
  exactly what was and was not sent.

## 4. Why an outbox

Directly calling `.delay()` after committing a run has a well-known failure: a
broker outage after the commit leaves a `queued` row that nothing will ever
dequeue. The outbox makes "create run" and "intend to dispatch" one atomic
write; the relay retries independently of request latency.

This also keeps the API's p99 independent of broker health. An earlier version
dispatched synchronously in the request path and opened a Celery result-backend
pubsub connection while doing so; with Redis down, a 202 took ~20 seconds. The
outbox plus `task_ignore_result=True` removed that class of coupling.

## 5. Data model

```
tenants(id, name, api_key_hash, role, is_active, authorized_targets jsonb)
  └─ campaigns(id, tenant_id, target_url, safety_ceiling, budget_requests, mode, status)
       └─ runs(id, tenant_id, campaign_id, status, lease_expires_at, cancel_requested,
               plan jsonb, plan_seed, evidence_root)
            └─ findings(id, tenant_id, run_id, fingerprint, probe_id, kind, severity,
                        confidence, status, cwe, remediation, evidence jsonb)
outbox(id, topic, payload, available_at, attempts, published_at)
evidence_blobs(id, digest, kind, label, size)
probe_stats(id, probe_id, target_host, alpha, beta, trials)
audit_logs(id, tenant_id, actor, action, resource_*, request_id, detail)
```

Notes:

- `runs.tenant_id` and `findings.tenant_id` are denormalized. Queries still
  verify through the campaign join; the extra column means a missed join cannot
  silently cross tenants, and tenant-wide finding queries stay index-friendly.
- `findings.fingerprint` is a stable hash of `(probe, kind, location, title)`, so
  re-running a hunt can be reconciled instead of duplicated.
- Types are dialect-portable (`app/db/types.GUID`, `JSONDoc`): native `uuid` and
  `jsonb` on PostgreSQL, `char(36)` and `json` on SQLite. Production DDL is
  unchanged; tests get real database semantics without a server.

## 6. Evidence

`EvidenceBundle` → content-addressed blobs → Merkle tree (RFC 6962 domain
separation: `0x00` leaf, `0x01` node) → manifest with root, leaf list and
metadata → HMAC-SHA256 signature.

The tree supports inclusion proofs, so a single finding's observation can be
proven against the run root without publishing the whole run. `verify` recomputes
the root, checks the signature and re-hashes every blob.

## 7. Failure behaviour summary

| Failure | Behaviour |
|---|---|
| Broker down at execute | Outbox row persists, relay retries, run stays `queued` |
| Worker killed mid-run | Reaper fails the run after the lease expires, frees the campaign |
| Target unreachable | Probe error recorded, run continues with remaining probes |
| Budget exhausted | Hunt halts, run marked `failed: halted: budget...`, partial findings kept |
| Redis down (API) | Rate limiter fails **open** with a warning (authorization is not affected) |
| Postgres down | Health reports `degraded`; mutations fail closed |
| Scope revoked before execution | Run fails with `Target is no longer authorized for this tenant` |
| Duplicate task delivery | `execute_run` is idempotent for terminal runs |

## 8. Scaling notes

Current design is one worker pool, one queue, one database. The next steps, in
order of value: per-tenant fair queues, KEDA on queue depth, read replica for
reporting, partitioning `findings` by month. Nothing in the engine blocks these;
the engine is stateless and horizontally scalable by construction.
