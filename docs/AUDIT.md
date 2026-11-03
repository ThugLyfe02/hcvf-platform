# HCVF Platform — Full Audit

| | |
|---|---|
| **Repo** | https://github.com/ThugLyfe02/hcvf-platform |
| **Commit audited** | `7945ffeb2e556a6699f74b3d5a470956cfd1560a` (`Clean run flow test imports`, branch `main`) |
| **Audit date** | 2026-11-03 |
| **Scope** | Every tracked file: 75 files, 2,294 Python LOC, 139 commits, one author (Benjamin Birnbaum), initial burst 2026‑08‑25 23:10 → 2026‑08‑26 14:33 ET |
| **Method** | Full source read; static verification of build-breaking defects via revision-graph reconstruction and import/call-site analysis. Runtime execution not performed — the only local interpreter is Python 3.14.5, the repo targets 3.13, and no Postgres/Redis stack was provisioned in this workspace. Nothing below is inferred from filenames. |
| **Other branches** | `origin/hcvf/operational-foundation-hardening` — stale, 1 commit ahead / 66 behind `main` (`9839b32`). Abandon or delete. |

---

## 0. Verdict

**This is a well-organized skeleton of a multi-tenant security-validation control plane whose actual validation engine is a single unauthenticated HTTP GET, and which does not currently boot from a fresh clone.**

The engineering *taste* is above average: service layer separated from routers, typed models, migrations, structured logging, request IDs, audit trail, tenant-scoped queries, health with circuit breakers, a real test suite shape. The problem is that the platform's spine is broken at three independent points (migration chain, scheduler import, HTTP metrics), its multi-tenant isolation is false in the most literal sense (any API key can read and rewrite every tenant), and the "Hybrid Concolic Validation Fabric" contains no concolic execution, no fuzzing, and no validation beyond `GET → record status code`.

Read positively: you have built the ~15% of a security platform that is genuinely hard to retrofit later — tenancy, authorization gating, audit, state, scheduling — and you have left the easy parts easy. That is the right order. But nothing ships until Phase 0 in §10 is done.

---

## 1. What this is, in entirety

### 1.1 One sentence

A FastAPI control plane + Celery/Redis workers + PostgreSQL store that lets tenant-authenticated callers register "campaigns" against explicitly authorized URLs, schedules or triggers them, executes a single outbound HTTP GET from a worker, and persists a run record plus one derived "finding".

### 1.2 The actual request lifecycle, end to end

```
client ──X-API-Key──▶ RequestIDMiddleware ─▶ RateLimitMiddleware (Redis INCR, fixed window)
                              │
                              ▼
                       AuditMiddleware (after response, separate DB session)
                              │
                              ▼
                       SecurityHeadersMiddleware
                              │
                              ▼
                  GET /api/v1/campaigns/{id}/execute
                              │
                    get_current_tenant()  ── 401 unless key ∈ HCVF_API_KEYS
                              │                └─ lookup tenants.api_key_hash (SHA-256)
                              ▼
             CampaignService.create_run()  ── INSERT runs(queued), campaigns.status=queued
                              │                └─ INSERT audit_logs (campaign.execute)
                              ▼
                    execute_campaign.delay(run_id)  ── Celery → Redis broker
                              │
                              ▼            [separate process]
                    CampaignPipeline.execute(run_id)
                              │  SELECT ... FOR UPDATE, status=running
                              ▼
                    FuzzRunner.run(target_url)  ── httpx GET, follow_redirects=True, 10s timeout
                              │
                              ▼
                    INSERT findings(http_reachability, info|medium)
                    runs.status=completed, campaigns.status=completed
```

Every other capability in the README is either a GET on stored rows or a piece of infrastructure that is defined and never called.

### 1.3 Repository inventory (complete)

```
app/
  main.py                     FastAPI app, lifespan, middleware wiring (60 lines)
  api/v1/{campaigns,campaign_runs,tenants,health,metrics}.py   5 routers, 11 endpoints
  core/{config,security,rate_limit,audit_middleware,security_headers,
        request_id,logging,metrics,circuit_breaker,distributed_lock,
        retry,errors,middleware}.py                            13 modules
  db/{base,session,init_db}.py                                 engine, session, Alembic entry
  models/{tenant,campaign,run,finding,audit}.py                5 tables
  services/{campaign_service,run_service,tenant_service,
            audit_service,bootstrap}.py                        5 services
worker/
  celery_app.py  tasks.py  pipeline.py  fuzz_runner.py  scheduler.py
alembic/versions/ 0001…0005                                   5 migrations (chain is broken, §3.1)
tests/ 8 test modules                                         integration-style, require live infra
scripts/ verify_runtime.py, preflight.sh, diagnostics.sh,
         bootstrap.sh, test.sh, smoke_test.sh                 6 verification scripts
Dockerfile, docker-compose.yml (5 services), requirements.txt (12 pinned direct deps)
README.md (298 lines), .env.example, .gitignore, MIT LICENSE
```

### 1.4 Runtime topology

Five Compose services: `postgres:16-alpine`, `redis:7-alpine`, `api` (uvicorn, migrations on start), `worker` (Celery, `acks_late`, `prefetch=1`, soft 270s / hard 300s), `scheduler` (poll loop, 5s). API, worker, scheduler all share one image and one mutable env block. Postgres and Redis are published to the host (`:5432`, `:6379`) with `hcvf/password`.

### 1.5 Data model

| Table | Columns that matter | Notes |
|---|---|---|
| `tenants` | `id`, `name` (unique), `api_key_hash` (unique), `authorized_targets` JSONB | No org, no owner, no status, no quota, no key expiry |
| `campaigns` | `tenant_id` FK→tenants, `name`, `target_url` TEXT, `authorization_attested` BOOL, `status` enum, `scheduled_at` | Status enum gained `cancelled` in 0002 |
| `runs` | `campaign_id` FK, `status` enum, `started_at`, `completed_at`, `http_status`, `error_message` | **No `tenant_id`** — isolation is join-only, no RLS |
| `findings` | `run_id` FK, `kind` str, `severity` str, `title`, `detail`, `evidence` JSONB | Severity is free text, no fingerprint, no lifecycle |
| `audit_logs` | `tenant_id`, `actor`, `action`, `resource_type/id`, `request_id`, `detail` JSONB | Append-only by convention only; no hash chain, no retention policy |

No table has an index supporting the scheduler's hot query (`status, scheduled_at`), no partitioning, no soft delete, no `statement_timeout`.

### 1.6 API surface (complete)

| Method | Path | Auth | Behavior |
|---|---|---|---|
| GET | `/` | none | `{"service":"hcvf","status":"ok"}` |
| GET | `/health` | none | Postgres `SELECT 1` + Redis `PING` behind circuit breakers; always HTTP 200 |
| GET | `/metrics` | none | Prometheus exposition |
| POST | `/api/v1/campaigns` | key | Requires `authorization_attested: true` **and** target ∈ tenant allowlist |
| GET | `/api/v1/campaigns` | key | All campaigns for tenant, no pagination |
| GET | `/api/v1/campaigns/{id}` | key | 404 if other tenant |
| POST | `/api/v1/campaigns/{id}/cancel` | key | Refuses `running`/terminal states |
| POST | `/api/v1/campaigns/{id}/execute` | key | Creates run, enqueues task, 202 |
| GET | `/api/v1/campaigns/{id}/runs` | key | Join-scoped list, no pagination, **no 404 if campaign doesn't exist** |
| GET | `/api/v1/campaigns/{id}/runs/{run_id}` | key | Join-scoped, 404 cross-tenant |
| GET | `/api/v1/campaigns/{id}/runs/{run_id}/findings` | key | Join-scoped list |
| GET | `/api/v1/campaigns/{id}/runs/{run_id}/findings/{fid}` | key | Join-scoped |
| POST | `/api/v1/tenants` | key | Mints `token_urlsafe(32)`, stores SHA-256, returns key once |
| GET | `/api/v1/tenants` | key | **Returns every tenant in the system** |
| GET | `/api/v1/tenants/{id}` | key | **Any tenant any other** |
| PATCH | `/api/v1/tenants/{id}` | key | **Rewrites any tenant's `authorized_targets`** |

### 1.7 Controls that genuinely exist

Request IDs propagated via `contextvars` and echoed in `X-Request-ID`; five security headers on every response; fixed-window Redis rate limiting keyed by hashed API key; SHA-256 API-key hashing with `compare_digest`; tenant-scoped SQL on campaigns/runs/findings; explicit authorization attestation gate at create *and* in the worker; structured JSON logs with run/campaign/tenant context; Prometheus counters/histograms for campaigns, findings, task duration; circuit breaker with half-open recovery; `SELECT … FOR UPDATE SKIP LOCKED` on due-campaign claiming; `acks_late` with prefetch 1 and bounded retries on `OperationalError`; Alembic with all models registered; six operator scripts with real failure handling.

### 1.8 Maturity snapshot

| Dimension | State |
|---|---|
| Boots from fresh clone | **No** — §3.1, §3.2 |
| Multi-tenant isolation | **False** — §3.4 |
| Validation capability | 1 probe (`GET`, reachability) |
| Test isolation | None — tests mutate the real database |
| CI | None — no `.github/` at all |
| Lint / types / coverage | None |
| Tracing / error tracking | None |
| Pagination / idempotency / RBAC | None |
| Deployment target | Single-host Compose only |

### 1.9 What it is **not** (be honest with yourself)

- Not concolic. No symbolic execution, no path constraints, no solver.
- Not a fuzzer. No mutation, no coverage feedback, no corpus, no crash triage.
- Not a scanner. It never sends a payload, never parses a body, never inspects a header beyond `server`.
- Not multi-tenant in the security sense. Isolation is a `WHERE tenant_id = ?` that tenants can rewrite.
- Not observable in production. The HTTP metrics are dead code; worker metrics are never scraped.
- Not reproducible. Findings carry no request/response artifact, so no finding can be re-proven later.

The gap between the name and the behavior is the single biggest product risk: a buyer who reads "Hybrid Concolic Validation Fabric" and then reads `fuzz_runner.py` will not buy twice.

---

## 2. Scorecard

| Domain | Grade | One-line justification |
|---|---|---|
| Layering & code organization | **B+** | Router → service → model is consistent; no business logic leaking into handlers |
| Type discipline | **B-** | Full annotations, `from __future__`, but duplicated response models and untyped `dict` evidence |
| Correctness at HEAD | **D** | Two independent boot failures + false tenancy claim |
| Security engineering | **D+** | One real auth bypass chain; good primitives, wrong composition |
| Data modeling | **C+** | Clean, minimal, but no tenancy denormalization, no indices for its own hot paths |
| Reliability | **C-** | No reaper, no outbox, no idempotency; broker blip strands runs forever |
| Observability | **C-** | Great logging/metrics scaffolding, then one dead middleware and an unscraped worker |
| Testing | **D+** | Meaningful scenarios, zero isolation, no unit layer, no CI, no coverage |
| DevEx / supply chain | **D** | No lint, no types, no lockfile, no CI, no pre-commit, no SBOM |
| Documentation | **B** | README is unusually honest about *how to run*, not about *what it does* |
| Product completeness | **D** | No UI, no reports, no integrations, no notifications, no triage |
| Scalability | **C** | Sync stack with default pool, single queue, no quotas, unbounded lists |
| Strategic differentiation | **B-** | The positioning ("authorized, auditable validation") is genuinely valuable; the product doesn't yet earn it |

**Overall: 4.1 / 10 as a product, 7.2 / 10 as a foundation.**

---

## 3. P0 — blocking (fix before anything else)

### 3.1 The Alembic chain is broken; the API container cannot start

`alembic/versions/0003_tenant_authorized_targets.py:14` declares

```python
down_revision: Union[str, None] = "0002_campaign_cancelled"
```

but `0002`'s actual revision id is `"0002_add_cancelled_campaign_status"`. Reconstructed graph:

```
0001_initial_schema
  ├── 0002_add_cancelled_campaign_status          ← head A (nothing builds on it)
  └── ??? 0002_campaign_cancelled (does not exist) ── 0003 ── 0004 ── 0005   ← head B
```

Verified mechanically: **dangling parent `0002_campaign_cancelled`, two heads.** `alembic upgrade head` raises `Can't locate revision identified by '0002_campaign_cancelled'`. Because `docker-compose.yml:40` runs `alembic upgrade head && uvicorn …`, the `api` service exits immediately on a fresh volume. `python -m app.db.init_db` fails the same way. `scripts/bootstrap.sh` fails at line 63. The entire documented quickstart is dead.

**Fix** (one line, then verify with `alembic heads` → exactly one):

```python
down_revision: Union[str, None] = "0002_add_cancelled_campaign_status"
```

Add a CI gate that fails if `alembic heads` returns more than one head, or if any `down_revision` is neither `None` nor a declared revision.

### 3.2 The scheduler crashes on import

`worker/scheduler.py:7` — `from app.core.logging import configure_logging`. That symbol does not exist; the module defines `setup_logging` (`app/core/logging.py:64`). `python -m worker.scheduler` raises `ImportError` before the loop starts, so the `scheduler` container crash-loops and **no `scheduled_at` campaign ever dispatches**. `create_run` is unaffected, so manual execution still works — which is exactly why this survived: the happy path you tested never touches the scheduler.

**Fix:** import `setup_logging` and call it at line 26, or add a `configure_logging = setup_logging` alias. Then add an import-smoke test that imports every `worker.*` and `app.*` module (catches this whole class instantly):

```python
@pytest.mark.parametrize("mod", ["worker.scheduler", "worker.tasks", "worker.pipeline", "app.main", "app.db.init_db"])
def test_modules_import(mod):
    importlib.import_module(mod)
```

### 3.3 API keys minted by the platform can never authenticate

`app/core/security.py:31`:

```python
if not api_key or not validate_configured_api_key(api_key):
    raise HTTPException(401, "Invalid API key")
```

`validate_configured_api_key` only accepts keys present in `HCVF_API_KEYS` from the environment. `TenantService.create_tenant` (`app/services/tenant_service.py:35`) mints a fresh `secrets.token_urlsafe(32)`, hashes it, persists it, returns it once — and that key is rejected forever, because it is not in the env allowlist.

So `POST /api/v1/tenants` is a key generator that produces keys which do not work. Self-service onboarding — the entire premise of multi-tenancy — is non-functional. The DB lookup on line 35 can never succeed for a key that passed line 31 either: both gates match the *same* hash, so the second lookup is redundant for env keys and unreachable for minted keys.

**Fix:** drop the env allowlist from the request path and make the database the single source of truth. Keep the env list only as a bootstrap seed (`bootstrap.py` already provisions those tenants). Add `revoked_at`, `last_used_at`, and `expires_at` while you are in there — you will need them within a month.

### 3.4 Any tenant can read and rewrite every other tenant

Two endpoints, both trivial:

- `app/api/v1/tenants.py:72-77` → `list_tenants()` returns `SELECT * FROM tenants ORDER BY created_at` with no tenant filter. Every customer's name, id, and full `authorized_targets` list leaks to every other customer.
- `app/api/v1/tenants.py:92-110` → `PATCH /tenants/{id}` loads by id with no ownership check (`TenantService.get_tenant` at `tenant_service.py:59`), then writes `authorized_targets` from the request body.

Chain this with §3.3 → §3.6 and it is a complete privilege-escalation path:

1. Authenticate with any provisioned key.
2. `PATCH` your own tenant's `authorized_targets` to `["http://169.254.169.254"]` (or any internal host).
3. `POST /campaigns` with that target — the authorization predicate now passes, because *you wrote the allowlist*.
4. The worker issues the request from inside your network. `FuzzRunner` returns `final_url` and the `server` header into the finding evidence.

Nothing in the request path prevents an authenticated tenant from unilaterally expanding its own authorized scope. The `authorization_attested` boolean is a checkbox the attacker also controls. That is the definition of an authorization control that authorizes the attacker.

**Fix (minimum):** scope every tenant endpoint to `tenant.id == current_tenant.id` for non-admins; introduce an `is_admin`/role claim resolved from the key; forbid a tenant from editing its own `authorized_targets` without an out-of-band approval record. **Fix (correct):** a `scope_grants` table with `created_by`, `approved_by`, `expires_at`, `evidence_uri` — dual control, time-boxed, immutable audit — and authorization checks that consult grants, not a mutable JSONB array the tenant owns.

### 3.5 Request metrics are recorded by dead code

`app/core/middleware.py` defines `RequestContextMiddleware`, which increments `HTTP_REQUESTS` and observes `HTTP_REQUEST_DURATION`. Nothing imports it. `app/main.py:43-46` wires `SecurityHeaders`, `Audit`, `RateLimit`, `RequestID` — not this one.

Result: `hcvf_http_requests_total` and `hcvf_http_request_duration_seconds` are **never populated**. Your Grafana would show a flat zero and your first production incident would be invisible. `app/core/middleware.py` is a stale duplicate of `rate_limit.py` (both define a class named `RateLimitMiddleware`, with different fail-closed semantics) — delete the file after porting the metric increments into `RequestIDMiddleware` or a single consolidated middleware.

### 3.6 The egress path has no SSRF defense, and authorization is only checked at create time

`worker/fuzz_runner.py:21-31`:

```python
with httpx.Client(timeout=..., follow_redirects=True, headers={...}) as client:
    response = client.get(target_url)
```

Three problems:

1. **Redirects are followed without re-validation.** An allowlisted URL that 302s to `http://169.254.169.254/latest/meta-data/` is followed. The allowlist is checked once, at campaign creation, on the *original* string.
2. **No connect-time address control.** `urlsplit` compares hostnames, then `httpx` resolves DNS independently. Classic DNS-rebinding: authorize `attacker.example`, resolve to `10.0.0.5` at request time.
3. **Authorization is never re-checked at execution.** `CampaignPipeline.execute` (`worker/pipeline.py:32`) verifies only that `authorization_attested` is true — not that the target is still in scope. Revoke a target after creating a campaign, and the queued run still fires. (This is also how a compromised DB or a stale queue becomes a live egress violation.)

**Fix:** validate every hop. Resolve to IPs yourself, reject loopback/link-local/RFC1918/metadata/ULA unless explicitly permitted for that tenant, pin the connection (`transport=httpx.HTTPTransport(local_address=…)` plus a custom resolver, or route all egress through an allowlisting proxy), disable automatic redirects and re-authorize each `Location`, and re-run the scope check inside the worker immediately before sending. Log every decision.

### 3.7 Broker failure strands runs forever

`app/api/v1/campaigns.py:153-157`:

```python
run = service.create_run(...)   # commits run=queued, campaign=queued
execute_campaign.delay(...)     # ← can raise; nothing compensates
```

If Redis is unavailable, the client gets a 500 *after* the run and campaign rows are committed as `queued`. Nothing will ever dequeue them. The campaign is stuck: not running (so `cancel` works only because the status is `queued`), never executing, no error surfaced. The scheduler ignores `queued` campaigns (it only claims `draft`).

**Fix:** transactional outbox. Write `outbox(run_id, available_at)` in the same transaction as the run; a relay process publishes and marks dispatched. Or, minimum viable: catch the enqueue failure, set `run.status=failed`, `campaign.status=failed`, and return 503 with the run id.

### 3.8 No reconciliation for `running` rows

A worker killed by the 300s hard `time_limit` (SIGKILL — `acks_late` does not help, `finally` does not run), an OOM, or a node eviction leaves `runs.status='running'` and `campaigns.status='running'` permanently. `cancel_campaign` explicitly refuses running campaigns (`campaign_service.py:86-87`), so there is **no operator path to clear it** — the campaign is a zombie, and `create_run` will refuse it forever with "Campaign is already running".

**Fix:** heartbeat/lease. Add `runs.lease_expires_at`, have the pipeline extend it, and add a reaper that flips runs whose lease expired to `failed` (`error_message="lease expired"`) and frees the campaign. Add `campaigns.status=queued` recovery on startup. Also allow an explicit `force=true` cancel that enqueues a revocation marker the worker checks between probes.

---

## 4. P1 — serious, not boot-blocking

| # | Finding | Evidence | Why it matters |
|---|---|---|---|
| 4.1 | Tenancy is join-only; no `tenant_id` on `runs`/`findings`, no Postgres RLS | `models/run.py:22-38` | Every isolation guarantee is one forgotten `WHERE` away from total. RLS makes it structural. |
| 4.2 | Audit is written twice per mutation, in two transactions | `campaign_service.py:46-58` + `audit_middleware.py:29-43` | Duplicate, partially-ordered rows; the service row and the middleware row can disagree on outcome |
| 4.3 | An audit write failure aborts a successful request | `audit_middleware.py:29-43` | Postgres blip → 500 after the mutation committed. Audit must be best-effort + outboxed. |
| 4.4 | Rate limiter fails **closed** with 503 | `core/rate_limit.py:33-37` | Redis hiccup = total API outage. Fail open with a metric, or use a local token bucket fallback. |
| 4.5 | Fixed-window rate limiting | `core/rate_limit.py:26-27` | 2× burst at window boundaries; use GCRA/sliding log |
| 4.6 | Unbounded list endpoints | `campaigns.py:99`, `campaign_runs.py:70,93`, `tenants.py:72` | One tenant with 200k runs pulls them all into memory; also a trivial DoS |
| 4.7 | No idempotency keys on POST | `campaigns.py:76,142` | Double-click → two runs, two audits, two egress events |
| 4.8 | No scopes/RBAC; one key = full tenant admin | `core/security.py:26-41` | Cannot build a read-only dashboard, a CI-scoped key, or an auditor role |
| 4.9 | Unsalted SHA-256 key hashes | `core/security.py:18-19` | Fine for 256-bit random keys, wrong pattern; use HMAC-SHA256 with a server pepper, or Argon2id |
| 4.10 | `compare_digest` on non-ASCII raises `TypeError` → 500 | `core/security.py:23` | `X-API-Key: café` crashes the handler instead of 401 |
| 4.11 | Authorization predicate ignores path and query | `campaign_service.py:161-188` | Authorizing `https://app/api/v3` also authorizes `https://app/admin` |
| 4.12 | Default-port mismatch causes false denials | `campaign_service.py:185` | Authorized `https://x:443` ≠ target `https://x` |
| 4.13 | Dev loopback bypass ignores ports entirely | `campaign_service.py:181-183` | Any loopback port becomes authorized in `development`; one env-var typo from prod |
| 4.14 | No index on `(status, scheduled_at)` | `0001` migration | Scheduler full-scans `campaigns` every 5s forever |
| 4.15 | Enum values added across 5 migrations instead of one | `0002`, `0005` | Schema drift risk; also `compare_type` autogenerate will keep flagging |
| 4.16 | `campaigns.status` is the only run-state authority | `campaign_service.py:117-118` | Two concurrent `execute` calls can both pass the `running` check (no row lock) → duplicate runs. Add `SELECT … FOR UPDATE` or a partial unique index on active runs. |
| 4.17 | `execute` on `completed`/`failed` campaigns silently re-queues | `campaign_service.py:112-115` | No run history guard; campaign status flip-flops |
| 4.18 | Findings have no fingerprint, lifecycle, or dedupe | `models/finding.py` | Re-running a campaign creates a new row for the same issue; counts become meaningless |
| 4.19 | `severity` is free text, default `"info"` | `models/finding.py:17` | Cannot sort, aggregate, or map to CVSS |
| 4.20 | Evidence JSONB unbounded, no schema | `models/finding.py:20` | Response bodies will land here; 1 GB JSONB rows are a Postgres footgun |
| 4.21 | No `statement_timeout`, connection pool untuned | `db/session.py:10` | One bad query pins a connection forever; default pool 5+10 per process |
| 4.22 | Sync SQLAlchemy inside async FastAPI (`def` handlers) | `app/api/v1/*.py` | Correct (threadpool) but pool exhaustion under load; no backpressure signal |
| 4.23 | `/metrics` and `/health` are unauthenticated and unthrottled | `main.py:48-49`, `rate_limit.py:58` | Health does 2 network round-trips per call; free amplification |
| 4.24 | HSTS emitted over HTTP in dev | `security_headers.py:14` | Browsers cache it for localhost; breaks local UI development later |
| 4.25 | `tenant_id` stored as `str` then coerced into a UUID column | `security.py:39`, `audit_middleware.py:31` | Works by implicit cast today; breaks on any stricter driver |
| 4.26 | Docker Compose publishes Postgres/Redis with a default password | `docker-compose.yml:11,26` | On any shared host this is a full compromise; bind to 127.0.0.1 |
| 4.27 | No resource limits, no read-only rootfs, no non-root user | `Dockerfile`, `docker-compose.yml` | Container escape blast radius; also no `--no-cache`-pinned base digest |
| 4.28 | `requirements.txt` has no hashes, no transitive pin, no lockfile | `requirements.txt` | Supply-chain reproducibility is zero; `pip install` today ≠ today+1 |

---

## 5. P2 — hygiene and dead weight

- `app/core/middleware.py` — dead duplicate of `rate_limit.py` (both export `RateLimitMiddleware`); delete.
- `app/core/distributed_lock.py` — never imported anywhere. Either use it (scheduler leader election — you need it) or delete it.
- `app/core/retry.py` — never used. Celery's `autoretry_for` covers the one call site.
- `app/db/init_db.py` — duplicates `bootstrap.sh`'s alembic step; unused.
- `RunResponse` defined twice, in `campaigns.py:40` and `campaign_runs.py:18`, with different fields (one omits timestamps). Consolidate into `app/api/schemas.py`.
- `app/core/errors.py` exists, but `campaign_runs.py` and `tenants.py` raise `HTTPException` inline instead. Pick one.
- `GET /runs` for a nonexistent campaign returns `200 []` instead of `404` — inconsistent with `GET /runs/{id}`.
- Campaign `name` is `.strip()`-ed but never length- or emptiness-checked (`campaigns.py:88`); empty names persist.
- `scheduler.py:21` puts a comma-joined list into a field named `run_id`; logs become unparseable.
- `pipeline.py:115` `self.db.refresh(run)` is unreachable on the failure path (the exception re-raises) — the bare `refresh` after `finally` is also redundant because `expire_on_commit=False`.
- `0003`'s docstring says `Revises: 0002_campaign_cancelled` — same stale name that broke the chain; fix the docstring too.
- `docs/` doesn't exist; no ADRs, no threat model, no architecture diagram, no `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, no `CODEOWNERS`.
- Two README claims are not true today: "Concolic", and "Integration tests covering … execution flows" (they require a live stack and are not runnable in CI).

---

## 6. Threat model of the platform itself (STRIDE)

| Threat | Vector | Current exposure | Required control |
|---|---|---|---|
| **Spoofing** | Key replay; no rotation, no expiry, no `last_used` | Any leaked env key is permanent and global | Short-lived scoped keys, rotation endpoint, anomaly detection on `last_used` |
| **Tampering** | Any key can `PATCH` any tenant (§3.4); audit rows unhashed | Privilege escalation + evidence repudiation | Ownership checks, hash-chained audit, S3 Object Lock for evidence |
| **Repudiation** | Actor is `api-key:<hash12>`; no user identity | "Not me" is unfalsifiable | OIDC users + service principals, signed session records |
| **Information disclosure** | `GET /tenants` returns all tenants; cross-tenant 404s are correct but lists are not; findings may embed response bodies later | Cross-customer leak | RLS + per-request tenant binding + response filtering |
| **Denial of service** | Unbounded lists, 2 network calls per `/health`, rate limit fails closed, worker pool exhaustible by one tenant | Trivial | Pagination caps, quotas, per-tenant queues, fail-open limiter |
| **Elevation of privilege** | §3.4 → §3.6 chain reaches internal network and cloud metadata | **Live** | Scope grants + egress proxy + IP pinning |
| **Supply chain** | Unpinned transitive deps, no SBOM, no image signing | High | Lockfile + hashes, `pip-audit`, Trivy, cosign, provenance |
| **Insider/misuse** | The product's own purpose is offensive capability; no kill switch, no dual control, no jurisdiction limits | Structural | RoE artifacts, approval workflow, kill switch, egress allowlist, geo-fence |

The last row is the one that decides whether this becomes a company or a liability. A platform that can be pointed at arbitrary hosts by whoever holds a key, with no signed authorization artifact and no kill switch, is a dual-use tool whose first serious incident is its last.

---

## 7. Test & CI assessment

**What exists:** 8 modules, ~292 lines, covering campaign create/list/cancel, tenant CRUD, run/finding retrieval, cross-tenant 404, security headers, health shape, metrics shape, and one genuine end-to-end execution against a `ThreadingHTTPServer` fixture. The end-to-end test is the best thing in the repo — it monkeypatches `.delay` and asserts the finding's evidence. That is the right instinct at the right level.

**What's missing:**

- No `conftest.py`. Every test opens `TestClient(app)`, which runs `lifespan` → `provision_configured_tenants()` → **requires a live Postgres**; the rate-limit middleware constructor opens a **live Redis** connection. So `pytest` cannot run without the full stack, cannot run in CI, and cannot run on a reviewer's laptop.
- No isolation: tests write to the real database and never clean up. `test_run_flow` asserts `any(...)` over the *entire* tenant's runs, so it passes even when the assertion is vacuous.
- No unit layer at all: `_is_authorized_target`, `CircuitBreaker`, `RedisRateLimiter.check`, `retry`, `JsonFormatter` are all pure and all untested. These are where the security bugs are.
- No negative tests for the authorization predicate (port mismatch, path prefix, redirect, rebinding, unicode host, `user@host`, `host:0`, IPv6 literal, `http://127.0.0.1.nip.io`).
- No test that a tenant cannot read another tenant's *list* (the §3.4 bug would have been caught by one line).
- No concurrency test for double-`execute`.
- No worker-failure test (kill mid-run → stuck `running`).
- No coverage measurement, no mutation testing, no contract tests.
- No CI: no `.github/workflows`, so nothing above is enforced on push. 139 commits in 14 hours with zero automated gate is exactly how §3.1–§3.3 reached `main`.

**Target:** `pytest` green in <90s with zero external services via `testcontainers` (or `pytest-postgresql` + `fakeredis`); ≥85% line coverage on `app/services` and `app/core`; `schemathesis` against the live OpenAPI schema; `mutmut` on the authorization predicate; one CI job per Python 3.13 target plus a Compose smoke job.

---

## 8. Documentation assessment

The README is better than most funded startups': it states the authorized-use boundary in a blockquote, documents the verification ladder (`verify_runtime → preflight → diagnostics → bootstrap → test → smoke`), and refuses to promise more than the endpoints do. That discipline is rare and should be preserved.

Weaknesses: it catalogs *endpoints* rather than *behaviors*; it never says "the engine currently performs a single GET"; there is no architecture diagram, no data-flow diagram, no threat model, no ADR trail explaining why Celery vs. Arq, why sync SQLAlchemy, why JSONB allowlists — the decisions most likely to be revisited. There is no `SECURITY.md` (a CVE intake path is mandatory for a security product), no `CONTRIBUTING.md`, no `CHANGELOG.md`, no versioning policy, no support matrix.

**Fix:** `docs/architecture.md` (one C4-context diagram + one sequence diagram), `docs/adr/0001…000N.md`, `SECURITY.md` with a disclosure SLA, and a README section titled **"What HCVF does today / what it does not do yet"**. That section will save you a customer conversation and will keep you honest.

---

## 9. What is genuinely good — keep it

1. **The layering is right.** Router → service → model, with `actor` and `request_id` threaded from the request into the audit record. Most projects at this stage have SQL in the handler. You don't.
2. **`SKIP LOCKED` claiming.** `claim_due_campaigns` uses the correct Postgres primitive for a work queue. That single line shows you understand concurrent dispatch.
3. **Attestation is checked twice** — at create and again in the worker before egress. Defense in depth in the place that matters.
4. **Cross-tenant reads return 404, not 403.** Correct choice: no existence oracle. Someone taught you this or you reasoned it out; either way it's right.
5. **`acks_late`, `prefetch=1`, bounded `OperationalError` retries, soft+hard time limits.** The Celery configuration is what an experienced operator writes, not what a tutorial writes.
6. **Circuit breakers on health checks with half-open recovery** and thread-safe state. Correctly implemented, correctly bounded.
7. **The verification ladder** (six scripts, each with real exit codes and pre-bootstrap-safe semantics). This is operational maturity that most repos never reach.
8. **JSON logs with domain context** (`run_id`, `campaign_id`, `tenant_id`) rather than `print(request)`. Future-you will thank present-you during the first incident.
9. **One-day full-stack construction.** 139 commits, coherent scope, no abandoned half-features. Whatever process produced this — small commits, one concern each — keep it.

The bones are good. The body is missing.

---

## 10. Phase 0 — the unbreak list (do this first, ~1 day)

| # | Fix | File | Effort |
|---|---|---|---|
| 1 | `down_revision = "0002_add_cancelled_campaign_status"`; assert single head in CI | `alembic/versions/0003_…py:14` | 1 min |
| 2 | `from app.core.logging import setup_logging`; call it | `worker/scheduler.py:7,26` | 2 min |
| 3 | Delete the env-allowlist gate; authenticate against `tenants.api_key_hash` only | `app/core/security.py:31` | 15 min |
| 4 | Scope `GET/PATCH /tenants/{id}` to the caller; `GET /tenants` returns self unless admin | `app/api/v1/tenants.py:72-110` | 30 min |
| 5 | Port HTTP metric increments into the live middleware; delete `app/core/middleware.py` | `app/main.py`, `app/core/middleware.py` | 20 min |
| 6 | Reject non-global IPs at connect time; re-authorize every redirect hop; re-check scope in worker | `worker/fuzz_runner.py`, `worker/pipeline.py` | 2–4 h |
| 7 | Wrap `delay()`; on failure mark run+campaign failed, return 503 | `app/api/v1/campaigns.py:157` | 20 min |
| 8 | Add `runs.lease_expires_at` + reaper task; allow forced cancel | `worker/pipeline.py`, new `worker/reaper.py` | 3 h |
| 9 | Add `conftest.py` with transactional fixtures + `fakeredis`; make `pytest` run with no services | `tests/` | 3 h |
| 10 | Add `.github/workflows/ci.yml`: ruff, mypy, pytest, `alembic heads` check, import-smoke, `pip-audit` | new | 1 h |

Then tag `v0.2.0` and write the honest README section. Only after that does §11 (the expansion plan) make sense — every capability you add on top of a false tenancy claim inherits the liability.
