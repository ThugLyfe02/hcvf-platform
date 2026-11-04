# Remediation status

Tracks every finding from [`AUDIT.md`](AUDIT.md) against the current commit.
"Fixed" means there is a test or a mechanical check that would fail if it
regressed.

## P0 — blocking

| ID | Finding | Status | Evidence |
|---|---|---|---|
| 3.1 | Alembic chain dangling `down_revision`, two heads, fresh clone cannot migrate | **Fixed** | `alembic/versions/0003…:14` corrected; `scripts/check_alembic_graph.py` runs in preflight and CI; `alembic upgrade head --sql` compiles all 6 revisions |
| 3.2 | Scheduler imports non-existent `configure_logging`, container crash-loops | **Fixed** | `worker/scheduler.py` uses `setup_logging`; import smoke in CI covers `app.main`, `worker.*`, `app.db.init_db` |
| 3.3 | Platform-minted API keys can never authenticate | **Fixed** | `app/core/security.py` authenticates against `tenants.api_key_hash` only; `test_cross_tenant_access_is_denied` proves a minted key works |
| 3.4 | Any tenant can list and rewrite every tenant | **Fixed** | Roles (`admin`/`member`/`auditor`), admin-only create/patch, self-scoped reads, 404 for foreign tenants; three tests |
| 3.5 | HTTP metrics recorded only by dead code | **Fixed** | `app/core/observability.py` wired outermost; `test_root_health_and_metrics` asserts the counter exists; dead `app/core/middleware.py` deleted |
| 3.6 | SSRF: redirects followed without re-authorization, DNS rebound, scope not re-checked | **Fixed** | `app/engine/policy.py` + `http.py`: address classification, IP-pinned connect, per-hop authorization, datastore port block; scope re-check in `HuntService.execute_run` |
| 3.7 | Broker outage strands `queued` runs forever | **Fixed** | Transactional outbox (`app/services/outbox.py`, migration 0006); `test_outbox_relay_claims_and_publishes_once` |
| 3.8 | No recovery from `running` after worker death; cancel impossible | **Fixed** | `runs.lease_expires_at` + `app/services/reaper.py`; cooperative cancel via `DbKillSwitch` and `runs.cancel_requested` |

## P1 — serious

| ID | Finding | Status |
|---|---|---|
| 4.1 | No RLS; isolation is join-only | **Partial** — `runs.tenant_id` and `findings.tenant_id` added and populated; RLS still deferred |
| 4.2 | Mutations audited twice (service + middleware) | **Open** — both records retained deliberately during transition; consolidate before GA |
| 4.3 | Audit failure turns a success into a 500 | **Fixed** — middleware is best-effort and logs |
| 4.4 | Rate limiter fails closed | **Fixed** — fails open with a warning (documented in SECURITY.md) |
| 4.5 | Fixed-window burst at boundaries | **Open** — GCRA deferred |
| 4.6 | Unbounded list endpoints | **Fixed** — `limit`/`offset` on campaigns, runs, findings (max 200) |
| 4.7 | No idempotency keys on POST | **Open** — campaign row lock plus status guards prevent duplicate runs; request-level idempotency keys deferred |
| 4.8 | One key = full tenant admin | **Partial** — admin/member/auditor roles; scoped keys deferred |
| 4.9 | Unsalted SHA-256 key hashes | **Accepted** — high-entropy random keys; documented. HMAC-with-pepper planned with key rotation |
| 4.10 | `compare_digest` TypeError on non-ASCII | **Fixed** — comparison removed from the request path entirely |
| 4.11 | Authorization ignores path/query | **Open** — origin-level grants; path-prefix support exists in `ScopeGrant` but tenant targets normalize to origins |
| 4.12 | Default-port mismatch false denial | **Fixed** — `TenantService._normalize_targets` normalizes default ports |
| 4.13 | Dev loopback bypass ignores ports | **Accepted (dev only)** — requires `ENVIRONMENT=development`; production must set otherwise |
| 4.14 | Missing `(status, scheduled_at)` index | **Fixed** — migration 0006 |
| 4.15 | Enum values spread across migrations | **Accepted** — historical; new enum changes start from `0006` |
| 4.16 | Double-execute race | **Fixed** — `SELECT … FOR UPDATE` in `create_run` |
| 4.17 | Re-executing a completed campaign | **Accepted** — runs are retained as history; no destructive effect |
| 4.18–4.20 | Findings lacked fingerprint, severity typing, evidence structure | **Fixed** — fingerprint, confidence, CWE, status lifecycle, digest-list evidence, `evidence_refs` |
| 4.21 | No `statement_timeout`, untuned pool | **Open** |
| 4.22 | Sync SQLAlchemy in async app | **Accepted** — sync handlers on the threadpool; revisit with async SQLAlchemy when pool saturation is measured |
| 4.23 | `/health`, `/metrics` unauthenticated | **Accepted** — standard for probes; health now uses 1s socket timeouts |
| 4.24 | HSTS over HTTP in dev | **Open** |
| 4.25 | `tenant_id` as `str` through request state | **Fixed** — typed UUIDs end to end |
| 4.26 | Postgres/Redis published on all interfaces | **Fixed** — loopback bindings in compose |
| 4.27 | Container runs as root | **Fixed** — `USER hcvf`, uid 10001 |
| 4.28 | No lockfile / hashes | **Partial** — split dev requirements; hash-pinned lock still pending |

## P2 — hygiene

- Dead duplicate middleware: **deleted**.
- `distributed_lock.py`: **still unused** — intended for scheduler leader election; keep or remove before GA.
- Duplicate `RunResponse` models in two routers: **open**.
- README overclaim ("concolic"): **fixed** — capability table states it is planned.
- Missing `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, ADRs, architecture docs: **added**.
- No CI: **fixed** — lint/graph/import-smoke/unit/integration jobs.

## Verification performed for this commit

```
python -m unittest discover -s tests/unit -t .   → 131 passed
ruff check .                                     → clean
ruff format --check                              → clean
python scripts/check_alembic_graph.py            → 6 revisions, 1 head
alembic upgrade head --sql                       → full chain compiles to 0006
python -c "import app.main, worker.*"            → ok
CLI hunt against fixture                         → 19 findings, evidence verified
autonomy tick → launch → execute → next tick      → learned 9-probe genome; 19 issues, 38 occurrences
deliberation against fixture                      → 3 rounds, consensus, 9 agents, 194 utterances
governance suite                                 → scopes, rotation, idempotency, quota, suppression, audit, webhook, cron, diff, risk, evidence
```

Not verified locally (no Docker/PostgreSQL in the build environment): a live
`alembic upgrade head` against PostgreSQL and the Postgres-backed integration
tests. Both run in the `integration` CI job, which is the gate that must pass
before release.
