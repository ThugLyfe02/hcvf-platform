# Hardening and governance (0.6.0)

Twenty changes that move the platform from "works" to "operable by someone who
is accountable for it". Each entry names where it is enforced and which test
proves it.

| # | Capability | Enforced in | Proof |
|---|---|---|---|
| 1 | PostgreSQL row-level security | `app/core/rls.py`, `scripts/enable_rls.py` | `test_hardening.TestRlsDdl` |
| 2 | API-key scopes | `app/core/security.py`, every router | `test_governance.test_scopes_restrict_what_a_key_can_do` |
| 3 | API-key rotation | `TenantService.rotate_api_key`, `POST /tenants/{id}/rotate-key` | `test_key_rotation_invalidates_the_old_key` |
| 4 | Idempotent execution | `app/services/idempotency.py`, campaign endpoints | `test_execute_is_idempotent`, `test_idempotency_conflict_on_different_request` |
| 5 | Daily quotas | `app/services/quotas.py`, `CampaignService.create_run` | `test_daily_run_quota_is_enforced` |
| 6 | Finding suppressions | `app/services/suppressions.py`, `HuntService._persist` | `test_suppressed_findings_are_not_stored` |
| 7 | Tamper-evident audit chain | `AuditService.record/verify_chain`, `GET /audit/verify` | `test_audit_chain_detects_tampering` |
| 8 | Signed webhooks | `app/services/webhooks.py`, outbox topic | `test_webhook_delivery_is_signed` |
| 9 | Cron scheduling | `app/services/cron.py`, `claim_cron_campaigns` | `test_cron_campaign_is_claimed_and_rescheduled`, `TestCron` |
| 10 | Baseline diff per campaign | `app/services/baseline.py`, `GET .../diff` | `test_risk_trend_and_baseline_diff` |
| 11 | Risk score + trend | `app/services/risk.py`, `runs.risk_score`, `GET .../risk-trend` | same |
| 12 | Evidence verification endpoint | `GET .../evidence/verify` | `test_evidence_verification_endpoint` |
| 13 | OpenAPI ingestion probe | `app/engine/probes/surface.py` | `test_openapi_spec_expands_the_surface` |
| 14 | Discovery-ordered replanning | `app/engine/executor.py`, `planner.py` | same |
| 15 | GCRA rate limiting | `app/core/gcra.py`, `rate_limit.py` | `TestGcra` |
| 16 | Log redaction | `app/core/redaction.py`, logging formatter | `TestRedaction` |
| 17 | Request body limit | `app/core/body_limit.py` | `test_body_size_limit` |
| 18 | W3C trace context | `app/core/tracing.py` | `test_traceparent_is_echoed`, `TestTracing` |
| 19 | RFC 9457 problem details | `app/core/problem.py` | `test_problem_details_shape` |
| 20 | Liveness vs readiness | `app/api/v1/health.py` (`/healthz`, `/readyz`) | `test_readiness_reflects_dependencies` |

Two supporting extras shipped with them: named **campaign profiles**
(`GET /api/v1/profiles`, `profile` on campaign creation) and a **CLI diff**
(`python -m app.engine.cli diff --left a/hunt.json --right b/hunt.json`).

---

## Notes that matter

### 1. RLS is an explicit switch, not a surprise

Policies are generated as plain DDL; enabling them is a deliberate operator
action:

```bash
python scripts/enable_rls.py --dry-run   # review the SQL
python scripts/enable_rls.py --apply     # ALTER TABLE ... ENABLE/FORCE
```

If RLS were enabled without setting `app.tenant_id` on every connection, every
query would return zero rows. The helper `apply_tenant_context` sets it per
transaction; the script exists so nobody enables enforcement by accident.

### 2. Scopes are deny-by-default

Bootstrap keys are `["*"]` admins. Platform-created tenants receive
`campaigns:read`, `campaigns:write`, `findings:read`, `findings:write`,
`autonomy:read` — and nothing else. `autonomy:admin` is never granted implicitly.
Every router now declares the scope it needs; the earlier version authenticated
callers and then let them do anything.

### 4. Idempotency is a claim, not a table of results

The key is **claimed before** the handler runs (`status_code = 0`) and completed
after. Two concurrent retries cannot both proceed: the second sees `in_progress`
and gets a 409. A replay returns the stored response byte-for-byte. Reusing a key
with a different body is a conflict, not a silent second action.

### 5. Quotas count runs, not campaigns

The first implementation counted campaigns created today, which meant creating a
campaign consumed the day's allowance before anything ran. It now counts `runs`
and the request budget those runs imply. Autonomy is subject to the same quota,
so a controller bug cannot outspend a tenant's allowance.

### 7. Why the audit chain needed a sequence

Chaining on `created_at` alone is broken: two records in the same microsecond
have no defined order, and the "previous hash" lookup could pick a different row
than the verifier walking the chain. `audit_logs.seq` is monotonic per tenant and
is part of the hashed payload, so tampering with a record — or reordering it —
fails verification at a precise row.

### 8. Webhooks reuse the SSRF policy

Delivery goes through the same `EgressPolicy` as probes. A tenant cannot use a
webhook to make the platform call a metadata service. Failures are retried by the
outbox with exponential backoff, and the webhook row records the last error.

### 13–14. Discovery before deliberation

Planning is two-phase, and phase two now waits until **all** surface-acquisition
probes have run (`surface-crawl` and `openapi-surface`). The OpenAPI probe turns
a published spec into routes, methods and parameter names, which is the highest
fidelity surface map a target will ever hand you. Only then do the agents
deliberate — so specialists are convened on real endpoints, not guesses.

### 15. GCRA replaces the fixed window

A fixed-window counter permits 2x burst across the boundary. GCRA enforces an
emission interval with a bounded burst; the burst tolerance is `(N-1)` intervals,
which the tests pin because an off-by-one there silently doubles the allowance.

### 16. Redaction is a filter, not a convention

`RedactionFilter` runs at the formatter, so no caller can forget it. It scrubs
inline patterns (`X-API-Key:`, `Authorization: Bearer`, `Set-Cookie`) and
sensitive `extra` fields, including nested dictionaries.

---

## Deliberate non-goals

- **No secret manager.** `EVIDENCE_KEY` and webhook secrets are read from env /
  stored in the row. Production should wrap both with a KMS; the interfaces are
  narrow enough to swap.
- **No distributed tracing backend.** We propagate W3C `traceparent` and log the
  trace id. Adding a collector is an infrastructure decision, not an application
  one.
- **No UI.** Everything in this release is API, CLI, or the HTML report.
