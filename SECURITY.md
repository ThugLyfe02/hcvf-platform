# Security policy

HCVF is a security tool that makes outbound requests. Vulnerabilities in it are
therefore higher-impact than in a typical web application: a flaw can turn an
authorized validation run into unauthorized access to a third party.

## Reporting

Email the maintainer listed in `LICENSE` with:
- affected version or commit,
- a description of the impact,
- reproduction steps (a failing test is ideal),
- whether the issue is already public.

Please do not open a public issue for anything that could enable unauthorized
access. Target acknowledgement within 3 business days and a remediation plan
within 10.

## Scope

In scope:
- scope-grant bypass (reaching a target the grant does not cover),
- SSRF/egress-guard bypass (loopback, RFC1918, link-local, cloud metadata,
  DNS rebinding, redirect escape, IPv4-mapped IPv6),
- cross-tenant data access or privilege escalation,
- evidence forgery (a manifest that verifies after modification),
- budget/kill-switch bypass,
- authentication bypass,
- remote code execution in API, worker or CLI.

Out of scope:
- findings produced by the engine against a target you are authorized to test,
- missing headers on the demo fixture (it is deliberately vulnerable),
- rate limiting on `/health` and `/metrics`,
- denial of service through deliberately huge campaigns on your own deployment.

## Security model in one page

| Control | Where |
|---|---|
| API keys hashed SHA-256, looked up in the database | `app/core/security.py` |
| Roles: admin / member / auditor; scope changes are admin-only | `app/api/v1/tenants.py` |
| Scope re-checked at execution, not only at creation | `app/services/hunt_service.py` |
| SSRF guard: hostname deny-list, address classification, IP pinning, per-hop redirect authorization | `app/engine/policy.py`, `app/engine/http.py` |
| Datastore ports refused (5432, 6379, 3306, ...) | `app/engine/policy.py` |
| Safety classes enforced in planner, arbiter, client, executor | `app/engine/{planner,arbiter,http,executor}.py` |
| Budget (requests, bytes, seconds) and kill switch | `app/engine/budget.py` |
| Evidence Merkle root + HMAC signature | `app/engine/evidence.py` |
| Audit trail on mutations | `app/services/audit_service.py` |
| Rate limiting per hashed identity | `app/core/rate_limit.py` |

### Deliberate trade-offs

- The rate limiter **fails open** when Redis is unavailable. It is a fairness
  control, not an authorization control; failing closed turns a cache outage
  into a total outage. Authorization fails closed.
- The development environment permits loopback targets by default so local
  fixtures work. `ALLOW_PRIVATE_TARGETS` defaults to `false`, and production
  deployments must keep `ENVIRONMENT` out of `development`.
- Postgres row-level security is not enabled yet; isolation is enforced in the
  query layer plus denormalized `tenant_id` columns. This is tracked as the
  highest-priority defense-in-depth item.

## Hardening checklist for operators

- [ ] Replace `HCVF_API_KEYS` with freshly generated keys; bootstrap keys are admins.
- [ ] Set `ENVIRONMENT=production` and `ALLOW_PRIVATE_TARGETS=false`.
- [ ] Set `EVIDENCE_KEY` to a generated 32+ byte secret and store it outside the image.
- [ ] Put TLS in front of the API; do not expose port 8000 directly.
- [ ] Replace the default Postgres password; do not publish 5432/6379 beyond loopback.
- [ ] Mount the evidence volume on encrypted storage with a retention policy.
- [ ] Run egress only through a proxy you control if your environment requires it.
- [ ] Alert on `hcvf_hunts_finished_total{outcome="failed"}` and on reaper activity.
