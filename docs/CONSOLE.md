# Operator console

The console is a server-rendered operator surface at `/console`. It exists because
watching a hunt should not require curl, and because an operator needs to see why
an objective blocked, not just that it did.

## Authentication

1. `GET /console/login` renders a single-field form.
2. `POST /console/login` resolves the pasted API key against the tenant table
   (the same hash lookup the API uses) and sets an HttpOnly, SameSite=Lax cookie.
3. The cookie contains only the tenant id and an expiry, signed with HMAC-SHA256.
   The raw key is never stored in the browser.

`HCVF_CONSOLE_SECRET` is the signing key. In development a stable value is
derived from the configured API keys so restarts do not drop sessions; production
must set the variable. Rotating the secret invalidates every console session,
which is the intended blast radius.

Console requests use the tenant dependency `app/web/auth.py:current_tenant`; an
unauthenticated request gets a 303 to the login page with a `next` parameter.

## Pages

| Page | What it shows |
|---|---|
| `/console` | objectives, completion rate, high findings, autonomy state |
| `/console/objectives` | filterable list with verdict and budget |
| `/console/objectives/{id}` | criteria, coverage, tasks, live events, artifacts |
| `/console/findings` | severity/status filters |
| `/console/runs` | campaign runs with risk score and evidence root |
| `/console/autonomy` | policy rules, targets, every decision with its reason |
| `/console/memory` | learned recipes with verified/refuted counts |
| `/console/workers` | the nine specialists and the doctrines |
| `/console/audit` | hash-chained tenant audit log |
| `/console/health` | probes registered, tables, active objectives |

## Live events

`/console/objectives/{id}/events.sse` streams `objective_events` as SSE frames
and closes when the objective is terminal. The same stream is available to
programmatic consumers at
`/api/v1/objectives/{id}/events/stream`, including a `once=1` replay mode for
tests and CI.

Events are read from the durable table, not from in-process state: a reconnecting
browser catches up instead of missing steps.

## Exports

Admin-only, tenant-scoped, signed with `X-HCVF-Signature` and `X-HCVF-SHA256`:

- `GET /api/v1/admin/export/findings.csv`
- `GET /api/v1/admin/export/audit.csv`
- `GET /api/v1/admin/export/objectives.csv`
- `GET /api/v1/admin/bundle/{objective_id}.zip` - evidence blobs, manifests,
  `objective.json`, `report.sarif` and `report.md` in one archive.

The bundle has a 64 MiB cap and refuses unknown objectives. Members receive 403:
exports are an admin capability, not a scope anyone can grant themselves.

## Design notes

- No client-side framework. Templates are Jinja2, static assets are one CSS file
  and one small JS file. The console must work behind an air-gapped jump host.
- Every page is a plain GET; the only writes are "run next steps" and "cancel",
  which call the same service methods as the API and therefore produce the same
  audit records.
- The console is included in `/openapi.json` as hidden routes, so it never
  pollutes the machine-facing API contract.
