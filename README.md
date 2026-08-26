# HCVF Platform

**Hybrid Concolic Validation Fabric**

HCVF is an authorized defensive security validation control plane built with FastAPI, Celery, PostgreSQL, and Redis. Campaigns are tenant-scoped, require explicit authorization attestation before execution, and produce auditable run state.

> **Authorized use only:** Execute HCVF only against systems you own or are explicitly authorized to test. It is not intended for unauthorized third-party scanning or bug-bounty automation against targets without permission.

## Current operational baseline

- FastAPI campaign control plane
- API-key tenant isolation
- Tenant management with one-time secure API-key issuance
- PostgreSQL persistence via SQLAlchemy 2 and psycopg 3
- Alembic migrations with all application models registered in metadata
- Celery worker execution through Redis
- Scheduler loop for due campaigns
- Bounded authorized target validation through `FuzzRunner`
- Structured JSON logging
- Prometheus metrics at `/metrics`
- PostgreSQL and Redis health checks at `/health`
- Circuit breakers around dependency health checks
- Redis-backed fixed-window API rate limiting
- Redis-backed distributed lock primitive with ownership-safe release
- Exponential retry utility with jitter
- Request IDs via `X-Request-ID`
- Security headers on every API response
- Centralized audit service for mutating operations
- Campaign creation, listing, retrieval, cancellation, and execution
- Tenant creation, listing, retrieval, and authorized-target updates
- Integration tests covering API campaign, tenant, security-header, smoke, and execution flows

## Requirements

- Python 3.13
- PostgreSQL 16
- Redis 7
- Docker with Docker Compose

## Configuration

Create local configuration from the safe development template:

```bash
cp .env.example .env
```

The default local database URL uses psycopg 3:

```text
postgresql+psycopg://hcvf:password@localhost:5432/hcvf
```

Configured API keys are supplied as a comma-separated `HCVF_API_KEYS` value. On application bootstrap, each configured key is hashed with SHA-256 and provisioned to a tenant record; plaintext keys are not stored in PostgreSQL.

## Local environment

Create a Python environment and install dependencies:

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
chmod +x scripts/*.sh
```

The scripts contain `#!/usr/bin/env bash` shebangs. If executable mode has not yet been set in a local checkout, each script can also be invoked explicitly with `bash scripts/<name>.sh`.

## Validation

The repository includes four scripts intended to be run in this order by a developer validating a fresh clone:

```bash
./scripts/bootstrap.sh
./scripts/diagnostics.sh
./scripts/test.sh
./scripts/smoke_test.sh
```

### `./scripts/bootstrap.sh`

Starts only PostgreSQL and Redis through Docker Compose, waits until both containers report healthy, and then applies all Alembic migrations through `alembic upgrade head`. If `.env` does not exist, the script creates it from `.env.example`.

Expected successful output resembles:

```text
Starting PostgreSQL and Redis...
postgres is healthy
redis is healthy
Applying Alembic migrations...
HCVF bootstrap complete: PostgreSQL and Redis are healthy and migrations are at head.
```

### `./scripts/diagnostics.sh`

Checks the local prerequisites and reports each item independently:

- Docker daemon availability
- Python 3.13
- required Python imports
- PostgreSQL container state
- Redis container state
- `.env` presence

Expected successful output resembles:

```text
HCVF diagnostics
================
[OK]   Docker daemon                running
[OK]   Python version               3.13.x
[OK]   Python packages              all required packages import successfully
[OK]   postgres container           running (healthy)
[OK]   redis container              running (healthy)
[OK]   .env file                    present
================
HCVF diagnostics: ALL CHECKS PASSED
```

### `./scripts/test.sh`

Runs the complete pytest suite with verbose output and `-x`, so execution stops immediately at the first failing test. It exits nonzero on failure and prints an explicit summary.

Expected final line on success:

```text
HCVF TESTS: PASSED
```

### `./scripts/smoke_test.sh`

Starts `uvicorn app.main:app` in the background, waits for the API to answer, validates the `/health` JSON contract, and verifies that `/metrics` returns Prometheus exposition text. The API process is always terminated when the script exits.

A degraded health response is accepted as a valid API response for smoke-test purposes because it proves the API is reachable and dependency state is being reported correctly. After `bootstrap.sh`, normal local output should be healthy.

Expected successful output resembles:

```text
Starting HCVF API on http://127.0.0.1:8000...
Health endpoint: PASS (HTTP 200)
Health payload: {"status":"ok",...}
Metrics endpoint: PASS (HTTP 200, Prometheus exposition detected)
HCVF SMOKE TEST: PASSED
```

The smoke test defaults to port `8000`, a 30-second startup timeout, and `/tmp/hcvf-smoke-uvicorn.log`. They can be overridden with `HCVF_SMOKE_PORT`, `HCVF_SMOKE_TIMEOUT`, and `HCVF_SMOKE_LOG`.

## Docker Compose

Start the complete stack:

```bash
docker compose up --build
```

The API applies `alembic upgrade head` before startup. PostgreSQL and Redis use named persistent volumes. API, worker, and scheduler use `restart: unless-stopped`. Every service has a health check.

## Campaign API example

Create an authorized campaign:

```bash
curl -X POST http://localhost:8000/api/v1/campaigns \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: dev-hcvf-key' \
  -d '{
    "name": "owned-service validation",
    "target_url": "https://service.example.test/",
    "authorization_attested": true
  }'
```

List campaigns:

```bash
curl http://localhost:8000/api/v1/campaigns \
  -H 'X-API-Key: dev-hcvf-key'
```

Cancel a non-running campaign:

```bash
curl -X POST http://localhost:8000/api/v1/campaigns/<campaign-id>/cancel \
  -H 'X-API-Key: dev-hcvf-key'
```

Execute it using the returned campaign ID:

```bash
curl -X POST http://localhost:8000/api/v1/campaigns/<campaign-id>/execute \
  -H 'X-API-Key: dev-hcvf-key'
```

## Tenant management

Tenant administration is available under `/api/v1/tenants`. Every endpoint requires an already provisioned API key. Tenant creation returns a newly generated API key exactly once; only its SHA-256 hash is persisted.

Create a tenant:

```bash
curl -X POST http://localhost:8000/api/v1/tenants \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: dev-hcvf-key' \
  -d '{
    "name": "security-team",
    "authorized_targets": [
      "https://owned.example.test",
      "https://api.owned.example.test"
    ]
  }'
```

List tenants:

```bash
curl http://localhost:8000/api/v1/tenants \
  -H 'X-API-Key: dev-hcvf-key'
```

Retrieve a tenant:

```bash
curl http://localhost:8000/api/v1/tenants/<tenant-id> \
  -H 'X-API-Key: dev-hcvf-key'
```

Update authorized targets:

```bash
curl -X PATCH http://localhost:8000/api/v1/tenants/<tenant-id> \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: dev-hcvf-key' \
  -d '{"authorized_targets": ["https://new-owned.example.test"]}'
```

## Logging

HCVF emits structured JSON logs to stdout from both FastAPI and Celery. Each record includes `timestamp`, `level`, `message`, `logger`, and exception details when present. Operational context such as `request_id`, `tenant_id`, `campaign_id`, `run_id`, task duration, and finding identifiers is included as structured fields when available.

## Metrics

Prometheus metrics are exposed at:

```text
GET /metrics
```

The endpoint includes application metrics such as `hcvf_campaigns_created_total`, `hcvf_campaigns_completed_total`, `hcvf_findings_detected_total`, and `hcvf_task_duration_seconds`.

## Health checks

Dependency health is exposed at:

```text
GET /health
```

The handler executes `SELECT 1` against PostgreSQL and `PING` against Redis. Each dependency check is protected by a circuit breaker. A fully healthy response returns HTTP 200 with `status: ok`. If either dependency is unavailable, HCVF returns HTTP 503 with `status: degraded` and dependency/circuit state.

## Security headers

Every API response includes:

```text
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
```

HSTS is intended for HTTPS deployments; terminate TLS appropriately in front of HCVF when deployed beyond local development.

## Circuit breaker

`app/core/circuit_breaker.py` provides dependency isolation with configurable failure thresholds and recovery timeouts. The breaker moves through `closed`, `open`, and `half_open` states. PostgreSQL and Redis health checks use independent breakers so repeated dependency failure does not continuously hammer an unavailable service.

## Distributed locking

`app/core/distributed_lock.py` provides Redis-backed distributed locks using a random UUID owner token and an expiration TTL. Lock acquisition uses Redis `SET NX EX`; release uses an atomic Lua compare-and-delete operation so one process cannot accidentally release a lock owned by another process.

## Retry utility

`app/core/retry.py` provides a synchronous retry decorator with exponential backoff, configurable retry count/base delay, exception filtering, and optional jitter. It is intended for bounded transient-failure handling rather than unbounded retry loops.

## Request IDs

Every request receives an `X-Request-ID`. If the client supplies one, HCVF propagates it; otherwise HCVF generates a UUID. The request ID is stored in request state, propagated using `contextvars`, returned in the response header, and included in audit/logging context where applicable.

## Rate limiting

API traffic is protected by a Redis-backed fixed-window limiter. `/health` and `/metrics` are excluded so orchestration and monitoring remain functional.

Configuration:

```text
RATE_LIMIT_REQUESTS=120
RATE_LIMIT_WINDOW_SECONDS=60
```

The limiter keys requests by a SHA-256-derived identifier rather than storing plaintext API keys in Redis. Requests exceeding the configured limit receive HTTP 429 and a `Retry-After` header. If Redis is unavailable, protected requests fail closed with HTTP 503 because the service cannot reliably enforce the configured policy.

## Audit logging

POST, PUT, PATCH, and DELETE operations are written to the `audit_logs` table when an authenticated tenant is present. GET operations are not written by the audit middleware. Service-level audit records are centralized through `AuditService` and include tenant, actor/user identifier, action, resource context, details, request ID, and an explicit timestamp.

## Tests

After bootstrap, run:

```bash
./scripts/test.sh
```

`tests/test_campaign_flow.py` verifies campaign creation, listing, and cancellation. `tests/test_tenant_flow.py` verifies tenant creation, listing, retrieval, and authorized-target updates. `tests/test_security_headers.py` verifies required response headers. `tests/test_smoke.py` verifies root reachability, health, and metrics. The execution integration test starts a local authorized HTTP fixture, executes the Celery task synchronously, and verifies the persisted run and finding.

## Alembic development workflow

All models are imported by `app/models/__init__.py`, and `alembic/env.py` points `target_metadata` at the shared declarative `Base`. New schema changes can therefore be generated with:

```bash
alembic revision --autogenerate -m "describe change"
alembic upgrade head
```

Review generated migrations before applying them.
