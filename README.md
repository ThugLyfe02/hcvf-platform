# HCVF Platform

**Hybrid Concolic Validation Fabric**

HCVF is an authorized defensive security validation control plane built with FastAPI, Celery, PostgreSQL, and Redis. Campaigns are tenant-scoped, require explicit authorization attestation before execution, and produce auditable run state.

> **Authorized use only:** Execute HCVF only against systems you own or are explicitly authorized to test. It is not intended for unauthorized third-party scanning or bug-bounty automation against targets without permission.

## Current operational baseline

- FastAPI campaign control plane
- API-key tenant isolation
- PostgreSQL persistence via SQLAlchemy 2 and psycopg 3
- Alembic migrations with all application models registered in metadata
- Celery worker execution through Redis
- Scheduler loop for due campaigns
- Bounded HTTP target validation through `FuzzRunner`
- Structured JSON logging
- Prometheus metrics at `/metrics`
- PostgreSQL and Redis health checks at `/health`
- Redis-backed fixed-window API rate limiting
- Request IDs via `X-Request-ID`
- Audit records for mutating campaign API operations
- End-to-end integration test for campaign creation and execution

## Requirements

- Python 3.13
- PostgreSQL 16
- Redis 7
- Docker and Docker Compose, if using containers

## Configuration

Copy the example configuration and change the development API key before using the service outside a local environment:

```bash
cp .env.example .env
```

The default local database URL uses psycopg 3:

```text
postgresql+psycopg://hcvf:password@localhost:5432/hcvf
```

Configured API keys are supplied as a comma-separated `HCVF_API_KEYS` value. On application bootstrap, each configured key is hashed with SHA-256 and provisioned to a tenant record; plaintext keys are not stored in PostgreSQL.

## Local startup

Install dependencies:

```bash
python3.13 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Start PostgreSQL and Redis:

```bash
docker compose up -d postgres redis
```

Initialize the database and provision configured tenants:

```bash
python -m app.db.init_db
```

Equivalent migration-only command:

```bash
alembic upgrade head
```

Start the API:

```bash
uvicorn app.main:app --reload
```

Start a worker in another shell:

```bash
celery -A worker.celery_app:celery_app worker --loglevel=info
```

Start the scheduler in another shell:

```bash
python -m worker.scheduler
```

## Docker Compose

The full stack applies `alembic upgrade head` before API startup:

```bash
docker compose up --build
```

## API example

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

Execute it using the returned campaign ID:

```bash
curl -X POST http://localhost:8000/api/v1/campaigns/<campaign-id>/execute \
  -H 'X-API-Key: dev-hcvf-key'
```

## Operational endpoints

```text
GET /health
GET /metrics
```

`/health` returns HTTP 503 when PostgreSQL or Redis is unavailable. Rate limiting intentionally fails closed with HTTP 503 if Redis cannot enforce the configured limit.

## Tests

With PostgreSQL and Redis running and the database migrated:

```bash
pytest -q
```

The campaign integration test starts a local authorized HTTP fixture, creates a campaign through FastAPI, executes the Celery task synchronously, and verifies the persisted run and finding.

## Alembic development workflow

All models are imported by `app/models/__init__.py`, and `alembic/env.py` points `target_metadata` at the shared declarative `Base`. New schema changes can therefore be generated with:

```bash
alembic revision --autogenerate -m "describe change"
alembic upgrade head
```

Review generated migrations before applying them.
