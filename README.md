# HCVF Platform

**Hybrid Concolic Validation Fabric**

An autonomous defensive security validation platform engineered for discovering, triaging, and remediating vulnerabilities across systems you own or are explicitly authorized to test.

> **Critical Notice:**  
> This platform is strictly for authorized defensive security operations.  
> Do not deploy or execute it against any system without explicit written authorization.

---

## Overview

HCVF is a modular security validation fabric that orchestrates campaign-based fuzzing, static analysis, intelligent triage, policy-driven remediation, structured reporting, and immutable audit logging.

It is designed to reduce manual security toil while maintaining strict operational control and full auditability.

---

## System Architecture

| Component   | Technology   | Responsibility                              |
|-------------|--------------|---------------------------------------------|
| API         | FastAPI      | Campaign management and control plane        |
| Worker      | Celery       | Asynchronous task execution                  |
| Scheduler   | Celery Beat  | Automated campaign scheduling                |
| Database    | PostgreSQL   | Persistent state and tenant isolation        |
| Broker      | Redis        | Message queue and result backend             |

---

## Core Capabilities

- Campaign creation, scheduling, and cancellation
- Fuzzing with AddressSanitizer instrumentation
- Static analysis for constraint extraction
- Severity triage and deduplication
- Policy-based remediation
- Structured report generation
- Immutable audit trail
- Tenant isolation via API key authentication

---

## Prerequisites

- Python 3.11+
- Docker
- Docker Compose
- PostgreSQL 16
- Redis 7

---

## Installation

```bash
# Clone the repository
git clone https://github.com/ThugLyfe02/hcvf-platform.git

# Enter the project directory
cd hcvf-platform

# Create environment configuration
cp .env.example .env

# Install Python dependencies
pip install -r requirements.txt

# Start supporting services
docker-compose up -d postgres redis

# Apply database migrations
alembic upgrade head

# Start the API
uvicorn app.main:app --reload

# In a separate terminal, start the worker
celery -A worker.celery_app worker --loglevel=info

# In another terminal, start the scheduler
celery -A worker.celery_app beat --loglevel=info
