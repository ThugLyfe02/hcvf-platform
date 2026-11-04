"""HCVF validation engine.

A deterministic, standard-library-only agentic hunting core. It is deliberately
free of FastAPI/SQLAlchemy/Celery imports so it can run inside a worker, in CI,
or from a CLI with no dependency surface — and so its decisions are testable in
isolation from infrastructure.
"""

from app.engine.types import (
    Cost,
    Endpoint,
    Finding,
    FindingDraft,
    HttpRequest,
    HttpResponse,
    ProbeContext,
    ProbeOutcome,
    SafetyClass,
    ScopeGrant,
    Severity,
    Target,
)

__all__ = [
    "Cost",
    "Endpoint",
    "Finding",
    "FindingDraft",
    "HttpRequest",
    "HttpResponse",
    "ProbeContext",
    "ProbeOutcome",
    "SafetyClass",
    "ScopeGrant",
    "Severity",
    "Target",
]

ENGINE_VERSION = "1.0.0"
