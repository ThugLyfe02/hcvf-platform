from __future__ import annotations

import structlog
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from starlette.responses import Response

from app.db.session import SessionLocal
from app.models.audit import AuditLog
from app.models.campaign import Campaign, CampaignStatus
from app.models.finding import Finding, FindingSeverity
from app.models.run import Run, RunStatus

logger = structlog.get_logger(__name__)

HTTP_REQUESTS = Counter(
    "hcvf_http_requests_total",
    "HTTP requests handled by the HCVF API.",
    ("method", "route", "status"),
)
HTTP_REQUEST_DURATION = Histogram(
    "hcvf_http_request_duration_seconds",
    "HCVF API request latency in seconds.",
    ("method", "route"),
)
CAMPAIGNS_CREATED = Counter(
    "hcvf_campaigns_created_total",
    "Campaigns created through the API.",
)
CAMPAIGN_EXECUTION_REQUESTS = Counter(
    "hcvf_campaign_execution_requests_total",
    "Campaign execution requests accepted in this process.",
    ("source",),
)
RATE_LIMIT_REJECTIONS = Counter(
    "hcvf_rate_limit_rejections_total",
    "Requests rejected by the API rate limiter.",
)
CAMPAIGNS_CURRENT = Gauge(
    "hcvf_campaigns_current",
    "Persisted campaigns by current status.",
    ("status",),
)
RUNS_CURRENT = Gauge(
    "hcvf_runs_current",
    "Persisted campaign runs by current status.",
    ("status",),
)
FINDINGS_CURRENT = Gauge(
    "hcvf_findings_current",
    "Persisted findings by severity.",
    ("severity",),
)
AUDIT_LOG_ENTRIES = Gauge(
    "hcvf_audit_log_entries",
    "Persisted audit log entries.",
)
DATABASE_METRICS_REFRESH_SUCCESS = Gauge(
    "hcvf_database_metrics_refresh_success",
    "Whether the latest database-backed metrics refresh succeeded.",
)


def refresh_database_metrics() -> None:
    """Refresh bounded-cardinality gauges from persisted platform state."""

    try:
        with SessionLocal() as db:
            campaign_counts = dict(
                db.execute(
                    select(Campaign.status, func.count(Campaign.id)).group_by(Campaign.status)
                ).all()
            )
            run_counts = dict(
                db.execute(select(Run.status, func.count(Run.id)).group_by(Run.status)).all()
            )
            finding_counts = dict(
                db.execute(
                    select(Finding.severity, func.count(Finding.id)).group_by(Finding.severity)
                ).all()
            )
            audit_count = db.scalar(select(func.count(AuditLog.id))) or 0

        for status in CampaignStatus:
            CAMPAIGNS_CURRENT.labels(status=status.value).set(campaign_counts.get(status, 0))
        for status in RunStatus:
            RUNS_CURRENT.labels(status=status.value).set(run_counts.get(status, 0))
        for severity in FindingSeverity:
            FINDINGS_CURRENT.labels(severity=severity.value).set(
                finding_counts.get(severity, 0)
            )
        AUDIT_LOG_ENTRIES.set(audit_count)
        DATABASE_METRICS_REFRESH_SUCCESS.set(1)
    except SQLAlchemyError as exc:
        DATABASE_METRICS_REFRESH_SUCCESS.set(0)
        logger.warning(
            "database_metrics_refresh_failed",
            error_type=exc.__class__.__name__,
        )


def prometheus_response() -> Response:
    refresh_database_metrics()
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
