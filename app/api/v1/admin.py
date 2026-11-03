"""Operator exports: CSV inventories and signed evidence bundles.

Everything an auditor asks for should be obtainable without database access:
findings and audit logs as CSV, and a single signed archive that contains the
evidence, the manifests and both report formats for one objective.

Exports are admin-only. They are generated from the same tenant-scoped queries
the API uses; there is no export path that can see another tenant.
"""

from __future__ import annotations

import contextlib
import csv
import io
import json
import zipfile
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import require_admin
from app.db.session import get_db
from app.models import AuditLog, Finding, Objective, Tenant
from app.services.objective_artifacts import build_markdown, build_sarif, sign, write_artifacts
from app.services.objective_service import ObjectiveService

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])

MAX_BUNDLE_BYTES = 64 * 1024 * 1024


def _csv_response(rows: list[list[object]], headers: list[str], filename: str) -> Response:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(headers)
    for row in rows:
        writer.writerow(row)
    body = buffer.getvalue().encode("utf-8")
    signature = sign(body)
    return Response(
        content=body,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-HCVF-Signature": f"sha256={signature['value']}",
            "X-HCVF-SHA256": signature["sha256"],
        },
    )


@router.get("/export/findings.csv")
def export_findings(
    tenant: Tenant = Depends(require_admin),
    db: Session = Depends(get_db),
    limit: int = Query(default=5000, ge=1, le=50000),
) -> Response:
    rows = [
        [
            finding.fingerprint,
            finding.kind,
            finding.severity,
            finding.status,
            finding.confidence,
            finding.cwe,
            finding.occurrences,
            finding.title,
            finding.last_seen_at.isoformat() if finding.last_seen_at else "",
        ]
        for finding in db.scalars(
            select(Finding).where(Finding.tenant_id == tenant.id).order_by(Finding.last_seen_at.desc()).limit(limit)
        )
    ]
    return _csv_response(
        rows,
        ["fingerprint", "kind", "severity", "status", "confidence", "cwe", "occurrences", "title", "last_seen_at"],
        "hcvf-findings.csv",
    )


@router.get("/export/audit.csv")
def export_audit(
    tenant: Tenant = Depends(require_admin),
    db: Session = Depends(get_db),
    limit: int = Query(default=5000, ge=1, le=50000),
) -> Response:
    rows = [
        [
            entry.seq,
            entry.action,
            entry.actor or "",
            entry.resource_type or "",
            entry.resource_id or "",
            entry.request_id or "",
            entry.hash or "",
            entry.created_at.isoformat() if entry.created_at else "",
        ]
        for entry in db.scalars(
            select(AuditLog).where(AuditLog.tenant_id == tenant.id).order_by(AuditLog.seq.asc()).limit(limit)
        )
    ]
    return _csv_response(
        rows,
        ["seq", "action", "actor", "resource_type", "resource_id", "request_id", "hash", "created_at"],
        "hcvf-audit.csv",
    )


@router.get("/export/objectives.csv")
def export_objectives(
    tenant: Tenant = Depends(require_admin),
    db: Session = Depends(get_db),
    limit: int = Query(default=5000, ge=1, le=50000),
) -> Response:
    rows = [
        [
            objective.key,
            objective.title,
            objective.target_url,
            objective.template,
            objective.status,
            objective.requests_used,
            objective.budget_requests,
            (objective.verdict or "")[:400],
            objective.created_at.isoformat() if objective.created_at else "",
            objective.completed_at.isoformat() if objective.completed_at else "",
        ]
        for objective in db.scalars(
            select(Objective).where(Objective.tenant_id == tenant.id).order_by(Objective.created_at.desc()).limit(limit)
        )
    ]
    return _csv_response(
        rows,
        [
            "key",
            "title",
            "target",
            "template",
            "status",
            "requests_used",
            "budget_requests",
            "verdict",
            "created_at",
            "completed_at",
        ],
        "hcvf-objectives.csv",
    )


@router.get("/bundle/{objective_id}.zip")
def export_bundle(
    objective_id: str,
    tenant: Tenant = Depends(require_admin),
    db: Session = Depends(get_db),
) -> Response:
    """One signed archive: evidence, manifests, SARIF, Markdown and the report."""

    from uuid import UUID

    try:
        parsed = UUID(objective_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="objective id must be a UUID") from exc

    service = ObjectiveService(db)
    objective = service.get(tenant_id=tenant.id, objective_id=parsed)
    if objective is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Objective not found")

    root = Path(service.evidence_root) / str(objective.id)
    with contextlib.suppress(OSError):
        write_artifacts(objective, service.evidence_root, objective.result)

    buffer = io.BytesIO()
    total = 0
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
        if root.exists():
            for path in sorted(root.rglob("*")):
                if not path.is_file():
                    continue
                payload = path.read_bytes()
                total += len(payload)
                if total > MAX_BUNDLE_BYTES:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail="evidence bundle exceeds the export limit",
                    )
                archive.writestr(str(path.relative_to(root)), payload)
        archive.writestr(
            "objective.json",
            json.dumps(service.report(objective), indent=2, sort_keys=True, default=str),
        )
        archive.writestr("report.sarif", json.dumps(build_sarif(objective), indent=2, sort_keys=True))
        archive.writestr("report.md", build_markdown(objective))

    body = buffer.getvalue()
    signature = sign(body)
    return Response(
        content=body,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{objective.key}.zip"',
            "X-HCVF-Signature": f"sha256={signature['value']}",
            "X-HCVF-SHA256": signature["sha256"],
            "X-HCVF-Evidence-Key": "configured" if settings.console_secret else "derived",
        },
    )
