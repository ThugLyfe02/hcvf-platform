"""SARIF generation from persisted findings (no engine run required)."""

from __future__ import annotations

from collections.abc import Iterable

from app.engine import ENGINE_VERSION
from app.engine.report import PROJECT_URL, SARIF_SCHEMA
from app.models import Finding, Run

_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def run_sarif(run: Run, findings: Iterable[Finding]) -> dict[str, object]:
    findings = list(findings)
    target = run.campaign.target_url if run.campaign is not None else ""

    rules: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []
    for finding in findings:
        if finding.kind not in rules:
            rules[finding.kind] = {
                "id": finding.kind,
                "name": finding.title[:120],
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.detail},
                "helpUri": PROJECT_URL,
                "defaultConfiguration": {"level": _LEVEL.get(finding.severity, "note")},
                "properties": {
                    "severity": finding.severity,
                    "cwe": finding.cwe,
                    "probe": finding.probe_id,
                },
            }
        location = (finding.evidence_refs or {}).get("location") or target
        results.append(
            {
                "ruleId": finding.kind,
                "level": _LEVEL.get(finding.severity, "note"),
                "message": {"text": f"{finding.title}. {finding.detail}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": location}}}],
                "partialFingerprints": {"hcvfFingerprint": finding.fingerprint},
                "properties": {
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "cwe": finding.cwe,
                    "probe": finding.probe_id,
                    "evidence": list(finding.evidence or []),
                    "status": finding.status,
                    "remediation": finding.remediation,
                },
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "HCVF",
                        "version": ENGINE_VERSION,
                        "informationUri": PROJECT_URL,
                        "rules": list(rules.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": run.status.value not in {"failed", "cancelled"},
                        "startTimeUtc": run.started_at.isoformat() if run.started_at else None,
                        "endTimeUtc": run.completed_at.isoformat() if run.completed_at else None,
                    }
                ],
                "results": results,
                "properties": {
                    "runId": str(run.id),
                    "target": target,
                    "evidenceRoot": run.evidence_root,
                    "decisionSeed": run.plan_seed,
                    "status": run.status.value,
                },
            }
        ],
    }
