"""Objective artifacts: SARIF, Markdown, signatures, and the run-over-run diff.

An objective report is a promise. It is useful only if a reviewer can take it
away, diff it against last week, and check that it was not edited in transit.
This module builds the portable forms and signs them with the same HMAC key the
evidence manifests use.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from app.engine.evidence import verification_key_from_env
from app.engine.report import PROJECT_URL, SARIF_SCHEMA

LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _findings(report: dict) -> list[dict]:
    return [finding for finding in report.get("findings", []) if isinstance(finding, dict)]


def _criteria(report: dict) -> list[dict]:
    return [item for item in report.get("criteria", []) if isinstance(item, dict)]


def build_sarif(objective, report: dict | None = None) -> dict[str, object]:
    """Portable SARIF for the findings an objective proved or observed."""

    payload = report if report is not None else (objective.result or {})
    findings = _findings(payload)
    rules: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []

    for finding in findings:
        kind = str(finding.get("kind", "unknown"))
        rules.setdefault(
            kind,
            {
                "id": kind,
                "name": kind.replace("-", " ").title(),
                "shortDescription": {"text": kind.replace("-", " ")},
                "helpUri": PROJECT_URL,
            },
        )
        severity = str(finding.get("severity", "info"))
        route = str(finding.get("route", "") or objective.target_url)
        results.append(
            {
                "ruleId": kind,
                "level": LEVEL.get(severity, "note"),
                "message": {"text": f"{kind} at {route}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": route}}}],
                "partialFingerprints": {"hcvf/v1": str(finding.get("fingerprint", ""))},
                "properties": {
                    "severity": severity,
                    "confidence": finding.get("confidence", 0.0),
                    "probe": finding.get("probe_id", ""),
                    "objective": objective.key,
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
                        "name": "hcvf-objective-worker",
                        "informationUri": PROJECT_URL,
                        "version": "0.8.0",
                        "rules": list(rules.values()),
                    }
                },
                "properties": {
                    "objective": objective.key,
                    "target": objective.target_url,
                    "status": objective.status,
                    "verdict": objective.verdict,
                    "requests_used": objective.requests_used,
                    "generated_at": datetime.now(UTC).isoformat(),
                },
                "results": results,
            }
        ],
    }


def build_markdown(objective, report: dict | None = None) -> str:
    payload = report if report is not None else (objective.result or {})
    evidence = payload.get("evidence", {}) or {}
    coverage = evidence.get("coverage", {}) or {}
    findings = _findings(payload)
    criteria = _criteria(payload)

    lines = [
        f"# Objective report: {objective.title}",
        "",
        f"- **Objective**: `{objective.key}`",
        f"- **Target**: {objective.target_url}",
        f"- **Template**: {objective.template}",
        f"- **Status**: {objective.status}",
        f"- **Requests used**: {objective.requests_used}/{objective.budget_requests}",
        f"- **Verdict**: {objective.verdict}",
        "",
        "## Acceptance criteria",
        "",
        "| Criterion | Satisfied | Observed |",
        "|---|---|---|",
    ]
    for item in criteria:
        mark = "PASS" if item.get("satisfied") else "FAIL"
        lines.append(f"| {item.get('description', item.get('kind', ''))} | {mark} | {item.get('observed', '')} |")
    lines += [
        "",
        "## Coverage",
        "",
        f"{coverage.get('covered', 0)}/{coverage.get('discovered', 0)} discovered routes probed "
        f"({float(coverage.get('ratio', 0.0)):.0%}); evidence manifests audited before this report.",
        "",
        "## Findings",
        "",
    ]
    if findings:
        lines += ["| Severity | Finding | Route | Probe |", "|---|---|---|---|"]
        for finding in sorted(findings, key=lambda item: str(item.get("severity")), reverse=True):
            lines.append(
                f"| {finding.get('severity', '')} | {finding.get('kind', '')} | "
                f"{finding.get('route', '')} | {finding.get('probe_id', '')} |"
            )
    else:
        lines.append("No findings were observed.")
    lines += [
        "",
        "## Evidence",
        "",
        f"- Findings: {evidence.get('findings', 0)}",
        f"- Verified: {evidence.get('verified', 0)}",
        f"- Refuted: {evidence.get('refuted', 0)}",
        f"- Requests: {evidence.get('requests_used', 0)}",
        f"- Coverage: {coverage.get('ratio', 0.0)}",
        "",
    ]
    return "\n".join(lines)


def sign(content: bytes, key: bytes | None = None) -> dict[str, str]:
    signing_key = key or verification_key_from_env()
    return {
        "alg": "HMAC-SHA256",
        "value": hmac.new(signing_key, content, hashlib.sha256).hexdigest(),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def write_artifacts(objective, root: Path | str, report: dict | None = None) -> dict[str, str]:
    """Write signed SARIF + Markdown next to the evidence and return their paths."""

    directory = Path(root) / str(objective.id)
    directory.mkdir(parents=True, exist_ok=True)
    sarif_bytes = json.dumps(build_sarif(objective, report), indent=2, sort_keys=True).encode("utf-8")
    markdown_bytes = build_markdown(objective, report).encode("utf-8")
    paths: dict[str, str] = {}
    for name, content in (("report.sarif", sarif_bytes), ("report.md", markdown_bytes)):
        path = directory / name
        path.write_bytes(content)
        signature = sign(content)
        (directory / f"{name}.sig.json").write_text(json.dumps(signature, indent=2), encoding="utf-8")
        paths[name] = str(path)
    return paths


def objective_diff(objective, previous, previous_report: dict | None = None) -> dict[str, object]:
    """What changed since the previous completed objective on the same target."""

    current_kinds = {str(finding.get("kind")) for finding in _findings(objective.result or {})}
    previous_kinds = {
        str(finding.get("kind"))
        for finding in _findings(previous_report or (previous.result if previous else {}) or {})
    }
    return {
        "objective": objective.key,
        "previous": getattr(previous, "key", ""),
        "previous_completed_at": (
            getattr(previous, "completed_at", None).isoformat() if getattr(previous, "completed_at", None) else ""
        ),
        "new": sorted(current_kinds - previous_kinds),
        "fixed": sorted(previous_kinds - current_kinds),
        "recurring": sorted(current_kinds & previous_kinds),
        "current_total": len(_findings(objective.result or {})),
        "previous_total": len(_findings(previous_report or (previous.result if previous else {}) or {})),
    }


def summarize_findings(findings: Iterable[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity", "info"))
        counts[severity] = counts.get(severity, 0) + 1
    return counts
