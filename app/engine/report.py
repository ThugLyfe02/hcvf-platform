"""Reporting: SARIF for machines, Markdown for PRs, HTML for humans.

SARIF is the interoperability bet: it drops straight into GitHub code scanning,
Azure DevOps, DefectDojo and most enterprise vuln-management stacks, which is
what turns findings into work items instead of screenshots.
"""

from __future__ import annotations

import html
import json
from datetime import UTC, datetime
from pathlib import Path

from app.engine import ENGINE_VERSION
from app.engine.executor import HuntResult
from app.engine.probes import registry
from app.engine.types import Severity

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
PROJECT_URL = "https://github.com/ThugLyfe02/hcvf-platform"

_LEVEL = {
    Severity.critical: "error",
    Severity.high: "error",
    Severity.medium: "warning",
    Severity.low: "note",
    Severity.info: "note",
}

_SEVERITY_COLOUR = {
    "critical": "#7f1d1d",
    "high": "#b91c1c",
    "medium": "#b45309",
    "low": "#1d4ed8",
    "info": "#475569",
}


def to_sarif(result: HuntResult) -> dict[str, object]:
    rules: dict[str, dict[str, object]] = {}
    for finding in result.findings:
        if finding.kind in rules:
            continue
        rules[finding.kind] = {
            "id": finding.kind,
            "name": finding.title[:120],
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.detail},
            "helpUri": PROJECT_URL,
            "defaultConfiguration": {"level": _LEVEL[finding.severity]},
            "properties": {
                "severity": finding.severity.value,
                "cwe": finding.cwe,
                "confidence": finding.confidence,
                "probe": finding.probe_id,
                "tags": list(finding.tags),
            },
        }

    results = []
    for finding in result.findings:
        locations = []
        if finding.location:
            locations.append(
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.location},
                    }
                }
            )
        results.append(
            {
                "ruleId": finding.kind,
                "level": _LEVEL[finding.severity],
                "message": {"text": f"{finding.title}. {finding.detail}"},
                "locations": locations,
                "partialFingerprints": {"hcvfFingerprint": finding.fingerprint},
                "properties": {
                    "severity": finding.severity.value,
                    "confidence": finding.confidence,
                    "cwe": finding.cwe,
                    "probe": finding.probe_id,
                    "evidence": list(finding.evidence),
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
                        "executionSuccessful": not result.halted,
                        "startTimeUtc": result.started_at,
                        "endTimeUtc": result.finished_at,
                    }
                ],
                "results": results,
                "properties": {
                    "target": result.target.origin,
                    "evidenceRoot": result.evidence_root,
                    "decisionSeed": result.plan.seed,
                    "safetyCeiling": result.plan.grant.max_safety.name,
                    "posterior": result.posterior_after.to_dict(),
                },
            }
        ],
    }


def to_markdown(result: HuntResult) -> str:
    counts: dict[str, int] = {}
    for finding in result.findings:
        counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1

    lines = [
        f"# HCVF hunt report — {result.target.origin}",
        "",
        f"- **Findings:** {len(result.findings)} "
        + (f"({', '.join(f'{k}: {v}' for k, v in sorted(counts.items()))})" if counts else ""),
        f"- **Probes executed:** {len(result.probe_runs)}",
        f"- **Requests sent:** {result.budget.get('used_requests', 0)}",
        f"- **Evidence root:** `{result.evidence_root or 'none'}`",
        f"- **Decision seed:** `{result.plan.seed}` (replayable)",
        "",
        "## Findings",
        "",
    ]
    if not result.findings:
        lines.append("No findings. The hunt still updated the platform's priors.")
    else:
        lines += ["| Severity | Confidence | Finding | Location | CWE |", "|---|---|---|---|---|"]
        for finding in sorted(result.findings, key=lambda f: f.severity.rank, reverse=True):
            lines.append(
                f"| {finding.severity.value} | {finding.confidence:.2f} | {_md(finding.title)} | "
                f"`{_md(finding.location)}` | {finding.cwe or '-'} |"
            )
    lines += ["", "## Why these probes", "", "```", result.plan.explain(), "```", ""]
    return "\n".join(lines)


def _md(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def to_html(result: HuntResult) -> str:
    rows = []
    for finding in sorted(result.findings, key=lambda f: (f.severity.rank, f.confidence), reverse=True):
        colour = _SEVERITY_COLOUR[finding.severity.value]
        rows.append(
            f"""
            <tr>
              <td><span class="sev" style="background:{colour}">{html.escape(finding.severity.value)}</span></td>
              <td>{finding.confidence:.2f}</td>
              <td><strong>{html.escape(finding.title)}</strong><div class="muted">{html.escape(finding.detail)}</div></td>
              <td><code>{html.escape(finding.location)}</code></td>
              <td>{html.escape(finding.cwe or "-")}</td>
            </tr>"""
        )
    if not rows:
        rows.append('<tr><td colspan="5" class="muted">No findings in this hunt.</td></tr>')

    probe_rows = "".join(
        f"<tr><td><code>{html.escape(run.probe_id)}</code></td><td>{html.escape(run.status)}</td>"
        f"<td>{run.findings}</td><td>{run.cost.requests}</td><td>{run.duration_ms:.0f} ms</td></tr>"
        for run in result.probe_runs
    )
    top_routes = (
        "".join(
            f"<li><code>{html.escape(route.target.url)}</code> — score {route.score:.2f} ({html.escape(route.rationale)})</li>"
            for route in result.plan.routes[:5]
        )
        or "<li>Entry point only</li>"
    )

    debate = result.plan.transcript
    deliberation_rows = "".join(
        "<tr>"
        f"<td>r{message.round}</td>"
        f"<td><code>{html.escape(message.agent)}</code></td>"
        f"<td>{html.escape(message.act)}</td>"
        f"<td><code>{html.escape(message.option_id)}</code></td>"
        f"<td>{html.escape(message.text)}</td>"
        f"<td>{'' if message.score is None else f'{message.score:.2f}'}</td>"
        "</tr>"
        for message in debate
    )
    verdict = "consensus" if result.plan.converged else "no consensus (dissent recorded)"

    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>HCVF report — {html.escape(result.target.origin)}</title>
<style>
:root {{ color-scheme: light; }}
* {{ box-sizing: border-box; }}
body {{ font: 15px/1.55 -apple-system,Segoe UI,Roboto,sans-serif; margin: 0; background:#f6f7f9; color:#0f172a; }}
header {{ background:#0f172a; color:#f8fafc; padding:28px 32px; }}
header h1 {{ margin:0 0 6px; font-size:22px; }}
header p {{ margin:0; color:#94a3b8; }}
main {{ max-width:1100px; margin:0 auto; padding:24px 20px 64px; }}
section {{ background:#fff; border:1px solid #e2e8f0; border-radius:12px; padding:20px 22px; margin-bottom:18px; }}
h2 {{ font-size:15px; text-transform:uppercase; letter-spacing:.06em; color:#475569; margin:0 0 14px; }}
.cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin-bottom:18px; }}
.card {{ background:#fff; border:1px solid #e2e8f0; border-radius:12px; padding:14px 16px; }}
.card .n {{ font-size:24px; font-weight:650; }}
.card .l {{ color:#64748b; font-size:12px; text-transform:uppercase; letter-spacing:.05em; }}
table {{ width:100%; border-collapse:collapse; font-size:14px; }}
th,td {{ text-align:left; padding:9px 10px; border-bottom:1px solid #eef2f7; vertical-align:top; }}
th {{ color:#64748b; font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:.05em; }}
.sev {{ color:#fff; border-radius:999px; padding:2px 9px; font-size:11px; font-weight:700; text-transform:uppercase; }}
.muted {{ color:#64748b; font-size:13px; margin-top:4px; }}
code {{ font:12.5px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace; background:#f1f5f9; padding:1px 5px; border-radius:5px; word-break:break-all; }}
pre {{ background:#0f172a; color:#e2e8f0; padding:16px; border-radius:10px; overflow:auto; font-size:12.5px; }}
ul {{ margin:0; padding-left:18px; }}
footer {{ text-align:center; color:#94a3b8; font-size:12px; }}
</style></head>
<body>
<header>
  <h1>HCVF validation report</h1>
  <p>{html.escape(result.target.origin)} · generated {generated} · engine {ENGINE_VERSION}</p>
</header>
<main>
  <div class="cards">
    <div class="card"><div class="n">{len(result.findings)}</div><div class="l">Findings</div></div>
    <div class="card"><div class="n">{len(result.probe_runs)}</div><div class="l">Probes</div></div>
    <div class="card"><div class="n">{result.budget.get("used_requests", 0)}</div><div class="l">Requests</div></div>
    <div class="card"><div class="n">{html.escape(result.highest_severity.value)}</div><div class="l">Highest severity</div></div>
  </div>

  <section>
    <h2>Findings</h2>
    <table><thead><tr><th>Severity</th><th>Conf.</th><th>Finding</th><th>Location</th><th>CWE</th></tr></thead>
    <tbody>{"".join(rows)}</tbody></table>
  </section>

  <section>
    <h2>Routes of approach</h2>
    <ul>{top_routes}</ul>
  </section>

  <section>
    <h2>Decision trace</h2>
    <pre>{html.escape(result.plan.explain())}</pre>
  </section>

  <section>
    <h2>Deliberation</h2>
    <p class="muted">
      {result.plan.rounds} rounds · {len(result.plan.agents)} agents · {html.escape(verdict)} ·
      {len(debate)} utterances
    </p>
    <details>
      <summary>Full transcript</summary>
      <table>
        <thead><tr><th>Round</th><th>Agent</th><th>Act</th><th>Option</th><th>Statement</th><th>Score</th></tr></thead>
        <tbody>{deliberation_rows}</tbody>
      </table>
    </details>
  </section>

  <section>
    <h2>Probe execution</h2>
    <table><thead><tr><th>Probe</th><th>Status</th><th>Findings</th><th>Requests</th><th>Duration</th></tr></thead>
    <tbody>{probe_rows}</tbody></table>
  </section>

  <section>
    <h2>Evidence</h2>
    <p class="muted">Every observation is content-addressed and combined into a Merkle tree. The root below is signed; any change to any captured request or response invalidates it.</p>
    <p><code>{html.escape(result.evidence_root or "no evidence captured")}</code></p>
    <p class="muted">Leaf count: {len(result.manifest.get("entries", []))} · signature: {html.escape(str(result.manifest.get("signature", {}).get("alg", "none")))}</p>
  </section>

  <footer>Generated by HCVF · authorized validation only</footer>
</main>
</body></html>
"""


def to_json(result: HuntResult) -> str:
    return json.dumps(result.to_dict(), indent=2, sort_keys=True, default=str)


def write_reports(result: HuntResult, directory: Path | str) -> dict[str, Path]:
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": out / "hunt.json",
        "sarif": out / "hunt.sarif",
        "html": out / "report.html",
        "markdown": out / "report.md",
        "manifest": out / "evidence-manifest.json",
    }
    paths["json"].write_text(to_json(result), encoding="utf-8")
    paths["sarif"].write_text(json.dumps(to_sarif(result), indent=2), encoding="utf-8")
    paths["html"].write_text(to_html(result), encoding="utf-8")
    paths["markdown"].write_text(to_markdown(result), encoding="utf-8")
    paths["manifest"].write_text(json.dumps(result.manifest, indent=2), encoding="utf-8")
    return paths


def rule_catalog() -> list[dict[str, object]]:
    return [
        {
            "id": spec.id,
            "name": spec.name,
            "safety": spec.safety.name,
            "targets": [target.value for target in spec.targets],
            "default_enabled": spec.default_enabled,
            "cwe": spec.cwe,
        }
        for spec in (cls.spec for cls in registry().values())
    ]
