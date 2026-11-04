"""Command-line interface for the HCVF engine.

python -m app.engine.cli probes
python -m app.engine.cli hunt --target http://127.0.0.1:8099 --authorized
python -m app.engine.cli hunt --target ... --authorized --allow-private --probes security-headers,graphql-introspection
python -m app.engine.cli memory --memory .hcvf/memory.json
python -m app.engine.cli verify --manifest out/evidence-manifest.json --evidence out/evidence
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from app.engine import ENGINE_VERSION
from app.engine.diff import diff
from app.engine.diff import summary as diff_summary
from app.engine.evidence import FileEvidenceStore, verify_manifest
from app.engine.executor import HuntExecutor
from app.engine.learn import HuntMemory, learn, probe_leaderboard, summarize_memory
from app.engine.policy import EgressPolicy
from app.engine.probes import default_probe_ids
from app.engine.report import rule_catalog, write_reports
from app.engine.target import build_grant, parse_target
from app.engine.transcript import render_markdown
from app.engine.types import SafetyClass


def _eprint(message: str) -> None:
    print(message, file=sys.stderr)


def cmd_probes(_: argparse.Namespace) -> int:
    rows = rule_catalog()
    print(f"{'PROBE':32} {'SAFETY':15} {'DEFAULT':8} TARGETS")
    for row in rows:
        print(f"{row['id']:32} {row['safety']:15} {row['default_enabled']!s:8} {','.join(row['targets'])}")
    print(f"\n{len(rows)} probes registered · engine {ENGINE_VERSION}")
    return 0


def cmd_hunt(args: argparse.Namespace) -> int:
    if not args.authorized:
        _eprint(
            "refusing to run: --authorized is required.\n"
            "Only validate systems you own or have written permission to test."
        )
        return 2

    target = parse_target(args.target)
    safety = SafetyClass.state_changing if args.allow_state_changing else SafetyClass.read_only
    statement = f"{target.origin}|{args.operator}|{safety.name}|authorized"
    grant = build_grant(
        target,
        safety=safety,
        max_rps=args.rps,
        approver=args.operator,
        evidence_sha256=hashlib.sha256(statement.encode("utf-8")).hexdigest(),
    )

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    store = FileEvidenceStore(out / "evidence")

    memory = HuntMemory.load(args.memory) if args.memory else HuntMemory()
    known = list(default_probe_ids())
    from app.engine.probes import registry

    known = list(registry().keys())
    genome = memory.current_genome(known) if memory.genome else None

    requested = [item.strip() for item in args.probes.split(",")] if args.probes else None

    executor = HuntExecutor(
        policy=EgressPolicy(allow_private=args.allow_private),
        store=store,
    )
    result = executor.run(
        target,
        grant,
        seed=args.seed,
        budget_requests=args.budget,
        aggression=args.aggression,
        posterior=memory.posterior_state() if memory.posterior else None,
        bandit=memory.bandit_state() if memory.bandit else None,
        genome=genome,
        requested_probes=requested,
    )

    memory, learning = learn(result, memory, known_probes=known)
    if args.memory:
        memory.save(args.memory)
    (out / "learning.json").write_text(json.dumps(learning.to_dict(), indent=2), encoding="utf-8")
    (out / "transcript.md").write_text(render_markdown(result.plan), encoding="utf-8")
    (out / "memory.json").write_text(json.dumps(memory.to_dict(), indent=2), encoding="utf-8")

    paths = write_reports(result, out)

    print(f"\nHCVF hunt - {target.origin} - engine {ENGINE_VERSION}")
    print(f"  probes        {len(result.probe_runs)} executed, {len(result.plan.probes)} planned")
    print(f"  requests      {result.budget.get('used_requests')}/{result.budget.get('max_requests')}")
    outcome = "consensus" if result.plan.converged else "no consensus"
    print(
        f"  deliberation  {result.plan.rounds} rounds, {outcome}, "
        f"{len(result.plan.transcript)} utterances, {len(result.plan.agents)} agents"
    )
    print(f"  findings      {len(result.findings)}")
    print(f"  evidence root {result.evidence_root or '(none)'}")
    print(f"  seed          {result.plan.seed} (replayable)")
    if result.halted:
        print(f"  halted        {result.halted}")

    if result.findings:
        print("\nFindings")
        for finding in sorted(result.findings, key=lambda f: (f.severity.rank, f.confidence), reverse=True):
            print(f"  [{finding.severity.value:8}] {finding.confidence:.2f}  {finding.title}")
            print(f"             {finding.location}")
    else:
        print("\n  no findings")

    print("\nWhy these probes")
    for line in result.plan.explain().splitlines():
        print(f"  {line}")

    print("\nLearning")
    print(f"  hunts={learning.hunts} evolved={learning.evolved} generations={learning.generations}")
    for note in learning.notes:
        print(f"  {note}")
    for row in probe_leaderboard(memory, limit=5):
        print(f"  {row['probe_id']:28} mean_reward={row['mean_reward']:.3f} trials={row['trials']:.1f}")

    print("\nArtifacts")
    for name, path in paths.items():
        print(f"  {name:9} {path}")

    return 0 if not result.halted else 3


def cmd_diff(args: argparse.Namespace) -> int:
    left = json.loads(Path(args.left).read_text(encoding="utf-8"))
    right = json.loads(Path(args.right).read_text(encoding="utf-8"))
    result = diff(left, right)
    print(diff_summary(result))
    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=2), encoding="utf-8")
    return 0


def cmd_memory(args: argparse.Namespace) -> int:
    memory = HuntMemory.load(args.memory)
    print(json.dumps(summarize_memory(memory), indent=2))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    manifest_path = Path(args.manifest)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    signature = str(manifest.get("signature", {}).get("value", ""))
    key = (args.key or "hcvf-development-evidence-key").encode("utf-8")

    ok_signature = verify_manifest(manifest, signature, key)
    entries = manifest.get("entries", [])
    from app.engine.evidence import MerkleTree

    root_ok = False
    if entries:
        tree = MerkleTree([bytes.fromhex(str(entry["digest"])) for entry in entries])
        root_ok = tree.root == manifest.get("root")

    blobs_ok = True
    if args.evidence:
        store = FileEvidenceStore(args.evidence)
        for entry in entries:
            try:
                store.get(str(entry["digest"]))
            except Exception:
                blobs_ok = False
                break

    print(f"signature   {'OK' if ok_signature else 'INVALID'}")
    print(f"merkle root {'OK' if root_ok else 'MISMATCH'}")
    if args.evidence:
        print(f"blobs       {'OK' if blobs_ok else 'MISSING OR CORRUPT'}")
    print(f"leaves      {len(entries)}")
    print(f"root        {manifest.get('root')}")
    return 0 if (ok_signature and root_ok and blobs_ok) else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hcvf", description="HCVF agentic validation engine")
    parser.add_argument("--version", action="version", version=f"hcvf {ENGINE_VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    probes = sub.add_parser("probes", help="list the probe catalog")
    probes.set_defaults(func=cmd_probes)

    hunt = sub.add_parser("hunt", help="plan and execute an authorized hunt")
    hunt.add_argument("--target", required=True, help="absolute http(s) URL in scope")
    hunt.add_argument("--authorized", action="store_true", help="attest you are authorized to test the target")
    hunt.add_argument("--allow-state-changing", action="store_true", help="permit state-changing probes")
    hunt.add_argument("--allow-private", action="store_true", help="permit private/loopback addresses (local testing)")
    hunt.add_argument("--budget", type=int, default=200, help="request budget")
    hunt.add_argument("--seed", type=int, default=7, help="decision seed (replayable)")
    hunt.add_argument("--rps", type=float, default=5.0, help="requests per second ceiling")
    hunt.add_argument("--aggression", type=float, default=0.4, help="planner aggression 0..1")
    hunt.add_argument("--probes", default="", help="comma-separated explicit probe ids")
    hunt.add_argument("--out", default="hcvf-out", help="artifact directory")
    hunt.add_argument("--memory", default="", help="path to persistent memory json")
    hunt.add_argument("--operator", default="cli", help="approver recorded in the grant")
    hunt.set_defaults(func=cmd_hunt)

    diff_cmd = sub.add_parser("diff", help="compare two hunt artifacts")
    diff_cmd.add_argument("--left", required=True)
    diff_cmd.add_argument("--right", required=True)
    diff_cmd.add_argument("--json", default="", help="write the structured diff here")
    diff_cmd.set_defaults(func=cmd_diff)

    memory = sub.add_parser("memory", help="inspect learned state")
    memory.add_argument("--memory", required=True)
    memory.set_defaults(func=cmd_memory)

    verify = sub.add_parser("verify", help="verify an evidence manifest")
    verify.add_argument("--manifest", required=True)
    verify.add_argument("--evidence", default="", help="evidence store directory to check blobs")
    verify.add_argument("--key", default="", help="HMAC key")
    verify.set_defaults(func=cmd_verify)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
