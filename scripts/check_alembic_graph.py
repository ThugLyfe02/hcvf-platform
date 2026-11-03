#!/usr/bin/env python3
"""Validate the Alembic revision graph without importing Alembic.

A dangling ``down_revision`` broke this repository once: ``alembic upgrade head``
could not resolve ``0002_campaign_cancelled``, so the API container exited on
every fresh volume. This check runs in preflight and CI and needs no database.

Exit codes: 0 = exactly one head and a complete chain; 1 = problem found.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

VERSIONS_DIR = Path(__file__).resolve().parents[1] / "alembic" / "versions"
_ASSIGN = re.compile(r"^(revision|down_revision)\s*(?::\s*[^=]+)?=\s*(.+)$", re.MULTILINE)


def _literal(node: ast.AST):
    try:
        return ast.literal_eval(node)
    except (ValueError, SyntaxError):
        return None


def load_revisions() -> dict[str, str | None]:
    revisions: dict[str, str | None] = {}
    if not VERSIONS_DIR.is_dir():
        print(f"[FAIL] versions directory missing: {VERSIONS_DIR}", file=sys.stderr)
        raise SystemExit(1)

    for path in sorted(VERSIONS_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        values: dict[str, object] = {}
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in {"revision", "down_revision"}:
                        values[target.id] = _literal(node.value)
            elif (
                isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name)
                and node.target.id in {"revision", "down_revision"}
            ):
                values[node.target.id] = _literal(node.value)
        revision = values.get("revision")
        if not isinstance(revision, str):
            print(f"[FAIL] {path.name}: no string revision id", file=sys.stderr)
            raise SystemExit(1)
        if revision in revisions:
            print(f"[FAIL] duplicate revision id {revision!r} in {path.name}", file=sys.stderr)
            raise SystemExit(1)
        if len(revision) > 32:
            print(
                f"[FAIL] revision id {revision!r} is {len(revision)} characters; "
                "alembic's version_num column is VARCHAR(32)",
                file=sys.stderr,
            )
            raise SystemExit(1)
        down = values.get("down_revision")
        revisions[revision] = down if isinstance(down, str) else None
    return revisions


def main() -> int:
    revisions = load_revisions()
    problems: list[str] = []

    dangling = {rid: down for rid, down in revisions.items() if down and down not in revisions}
    for rid, down in dangling.items():
        problems.append(f"{rid} declares a down_revision that does not exist: {down!r}")

    parents = {down for down in revisions.values() if down}
    heads = sorted(set(revisions) - parents)
    if len(heads) != 1:
        problems.append(f"expected exactly one head, found {len(heads)}: {heads}")

    reachable: set[str] = set()
    if heads:
        current: str | None = heads[0]
        while current:
            reachable.add(current)
            current = revisions.get(current)
        unreachable = set(revisions) - reachable
        if unreachable:
            problems.append(f"revisions not reachable from head {heads[0]}: {sorted(unreachable)}")

    print(f"revisions: {len(revisions)} | head: {heads[0] if len(heads) == 1 else heads}")
    for problem in problems:
        print(f"[FAIL] {problem}", file=sys.stderr)
    if problems:
        return 1
    print("HCVF ALEMBIC GRAPH: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
