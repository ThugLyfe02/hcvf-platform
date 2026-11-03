"""Compare two hunt artifacts by finding fingerprint."""

from __future__ import annotations

from collections.abc import Iterable


def _fingerprints(payload: dict) -> dict[str, dict]:
    findings = payload.get("findings") or []
    return {str(item.get("fingerprint", "")): item for item in findings if item.get("fingerprint")}


def diff(left: dict, right: dict) -> dict[str, object]:
    before = _fingerprints(left)
    after = _fingerprints(right)
    new = sorted(set(after) - set(before))
    fixed = sorted(set(before) - set(after))
    recurring = sorted(set(before) & set(after))
    return {
        "left": {"target": left.get("target"), "findings": len(before)},
        "right": {"target": right.get("target"), "findings": len(after)},
        "new": [after[key] for key in new],
        "fixed": [before[key] for key in fixed],
        "recurring": [after[key] for key in recurring],
        "counts": {"new": len(new), "fixed": len(fixed), "recurring": len(recurring)},
    }


def summary(result: dict[str, object], limit: int = 10) -> str:
    counts = result["counts"]
    lines = [
        f"Compared {result['left']['target']} ({result['left']['findings']} findings) with "
        f"{result['right']['target']} ({result['right']['findings']} findings)",
        f"new={counts['new']} fixed={counts['fixed']} recurring={counts['recurring']}",
    ]
    for label in ("new", "fixed"):
        items: Iterable[dict] = result[label]  # type: ignore[assignment]
        for item in list(items)[:limit]:
            lines.append(
                f"  [{label}] {item.get('severity', '?')}: {item.get('title', '')} ({item.get('location', '')})"
            )
    return "\n".join(lines)
