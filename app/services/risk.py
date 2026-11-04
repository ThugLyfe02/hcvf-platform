from __future__ import annotations

import math
from collections.abc import Iterable

SEVERITY_WEIGHTS = {"critical": 12.0, "high": 7.0, "medium": 3.0, "low": 1.0, "info": 0.2}


def score(findings: Iterable[tuple[str, float]]) -> float:
    """Composite risk 0-100 with diminishing returns.

    Ten medium findings should not read as ten times one medium finding: a log
    curve keeps the number comparable across hunts while still ranking severity
    correctly.
    """

    total = 0.0
    for severity, confidence in findings:
        weight = SEVERITY_WEIGHTS.get(str(severity).lower(), 0.0)
        total += weight * max(0.0, min(1.0, float(confidence)))
    if total <= 0:
        return 0.0
    return round(min(100.0, 10.0 * math.log2(1.0 + total)), 2)


def band(value: float) -> str:
    if value >= 70:
        return "critical"
    if value >= 45:
        return "high"
    if value >= 20:
        return "medium"
    if value > 0:
        return "low"
    return "none"
