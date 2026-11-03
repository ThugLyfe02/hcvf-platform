"""Probe registry. Importing this module registers every shipped probe."""

from __future__ import annotations

# Import for side effects: each module registers its probes.
from app.engine.probes import crypto as _crypto  # noqa: F401
from app.engine.probes import discovery as _discovery  # noqa: F401
from app.engine.probes import identity as _identity  # noqa: F401
from app.engine.probes import inputs as _inputs  # noqa: F401
from app.engine.probes import surface as _surface  # noqa: F401
from app.engine.probes import web as _web  # noqa: F401
from app.engine.probes.base import (
    Probe,
    ProbeSpec,
    cost_of,
    default_probe_ids,
    filter_by_safety,
    get_probe,
    models_for,
    register,
    registry,
    safety_of,
    specs,
)

__all__ = [
    "Probe",
    "ProbeSpec",
    "cost_of",
    "default_probe_ids",
    "filter_by_safety",
    "get_probe",
    "models_for",
    "register",
    "registry",
    "safety_of",
    "specs",
]
