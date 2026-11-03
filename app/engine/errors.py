from __future__ import annotations


class EngineError(RuntimeError):
    """Base class for all engine failures."""


class ScopeViolation(EngineError):
    """The request was not covered by an active scope grant."""


class EgressDenied(EngineError):
    """The destination is not permitted by the egress policy (SSRF guard)."""


class BudgetExceeded(EngineError):
    """The hunt ran out of an allocated resource."""


class HuntHalted(EngineError):
    """The kill switch was engaged."""


class TransportError(EngineError):
    """The target could not be reached."""


class ProbeError(EngineError):
    """A probe failed in a way that should be recorded but not fatal."""


class EvidenceError(EngineError):
    """Evidence could not be sealed or verified."""
