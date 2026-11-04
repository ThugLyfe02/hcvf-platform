from __future__ import annotations

from urllib.parse import urlsplit

from app.engine.errors import EngineError
from app.engine.types import SafetyClass, ScopeGrant, Target


def parse_target(url: str) -> Target:
    """Parse and normalize a target URL, rejecting anything ambiguous."""

    if not url or "://" not in url:
        raise EngineError(f"target must be an absolute URL, got {url!r}")
    parts = urlsplit(url.strip())
    if parts.scheme not in {"http", "https"}:
        raise EngineError(f"unsupported scheme {parts.scheme!r}")
    if not parts.hostname:
        raise EngineError("target URL has no host")
    if parts.username or parts.password:
        raise EngineError("credentials in target URLs are not permitted")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    return Target(scheme=parts.scheme, host=parts.hostname, port=port, base_path=path)


def build_grant(
    target: Target,
    *,
    safety: SafetyClass = SafetyClass.read_only,
    methods: frozenset[str] | None = None,
    max_rps: float = 5.0,
    approver: str = "operator",
    evidence_sha256: str = "",
    path_prefix: str = "/",
) -> ScopeGrant:
    """Build the narrowest grant that still permits the requested class."""

    if methods is None:
        methods = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
        if safety >= SafetyClass.state_changing:
            methods = methods | {"POST", "PUT", "PATCH", "DELETE"}
    return ScopeGrant(
        origin=target.origin,
        methods=frozenset(methods),
        path_prefix=path_prefix,
        max_safety=safety,
        max_rps=max_rps,
        approver=approver,
        evidence_sha256=evidence_sha256,
    )
