from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass

from app.engine.bayes import ProbeModel, VulnClass
from app.engine.types import (
    Cost,
    Endpoint,
    FindingDraft,
    HttpRequest,
    HttpResponse,
    Observation,
    ProbeContext,
    ProbeOutcome,
    SafetyClass,
    Severity,
)


@dataclass(frozen=True)
class ProbeSpec:
    id: str
    name: str
    safety: SafetyClass
    targets: tuple[VulnClass, ...]
    cost: Cost
    description: str
    cwe: str = ""
    remediation: str = ""
    default_enabled: bool = True
    sensitivity: float = 0.85
    false_positive_rate: float = 0.05

    def model(self) -> ProbeModel:
        return ProbeModel(
            probe_id=self.id,
            targets=self.targets,
            sensitivity=self.sensitivity,
            false_positive_rate=self.false_positive_rate,
        )


class Probe(ABC):
    spec: ProbeSpec

    @abstractmethod
    def run(self, ctx: ProbeContext) -> ProbeOutcome: ...

    # -- helpers ---------------------------------------------------------
    def observe(
        self,
        ctx: ProbeContext,
        response: HttpResponse,
        *,
        method: str = "GET",
        url: str | None = None,
        headers: Sequence[tuple[str, str]] | None = None,
        body: bytes = b"",
        note: str = "",
    ) -> Observation:
        return Observation(
            probe_id=self.spec.id,
            request=HttpRequest(method=method, url=url or response.url, headers=tuple(headers or ()), body=body),
            response=response,
            note=note,
        )

    def finding(
        self,
        *,
        kind: str,
        title: str,
        detail: str,
        severity: Severity,
        confidence: float,
        location: str = "",
        remediation: str | None = None,
        cwe: str | None = None,
        tags: Sequence[str] = (),
    ) -> FindingDraft:
        return FindingDraft(
            probe_id=self.spec.id,
            kind=kind,
            title=title,
            detail=detail,
            severity=severity,
            confidence=confidence,
            cwe=cwe if cwe is not None else self.spec.cwe,
            remediation=remediation if remediation is not None else self.spec.remediation,
            location=location,
            tags=tuple(tags),
        )

    def endpoint(
        self,
        url: str,
        *,
        method: str = "GET",
        response: HttpResponse | None = None,
        value: float = 0.0,
        source: str = "",
        title: str = "",
    ) -> Endpoint:
        from app.engine.graph import endpoint_value

        return Endpoint(
            url=url,
            method=method,
            status=response.status if response else None,
            content_type=(response.header("content-type") or "") if response else "",
            value=value or endpoint_value(url, status=response.status if response else None),
            source=source,
            title=title,
        )


Registry = dict[str, type[Probe]]
_REGISTRY: Registry = {}


def register(probe_cls: type[Probe]) -> type[Probe]:
    probe_id = probe_cls.spec.id
    if probe_id in _REGISTRY:
        raise RuntimeError(f"duplicate probe id: {probe_id}")
    _REGISTRY[probe_id] = probe_cls
    return probe_cls


def registry() -> Registry:
    return dict(_REGISTRY)


def get_probe(probe_id: str) -> Probe:
    try:
        return _REGISTRY[probe_id]()
    except KeyError as exc:
        raise KeyError(f"unknown probe: {probe_id}") from exc


def specs() -> list[ProbeSpec]:
    return sorted((cls.spec for cls in _REGISTRY.values()), key=lambda spec: spec.id)


def default_probe_ids() -> list[str]:
    return [spec.id for spec in specs() if spec.default_enabled]


def models_for(probe_ids: list[str]) -> list[ProbeModel]:
    return [_REGISTRY[pid].spec.model() for pid in probe_ids if pid in _REGISTRY]


def cost_of(probe_id: str) -> Cost:
    return _REGISTRY[probe_id].spec.cost


def safety_of(probe_id: str) -> SafetyClass:
    return _REGISTRY[probe_id].spec.safety


def filter_by_safety(probe_ids: list[str], ceiling: SafetyClass) -> list[str]:
    return [pid for pid in probe_ids if pid in _REGISTRY and _REGISTRY[pid].spec.safety.allowed_by(ceiling)]
