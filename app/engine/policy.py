from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field

from app.engine.errors import EgressDenied

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

#: Hostnames that resolve to cloud metadata services. Blocked by name *and* by
#: address, because either layer can be bypassed on its own.
_DENIED_HOSTNAMES = frozenset(
    {
        "metadata",
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",
        "instance-data.ec2.internal",
        "169.254.169.254",
        "fd00:ec2::254",
    }
)

_DENIED_NETWORKS: tuple[IPNetwork, ...] = (
    ipaddress.ip_network("169.254.0.0/16"),  # link-local + AWS/GCP/Azure metadata
    ipaddress.ip_network("fd00:ec2::/32"),  # AWS IMDSv2 IPv6
    ipaddress.ip_network("100.64.0.0/10"),  # carrier-grade NAT
    ipaddress.ip_network("192.0.0.0/24"),  # IETF protocol assignments
    ipaddress.ip_network("198.18.0.0/15"),  # benchmarking
    ipaddress.ip_network("240.0.0.0/4"),  # reserved
)

_PRIVATE_NETWORKS: tuple[IPNetwork, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)

#: Ports that are never valid HTTP(S) validation targets. Prevents a typo'd
#: scope grant from turning a web scanner into a database prober.
_DEFAULT_BLOCKED_PORTS = frozenset(
    {22, 23, 25, 110, 143, 465, 587, 993, 995, 3306, 5432, 6379, 9042, 9200, 11211, 27017}
)


def normalize_host(host: str) -> str:
    """Lowercase, strip a trailing dot and any IPv6 zone index."""

    return host.strip().rstrip(".").split("%", 1)[0].lower()


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _as_ip(value: str) -> IPAddress:
    ip = ipaddress.ip_address(value)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


@dataclass(frozen=True)
class EgressPolicy:
    """Deny-by-default destination policy for validation traffic.

    Two independent layers, because DNS is attacker-influenced:
      1. name layer — refuse known metadata hostnames outright;
      2. address layer — resolve, classify, and connect to a *validated* address.
    The HTTP client is expected to connect to the address returned by
    :meth:`validate`, never to re-resolve the hostname itself. That closes the
    DNS-rebinding window.
    """

    allow_private: bool = False
    allow_metadata: bool = False
    blocked_ports: frozenset[int] = field(default=_DEFAULT_BLOCKED_PORTS)
    resolver: object | None = None

    # -- classification -------------------------------------------------
    def classify(self, address: str) -> str:
        ip = _as_ip(address)
        if self.allow_metadata is False and any(ip in net for net in _DENIED_NETWORKS if net.version == ip.version):
            return "metadata-or-reserved"
        for net in _PRIVATE_NETWORKS:
            if net.version == ip.version and ip in net:
                return "private"
        if ip.is_multicast:
            return "multicast"
        if ip.is_unspecified:
            return "unspecified"
        return "public"

    def is_blocked(self, address: str) -> bool:
        kind = self.classify(address)
        if kind in {"multicast", "unspecified", "metadata-or-reserved"}:
            return True
        return kind == "private" and not self.allow_private

    # -- validation -----------------------------------------------------
    def validate_hostname(self, host: str) -> str:
        normalized = normalize_host(host)
        if not normalized:
            raise EgressDenied("empty hostname")
        if normalized in _DENIED_HOSTNAMES:
            raise EgressDenied(f"hostname {normalized!r} is a denied metadata endpoint")
        return normalized

    def validate_port(self, port: int) -> None:
        if port < 1 or port > 65535:
            raise EgressDenied(f"invalid port {port}")
        if port in self.blocked_ports:
            raise EgressDenied(f"port {port} is blocked for validation traffic")

    def resolve(self, host: str) -> list[str]:
        """Resolve a hostname to unique, ordered addresses (IPv4 first)."""

        normalized = self.validate_hostname(host)
        if _is_ip_literal(normalized):
            return [normalized]
        if self.resolver is not None:  # injected in tests
            return list(self.resolver(normalized))  # type: ignore[operator]
        try:
            infos = socket.getaddrinfo(normalized, None, proto=socket.IPPROTO_TCP)
        except OSError as exc:
            raise EgressDenied(f"resolution failed for {normalized}: {exc}") from exc
        addresses: list[str] = []
        for info in infos:
            address = str(info[4][0])
            if address not in addresses:
                addresses.append(address)
        addresses.sort(key=lambda a: 0 if ":" not in a else 1)
        return addresses

    def validate(self, host: str, port: int) -> list[str]:
        """Return the addresses that may legally be connected to, or raise."""

        self.validate_port(port)
        addresses = self.resolve(host)
        if not addresses:
            raise EgressDenied(f"no addresses for {host!r}")
        allowed = [a for a in addresses if not self.is_blocked(a)]
        if not allowed:
            blocked_kinds = ", ".join(sorted({self.classify(a) for a in addresses}))
            raise EgressDenied(f"all addresses for {host!r} are blocked ({blocked_kinds})")
        return allowed


def describe_denial(exc: EgressDenied) -> str:
    return f"egress denied: {exc}"
