from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_address
from urllib.parse import urlparse, urlunparse


@dataclass(slots=True)
class ResolverEndpoint:
    endpoint_id: str | None = None
    ip: str | None = None
    port: int | None = None
    transport: str = "udp"
    uri: str | None = None
    server_name: str | None = None
    alpn: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "ResolverEndpoint":
        return cls(
            endpoint_id=data.get("endpoint_id"),
            ip=data.get("ip"),
            port=data.get("port"),
            transport=(data.get("transport") or "udp").lower(),
            uri=data.get("uri"),
            server_name=data.get("server_name"),
            alpn=list(data.get("alpn") or []),
        ).normalized()

    def normalized(self) -> "ResolverEndpoint":
        ip_norm = canonical_ip(self.ip) if self.ip else None
        server_name = normalize_name(self.server_name) if self.server_name else None
        uri = canonical_uri(self.uri) if self.uri else None
        return ResolverEndpoint(
            endpoint_id=self.endpoint_id,
            ip=ip_norm,
            port=int(self.port) if self.port is not None else default_port(self.transport),
            transport=self.transport.lower(),
            uri=uri,
            server_name=server_name,
            alpn=[a.lower() for a in self.alpn],
        )

    def to_dict(self) -> dict:
        out = {
            "endpoint_id": self.endpoint_id,
            "ip": self.ip,
            "port": self.port,
            "transport": self.transport,
            "uri": self.uri,
            "server_name": self.server_name,
            "alpn": list(self.alpn),
        }
        return {k: v for k, v in out.items() if v is not None and v != []}

    def matches(self, observed: "ResolverEndpoint") -> bool:
        expected = self.normalized()
        observed = observed.normalized()
        if expected.transport != observed.transport:
            return False
        if expected.port != observed.port:
            return False
        if expected.ip and observed.ip and expected.ip != observed.ip:
            return False
        if expected.uri and observed.uri and expected.uri != observed.uri:
            return False
        if expected.server_name and observed.server_name and expected.server_name != observed.server_name:
            return False
        return bool((expected.ip and observed.ip) or (expected.uri and observed.uri) or (expected.server_name and observed.server_name))


def canonical_ip(value: str) -> str:
    return str(ip_address(value.strip()))


def normalize_name(value: str) -> str:
    return value.strip().rstrip(".").lower()


def canonical_uri(value: str) -> str:
    parsed = urlparse(value.strip())
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    return urlunparse((scheme, netloc, path, "", parsed.query, ""))


def default_port(transport: str) -> int:
    return {"udp": 53, "tcp": 53, "dot": 853, "doh": 443, "doq": 853}.get(transport.lower(), 53)
