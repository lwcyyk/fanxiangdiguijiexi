from __future__ import annotations

from resolver_identity.models.endpoint import ResolverEndpoint


def first_hop_observed_resolver(ip: str, port: int = 53, transport: str = "udp") -> list[ResolverEndpoint]:
    return [ResolverEndpoint(ip=ip, port=port, transport=transport).normalized()]


def observed_resolvers_from_agent_payload(payload: dict) -> list[ResolverEndpoint]:
    return [ResolverEndpoint.from_dict(item).normalized() for item in payload.get("observed_resolvers", [])]
