from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from resolver_identity.crypto.signatures import sign_object, sign_object_ed25519, verify_ed25519_signature, verify_object_signature
from resolver_identity.models.endpoint import ResolverEndpoint


AGENT_SCHEMA_VERSION = "resolver-identity-agent-v1"


@dataclass(slots=True)
class AgentIdentity:
    resolver_id: str
    endpoint: ResolverEndpoint
    upstreams: list[ResolverEndpoint]
    config_version: str
    health: str = "ok"
    issued_at: int = field(default_factory=lambda: int(time.time()))
    expires_at: int | None = None
    issuer: str = "resolver-agent"
    key_id: str = "agent-key-01"
    schema_version: str = AGENT_SCHEMA_VERSION
    signature: str | None = None

    def to_dict(self, include_signature: bool = True) -> dict[str, Any]:
        out = {
            "schema_version": self.schema_version,
            "resolver_id": self.resolver_id,
            "endpoint": self.endpoint.normalized().to_dict(),
            "upstreams": [endpoint.normalized().to_dict() for endpoint in self.upstreams],
            "config_version": str(self.config_version),
            "health": self.health,
            "issued_at": int(self.issued_at),
            "expires_at": int(self.expires_at if self.expires_at is not None else self.issued_at + 30),
            "issuer": self.issuer,
            "key_id": self.key_id,
        }
        if include_signature and self.signature is not None:
            out["signature"] = self.signature
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AgentIdentity":
        return cls(
            schema_version=data.get("schema_version", AGENT_SCHEMA_VERSION),
            resolver_id=data["resolver_id"],
            endpoint=ResolverEndpoint.from_dict(data["endpoint"]),
            upstreams=[ResolverEndpoint.from_dict(item) for item in data.get("upstreams", [])],
            config_version=str(data["config_version"]),
            health=data.get("health", "unknown"),
            issued_at=int(data["issued_at"]),
            expires_at=int(data["expires_at"]),
            issuer=data.get("issuer", "resolver-agent"),
            key_id=data.get("key_id", "agent-key-01"),
            signature=data.get("signature"),
        )


def build_agent_identity(
    resolver_id: str,
    endpoint: ResolverEndpoint,
    upstreams: list[ResolverEndpoint],
    config_version: str,
    signature_secret: str,
    max_age_seconds: int = 30,
    health: str = "ok",
    issuer: str = "resolver-agent",
    key_id: str = "agent-key-01",
) -> dict[str, Any]:
    now = int(time.time())
    identity = AgentIdentity(
        resolver_id=resolver_id,
        endpoint=endpoint,
        upstreams=upstreams,
        config_version=config_version,
        health=health,
        issued_at=now,
        expires_at=now + max_age_seconds,
        issuer=issuer,
        key_id=key_id,
    )
    unsigned = identity.to_dict(include_signature=False)
    identity.signature = sign_object(unsigned, signature_secret)
    return identity.to_dict(include_signature=True)


def build_agent_identity_ed25519(
    resolver_id: str,
    endpoint: ResolverEndpoint,
    upstreams: list[ResolverEndpoint],
    config_version: str,
    private_key_b64: str,
    max_age_seconds: int = 30,
    health: str = "ok",
    issuer: str = "resolver-agent",
    key_id: str = "agent-key-01",
) -> dict[str, Any]:
    now = int(time.time())
    identity = AgentIdentity(
        resolver_id=resolver_id,
        endpoint=endpoint,
        upstreams=upstreams,
        config_version=config_version,
        health=health,
        issued_at=now,
        expires_at=now + max_age_seconds,
        issuer=issuer,
        key_id=key_id,
    )
    unsigned = identity.to_dict(include_signature=False)
    identity.signature = sign_object_ed25519(unsigned, private_key_b64)
    return identity.to_dict(include_signature=True)


def verify_agent_identity_payload(
    payload: dict[str, Any],
    signature_secret: str,
    expected_endpoint: ResolverEndpoint | None = None,
    now: int | None = None,
    max_clock_skew_seconds: int = 5,
) -> AgentIdentity:
    now = int(time.time()) if now is None else int(now)
    if payload.get("schema_version") != AGENT_SCHEMA_VERSION:
        raise ValueError("unsupported agent schema_version")
    if not verify_object_signature(payload, signature_secret):
        raise ValueError("agent signature invalid")
    return _validate_agent_identity_payload(payload, expected_endpoint, now, max_clock_skew_seconds)


def verify_agent_identity_payload_with_public_key(
    payload: dict[str, Any],
    public_key_b64: str,
    expected_endpoint: ResolverEndpoint | None = None,
    now: int | None = None,
    max_clock_skew_seconds: int = 5,
) -> AgentIdentity:
    now = int(time.time()) if now is None else int(now)
    if payload.get("schema_version") != AGENT_SCHEMA_VERSION:
        raise ValueError("unsupported agent schema_version")
    if not verify_ed25519_signature(payload, public_key_b64):
        raise ValueError("agent signature invalid")
    return _validate_agent_identity_payload(payload, expected_endpoint, now, max_clock_skew_seconds)


def _validate_agent_identity_payload(
    payload: dict[str, Any],
    expected_endpoint: ResolverEndpoint | None,
    now: int,
    max_clock_skew_seconds: int,
) -> AgentIdentity:
    identity = AgentIdentity.from_dict(payload)
    if identity.health != "ok":
        raise ValueError("agent health is not ok")
    if identity.issued_at > now + max_clock_skew_seconds:
        raise ValueError("agent response issued_at is in the future")
    if identity.expires_at is None or identity.expires_at < now:
        raise ValueError("agent response expired")
    if expected_endpoint is not None and not identity.endpoint.matches(expected_endpoint):
        raise ValueError("agent endpoint does not match observed resolver")
    return identity
