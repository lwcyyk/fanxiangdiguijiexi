from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from resolver_identity.models.endpoint import ResolverEndpoint


ACTIVE = "ACTIVE"
SUSPENDED = "SUSPENDED"
REVOKED = "REVOKED"
EXPIRED = "EXPIRED"
UNKNOWN = "UNKNOWN"


@dataclass(slots=True)
class Operator:
    operator_id: str
    name: str
    trust_domain: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "Operator":
        return cls(data["operator_id"], data["name"], data.get("trust_domain"))

    def to_dict(self) -> dict:
        out = {"operator_id": self.operator_id, "name": self.name, "trust_domain": self.trust_domain}
        return {k: v for k, v in out.items() if v is not None}


@dataclass(slots=True)
class ResolverAuthenticityObjectV1:
    resolver_id: str
    resolver_type: str
    operator: Operator
    endpoints: list[ResolverEndpoint]
    valid_from: str
    valid_until: str
    object_version: int
    issuer: str
    key_id: str
    schema_version: str = "resolver-auth-object-v1"
    canonical_version: int = 1
    status: str = ACTIVE
    attestation: dict[str, Any] = field(default_factory=dict)
    signature: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "ResolverAuthenticityObjectV1":
        return cls(
            schema_version=data.get("schema_version", "resolver-auth-object-v1"),
            canonical_version=int(data.get("canonical_version", 1)),
            resolver_id=data["resolver_id"],
            resolver_type=data.get("resolver_type", "recursive-forwarder"),
            operator=Operator.from_dict(data["operator"]),
            endpoints=[ResolverEndpoint.from_dict(e) for e in data.get("endpoints", [])],
            attestation=dict(data.get("attestation") or {}),
            valid_from=data["valid_from"],
            valid_until=data["valid_until"],
            status=data.get("status", ACTIVE),
            object_version=int(data.get("object_version", 1)),
            issuer=data["issuer"],
            key_id=data["key_id"],
            signature=data.get("signature"),
        )

    def to_dict(self, include_signature: bool = True) -> dict:
        out = {
            "schema_version": self.schema_version,
            "canonical_version": self.canonical_version,
            "resolver_id": self.resolver_id,
            "resolver_type": self.resolver_type,
            "operator": self.operator.to_dict(),
            "endpoints": [e.normalized().to_dict() for e in self.endpoints],
            "attestation": self.attestation,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "status": self.status,
            "object_version": self.object_version,
            "issuer": self.issuer,
            "key_id": self.key_id,
        }
        if include_signature and self.signature is not None:
            out["signature"] = self.signature
        return out
