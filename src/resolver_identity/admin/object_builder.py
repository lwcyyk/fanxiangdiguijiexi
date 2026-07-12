from __future__ import annotations

from resolver_identity.models.authenticity_object import Operator, ResolverAuthenticityObjectV1
from resolver_identity.models.endpoint import ResolverEndpoint


def build_resolver_object(
    resolver_id: str,
    operator_id: str,
    operator_name: str,
    endpoints: list[dict],
    valid_from: str,
    valid_until: str,
    issuer: str = "resolver-trust-authority-01",
    key_id: str = "issuer-key-01",
    object_version: int = 1,
    status: str = "ACTIVE",
    agent_public_key_b64: str | None = None,
    agent_key_id: str = "agent-key-01",
) -> ResolverAuthenticityObjectV1:
    attestation = {"type": "operator-signature", "value": "prototype"}
    if agent_public_key_b64:
        attestation["agent"] = {"algorithm": "ed25519", "public_key": agent_public_key_b64, "key_id": agent_key_id}
    return ResolverAuthenticityObjectV1(
        resolver_id=resolver_id,
        resolver_type="recursive-forwarder",
        operator=Operator(operator_id=operator_id, name=operator_name, trust_domain=f"{operator_id}.example"),
        endpoints=[ResolverEndpoint.from_dict(e) for e in endpoints],
        attestation=attestation,
        valid_from=valid_from,
        valid_until=valid_until,
        status=status,
        object_version=object_version,
        issuer=issuer,
        key_id=key_id,
    )
