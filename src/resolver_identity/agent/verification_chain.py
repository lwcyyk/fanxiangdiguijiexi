from __future__ import annotations

import time
from dataclasses import dataclass, field
from copy import deepcopy
from typing import Any

from resolver_identity.admin.publisher import endpoint_lookup_key
from resolver_identity.crypto.hashes import resolver_id_key
from resolver_identity.crypto.signatures import sign_object_ed25519, verify_ed25519_signature
from resolver_identity.models.endpoint import ResolverEndpoint
from resolver_identity.models.verification import VerificationResult


HOP_VERIFICATION_SCHEMA_VERSION = "resolver-identity-hop-verification-v1"
VERIFICATION_CHAIN_SCHEMA_VERSION = "resolver-identity-verification-chain-v1"


@dataclass(slots=True)
class HopVerificationResult:
    from_resolver_id: str
    from_endpoint: ResolverEndpoint
    upstream_endpoint: ResolverEndpoint
    accepted: bool
    status: str
    upstream_resolver_id: str | None = None
    reasons: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    issued_at: int = field(default_factory=lambda: int(time.time()))
    expires_at: int | None = None
    issuer: str = "resolver-agent"
    key_id: str = "agent-key-01"
    schema_version: str = HOP_VERIFICATION_SCHEMA_VERSION
    signature: str | None = None

    @classmethod
    def from_verification_result(
        cls,
        from_resolver_id: str,
        from_endpoint: ResolverEndpoint,
        upstream_endpoint: ResolverEndpoint,
        verification: VerificationResult,
        max_age_seconds: int = 30,
        issuer: str = "resolver-agent",
        key_id: str = "agent-key-01",
    ) -> "HopVerificationResult":
        now = int(time.time())
        return cls(
            from_resolver_id=from_resolver_id,
            from_endpoint=from_endpoint.normalized(),
            upstream_endpoint=upstream_endpoint.normalized(),
            upstream_resolver_id=verification.resolver_id,
            accepted=verification.accepted,
            status=verification.status,
            reasons=list(verification.reasons),
            evidence=normalize_hop_evidence(
                verification.evidence,
                from_resolver_id=from_resolver_id,
                upstream_resolver_id=verification.resolver_id,
                upstream_endpoint=upstream_endpoint,
                accepted=verification.accepted,
                status=verification.status,
                reasons=verification.reasons,
                issued_at=now,
                expires_at=now + max_age_seconds,
                issuer=issuer,
                key_id=key_id,
            ),
            issued_at=now,
            expires_at=now + max_age_seconds,
            issuer=issuer,
            key_id=key_id,
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "HopVerificationResult":
        return cls(
            schema_version=data.get("schema_version", HOP_VERIFICATION_SCHEMA_VERSION),
            from_resolver_id=data["from_resolver_id"],
            from_endpoint=ResolverEndpoint.from_dict(data["from_endpoint"]),
            upstream_endpoint=ResolverEndpoint.from_dict(data["upstream_endpoint"]),
            upstream_resolver_id=data.get("upstream_resolver_id"),
            accepted=bool(data["accepted"]),
            status=data["status"],
            reasons=list(data.get("reasons") or []),
            evidence=dict(data.get("evidence") or {}),
            issued_at=int(data["issued_at"]),
            expires_at=int(data["expires_at"]) if data.get("expires_at") is not None else None,
            issuer=data.get("issuer", "resolver-agent"),
            key_id=data.get("key_id", "agent-key-01"),
            signature=data.get("signature"),
        )

    def to_dict(self, include_signature: bool = True) -> dict[str, Any]:
        out = {
            "schema_version": self.schema_version,
            "from_resolver_id": self.from_resolver_id,
            "from_endpoint": self.from_endpoint.normalized().to_dict(),
            "upstream_endpoint": self.upstream_endpoint.normalized().to_dict(),
            "upstream_resolver_id": self.upstream_resolver_id,
            "accepted": bool(self.accepted),
            "status": self.status,
            "reasons": list(self.reasons),
            "evidence": dict(self.evidence),
            "issued_at": int(self.issued_at),
            "expires_at": int(self.expires_at if self.expires_at is not None else self.issued_at + 30),
            "issuer": self.issuer,
            "key_id": self.key_id,
        }
        if include_signature and self.signature is not None:
            out["signature"] = self.signature
        return out

    def to_verification_result(self) -> VerificationResult:
        if self.accepted:
            return VerificationResult.accept(self.upstream_resolver_id or "", status=self.status, **self.evidence)
        reason = self.reasons[0] if self.reasons else "hop_verification_failed"
        return VerificationResult.reject(reason, self.upstream_resolver_id, **self.evidence)


@dataclass(slots=True)
class VerificationChain:
    resolver_id: str
    endpoint: ResolverEndpoint
    config_version: str
    challenge: str | None = None
    hops: list[HopVerificationResult] = field(default_factory=list)
    downstream_chains: list["VerificationChain"] = field(default_factory=list)
    terminal_upstreams: list[ResolverEndpoint] = field(default_factory=list)
    chain_errors: list[str] = field(default_factory=list)
    final_result: bool = True
    issued_at: int = field(default_factory=lambda: int(time.time()))
    expires_at: int | None = None
    issuer: str = "resolver-agent"
    key_id: str = "agent-key-01"
    schema_version: str = VERIFICATION_CHAIN_SCHEMA_VERSION
    signature: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VerificationChain":
        return cls(
            schema_version=data.get("schema_version", VERIFICATION_CHAIN_SCHEMA_VERSION),
            resolver_id=data["resolver_id"],
            endpoint=ResolverEndpoint.from_dict(data["endpoint"]),
            config_version=str(data["config_version"]),
            challenge=data.get("challenge"),
            hops=[HopVerificationResult.from_dict(item) for item in data.get("hops", [])],
            downstream_chains=[VerificationChain.from_dict(item) for item in data.get("downstream_chains", [])],
            terminal_upstreams=[ResolverEndpoint.from_dict(item) for item in data.get("terminal_upstreams", [])],
            chain_errors=list(data.get("chain_errors") or []),
            final_result=bool(data.get("final_result", False)),
            issued_at=int(data["issued_at"]),
            expires_at=int(data["expires_at"]) if data.get("expires_at") is not None else None,
            issuer=data.get("issuer", "resolver-agent"),
            key_id=data.get("key_id", "agent-key-01"),
            signature=data.get("signature"),
        )

    def to_dict(self, include_signature: bool = True) -> dict[str, Any]:
        out = {
            "schema_version": self.schema_version,
            "resolver_id": self.resolver_id,
            "endpoint": self.endpoint.normalized().to_dict(),
            "config_version": str(self.config_version),
            "challenge": self.challenge,
            "hops": [hop.to_dict(include_signature=True) for hop in self.hops],
            "downstream_chains": [chain.to_dict(include_signature=True) for chain in self.downstream_chains],
            "terminal_upstreams": [endpoint.normalized().to_dict() for endpoint in self.terminal_upstreams],
            "chain_errors": list(self.chain_errors),
            "final_result": bool(self.final_result),
            "issued_at": int(self.issued_at),
            "expires_at": int(self.expires_at if self.expires_at is not None else self.issued_at + 30),
            "issuer": self.issuer,
            "key_id": self.key_id,
        }
        if include_signature and self.signature is not None:
            out["signature"] = self.signature
        return out


def validate_verification_chain_semantics(chain: VerificationChain, max_nodes: int = 64) -> None:
    state = {"nodes": 0}
    _validate_chain_node_semantics(chain, state, max_nodes)


def _validate_chain_node_semantics(chain: VerificationChain, state: dict[str, int], max_nodes: int) -> bool:
    state["nodes"] += 1
    if state["nodes"] > max_nodes:
        raise ValueError("verification chain exceeds maximum node count")

    hop_keys: set[tuple[str | None, str]] = set()
    accepted_by_resolver: dict[str, HopVerificationResult] = {}
    effective = not chain.chain_errors
    for hop in chain.hops:
        if hop.from_resolver_id != chain.resolver_id or not hop.from_endpoint.matches(chain.endpoint):
            raise ValueError("hop signer does not match enclosing chain")
        key = (hop.upstream_resolver_id, endpoint_lookup_key(hop.upstream_endpoint))
        if key in hop_keys:
            raise ValueError("duplicate verification hop")
        hop_keys.add(key)
        if not hop.accepted:
            effective = False
            continue
        if not hop.upstream_resolver_id:
            raise ValueError("accepted hop missing upstream resolver_id")
        if hop.upstream_resolver_id in accepted_by_resolver:
            raise ValueError("duplicate accepted upstream resolver_id")
        accepted_by_resolver[hop.upstream_resolver_id] = hop

    terminal_keys: set[str] = set()
    for terminal in chain.terminal_upstreams:
        terminal_key = endpoint_lookup_key(terminal)
        if terminal_key in terminal_keys:
            raise ValueError("duplicate terminal upstream")
        terminal_keys.add(terminal_key)
        if any(endpoint_lookup_key(hop.upstream_endpoint) == terminal_key for hop in chain.hops):
            raise ValueError("terminal upstream overlaps resolver hop")
        if any(endpoint_lookup_key(downstream.endpoint) == terminal_key for downstream in chain.downstream_chains):
            raise ValueError("terminal upstream overlaps downstream chain")

    consumed: set[str] = set()
    for downstream in chain.downstream_chains:
        if downstream.challenge != chain.challenge:
            raise ValueError("downstream chain challenge mismatch")
        if downstream.resolver_id in consumed:
            raise ValueError("duplicate downstream chain")
        parent_hop = accepted_by_resolver.get(downstream.resolver_id)
        if parent_hop is None:
            raise ValueError("downstream chain lacks accepted parent hop")
        if not downstream.endpoint.matches(parent_hop.upstream_endpoint):
            raise ValueError("downstream chain endpoint does not match parent hop")
        consumed.add(downstream.resolver_id)
        if not _validate_chain_node_semantics(downstream, state, max_nodes):
            effective = False

    for resolver_id, hop in accepted_by_resolver.items():
        if hop.evidence.get("agent_public_key") and resolver_id not in consumed:
            raise ValueError("Agent-capable resolver hop missing downstream chain")

    if bool(chain.final_result) != bool(effective):
        raise ValueError("verification chain final_result is inconsistent")
    return effective


def normalize_hop_evidence(
    evidence: dict[str, Any],
    *,
    from_resolver_id: str,
    upstream_resolver_id: str | None,
    upstream_endpoint: ResolverEndpoint,
    accepted: bool,
    status: str,
    reasons: list[str],
    issued_at: int,
    expires_at: int,
    issuer: str,
    key_id: str,
) -> dict[str, Any]:
    out = deepcopy(evidence)
    out.setdefault("from_resolver_id", from_resolver_id)
    out.setdefault("upstream_resolver_id", upstream_resolver_id)
    out.setdefault("upstream_endpoint", upstream_endpoint.normalized().to_dict())
    out.setdefault("upstream_type", "recursive_or_forwarder")
    out.setdefault("verification_result", "VERIFIED" if accepted else "REJECTED")
    out.setdefault("resolver_status", out.get("chain_status", status))
    out.setdefault("root_status", out.get("root_status", "ACTIVE" if accepted else None))
    out.setdefault("endpoint_binding_status", out.get("endpoint_binding_status", "MATCHED" if accepted else None))
    out.setdefault("issuer", issuer)
    out.setdefault("key_id", key_id)
    out.setdefault("checked_at", issued_at)
    out.setdefault("expires_at", expires_at)
    out.setdefault("config_version", out.get("object_version"))
    out.setdefault("verifier_agent_id", from_resolver_id)
    out.setdefault("hop_status", status)
    out.setdefault("hop_accepted", accepted)
    out.setdefault("hop_reasons", list(reasons))
    return out


def validate_hop_evidence_integrity(hop: HopVerificationResult) -> None:
    evidence = hop.evidence or {}
    if evidence.get("from_resolver_id") not in (None, hop.from_resolver_id):
        raise ValueError("hop evidence from_resolver_id mismatch")
    if evidence.get("upstream_resolver_id") not in (None, hop.upstream_resolver_id):
        raise ValueError("hop evidence upstream_resolver_id mismatch")
    endpoint_data = evidence.get("upstream_endpoint")
    if endpoint_data is not None and not ResolverEndpoint.from_dict(endpoint_data).matches(hop.upstream_endpoint):
        raise ValueError("hop evidence upstream_endpoint mismatch")
    if evidence.get("verification_result") not in (None, "VERIFIED" if hop.accepted else "REJECTED"):
        raise ValueError("hop evidence verification_result mismatch")
    if hop.accepted:
        upstream_type = evidence.get("upstream_type")
        if upstream_type in ("terminal", "terminal_upstream", "authoritative", "authoritative_boundary", "external", "external_boundary"):
            raise ValueError("terminal boundary must not appear as verified resolver hop")
        if evidence.get("object_hash") in (None, ""):
            raise ValueError("hop evidence missing object_hash")
        if evidence.get("object_version") is None:
            raise ValueError("hop evidence missing object_version")
        if evidence.get("state_root") in (None, ""):
            raise ValueError("hop evidence missing state_root")
        if evidence.get("resolver_status") not in ("ACTIVE", None):
            raise ValueError("hop evidence resolver_status is not ACTIVE")
        if evidence.get("root_status") not in ("ACTIVE", None):
            raise ValueError("hop evidence root_status is not ACTIVE")
        if evidence.get("endpoint_binding_status") not in ("MATCHED", None):
            raise ValueError("hop evidence endpoint binding is not matched")
        expected_rid_key = resolver_id_key(hop.upstream_resolver_id) if hop.upstream_resolver_id else None
        if expected_rid_key and evidence.get("resolver_id_key") not in (None, expected_rid_key):
            raise ValueError("hop evidence resolver_id_key mismatch")
        expected_endpoint_key = endpoint_lookup_key(hop.upstream_endpoint)
        if evidence.get("endpoint_key") not in (None, expected_endpoint_key):
            raise ValueError("hop evidence endpoint_key mismatch")
    if evidence.get("checked_at") is not None and int(evidence["checked_at"]) > int(hop.issued_at):
        raise ValueError("hop evidence checked_at is after hop issued_at")
    if evidence.get("expires_at") is not None and int(evidence["expires_at"]) != int(hop.expires_at or 0):
        raise ValueError("hop evidence expires_at mismatch")
    if evidence.get("verifier_agent_id") not in (None, hop.from_resolver_id):
        raise ValueError("hop evidence verifier_agent_id mismatch")


def sign_hop_verification_result(hop: HopVerificationResult, private_key_b64: str) -> dict[str, Any]:
    unsigned = hop.to_dict(include_signature=False)
    hop.signature = sign_object_ed25519(unsigned, private_key_b64)
    return hop.to_dict(include_signature=True)


def sign_verification_chain(chain: VerificationChain, private_key_b64: str) -> dict[str, Any]:
    unsigned = chain.to_dict(include_signature=False)
    chain.signature = sign_object_ed25519(unsigned, private_key_b64)
    return chain.to_dict(include_signature=True)


def verify_hop_verification_result_payload(
    payload: dict[str, Any],
    public_key_b64: str,
    expected_from_resolver_id: str | None = None,
    expected_from_endpoint: ResolverEndpoint | None = None,
    now: int | None = None,
    max_clock_skew_seconds: int = 5,
) -> HopVerificationResult:
    now = int(time.time()) if now is None else int(now)
    if payload.get("schema_version") != HOP_VERIFICATION_SCHEMA_VERSION:
        raise ValueError("unsupported hop verification schema_version")
    if not verify_ed25519_signature(payload, public_key_b64):
        raise ValueError("hop verification signature invalid")
    hop = HopVerificationResult.from_dict(payload)
    _validate_signed_window(hop.issued_at, hop.expires_at, now, max_clock_skew_seconds, "hop verification")
    if expected_from_resolver_id is not None and hop.from_resolver_id != expected_from_resolver_id:
        raise ValueError("hop verification signer resolver_id mismatch")
    if expected_from_endpoint is not None and not hop.from_endpoint.matches(expected_from_endpoint):
        raise ValueError("hop verification signer endpoint mismatch")
    validate_hop_evidence_integrity(hop)
    return hop


def verify_verification_chain_payload(
    payload: dict[str, Any],
    public_key_b64: str,
    expected_resolver_id: str | None = None,
    expected_endpoint: ResolverEndpoint | None = None,
    now: int | None = None,
    max_clock_skew_seconds: int = 5,
    expected_challenge: str | None = None,
) -> VerificationChain:
    now = int(time.time()) if now is None else int(now)
    if payload.get("schema_version") != VERIFICATION_CHAIN_SCHEMA_VERSION:
        raise ValueError("unsupported verification chain schema_version")
    if not verify_ed25519_signature(payload, public_key_b64):
        raise ValueError("verification chain signature invalid")
    chain = VerificationChain.from_dict(payload)
    _validate_signed_window(chain.issued_at, chain.expires_at, now, max_clock_skew_seconds, "verification chain")
    if expected_resolver_id is not None and chain.resolver_id != expected_resolver_id:
        raise ValueError("verification chain resolver_id mismatch")
    if expected_endpoint is not None and not chain.endpoint.matches(expected_endpoint):
        raise ValueError("verification chain endpoint mismatch")
    if expected_challenge is not None and chain.challenge != expected_challenge:
        raise ValueError("verification chain challenge mismatch")
    validate_verification_chain_semantics(chain)
    return chain


def _validate_signed_window(issued_at: int, expires_at: int | None, now: int, max_clock_skew_seconds: int, label: str) -> None:
    if issued_at > now + max_clock_skew_seconds:
        raise ValueError(f"{label} issued_at is in the future")
    if expires_at is None or expires_at < now:
        raise ValueError(f"{label} expired")
