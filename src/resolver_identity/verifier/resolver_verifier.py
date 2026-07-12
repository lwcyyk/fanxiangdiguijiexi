from __future__ import annotations

import json

from resolver_identity.admin.publisher import endpoint_lookup_key
from resolver_identity.chain.registry_client import SQLiteRegistryClient
from resolver_identity.common.time import parse_rfc3339, utc_now
from resolver_identity.crypto.hashes import object_hash, resolver_id_key
from resolver_identity.crypto.keys import IssuerKeyRegistry
from resolver_identity.crypto.merkle import merkle_leaf
from resolver_identity.crypto.signatures import verify_object_signature_with_registry
from resolver_identity.db.repositories import IndexerRepository
from resolver_identity.models.authenticity_object import ResolverAuthenticityObjectV1
from resolver_identity.models.endpoint import ResolverEndpoint
from resolver_identity.models.verification import VerificationResult
from resolver_identity.verifier.cache_manager import CacheManager
from resolver_identity.verifier.policy import VerificationPolicy
from resolver_identity.verifier.proof_verifier import ProofVerifier


class ResolverVerifier:
    def __init__(self, indexer: IndexerRepository, registry: SQLiteRegistryClient, cache: CacheManager, policy: VerificationPolicy, signature_secret: str, issuer_keys: IssuerKeyRegistry | None = None, allow_hmac_signatures: bool = True):
        self.indexer = indexer
        self.registry = registry
        self.cache = cache
        self.policy = policy
        self.signature_secret = signature_secret
        self.issuer_keys = issuer_keys
        self.allow_hmac_signatures = allow_hmac_signatures
        self.proofs = ProofVerifier()

    def verify_endpoint(self, endpoint: ResolverEndpoint) -> VerificationResult:
        now = utc_now()
        endpoint = endpoint.normalized()
        cache_key = endpoint_lookup_key(endpoint)
        cached = self.cache.get_valid(cache_key, endpoint, now)
        if cached:
            return cached
        generation = self.cache.current_generation()
        try:
            return self._verify_cold(endpoint, cache_key, now, generation)
        except Exception as exc:
            # Out-of-band services are intentionally fail-closed after cache miss
            # or hard TTL expiry. A valid hot cache would already have returned.
            return VerificationResult.reject("out_of_band_unavailable", endpoint_key=cache_key, error=str(exc))

    def refresh_endpoint(self, endpoint: ResolverEndpoint) -> VerificationResult:
        endpoint = endpoint.normalized()
        cache_key = endpoint_lookup_key(endpoint)
        generation = self.cache.current_generation()
        try:
            return self._verify_cold(endpoint, cache_key, utc_now(), generation)
        except Exception as exc:
            return VerificationResult.reject("out_of_band_unavailable", endpoint_key=cache_key, error=str(exc))

    def _verify_cold(self, endpoint: ResolverEndpoint, cache_key: str, now, expected_generation: int) -> VerificationResult:
        lookup = self.indexer.lookup(cache_key)
        if not lookup:
            return VerificationResult.reject("lookup_not_found", evidence={"endpoint_key": cache_key})
        rid_key = lookup["resolver_id_key"]
        bound = self.registry.get_endpoint_binding(cache_key)
        if bound != rid_key:
            return VerificationResult.reject("endpoint_binding_mismatch", lookup.get("resolver_id"), endpoint_key=cache_key, bound=bound, expected=rid_key)
        anchor = self.registry.get_anchor(rid_key)
        if not anchor:
            return VerificationResult.reject("chain_anchor_not_found", lookup.get("resolver_id"))
        if anchor.status != "ACTIVE":
            return VerificationResult.reject("chain_status_not_active", lookup.get("resolver_id"), chain_status=anchor.status)
        row = self.indexer.get_resolver(lookup["resolver_id"])
        if not row:
            return VerificationResult.reject("resolver_object_not_found", lookup.get("resolver_id"))
        obj_dict = json.loads(row["object_json"])
        obj = ResolverAuthenticityObjectV1.from_dict(obj_dict)
        local_hash = object_hash(obj_dict)
        if local_hash != row["object_hash"]:
            return VerificationResult.reject("indexer_object_hash_metadata_mismatch", obj.resolver_id, local_hash=local_hash, indexer_hash=row["object_hash"])
        if local_hash != anchor.object_hash:
            return VerificationResult.reject("chain_object_hash_mismatch", obj.resolver_id, local_hash=local_hash, chain_hash=anchor.object_hash)
        if obj.object_version != anchor.object_version:
            return VerificationResult.reject("object_version_mismatch", obj.resolver_id, object_version=obj.object_version, chain_version=anchor.object_version)
        if resolver_id_key(obj.resolver_id) != rid_key:
            return VerificationResult.reject("resolver_id_key_mismatch", obj.resolver_id)
        fallback_secret = self.signature_secret if self.allow_hmac_signatures else None
        if not verify_object_signature_with_registry(obj_dict, self.issuer_keys, fallback_secret):
            return VerificationResult.reject("signature_invalid", obj.resolver_id)
        root_status = self.registry.get_root_status(anchor.state_root)
        proof_row = self.indexer.get_proof(obj.resolver_id)
        expected_leaf = merkle_leaf(rid_key, local_hash, obj.object_version, obj.status)
        proof_error = self.proofs.bound_failure_reason(proof_row, root_status, anchor.state_root, expected_leaf)
        if proof_error:
            return VerificationResult.reject(proof_error, obj.resolver_id, root_status=root_status, expected_leaf=expected_leaf)
        semantic_error = self.policy.check_object_semantics(obj, now)
        if semantic_error:
            return VerificationResult.reject(semantic_error, obj.resolver_id)
        if not any(candidate.matches(endpoint) for candidate in obj.endpoints):
            return VerificationResult.reject("endpoint_not_in_object", obj.resolver_id)
        valid_until = parse_rfc3339(obj.valid_until)
        soft, hard = self.policy.expirations(now, valid_until)
        agent_key = extract_agent_key(obj)
        evidence = {
            "endpoint_key": cache_key,
            "resolver_id_key": rid_key,
            "object_hash": local_hash,
            "object_version": obj.object_version,
            "resolver_status": obj.status,
            "state_root": anchor.state_root,
            "chain_status": anchor.status,
            "root_status": root_status,
            "endpoint_binding_status": "MATCHED",
            **agent_key,
        }
        final_bound = self.registry.get_endpoint_binding(cache_key)
        final_anchor = self.registry.get_anchor(rid_key)
        final_root_status = self.registry.get_root_status(anchor.state_root)
        if (
            final_bound != rid_key
            or final_anchor is None
            or final_anchor.status != "ACTIVE"
            or final_anchor.object_hash != local_hash
            or final_anchor.object_version != obj.object_version
            or final_anchor.state_root != anchor.state_root
            or final_root_status != "ACTIVE"
        ):
            return VerificationResult.reject("registry_changed_during_verification", obj.resolver_id)
        if not self.cache.store_verified(
            cache_key, obj.resolver_id, endpoint, local_hash, obj.object_version,
            anchor.state_root, soft, hard, evidence, expected_generation=expected_generation,
        ):
            return VerificationResult.reject("verification_invalidated_during_commit", obj.resolver_id)
        evidence["cache_generation"] = expected_generation
        evidence["cache_generation_owner"] = self.cache.generation_owner
        return VerificationResult.accept(obj.resolver_id, cache="miss", **evidence)


def extract_agent_key(obj: ResolverAuthenticityObjectV1) -> dict[str, str]:
    agent = (obj.attestation or {}).get("agent") or {}
    if not isinstance(agent, dict):
        return {}
    public_key = agent.get("public_key")
    algorithm = str(agent.get("algorithm", "")).lower()
    key_id = agent.get("key_id")
    if not public_key or algorithm != "ed25519":
        return {}
    return {"agent_public_key": public_key, "agent_key_algorithm": "ed25519", "agent_key_id": key_id or "agent-key-01"}
