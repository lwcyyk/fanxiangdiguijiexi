from __future__ import annotations

from resolver_identity.common.time import parse_rfc3339
from resolver_identity.crypto.canonical_json import canonical_json_text
from resolver_identity.crypto.hashes import ip_lookup_key, name_lookup_key, object_hash, resolver_id_key, sha256_hex
from resolver_identity.crypto.merkle import build_merkle_proof, merkle_leaf, merkle_root
from resolver_identity.crypto.signatures import sign_object, sign_object_ed25519
from resolver_identity.db.repositories import IndexerRepository
from resolver_identity.models.authenticity_object import ResolverAuthenticityObjectV1
from resolver_identity.models.endpoint import ResolverEndpoint
from resolver_identity.chain.backend import RegistryBackend


class AdminPublisher:
    def __init__(
        self,
        indexer: IndexerRepository,
        registry: RegistryBackend,
        signature_secret: str,
        ed25519_private_key_b64: str | None = None,
    ):
        self.indexer = indexer
        self.registry = registry
        self.signature_secret = signature_secret
        self.ed25519_private_key_b64 = ed25519_private_key_b64

    def publish(self, obj: ResolverAuthenticityObjectV1, state_root: str | None = None) -> dict:
        rid_key = resolver_id_key(obj.resolver_id)
        unsigned = obj.to_dict(include_signature=False)
        if self.ed25519_private_key_b64:
            obj.signature = sign_object_ed25519(unsigned, self.ed25519_private_key_b64)
        else:
            obj.signature = sign_object(unsigned, self.signature_secret)
        signed = obj.to_dict(include_signature=True)
        obj_hash = object_hash(signed)
        leaf = merkle_leaf(rid_key, obj_hash, obj.object_version, obj.status)
        proof = build_merkle_proof([leaf], 0)
        state_root = state_root or merkle_root([leaf])
        endpoint_pairs: list[tuple[ResolverEndpoint, str]] = []
        for endpoint in obj.endpoints:
            key = endpoint_lookup_key(endpoint)
            endpoint_pairs.append((endpoint, key))
        new_endpoint_keys = {key for _, key in endpoint_pairs}
        previous_endpoint_keys = set(self.indexer.list_endpoint_keys(obj.resolver_id))
        valid_until_epoch = int(parse_rfc3339(obj.valid_until).timestamp())

        root_status = self.registry.get_root_status(state_root)
        if root_status == "REVOKED":
            raise ValueError("cannot reuse a revoked state root")
        if root_status != "ACTIVE":
            self.registry.publish_root(state_root, "ACTIVE")

        current_anchor = self.registry.get_anchor(rid_key)
        idempotent = False
        if current_anchor is None:
            self.registry.publish_resolver(rid_key, obj_hash, state_root, obj.object_version, valid_until_epoch, obj.status)
        elif current_anchor.object_version == obj.object_version:
            if current_anchor.object_hash != obj_hash or current_anchor.state_root != state_root or current_anchor.status != obj.status:
                raise ValueError("resolver object_version already exists with different anchored content")
            idempotent = True
        elif current_anchor.object_version > obj.object_version:
            raise ValueError("resolver object_version must increase")
        else:
            self.registry.update_resolver(rid_key, obj_hash, state_root, obj.object_version, valid_until_epoch, obj.status)

        for _, key in endpoint_pairs:
            self.registry.bind_endpoint(key, rid_key)
        for removed_key in previous_endpoint_keys - new_endpoint_keys:
            if self.registry.get_endpoint_binding(removed_key) == rid_key:
                self.registry.unbind_endpoint(removed_key)

        self.indexer.upsert_resolver_object(obj, obj_hash, state_root)
        self.indexer.put_proof(obj.resolver_id, leaf, proof, state_root)
        for endpoint, key in endpoint_pairs:
            self.indexer.put_lookup(key, obj.resolver_id)
            if endpoint.ip:
                self.indexer.put_lookup(ip_lookup_key(endpoint.ip), obj.resolver_id)
            if endpoint.server_name:
                self.indexer.put_lookup(name_lookup_key(endpoint.server_name), obj.resolver_id)
        for removed_key in previous_endpoint_keys - new_endpoint_keys:
            self.indexer.delete_lookup(removed_key, obj.resolver_id)
        self.indexer.put_lookup(rid_key, obj.resolver_id)
        self.indexer.replace_endpoints(obj.resolver_id, endpoint_pairs)
        self.indexer.publish_root(state_root, "ACTIVE")
        return {
            "resolver_id": obj.resolver_id,
            "resolver_id_key": rid_key,
            "object_hash": obj_hash,
            "leaf_hash": leaf,
            "state_root": state_root,
            "signature": obj.signature,
            "idempotent": idempotent,
        }


def endpoint_lookup_key(endpoint: ResolverEndpoint) -> str:
    endpoint = endpoint.normalized()
    if not (endpoint.ip or endpoint.server_name or endpoint.uri):
        raise ValueError("endpoint must include ip, server_name, or uri")
    binding = endpoint.to_dict()
    binding.pop("endpoint_id", None)
    return sha256_hex("endpoint-v2:" + canonical_json_text(binding))
