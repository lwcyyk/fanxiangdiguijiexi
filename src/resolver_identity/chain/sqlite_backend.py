from __future__ import annotations

from resolver_identity.chain.backend import ResolverAnchor
from resolver_identity.db.repositories import RegistryRepository


class SQLiteRegistryBackend:
    """SQLite test double for the Solidity registry backend."""

    def __init__(self, repository: RegistryRepository):
        self.repository = repository

    def publish_resolver(self, resolver_id_key: str, object_hash: str, state_root: str, object_version: int, valid_until: int, status: str = "ACTIVE") -> None:
        self.repository.publish_anchor(resolver_id_key, object_hash, state_root, object_version, valid_until, status)

    def update_resolver(self, resolver_id_key: str, object_hash: str, state_root: str, object_version: int, valid_until: int, status: str = "ACTIVE") -> None:
        self.repository.publish_anchor(resolver_id_key, object_hash, state_root, object_version, valid_until, status)

    def revoke_resolver(self, resolver_id_key: str) -> None:
        self.repository.revoke_resolver(resolver_id_key)

    def bind_endpoint(self, endpoint_key: str, resolver_id_key: str) -> None:
        self.repository.bind_endpoint(endpoint_key, resolver_id_key)

    def unbind_endpoint(self, endpoint_key: str) -> None:
        self.repository.unbind_endpoint(endpoint_key)

    def publish_root(self, state_root: str, status: str = "ACTIVE", version: int = 1) -> None:
        self.repository.publish_root(state_root, status)

    def revoke_root(self, state_root: str) -> None:
        self.repository.publish_root(state_root, "REVOKED")

    def get_anchor(self, resolver_id_key: str) -> ResolverAnchor | None:
        row = self.repository.get_anchor(resolver_id_key)
        return ResolverAnchor(**row) if row else None

    def get_resolver_anchor(self, resolver_id_key: str) -> ResolverAnchor | None:
        return self.get_anchor(resolver_id_key)

    def get_endpoint_binding(self, endpoint_key: str) -> str | None:
        return self.repository.get_endpoint_binding(endpoint_key)

    def lookup_resolver_by_endpoint(self, endpoint_key: str) -> str | None:
        return self.get_endpoint_binding(endpoint_key)

    def get_root_status(self, state_root: str) -> str | None:
        return self.repository.get_root_status(state_root)


SQLiteRegistryClient = SQLiteRegistryBackend
