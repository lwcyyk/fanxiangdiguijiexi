from __future__ import annotations

from resolver_identity.crypto.hashes import sha256_hex
from resolver_identity.models.endpoint import ResolverEndpoint


def trusted_cache_key(endpoint: ResolverEndpoint, resolver_id: str | None = None, object_version: int | None = None) -> str:
    endpoint = endpoint.normalized()
    parts = [
        "trusted-cache-v1",
        resolver_id or "",
        endpoint.ip or "",
        str(endpoint.port or ""),
        endpoint.transport or "",
        endpoint.server_name or "",
        endpoint.uri or "",
        str(object_version) if object_version is not None else "",
    ]
    return sha256_hex("|".join(parts))
