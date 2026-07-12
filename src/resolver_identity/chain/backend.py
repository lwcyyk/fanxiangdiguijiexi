from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


STATUS_BY_ID = {
    0: "UNKNOWN",
    1: "ACTIVE",
    2: "SUSPENDED",
    3: "REVOKED",
    4: "EXPIRED",
}
STATUS_TO_ID = {value: key for key, value in STATUS_BY_ID.items()}


@dataclass(slots=True)
class ResolverAnchor:
    resolver_id_key: str
    object_hash: str
    state_root: str
    object_version: int
    valid_until: int
    status: str


class RegistryBackend(Protocol):
    def get_anchor(self, resolver_id_key: str) -> ResolverAnchor | None: ...
    def get_resolver_anchor(self, resolver_id_key: str) -> ResolverAnchor | None: ...
    def get_root_status(self, state_root: str) -> str | None: ...
    def get_endpoint_binding(self, endpoint_key: str) -> str | None: ...
    def lookup_resolver_by_endpoint(self, endpoint_key: str) -> str | None: ...
    def publish_root(self, state_root: str, status: str = "ACTIVE", version: int = 1) -> None: ...
    def publish_resolver(self, resolver_id_key: str, object_hash: str, state_root: str, object_version: int, valid_until: int, status: str = "ACTIVE") -> None: ...
    def update_resolver(self, resolver_id_key: str, object_hash: str, state_root: str, object_version: int, valid_until: int, status: str = "ACTIVE") -> None: ...
    def revoke_resolver(self, resolver_id_key: str) -> None: ...
    def revoke_root(self, state_root: str) -> None: ...
    def bind_endpoint(self, endpoint_key: str, resolver_id_key: str) -> None: ...
    def unbind_endpoint(self, endpoint_key: str) -> None: ...


def normalize_bytes32(value: str | bytes) -> str:
    if isinstance(value, bytes):
        if len(value) != 32:
            raise ValueError("bytes32 value must be exactly 32 bytes")
        return "0x" + value.hex()
    if not isinstance(value, str):
        raise TypeError("bytes32 value must be str or bytes")
    prefix = value[:2].lower()
    raw = value[2:] if prefix == "0x" else value
    if len(raw) != 64:
        raise ValueError("bytes32 hex value must be 32 bytes")
    int(raw, 16)
    return "0x" + raw.lower()


def bytes32_to_bytes(value: str | bytes) -> bytes:
    return bytes.fromhex(normalize_bytes32(value)[2:])


def decode_status(value: int | str) -> str:
    if isinstance(value, str):
        upper = value.upper()
        if upper in STATUS_TO_ID:
            return upper
        if value.isdigit():
            return STATUS_BY_ID.get(int(value), "UNKNOWN")
        return upper
    return STATUS_BY_ID.get(int(value), "UNKNOWN")


def encode_status(value: str | int) -> int:
    if isinstance(value, int):
        return value
    return STATUS_TO_ID[value.upper()]


def decode_anchor(raw) -> ResolverAnchor | None:
    if raw is None:
        return None
    if isinstance(raw, dict):
        resolver_id_key = raw.get("resolverIdKey") or raw.get("resolver_id_key")
        object_hash = raw.get("objectHash") or raw.get("object_hash")
        state_root = raw.get("stateRoot") or raw.get("state_root")
        object_version = raw.get("objectVersion") or raw.get("object_version")
        valid_until = raw.get("validUntil") or raw.get("valid_until")
        status = raw.get("status")
    else:
        resolver_id_key, object_hash, state_root, object_version, valid_until, status = raw
    resolver_id_key = normalize_bytes32(resolver_id_key)
    if int(resolver_id_key, 16) == 0:
        return None
    return ResolverAnchor(
        resolver_id_key=resolver_id_key,
        object_hash=normalize_bytes32(object_hash),
        state_root=normalize_bytes32(state_root),
        object_version=int(object_version),
        valid_until=int(valid_until),
        status=decode_status(status),
    )
