from __future__ import annotations

import hashlib

from resolver_identity.crypto.canonical_json import canonical_json_bytes
from resolver_identity.models.endpoint import canonical_ip, normalize_name


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return "0x" + hashlib.sha256(data).hexdigest()


def object_hash(obj_dict: dict) -> str:
    return sha256_hex(canonical_json_bytes(obj_dict))


def ip_lookup_key(ip: str) -> str:
    return sha256_hex("ip:" + canonical_ip(ip))


def name_lookup_key(name: str) -> str:
    return sha256_hex("name:" + normalize_name(name))


def resolver_id_key(resolver_id: str) -> str:
    return sha256_hex("resolver-id:" + normalize_name(resolver_id))
