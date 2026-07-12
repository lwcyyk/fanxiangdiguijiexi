from __future__ import annotations

from resolver_identity.crypto.hashes import sha256_hex


def _hex_to_bytes(value: str) -> bytes:
    value = value[2:] if value.startswith("0x") else value
    return bytes.fromhex(value)


def _bytes_to_hex(value: bytes) -> str:
    return "0x" + value.hex()


def merkle_leaf(resolver_id_key: str, object_hash: str, object_version: int, status: str) -> str:
    payload = "|".join(["resolver-leaf-v1", resolver_id_key.lower(), object_hash.lower(), str(object_version), status.upper()])
    return sha256_hex(payload)


def merkle_parent(left: str, right: str) -> str:
    return _bytes_to_hex(__import__('hashlib').sha256(b"node-v1" + _hex_to_bytes(left) + _hex_to_bytes(right)).digest())


def merkle_root(leaves: list[str]) -> str:
    if not leaves:
        return sha256_hex("empty-root-v1")
    level = [leaf.lower() for leaf in leaves]
    while len(level) > 1:
        next_level: list[str] = []
        for idx in range(0, len(level), 2):
            left = level[idx]
            right = level[idx + 1] if idx + 1 < len(level) else left
            next_level.append(merkle_parent(left, right))
        level = next_level
    return level[0]


def build_merkle_proof(leaves: list[str], target_index: int) -> dict:
    if target_index < 0 or target_index >= len(leaves):
        raise IndexError("target_index outside leaves")
    proof = []
    index = target_index
    level = [leaf.lower() for leaf in leaves]
    while len(level) > 1:
        sibling_index = index ^ 1
        if sibling_index >= len(level):
            sibling_index = index
        proof.append({"position": "left" if sibling_index < index else "right", "hash": level[sibling_index]})
        next_level = []
        for idx in range(0, len(level), 2):
            left = level[idx]
            right = level[idx + 1] if idx + 1 < len(level) else left
            next_level.append(merkle_parent(left, right))
        index //= 2
        level = next_level
    return {"leaf_hash": leaves[target_index].lower(), "siblings": proof, "root": level[0] if level else merkle_root([])}


def verify_merkle_proof(leaf_hash: str, proof: dict, expected_root: str) -> bool:
    current = leaf_hash.lower()
    for item in proof.get("siblings", []):
        sibling = item["hash"].lower()
        if item.get("position") == "left":
            current = merkle_parent(sibling, current)
        else:
            current = merkle_parent(current, sibling)
    return current.lower() == expected_root.lower() and proof.get("root", expected_root).lower() == expected_root.lower()
