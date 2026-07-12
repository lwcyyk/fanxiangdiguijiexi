from resolver_identity.crypto.hashes import sha256_hex
from resolver_identity.crypto.merkle import build_merkle_proof, merkle_leaf, merkle_root, verify_merkle_proof


def test_merkle_single_leaf_proof_verifies():
    leaf = merkle_leaf("0x" + "11" * 32, "0x" + "22" * 32, 1, "ACTIVE")
    root = merkle_root([leaf])
    proof = build_merkle_proof([leaf], 0)
    assert proof["root"] == root
    assert verify_merkle_proof(leaf, proof, root)


def test_merkle_multi_leaf_proof_verifies_and_tamper_fails():
    leaves = [sha256_hex(f"leaf:{idx}") for idx in range(3)]
    root = merkle_root(leaves)
    proof = build_merkle_proof(leaves, 1)
    assert verify_merkle_proof(leaves[1], proof, root)
    assert not verify_merkle_proof(leaves[1], proof, sha256_hex("wrong-root"))
    tampered = dict(proof)
    tampered["siblings"] = list(proof["siblings"])
    tampered["siblings"][0] = {**tampered["siblings"][0], "hash": sha256_hex("tampered")}
    assert not verify_merkle_proof(leaves[1], tampered, root)
