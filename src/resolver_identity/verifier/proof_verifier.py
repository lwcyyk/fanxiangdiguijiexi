from __future__ import annotations

from resolver_identity.crypto.merkle import verify_merkle_proof


class ProofVerifier:
    def verify(self, proof_row: dict | None, root_status: str | None, expected_root: str | None = None) -> bool:
        """Compatibility membership check for low-level proof callers."""
        return self.failure_reason(proof_row, root_status, expected_root) is None

    def verify_bound(self, proof_row: dict | None, root_status: str | None, expected_root: str | None, expected_leaf: str) -> bool:
        return self.bound_failure_reason(proof_row, root_status, expected_root, expected_leaf) is None

    def failure_reason(self, proof_row: dict | None, root_status: str | None, expected_root: str | None) -> str | None:
        if root_status != "ACTIVE":
            return "root_status_invalid"
        if not proof_row or not expected_root:
            return "merkle_proof_missing"
        proof = proof_row.get("proof") or proof_row
        leaf_hash = proof_row.get("leaf_hash") or proof.get("leaf_hash")
        if not leaf_hash:
            return "merkle_proof_missing_leaf"
        try:
            if not verify_merkle_proof(leaf_hash, proof, expected_root):
                return "merkle_proof_invalid"
        except (KeyError, TypeError, ValueError):
            return "merkle_proof_invalid"
        return None

    def bound_failure_reason(
        self,
        proof_row: dict | None,
        root_status: str | None,
        expected_root: str | None,
        expected_leaf: str,
    ) -> str | None:
        base = self.failure_reason(proof_row, root_status, expected_root)
        if base is not None:
            return base
        assert proof_row is not None and expected_root is not None
        proof = proof_row.get("proof") or proof_row
        row_root = proof_row.get("state_root")
        proof_root = proof.get("root")
        if row_root and row_root.lower() != expected_root.lower():
            return "merkle_proof_root_mismatch"
        if proof_root and proof_root.lower() != expected_root.lower():
            return "merkle_proof_root_mismatch"
        row_leaf = proof_row.get("leaf_hash")
        proof_leaf = proof.get("leaf_hash")
        if row_leaf and row_leaf.lower() != expected_leaf.lower():
            return "merkle_leaf_binding_mismatch"
        if proof_leaf and proof_leaf.lower() != expected_leaf.lower():
            return "merkle_leaf_binding_mismatch"
        if row_leaf and proof_leaf and row_leaf.lower() != proof_leaf.lower():
            return "merkle_leaf_binding_mismatch"
        try:
            if not verify_merkle_proof(expected_leaf, proof, expected_root):
                return "merkle_proof_invalid"
        except (KeyError, TypeError, ValueError):
            return "merkle_proof_invalid"
        return None
