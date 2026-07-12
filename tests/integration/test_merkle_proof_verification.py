import json

from resolver_identity.admin.object_builder import build_resolver_object
from resolver_identity.common.factory import create_prototype_stack
from resolver_identity.crypto.hashes import object_hash, resolver_id_key
from resolver_identity.crypto.merkle import build_merkle_proof, merkle_leaf, merkle_root
from resolver_identity.models.endpoint import ResolverEndpoint


def test_missing_merkle_proof_fails_closed():
    stack = create_prototype_stack(signature_secret="secret")
    obj = build_resolver_object(
        "operator-a/resolver-01",
        "operator-a",
        "Operator A",
        [{"ip": "192.0.2.53", "port": 53, "transport": "udp"}],
        "2026-07-01T00:00:00Z",
        "2027-07-01T00:00:00Z",
    )
    stack.publisher.publish(obj)
    stack.conn.execute("DELETE FROM resolver_proofs WHERE resolver_id=?", (obj.resolver_id,))
    stack.conn.commit()
    result = stack.verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp"))
    assert not result.accepted
    assert result.reasons == ["merkle_proof_missing"]


def test_tampered_merkle_proof_fails_closed():
    stack = create_prototype_stack(signature_secret="secret")
    obj = build_resolver_object(
        "operator-a/resolver-01",
        "operator-a",
        "Operator A",
        [{"ip": "192.0.2.53", "port": 53, "transport": "udp"}],
        "2026-07-01T00:00:00Z",
        "2027-07-01T00:00:00Z",
    )
    stack.publisher.publish(obj)
    row = stack.indexer.get_proof(obj.resolver_id)
    proof = row["proof"]
    proof["root"] = "0x" + "00" * 32
    stack.conn.execute("UPDATE resolver_proofs SET proof_json=? WHERE resolver_id=?", (json.dumps(proof), obj.resolver_id))
    stack.conn.commit()
    result = stack.verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp"))
    assert not result.accepted
def test_valid_proof_for_another_leaf_cannot_be_substituted():
    stack = create_prototype_stack(signature_secret="secret")
    objects = []
    for resolver_id, ip in (("operator-a/resolver-a", "192.0.2.53"), ("operator-a/resolver-b", "192.0.2.54")):
        obj = build_resolver_object(
            resolver_id,
            "operator-a",
            "Operator A",
            [{"ip": ip, "port": 53, "transport": "udp"}],
            "2026-07-01T00:00:00Z",
            "2027-07-01T00:00:00Z",
        )
        stack.publisher.publish(obj)
        objects.append(obj)

    rows = [stack.indexer.get_resolver(obj.resolver_id) for obj in objects]
    leaves = [merkle_leaf(resolver_id_key(obj.resolver_id), object_hash(json.loads(row["object_json"])), obj.object_version, obj.status) for obj, row in zip(objects, rows)]
    shared_root = merkle_root(leaves)
    for index, (obj, row) in enumerate(zip(objects, rows)):
        proof = build_merkle_proof(leaves, index)
        stack.conn.execute(
            "UPDATE resolver_proofs SET leaf_hash=?, proof_json=?, state_root=? WHERE resolver_id=?",
            (leaves[index], json.dumps(proof), shared_root, obj.resolver_id),
        )
        stack.conn.execute("UPDATE resolver_objects SET state_root=? WHERE resolver_id=?", (shared_root, obj.resolver_id))
        stack.conn.execute("UPDATE registry_anchors SET state_root=? WHERE resolver_id_key=?", (shared_root, resolver_id_key(obj.resolver_id)))
    stack.registry.publish_root(shared_root, "ACTIVE")
    stack.conn.commit()

    proof_b = stack.indexer.get_proof(objects[1].resolver_id)
    stack.conn.execute(
        "UPDATE resolver_proofs SET leaf_hash=?, proof_json=?, state_root=? WHERE resolver_id=?",
        (proof_b["leaf_hash"], json.dumps(proof_b["proof"]), shared_root, objects[0].resolver_id),
    )
    stack.conn.commit()

    result = stack.verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp"))

    assert not result.accepted
    assert result.reasons == ["merkle_leaf_binding_mismatch"]


def test_proof_row_root_must_match_chain_anchor_root():
    stack = create_prototype_stack(signature_secret="secret")
    obj = build_resolver_object(
        "operator-a/resolver-01",
        "operator-a",
        "Operator A",
        [{"ip": "192.0.2.53", "port": 53, "transport": "udp"}],
        "2026-07-01T00:00:00Z",
        "2027-07-01T00:00:00Z",
    )
    stack.publisher.publish(obj)
    stack.conn.execute("UPDATE resolver_proofs SET state_root=? WHERE resolver_id=?", ("0x" + "44" * 32, obj.resolver_id))
    stack.conn.commit()

    result = stack.verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp"))

    assert not result.accepted
    assert result.reasons == ["merkle_proof_root_mismatch"]
