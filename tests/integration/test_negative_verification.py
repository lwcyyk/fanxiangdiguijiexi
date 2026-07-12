import json

from resolver_identity.admin.object_builder import build_resolver_object
from resolver_identity.common.factory import create_prototype_stack
from resolver_identity.crypto.hashes import object_hash, resolver_id_key
from resolver_identity.models.endpoint import ResolverEndpoint


def publish_default(stack, **overrides):
    obj = build_resolver_object(
        overrides.get("resolver_id", "operator-a/resolver-01"),
        "operator-a",
        "Operator A",
        [{"endpoint_id": "udp-01", "ip": "192.0.2.53", "port": 53, "transport": overrides.get("transport", "udp")}],
        overrides.get("valid_from", "2026-07-01T00:00:00Z"),
        overrides.get("valid_until", "2027-07-01T00:00:00Z"),
        object_version=overrides.get("object_version", 1),
        status=overrides.get("status", "ACTIVE"),
    )
    stack.publisher.publish(obj)
    return obj


def test_indexer_tampering_fails_hash_metadata_check():
    stack = create_prototype_stack(signature_secret="secret")
    obj = publish_default(stack)
    row = stack.indexer.get_resolver(obj.resolver_id)
    data = json.loads(row["object_json"])
    data["operator"]["name"] = "Attacker"
    stack.conn.execute("UPDATE resolver_objects SET object_json=? WHERE resolver_id=?", (json.dumps(data), obj.resolver_id))
    stack.conn.commit()

    result = stack.verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp"))
    assert not result.accepted
    assert result.reasons == ["indexer_object_hash_metadata_mismatch"]


def test_chain_hash_mismatch_fails_closed():
    stack = create_prototype_stack(signature_secret="secret")
    obj = publish_default(stack)
    rid_key = resolver_id_key(obj.resolver_id)
    stack.conn.execute("UPDATE registry_anchors SET object_hash=? WHERE resolver_id_key=?", ("0x" + "00" * 32, rid_key))
    stack.conn.commit()

    result = stack.verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp"))
    assert not result.accepted
    assert result.reasons == ["chain_object_hash_mismatch"]


def test_stale_object_version_replay_fails_closed():
    stack = create_prototype_stack(signature_secret="secret")
    obj = publish_default(stack)
    rid_key = resolver_id_key(obj.resolver_id)
    stack.conn.execute("UPDATE registry_anchors SET object_version=? WHERE resolver_id_key=?", (2, rid_key))
    stack.conn.commit()

    result = stack.verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp"))
    assert not result.accepted
    assert result.reasons == ["object_version_mismatch"]


def test_expired_object_fails_closed():
    stack = create_prototype_stack(signature_secret="secret")
    publish_default(stack, valid_until="2020-01-01T00:00:00Z")
    result = stack.verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp"))
    assert not result.accepted
    assert result.reasons == ["object_expired"]


def test_non_active_object_fails_closed():
    stack = create_prototype_stack(signature_secret="secret")
    publish_default(stack, status="SUSPENDED")
    result = stack.verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp"))
    assert not result.accepted
    assert result.reasons == ["chain_status_not_active"]


def test_root_revoked_fails_closed():
    stack = create_prototype_stack(signature_secret="secret")
    obj = publish_default(stack)
    row = stack.indexer.get_resolver(obj.resolver_id)
    stack.registry.publish_root(row["state_root"], "REVOKED")
    result = stack.verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp"))
    assert not result.accepted
    assert result.reasons == ["root_status_invalid"]


def test_transport_policy_rejects_disallowed_transport():
    stack = create_prototype_stack(signature_secret="secret", allowed_transports={"tcp", "doh"})
    publish_default(stack, transport="udp")
    result = stack.verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp"))
    assert not result.accepted
    assert result.reasons == ["transport_not_allowed"]


def test_signature_tampering_fails_closed_when_hash_reanchored_to_tampered_object():
    stack = create_prototype_stack(signature_secret="secret")
    obj = publish_default(stack)
    row = stack.indexer.get_resolver(obj.resolver_id)
    data = json.loads(row["object_json"])
    data["operator"]["name"] = "Attacker"
    tampered_hash = object_hash(data)
    stack.conn.execute("UPDATE resolver_objects SET object_json=?, object_hash=? WHERE resolver_id=?", (json.dumps(data), tampered_hash, obj.resolver_id))
    stack.conn.execute("UPDATE registry_anchors SET object_hash=? WHERE resolver_id_key=?", (tampered_hash, resolver_id_key(obj.resolver_id)))
    stack.conn.commit()

    result = stack.verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp"))
    assert not result.accepted
    assert result.reasons == ["signature_invalid"]
