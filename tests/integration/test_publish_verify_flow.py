from resolver_identity.admin.object_builder import build_resolver_object
from resolver_identity.common.factory import create_prototype_stack
from resolver_identity.crypto.hashes import resolver_id_key
from resolver_identity.models.endpoint import ResolverEndpoint


def test_publish_verify_cache_revoke_flow():
    stack = create_prototype_stack(signature_secret="secret")
    obj = build_resolver_object(
        "operator-a/resolver-01",
        "operator-a",
        "Operator A",
        [{"endpoint_id": "udp-01", "ip": "192.0.2.53", "port": 53, "transport": "udp"}],
        "2026-07-01T00:00:00Z",
        "2027-07-01T00:00:00Z",
    )
    published = stack.publisher.publish(obj)
    assert published["object_hash"].startswith("0x")

    endpoint = ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp")
    cold = stack.verifier.verify_endpoint(endpoint)
    assert cold.accepted, cold.to_dict()
    assert cold.evidence["cache"] == "miss"

    hot = stack.verifier.verify_endpoint(endpoint)
    assert hot.accepted, hot.to_dict()
    assert hot.evidence["cache"] == "hit"

    stack.registry.revoke_resolver(resolver_id_key(obj.resolver_id))
    stack.cache.invalidate_resolver(obj.resolver_id, "REVOKED")
    revoked = stack.verifier.verify_endpoint(endpoint)
    assert not revoked.accepted
    assert revoked.reasons == ["cache_revoked"]


def test_endpoint_mismatch_fails_closed():
    stack = create_prototype_stack(signature_secret="secret")
    obj = build_resolver_object(
        "operator-a/resolver-01",
        "operator-a",
        "Operator A",
        [{"endpoint_id": "udp-01", "ip": "192.0.2.53", "port": 53, "transport": "udp"}],
        "2026-07-01T00:00:00Z",
        "2027-07-01T00:00:00Z",
    )
    stack.publisher.publish(obj)
    result = stack.verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.54", port=53, transport="udp"))
    assert not result.accepted
    assert result.reasons == ["lookup_not_found"]
