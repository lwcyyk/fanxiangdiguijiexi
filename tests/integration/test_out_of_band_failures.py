from resolver_identity.admin.object_builder import build_resolver_object
from resolver_identity.common.factory import create_prototype_stack
from resolver_identity.models.endpoint import ResolverEndpoint


def publish(stack):
    obj = build_resolver_object(
        "operator-a/resolver-01",
        "operator-a",
        "Operator A",
        [{"ip": "192.0.2.53", "port": 53, "transport": "udp"}],
        "2026-07-01T00:00:00Z",
        "2027-07-01T00:00:00Z",
    )
    stack.publisher.publish(obj)
    return obj


def test_valid_hot_cache_survives_indexer_and_registry_unavailable():
    stack = create_prototype_stack(signature_secret="secret")
    publish(stack)
    endpoint = ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp")
    cold = stack.verifier.verify_endpoint(endpoint)
    assert cold.accepted

    def unavailable(*args, **kwargs):
        raise ConnectionError("out-of-band unavailable")

    stack.indexer.lookup = unavailable
    stack.registry.get_endpoint_binding = unavailable
    stack.registry.get_anchor = unavailable
    hot = stack.verifier.verify_endpoint(endpoint)
    assert hot.accepted
    assert hot.evidence["cache"] == "hit"


def test_no_cache_fails_closed_when_indexer_unavailable():
    stack = create_prototype_stack(signature_secret="secret")
    endpoint = ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp")

    def unavailable(*args, **kwargs):
        raise ConnectionError("indexer unavailable")

    stack.indexer.lookup = unavailable
    result = stack.verifier.verify_endpoint(endpoint)
    assert not result.accepted
    assert result.reasons == ["out_of_band_unavailable"]


def test_no_cache_fails_closed_when_registry_unavailable():
    stack = create_prototype_stack(signature_secret="secret")
    publish(stack)
    endpoint = ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp")

    def unavailable(*args, **kwargs):
        raise ConnectionError("registry unavailable")

    stack.registry.get_endpoint_binding = unavailable
    result = stack.verifier.verify_endpoint(endpoint)
    assert not result.accepted
    assert result.reasons == ["out_of_band_unavailable"]


def test_expired_cache_fails_closed_when_out_of_band_unavailable():
    stack = create_prototype_stack(signature_secret="secret")
    publish(stack)
    endpoint = ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp")
    assert stack.verifier.verify_endpoint(endpoint).accepted

    # Force both in-memory and persistent cache entries beyond hard TTL.
    for row in stack.cache.memory.values():
        row["hard_expire_at"] = "2020-01-01T00:00:00Z"
    stack.conn.execute("UPDATE trusted_cache SET hard_expire_at='2020-01-01T00:00:00Z'")
    stack.conn.commit()

    def unavailable(*args, **kwargs):
        raise ConnectionError("out-of-band unavailable")

    stack.indexer.lookup = unavailable
    result = stack.verifier.verify_endpoint(endpoint)
    assert not result.accepted
    assert result.reasons == ["out_of_band_unavailable"]
