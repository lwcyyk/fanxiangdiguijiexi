from resolver_identity.admin.object_builder import build_resolver_object
from resolver_identity.common.factory import create_prototype_stack
from resolver_identity.models.endpoint import ResolverEndpoint


def test_hot_cache_path_reports_cache_hit():
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
    endpoint = ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp")
    cold = stack.verifier.verify_endpoint(endpoint)
    hot = stack.verifier.verify_endpoint(endpoint)
    assert cold.accepted and cold.evidence["cache"] == "miss"
    assert hot.accepted and hot.evidence["cache"] == "hit"
