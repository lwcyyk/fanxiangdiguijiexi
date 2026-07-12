from __future__ import annotations

from resolver_identity.admin.object_builder import build_resolver_object
from resolver_identity.common.factory import create_prototype_stack
from resolver_identity.crypto.hashes import resolver_id_key
from resolver_identity.models.endpoint import ResolverEndpoint
from resolver_identity.wrapper.dns_message import make_servfail


def main() -> None:
    stack = create_prototype_stack(signature_secret="demo-secret")
    obj = build_resolver_object(
        resolver_id="operator-a/resolver-01",
        operator_id="operator-a",
        operator_name="Operator A",
        endpoints=[{"endpoint_id": "udp-01", "ip": "192.0.2.53", "port": 53, "transport": "udp"}],
        valid_from="2026-07-01T00:00:00Z",
        valid_until="2027-07-01T00:00:00Z",
    )
    published = stack.publisher.publish(obj)
    endpoint = ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp")
    first = stack.verifier.verify_endpoint(endpoint)
    second = stack.verifier.verify_endpoint(endpoint)
    stack.registry.revoke_resolver(resolver_id_key(obj.resolver_id))
    stack.cache.invalidate_resolver(obj.resolver_id, "REVOKED")
    revoked = stack.verifier.verify_endpoint(endpoint)

    query = bytes.fromhex("123401000001000000000000") + b"\x07example\x03com\x00\x00\x01\x00\x01"
    servfail = make_servfail(query)

    print("published:", published)
    print("first verification:", first.to_dict())
    print("hot-cache verification:", second.to_dict())
    print("after revocation:", revoked.to_dict())
    print("servfail_rcode:", servfail[3] & 0x0F)


if __name__ == "__main__":
    main()
