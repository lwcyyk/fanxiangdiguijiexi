from resolver_identity.admin.object_builder import build_resolver_object
from resolver_identity.common.factory import create_prototype_stack
from resolver_identity.crypto.keys import IssuerKeyRegistry, IssuerPublicKey
from resolver_identity.crypto.signatures import generate_ed25519_keypair
from resolver_identity.models.endpoint import ResolverEndpoint


def test_ed25519_issuer_key_verifies_object_signature():
    private_key, public_key = generate_ed25519_keypair()
    keys = IssuerKeyRegistry([IssuerPublicKey("resolver-trust-authority-01", "issuer-key-01", "ed25519", public_key)])
    stack = create_prototype_stack(
        signature_secret="fallback-secret",
        issuer_keys=keys,
        ed25519_private_key_b64=private_key,
    )
    obj = build_resolver_object(
        "operator-a/resolver-01",
        "operator-a",
        "Operator A",
        [{"ip": "192.0.2.53", "port": 53, "transport": "udp"}],
        "2026-07-01T00:00:00Z",
        "2027-07-01T00:00:00Z",
    )
    stack.publisher.publish(obj)
    result = stack.verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp"))
    assert result.accepted, result.to_dict()


def test_missing_issuer_key_rejects_ed25519_signature():
    private_key, _ = generate_ed25519_keypair()
    stack = create_prototype_stack(
        signature_secret="fallback-secret",
        issuer_keys=IssuerKeyRegistry([]),
        ed25519_private_key_b64=private_key,
    )
    obj = build_resolver_object(
        "operator-a/resolver-01",
        "operator-a",
        "Operator A",
        [{"ip": "192.0.2.53", "port": 53, "transport": "udp"}],
        "2026-07-01T00:00:00Z",
        "2027-07-01T00:00:00Z",
    )
    stack.publisher.publish(obj)
    result = stack.verifier.verify_endpoint(ResolverEndpoint(ip="192.0.2.53", port=53, transport="udp"))
    assert not result.accepted
    assert result.reasons == ["signature_invalid"]
